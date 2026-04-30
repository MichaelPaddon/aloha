// Request counters, per-status-class tallies, latency histogram, and a
// sliding-window request-rate ring buffer.  All fields use atomics so
// metrics can be read from the status handler without locking.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::time::interval;

// Ring-buffer slot width: one entry per WINDOW_SECS seconds.
pub const WINDOW_SECS: u64 = 5;
// 180 x 5 s = 15 minutes of history.
const HISTORY_SLOTS: usize = 180;
// How many slots to expose in Snapshot history slices (2.5 minutes).
const SPARKLINE_SLOTS: usize = 30;
// Cap on distinct paths to track; prevents unbounded allocations.
const MAX_TRACKED_PATHS: usize = 200;
// How many top paths to include in each window snapshot.
const TOP_PATHS_LIMIT: usize = 20;

// -- Core data ----------------------------------------------------

pub struct Metrics {
    pub start_time: Instant,
    // Counters incremented atomically per request.
    pub requests_total: AtomicU64,
    // In-flight request count (inc before handler, dec after).
    pub requests_active: AtomicI64,
    pub status_2xx: AtomicU64,
    pub status_3xx: AtomicU64,
    pub status_4xx: AtomicU64,
    pub status_5xx: AtomicU64,
    // Latency histogram: <1ms <10ms <50ms <200ms <1s >=1s
    pub latency: [AtomicU64; 6],
    // Written only by the background tick task.
    history: Mutex<RateHistory>,
    // Per-path hit counts, written per-request and flushed each tick.
    path_history: Mutex<PathHistory>,
}

struct PathHistory {
    // Ring buffer of per-window path hit maps (aligned with RateHistory).
    slots: Vec<HashMap<String, u64>>,
    // Accumulator for the current in-progress window.
    current: HashMap<String, u64>,
    // All-time totals (bounded by MAX_TRACKED_PATHS).
    total: HashMap<String, u64>,
    // Next-write index, kept in step with RateHistory.head.
    head: usize,
}

struct RateHistory {
    // Per-window request counts. head is the *next write* index.
    slots: [u64; HISTORY_SLOTS],
    // VmRSS KiB per slot; 0 means no data (pre-tick or non-Linux).
    mem_slots: [u64; HISTORY_SLOTS],
    // CPU ticks delta per slot (utime+stime from /proc/self/stat).
    cpu_slots: [u64; HISTORY_SLOTS],
    head: usize,
    // requests_total at the end of the previous tick.
    last_total: u64,
    // CPU ticks at the previous tick; 0 means not yet sampled.
    last_cpu_ticks: u64,
}

// -- Snapshot (used by the status handler) ------------------------

pub struct Snapshot {
    pub uptime: Duration,
    pub requests_total: u64,
    pub requests_active: i64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    // Counts per latency bucket: <1ms <10ms <50ms <200ms <1s >=1s
    pub latency: [u64; 6],
    // Requests/second over the partial current window,
    // and completed 1/5/15-minute windows.
    pub rate_current: f64,
    pub rate_1min: f64,
    pub rate_5min: f64,
    pub rate_15min: f64,
    // Resident set size in KiB; None on non-Linux platforms.
    pub memory_kb: Option<u64>,
    // Process CPU percentage (utime+stime); None on non-Linux.
    pub cpu_percent: Option<f64>,
    // Last SPARKLINE_SLOTS request-rate samples, oldest first.
    pub rate_history: Vec<f64>,
    // Last SPARKLINE_SLOTS memory samples (KiB); None = no data.
    pub memory_history: Vec<Option<u64>>,
    // Last SPARKLINE_SLOTS CPU percentage samples; None = no data.
    pub cpu_history: Vec<Option<f64>>,
    // Top-N paths by hit count for each window (path, count).
    pub top_paths_1min:  Vec<(String, u64)>,
    pub top_paths_5min:  Vec<(String, u64)>,
    pub top_paths_15min: Vec<(String, u64)>,
    pub top_paths_total: Vec<(String, u64)>,
}

impl Snapshot {
    // Human-readable uptime: "2d 3h 14m" / "45m 30s" / "8s".
    pub fn uptime_human(&self) -> String {
        let s = self.uptime.as_secs();
        let (d, h, m, s) = (
            s / 86400,
            (s % 86400) / 3600,
            (s % 3600) / 60,
            s % 60,
        );
        if d > 0 {
            format!("{d}d {h}h {m}m")
        } else if h > 0 {
            format!("{h}h {m}m {s}s")
        } else if m > 0 {
            format!("{m}m {s}s")
        } else {
            format!("{s}s")
        }
    }
}

// -- Metrics implementation ----------------------------------------

impl Metrics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            requests_total: AtomicU64::new(0),
            requests_active: AtomicI64::new(0),
            status_2xx: AtomicU64::new(0),
            status_3xx: AtomicU64::new(0),
            status_4xx: AtomicU64::new(0),
            status_5xx: AtomicU64::new(0),
            latency: std::array::from_fn(|_| AtomicU64::new(0)),
            history: Mutex::new(RateHistory {
                slots: [0u64; HISTORY_SLOTS],
                mem_slots: [0u64; HISTORY_SLOTS],
                cpu_slots: [0u64; HISTORY_SLOTS],
                head: 0,
                last_total: 0,
                last_cpu_ticks: 0,
            }),
            path_history: Mutex::new(PathHistory {
                slots: (0..HISTORY_SLOTS)
                    .map(|_| HashMap::new())
                    .collect(),
                current: HashMap::new(),
                total: HashMap::new(),
                head: 0,
            }),
        }
    }

    // Record a hit for the given URI path.  Call once per request,
    // with the path portion only (no query string).  Bounded to
    // MAX_TRACKED_PATHS distinct paths to prevent unbounded allocation.
    pub fn record_path(&self, path: &str) {
        let p = if path.len() > 128 {
            &path[..128]
        } else {
            path
        };
        let mut ph = self
            .path_history
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let under_cap = ph.total.len() < MAX_TRACKED_PATHS;
        if under_cap || ph.total.contains_key(p) {
            *ph.total.entry(p.to_owned()).or_insert(0) += 1;
        }
        let cur_under = ph.current.len() < MAX_TRACKED_PATHS;
        if cur_under || ph.current.contains_key(p) {
            *ph.current.entry(p.to_owned()).or_insert(0) += 1;
        }
    }

    // Called once per completed request.  Does not touch requests_active.
    pub fn record(&self, status: u16, latency_ms: u128) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        match status / 100 {
            2 => { self.status_2xx.fetch_add(1, Ordering::Relaxed); }
            3 => { self.status_3xx.fetch_add(1, Ordering::Relaxed); }
            4 => { self.status_4xx.fetch_add(1, Ordering::Relaxed); }
            5 => { self.status_5xx.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
        let bucket = match latency_ms {
            ms if ms < 1    => 0,
            ms if ms < 10   => 1,
            ms if ms < 50   => 2,
            ms if ms < 200  => 3,
            ms if ms < 1000 => 4,
            _               => 5,
        };
        self.latency[bucket].fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_active(&self) {
        self.requests_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active(&self) {
        self.requests_active.fetch_sub(1, Ordering::Relaxed);
    }

    // Collect a snapshot for the status handler.
    pub fn snapshot(&self) -> Snapshot {
        let total = self.requests_total.load(Ordering::Relaxed);
        let hist = self.history.lock().unwrap_or_else(|p| p.into_inner());

        // Current-window rate: requests since the last tick.
        let since_last = total.saturating_sub(hist.last_total);
        let rate_current = since_last as f64 / WINDOW_SECS as f64;

        let rate_1min  = window_rate(&hist, 12);   // 12 x 5 s = 60 s
        let rate_5min  = window_rate(&hist, 60);   // 60 x 5 s = 300 s
        let rate_15min = window_rate(&hist, 180);  // 180 x 5 s = 900 s

        // Oldest-first slices of the last SPARKLINE_SLOTS ticks.
        let n = SPARKLINE_SLOTS;
        let rate_history: Vec<f64> = (0..n)
            .map(|i| {
                let idx =
                    (hist.head + HISTORY_SLOTS - n + i) % HISTORY_SLOTS;
                hist.slots[idx] as f64 / WINDOW_SECS as f64
            })
            .collect();
        let memory_history: Vec<Option<u64>> = (0..n)
            .map(|i| {
                let idx =
                    (hist.head + HISTORY_SLOTS - n + i) % HISTORY_SLOTS;
                let v = hist.mem_slots[idx];
                if v == 0 { None } else { Some(v) }
            })
            .collect();

        // Instantaneous CPU % from the most-recent completed tick.
        let latest = (hist.head + HISTORY_SLOTS - 1) % HISTORY_SLOTS;
        let cpu_percent =
            cpu_pct_from_delta(hist.cpu_slots[latest]);
        let cpu_history: Vec<Option<f64>> = (0..n)
            .map(|i| {
                let idx =
                    (hist.head + HISTORY_SLOTS - n + i) % HISTORY_SLOTS;
                cpu_pct_from_delta(hist.cpu_slots[idx])
            })
            .collect();

        drop(hist);

        let ph = self
            .path_history
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let top_paths_1min  = top_paths_window(&ph, 12);
        let top_paths_5min  = top_paths_window(&ph, 60);
        let top_paths_15min = top_paths_window(&ph, 180);
        let mut top_paths_total: Vec<(String, u64)> =
            ph.total.iter().map(|(k, v)| (k.clone(), *v)).collect();
        top_paths_total.sort_by(|a, b| b.1.cmp(&a.1));
        top_paths_total.truncate(TOP_PATHS_LIMIT);
        drop(ph);

        Snapshot {
            uptime: self.start_time.elapsed(),
            requests_total: total,
            requests_active: self.requests_active.load(Ordering::Relaxed),
            status_2xx: self.status_2xx.load(Ordering::Relaxed),
            status_3xx: self.status_3xx.load(Ordering::Relaxed),
            status_4xx: self.status_4xx.load(Ordering::Relaxed),
            status_5xx: self.status_5xx.load(Ordering::Relaxed),
            latency: std::array::from_fn(|i| {
                self.latency[i].load(Ordering::Relaxed)
            }),
            rate_current,
            rate_1min,
            rate_5min,
            rate_15min,
            memory_kb: read_memory_kb(),
            cpu_percent,
            rate_history,
            memory_history,
            cpu_history,
            top_paths_1min,
            top_paths_5min,
            top_paths_15min,
            top_paths_total,
        }
    }

    // Background task: tick every WINDOW_SECS seconds, advancing the
    // ring buffer.  Runs independently; not joined on shutdown.
    pub async fn tick_loop(self: std::sync::Arc<Self>) {
        // interval() fires immediately on first call; skip that tick
        // so the first real slot represents a complete window.
        let mut iv = interval(Duration::from_secs(WINDOW_SECS));
        iv.tick().await; // immediate first tick -- discard
        loop {
            iv.tick().await;
            let total =
                self.requests_total.load(Ordering::Relaxed);
            let mem_kb = read_memory_kb().unwrap_or(0);
            let cpu_now = read_cpu_ticks().unwrap_or(0);
            let mut hist = self.history
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let delta = total.saturating_sub(hist.last_total);
            // Skip first CPU sample: last_cpu_ticks == 0 means we
            // have no baseline yet, so the delta would be huge.
            let cpu_delta = if hist.last_cpu_ticks == 0 {
                0
            } else {
                cpu_now.saturating_sub(hist.last_cpu_ticks)
            };
            let head = hist.head;
            hist.slots[head] = delta;
            hist.mem_slots[head] = mem_kb;
            hist.cpu_slots[head] = cpu_delta;
            hist.head = (head + 1) % HISTORY_SLOTS;
            hist.last_total = total;
            hist.last_cpu_ticks = cpu_now;
            drop(hist);

            // Flush per-path accumulator into the ring buffer slot,
            // aligned with the rate ring buffer (same head index).
            let mut ph = self
                .path_history
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let ph_head = ph.head;
            ph.slots[ph_head] = std::mem::take(&mut ph.current);
            ph.head = (ph_head + 1) % HISTORY_SLOTS;
        }
    }
}

// Aggregate path counts across the `n` most-recent completed slots,
// plus the in-progress current window, returning top-N sorted descending.
fn top_paths_window(
    ph: &PathHistory,
    n: usize,
) -> Vec<(String, u64)> {
    let n = n.min(HISTORY_SLOTS);
    let mut counts: HashMap<String, u64> = HashMap::new();
    for i in 0..n {
        let idx =
            (ph.head + HISTORY_SLOTS - 1 - i) % HISTORY_SLOTS;
        for (k, v) in &ph.slots[idx] {
            *counts.entry(k.clone()).or_insert(0) += v;
        }
    }
    // Include the in-progress current window.
    for (k, v) in &ph.current {
        *counts.entry(k.clone()).or_insert(0) += v;
    }
    let mut top: Vec<(String, u64)> =
        counts.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    top.truncate(TOP_PATHS_LIMIT);
    top
}

// Sum `n` most-recent slots and convert to requests/second.
fn window_rate(hist: &RateHistory, n: usize) -> f64 {
    let n = n.min(HISTORY_SLOTS);
    let total: u64 = (0..n)
        .map(|i| {
            // Walk backwards from head (head - 1 is most recent).
            let idx = (hist.head + HISTORY_SLOTS - 1 - i) % HISTORY_SLOTS;
            hist.slots[idx]
        })
        .sum();
    total as f64 / (n as f64 * WINDOW_SECS as f64)
}

// Read VmRSS from /proc/self/status (Linux only).
#[cfg(target_os = "linux")]
fn read_memory_kb() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok());
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn read_memory_kb() -> Option<u64> {
    None
}

// Read cumulative CPU ticks (utime + stime) from /proc/self/stat.
// The comm field (field 2) may contain spaces wrapped in '()';
// we split at ')' to skip it and index from the remainder.
#[cfg(target_os = "linux")]
fn read_cpu_ticks() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/stat").ok()?;
    let after = s.split(')').nth(1)?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // After ')': [0]=state [1]=ppid ... [11]=utime [12]=stime
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some(utime + stime)
}

#[cfg(not(target_os = "linux"))]
fn read_cpu_ticks() -> Option<u64> {
    None
}

// Convert a CPU tick delta (over WINDOW_SECS) to a percentage.
// Assumes 100 Hz clock (standard on all modern Linux kernels).
// Returns None on non-Linux where ticks are not meaningful.
#[cfg(target_os = "linux")]
fn cpu_pct_from_delta(delta: u64) -> Option<f64> {
    // delta ticks / (WINDOW_SECS * 100 ticks/s) * 100 % simplifies
    // to delta / WINDOW_SECS.  Cap at 100 % for single-core display.
    Some((delta as f64 / WINDOW_SECS as f64).min(100.0))
}

#[cfg(not(target_os = "linux"))]
fn cpu_pct_from_delta(_delta: u64) -> Option<f64> {
    None
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_metrics_start_at_zero() {
        let m = Metrics::new();
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 0);
        assert_eq!(m.requests_active.load(Ordering::Relaxed), 0);
        assert_eq!(m.status_2xx.load(Ordering::Relaxed), 0);
        assert_eq!(m.status_5xx.load(Ordering::Relaxed), 0);
        for b in &m.latency {
            assert_eq!(b.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn record_increments_correct_status_bucket() {
        let m = Metrics::new();
        m.record(200, 1);
        m.record(204, 1);
        m.record(301, 1);
        m.record(404, 1);
        m.record(503, 1);
        assert_eq!(m.status_2xx.load(Ordering::Relaxed), 2);
        assert_eq!(m.status_3xx.load(Ordering::Relaxed), 1);
        assert_eq!(m.status_4xx.load(Ordering::Relaxed), 1);
        assert_eq!(m.status_5xx.load(Ordering::Relaxed), 1);
        assert_eq!(m.requests_total.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn record_increments_correct_latency_bucket() {
        let m = Metrics::new();
        m.record(200, 0);    // <1ms  -> bucket 0
        m.record(200, 5);    // <10ms -> bucket 1
        m.record(200, 30);   // <50ms -> bucket 2
        m.record(200, 100);  // <200ms -> bucket 3
        m.record(200, 500);  // <1s -> bucket 4
        m.record(200, 2000); // >=1s -> bucket 5
        for (i, b) in m.latency.iter().enumerate() {
            assert_eq!(
                b.load(Ordering::Relaxed), 1,
                "bucket {i} should have count 1"
            );
        }
    }

    #[test]
    fn inc_dec_active_tracks_concurrency() {
        let m = Metrics::new();
        m.inc_active();
        m.inc_active();
        m.inc_active();
        assert_eq!(m.requests_active.load(Ordering::Relaxed), 3);
        m.dec_active();
        assert_eq!(m.requests_active.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn rate_is_zero_before_any_tick() {
        let m = Metrics::new();
        m.record(200, 1);
        let snap = m.snapshot();
        // Ring buffer has no completed windows yet -- all rates are 0.
        assert_eq!(snap.rate_1min, 0.0);
        assert_eq!(snap.rate_5min, 0.0);
        assert_eq!(snap.rate_15min, 0.0);
        // But current-window rate reflects the request.
        assert!(snap.rate_current > 0.0);
    }

    #[test]
    fn tick_advances_ring_buffer() {
        let m = Metrics::new();
        // Simulate 5 completed requests.
        for _ in 0..5 {
            m.record(200, 1);
        }
        // Manually invoke a tick (simulating the background task).
        let total = m.requests_total.load(Ordering::Relaxed);
        {
            let mut hist = m.history.lock().unwrap();
            let delta = total.saturating_sub(hist.last_total);
            let head = hist.head;
            hist.slots[head] = delta;
            hist.head = (head + 1) % HISTORY_SLOTS;
            hist.last_total = total;
        }
        let snap = m.snapshot();
        // 5 requests spread across one 5-second window out of the
        // 12 windows that make up 1 minute -> 5 / (12x5) = 0.0833 req/s.
        let expected = 5.0 / (12.0 * WINDOW_SECS as f64);
        assert!(
            (snap.rate_1min - expected).abs() < 0.001,
            "rate_1min={} expected={}", snap.rate_1min, expected
        );
    }

    #[test]
    fn uptime_human_formats_correctly() {
        let snap = |secs: u64| -> String {
            Snapshot {
                uptime: Duration::from_secs(secs),
                requests_total: 0, requests_active: 0,
                status_2xx: 0, status_3xx: 0,
                status_4xx: 0, status_5xx: 0,
                latency: [0; 6],
                rate_current: 0.0, rate_1min: 0.0,
                rate_5min: 0.0, rate_15min: 0.0,
                memory_kb: None,
                cpu_percent: None,
                rate_history: vec![],
                memory_history: vec![],
                cpu_history: vec![],
                top_paths_1min:  vec![],
                top_paths_5min:  vec![],
                top_paths_15min: vec![],
                top_paths_total: vec![],
            }.uptime_human()
        };
        assert_eq!(snap(30), "30s");
        assert_eq!(snap(90), "1m 30s");
        assert_eq!(snap(3661), "1h 1m 1s");
        assert_eq!(snap(86400 + 3661), "1d 1h 1m");
    }

    #[test]
    fn snapshot_history_slices_have_correct_length() {
        let m = Metrics::new();
        let snap = m.snapshot();
        assert_eq!(snap.rate_history.len(), SPARKLINE_SLOTS);
        assert_eq!(snap.memory_history.len(), SPARKLINE_SLOTS);
        assert_eq!(snap.cpu_history.len(), SPARKLINE_SLOTS);
    }

    #[test]
    fn record_path_appears_in_snapshot() {
        let m = Metrics::new();
        m.record_path("/foo");
        m.record_path("/foo");
        m.record_path("/bar");
        let snap = m.snapshot();
        // All-time totals include in-progress current window.
        assert!(
            snap.top_paths_total.iter().any(|(p, c)| p == "/foo" && *c == 2),
            "expected /foo with count 2 in top_paths_total"
        );
        assert!(
            snap.top_paths_total.iter().any(|(p, c)| p == "/bar" && *c == 1),
            "expected /bar with count 1 in top_paths_total"
        );
    }

    #[test]
    fn rate_history_reflects_ticked_data() {
        let m = Metrics::new();
        for _ in 0..10 {
            m.record(200, 1);
        }
        // Simulate one tick manually.
        let total = m.requests_total.load(Ordering::Relaxed);
        {
            let mut hist = m.history.lock().unwrap();
            let delta = total.saturating_sub(hist.last_total);
            let head = hist.head;
            hist.slots[head] = delta;
            hist.head = (head + 1) % HISTORY_SLOTS;
            hist.last_total = total;
        }
        let snap = m.snapshot();
        // Most recent slot (last in oldest-first Vec) should be
        // 10 requests / 5 s = 2.0 req/s.
        let last = *snap.rate_history.last().unwrap();
        assert!(
            (last - 2.0).abs() < 0.01,
            "expected ~2.0 req/s, got {last}"
        );
    }
}
