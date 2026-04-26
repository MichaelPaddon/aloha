use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::time::interval;

// Ring-buffer slot width: one entry per WINDOW_SECS seconds.
pub const WINDOW_SECS: u64 = 5;
// 180 × 5 s = 15 minutes of history.
const HISTORY_SLOTS: usize = 180;

// ── Core data ────────────────────────────────────────────────────

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
    // Latency histogram: <1ms <10ms <50ms <200ms <1s ≥1s
    pub latency: [AtomicU64; 6],
    // Written only by the background tick task.
    history: Mutex<RateHistory>,
}

struct RateHistory {
    // Per-window request counts. head is the *next write* index.
    slots: [u64; HISTORY_SLOTS],
    head: usize,
    // requests_total at the end of the previous tick.
    last_total: u64,
}

// ── Snapshot (used by the status handler) ────────────────────────

pub struct Snapshot {
    pub uptime: Duration,
    pub requests_total: u64,
    pub requests_active: i64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    // Counts per latency bucket: <1ms <10ms <50ms <200ms <1s ≥1s
    pub latency: [u64; 6],
    // Requests/second over the partial current window,
    // and completed 1/5/15-minute windows.
    pub rate_current: f64,
    pub rate_1min: f64,
    pub rate_5min: f64,
    pub rate_15min: f64,
    // Resident set size in KiB; None on non-Linux platforms.
    pub memory_kb: Option<u64>,
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

// ── Metrics implementation ────────────────────────────────────────

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
                head: 0,
                last_total: 0,
            }),
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

        let rate_1min  = window_rate(&hist, 12);   // 12 × 5 s = 60 s
        let rate_5min  = window_rate(&hist, 60);   // 60 × 5 s = 300 s
        let rate_15min = window_rate(&hist, 180);  // 180 × 5 s = 900 s
        drop(hist);

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
        }
    }

    // Background task: tick every WINDOW_SECS seconds, advancing the
    // ring buffer.  Runs independently; not joined on shutdown.
    pub async fn tick_loop(self: std::sync::Arc<Self>) {
        // interval() fires immediately on first call; skip that tick
        // so the first real slot represents a complete window.
        let mut iv = interval(Duration::from_secs(WINDOW_SECS));
        iv.tick().await; // immediate first tick — discard
        loop {
            iv.tick().await;
            let total =
                self.requests_total.load(Ordering::Relaxed);
            let mut hist = self.history
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let delta = total.saturating_sub(hist.last_total);
            let head = hist.head;
            hist.slots[head] = delta;
            hist.head = (head + 1) % HISTORY_SLOTS;
            hist.last_total = total;
        }
    }
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

// ── Tests ─────────────────────────────────────────────────────────

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
        m.record(200, 0);    // <1ms  → bucket 0
        m.record(200, 5);    // <10ms → bucket 1
        m.record(200, 30);   // <50ms → bucket 2
        m.record(200, 100);  // <200ms → bucket 3
        m.record(200, 500);  // <1s → bucket 4
        m.record(200, 2000); // ≥1s → bucket 5
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
        // Ring buffer has no completed windows yet — all rates are 0.
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
        // 12 windows that make up 1 minute → 5 / (12×5) = 0.0833 req/s.
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
                status_2xx: 0, status_3xx: 0, status_4xx: 0, status_5xx: 0,
                latency: [0; 6],
                rate_current: 0.0, rate_1min: 0.0,
                rate_5min: 0.0, rate_15min: 0.0,
                memory_kb: None,
            }.uptime_human()
        };
        assert_eq!(snap(30), "30s");
        assert_eq!(snap(90), "1m 30s");
        assert_eq!(snap(3661), "1h 1m 1s");
        assert_eq!(snap(86400 + 3661), "1d 1h 1m");
    }
}
