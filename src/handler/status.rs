// Built-in server status page: serves request counters, latency
// histogram, and uptime as HTML or JSON depending on Accept header.

use crate::error::{bytes_body, HttpResponse};
use crate::metrics::{Metrics, Snapshot};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;

pub struct StatusHandler {
    metrics: Arc<Metrics>,
}

impl StatusHandler {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics }
    }

    pub async fn serve(
        &self,
        req: Request<Incoming>,
        _matched_prefix: &str,
    ) -> HttpResponse {
        let snap = self.metrics.snapshot();
        if accept_json(req.headers()) {
            render_json(&snap)
        } else {
            render_html(&snap)
        }
    }
}

// True when the client explicitly accepts JSON.
fn accept_json(headers: &hyper::HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false)
}

// -- JSON output ---------------------------------------------------

fn render_json(s: &Snapshot) -> HttpResponse {
    let body = serde_json::json!({
        "uptime_secs":     s.uptime.as_secs(),
        "uptime_human":    s.uptime_human(),
        "requests_total":  s.requests_total,
        "requests_active": s.requests_active,
        "status": {
            "2xx": s.status_2xx,
            "3xx": s.status_3xx,
            "4xx": s.status_4xx,
            "5xx": s.status_5xx,
        },
        "rates": {
            "current_per_sec": s.rate_current,
            "avg_1min":        s.rate_1min,
            "avg_5min":        s.rate_5min,
            "avg_15min":       s.rate_15min,
        },
        "latency_ms": {
            "lt_1":    s.latency[0],
            "lt_10":   s.latency[1],
            "lt_50":   s.latency[2],
            "lt_200":  s.latency[3],
            "lt_1000": s.latency[4],
            "ge_1000": s.latency[5],
        },
        "memory_kb": s.memory_kb,
    })
    .to_string();

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(bytes_body(Bytes::from(body)))
        .expect("known-valid response")
}

// -- HTML output ---------------------------------------------------

fn render_html(s: &Snapshot) -> HttpResponse {
    let total_lat: u64 = s.latency.iter().sum();
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="10">
<title>aloha -- Status</title>
<style>
*,*::before,*::after{{box-sizing:border-box}}
:root{{
  --bg:#f5f7fa;--surface:#fff;--border:#dde3eb;
  --text:#1a2332;--muted:#5e6e82;--accent:#1e3a5f;
  --accent-bg:#edf2f8;--green:#16a34a;--green-bg:#dcfce7;
  --amber:#b45309;--amber-bg:#fef3c7;--red:#b91c1c;--red-bg:#fee2e2;
}}
body{{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",
  system-ui,sans-serif;font-size:15px;line-height:1.6;color:var(--text);
  background:var(--bg)}}
.topbar{{position:fixed;top:0;left:0;right:0;height:54px;background:#1e3a5f;
  border-bottom:1px solid #162e4e;display:flex;align-items:center;
  padding:0 1.5rem;gap:.75rem;z-index:100}}
.topbar-logo{{height:28px;filter:brightness(0) invert(1);flex-shrink:0}}
.topbar-sep{{width:1px;height:1.2rem;background:rgba(255,255,255,.18)}}
.topbar-title{{font-size:.82rem;color:rgba(255,255,255,.55);
  letter-spacing:.02em;text-transform:uppercase;font-weight:600}}
.topbar-home{{margin-left:auto;font-size:.82rem;color:rgba(255,255,255,.55);
  text-decoration:none;padding:.3rem .7rem;
  border:1px solid rgba(255,255,255,.20);border-radius:6px}}
.topbar-home:hover{{color:#fff;border-color:rgba(255,255,255,.55)}}
.main{{max-width:900px;margin:0 auto;
  padding:calc(54px + 2rem) 1.5rem 3rem}}
h2{{font-size:.85rem;font-weight:700;color:var(--muted);
  text-transform:uppercase;letter-spacing:.06em;margin:0 0 .75rem}}
.grid-3{{display:grid;grid-template-columns:repeat(3,1fr);
  gap:1rem;margin-bottom:1.25rem}}
.grid-2{{display:grid;grid-template-columns:repeat(2,1fr);
  gap:1rem;margin-bottom:1.25rem}}
.card{{background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:1.25rem 1.5rem;margin-bottom:0}}
.card+.card{{margin-top:0}}
.sec{{margin-bottom:1.25rem}}
.stat-val{{font-size:2rem;font-weight:800;color:var(--accent);
  letter-spacing:-.03em;margin:.15rem 0 0}}
.stat-label{{font-size:.82rem;color:var(--muted)}}
.rate-table{{width:100%;border-collapse:collapse;font-size:.875rem}}
.rate-table th{{text-align:left;color:var(--muted);font-weight:600;
  font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;
  padding:.3rem .5rem .5rem 0}}
.rate-table td{{padding:.35rem .5rem .35rem 0;
  border-top:1px solid var(--border)}}
.rate-table td:last-child{{text-align:right;
  font-variant-numeric:tabular-nums;font-weight:600;color:var(--accent)}}
.sc-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:.75rem}}
.sc{{border-radius:8px;padding:1rem;text-align:center}}
.sc-val{{font-size:1.5rem;font-weight:800;letter-spacing:-.02em}}
.sc-label{{font-size:.78rem;font-weight:600;text-transform:uppercase;
  letter-spacing:.05em;margin-top:.15rem;opacity:.85}}
.sc-2xx{{background:var(--green-bg);color:var(--green)}}
.sc-3xx{{background:var(--accent-bg);color:var(--accent)}}
.sc-4xx{{background:var(--amber-bg);color:var(--amber)}}
.sc-5xx{{background:var(--red-bg);color:var(--red)}}
.bar-row{{display:flex;align-items:center;gap:.6rem;margin:.3rem 0;
  font-size:.82rem}}
.bar-label{{width:5.5rem;color:var(--muted);flex-shrink:0;text-align:right;
  white-space:nowrap}}
.bar-track{{flex:1;background:var(--accent-bg);border-radius:4px;
  height:.85rem;overflow:hidden}}
.bar-fill{{height:100%;background:var(--accent);border-radius:4px;
  min-width:2px}}
.bar-count{{width:4.5rem;color:var(--text);
  font-variant-numeric:tabular-nums;text-align:right}}
.mem-val{{font-size:1.25rem;font-weight:700;color:var(--accent)}}
.note{{font-size:.75rem;color:var(--muted);text-align:right;margin-top:.5rem}}
@media(max-width:640px){{
  .grid-3,.grid-2,.sc-grid{{grid-template-columns:1fr 1fr}}
}}
</style>
</head>
<body>
<header class="topbar">
  <img class="topbar-logo" src="/aloha-logo.svg" alt="aloha">
  <div class="topbar-sep"></div>
  <span class="topbar-title">Server Status</span>
  <a class="topbar-home" href="/">&larr; Home</a>
</header>
<main class="main">

<div class="grid-3">
  <div class="card">
    <div class="stat-label">Uptime</div>
    <div class="stat-val">{uptime}</div>
  </div>
  <div class="card">
    <div class="stat-label">Active Requests</div>
    <div class="stat-val">{active}</div>
  </div>
  <div class="card">
    <div class="stat-label">Total Requests</div>
    <div class="stat-val">{total}</div>
  </div>
</div>

<div class="grid-2">
  <div class="card sec">
    <h2>Request Rate</h2>
    <table class="rate-table">
      <tr><th>Window</th><th>req / s</th></tr>
      <tr><td>Last 5 s</td><td>{rate_cur:.2}</td></tr>
      <tr><td>1 min avg</td><td>{rate_1m:.2}</td></tr>
      <tr><td>5 min avg</td><td>{rate_5m:.2}</td></tr>
      <tr><td>15 min avg</td><td>{rate_15m:.2}</td></tr>
    </table>
  </div>
  <div class="card sec">
    <h2>Status Codes</h2>
    <div class="sc-grid">
      <div class="sc sc-2xx">
        <div class="sc-val">{s2xx}</div>
        <div class="sc-label">2xx</div>
      </div>
      <div class="sc sc-3xx">
        <div class="sc-val">{s3xx}</div>
        <div class="sc-label">3xx</div>
      </div>
      <div class="sc sc-4xx">
        <div class="sc-val">{s4xx}</div>
        <div class="sc-label">4xx</div>
      </div>
      <div class="sc sc-5xx">
        <div class="sc-val">{s5xx}</div>
        <div class="sc-label">5xx</div>
      </div>
    </div>
  </div>
</div>

<div class="card sec">
  <h2>Latency Distribution</h2>
  {latency_bars}
</div>

{memory_section}<p class="note">Page auto-refreshes every 10 s</p>
</main>
</body>
</html>"#,
        uptime       = s.uptime_human(),
        active       = s.requests_active,
        total        = fmt_num(s.requests_total),
        rate_cur     = s.rate_current,
        rate_1m      = s.rate_1min,
        rate_5m      = s.rate_5min,
        rate_15m     = s.rate_15min,
        s2xx         = fmt_num(s.status_2xx),
        s3xx         = fmt_num(s.status_3xx),
        s4xx         = fmt_num(s.status_4xx),
        s5xx         = fmt_num(s.status_5xx),
        latency_bars   = latency_bars(&s.latency, total_lat),
        memory_section = memory_html(s.memory_kb),
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .body(bytes_body(Bytes::from(html)))
        .expect("known-valid response")
}

fn latency_bars(counts: &[u64; 6], total: u64) -> String {
    const LABELS: &[&str] = &[
        "&lt;&nbsp;1&nbsp;ms",
        "&lt;&nbsp;10&nbsp;ms",
        "&lt;&nbsp;50&nbsp;ms",
        "&lt;&nbsp;200&nbsp;ms",
        "&lt;&nbsp;1&nbsp;s",
        "&#8805;&nbsp;1&nbsp;s",
    ];
    let mut out = String::new();
    for (count, label) in counts.iter().zip(LABELS.iter()) {
        let pct = if total > 0 {
            ((*count) as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        out.push_str(&format!(
            "<div class=\"bar-row\">\
<span class=\"bar-label\">{label}</span>\
<div class=\"bar-track\">\
<div class=\"bar-fill\" style=\"width:{pct:.1}%\"></div>\
</div>\
<span class=\"bar-count\">{count}</span>\
</div>",
        ));
    }
    out
}

fn memory_html(kb: Option<u64>) -> String {
    match kb {
        None => String::new(),
        Some(kb) => format!(
            "<div class=\"card sec\">\
<h2>Memory</h2>\
<div class=\"mem-val\">{} MiB</div>\
<div class=\"stat-label\">Resident set size</div>\
</div>",
            kb / 1024
        ),
    }
}

// Format an integer with thousands-separator commas.
fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use std::time::Duration;

    fn sample_snap() -> Snapshot {
        Snapshot {
            uptime:          Duration::from_secs(3661),
            requests_total:  1234,
            requests_active: 3,
            status_2xx:      1100,
            status_3xx:      80,
            status_4xx:      50,
            status_5xx:      4,
            latency:         [800, 300, 100, 20, 10, 4],
            rate_current:    12.5,
            rate_1min:       10.2,
            rate_5min:       8.7,
            rate_15min:      7.1,
            memory_kb:       Some(32768),
        }
    }

    // -- accept_json ----------------------------------------------

    #[test]
    fn accept_json_true_for_application_json() {
        let mut map = hyper::HeaderMap::new();
        map.insert(
            "accept",
            HeaderValue::from_static("application/json"),
        );
        assert!(accept_json(&map));
    }

    #[test]
    fn accept_json_false_for_text_html() {
        let mut map = hyper::HeaderMap::new();
        map.insert("accept", HeaderValue::from_static("text/html"));
        assert!(!accept_json(&map));
    }

    #[test]
    fn accept_json_false_when_header_absent() {
        assert!(!accept_json(&hyper::HeaderMap::new()));
    }

    // -- render_json ----------------------------------------------

    #[tokio::test]
    async fn render_json_contains_required_keys() {
        use http_body_util::BodyExt;
        let resp = render_json(&sample_snap());
        assert_eq!(resp.status(), 200);
        let bytes = resp.into_body()
            .collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("\"uptime_secs\""));
        assert!(text.contains("\"requests_total\""));
        assert!(text.contains("\"rates\""));
        assert!(text.contains("\"latency_ms\""));
        assert!(text.contains("\"memory_kb\""));
    }

    #[tokio::test]
    async fn render_json_status_code_values() {
        use http_body_util::BodyExt;
        let resp = render_json(&sample_snap());
        let bytes = resp.into_body()
            .collect().await.unwrap().to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        // 1100 is status_2xx in sample_snap
        assert!(text.contains("1100"));
    }

    // -- render_html ----------------------------------------------

    #[tokio::test]
    async fn render_html_contains_status_classes() {
        use http_body_util::BodyExt;
        let resp = render_html(&sample_snap());
        assert_eq!(resp.status(), 200);
        let bytes = resp.into_body()
            .collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("2xx"), "missing 2xx label");
        assert!(html.contains("5xx"), "missing 5xx label");
        assert!(html.contains("Uptime"), "missing Uptime");
        assert!(html.contains("Request Rate"), "missing rates section");
        assert!(html.contains("Latency"), "missing latency section");
        assert!(html.contains("Memory"), "missing memory section");
    }

    #[tokio::test]
    async fn render_html_no_memory_section_when_none() {
        use http_body_util::BodyExt;
        let mut s = sample_snap();
        s.memory_kb = None;
        let resp = render_html(&s);
        let bytes = resp.into_body()
            .collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(!html.contains("Memory"), "memory section should be absent");
    }

    // -- fmt_num --------------------------------------------------

    #[test]
    fn fmt_num_zero() {
        assert_eq!(fmt_num(0), "0");
    }

    #[test]
    fn fmt_num_below_threshold() {
        assert_eq!(fmt_num(999), "999");
    }

    #[test]
    fn fmt_num_adds_commas() {
        assert_eq!(fmt_num(1000), "1,000");
        assert_eq!(fmt_num(1234567), "1,234,567");
    }
}
