// Built-in server status page: serves request counters, latency
// histogram, and uptime as HTML or JSON depending on Accept header.

use crate::config::{
    AuthBackend, Config, HandlerConfig, TlsConfig,
};
use crate::error::{bytes_body, HttpResponse};
use crate::metrics::{Metrics, Snapshot};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;

// -- Server summary ------------------------------------------------
//
// Derived once from Config at startup; passed into StatusHandler so
// the status page can show configuration alongside runtime metrics.

pub struct ListenerSummary {
    pub address: String,
    pub protocol: String,
    pub acme_domains: Vec<String>,
}

pub struct LocationSummary {
    pub path: String,
    pub handler: String,
}

pub struct VHostSummary {
    pub name: String,
    pub aliases: Vec<String>,
    pub locations: Vec<LocationSummary>,
}

pub struct ServerSummary {
    pub version: &'static str,
    pub listeners: Vec<ListenerSummary>,
    pub vhosts: Vec<VHostSummary>,
    // None = no auth; Some("pam:service") or Some("ldap:url")
    pub auth: Option<String>,
}

impl ServerSummary {
    pub fn from_config(config: &Config) -> Self {
        let listeners = config
            .listeners
            .iter()
            .map(|l| {
                let address = match (&l.bind, l.fd) {
                    (Some(addr), _) => addr.clone(),
                    (_, Some(n)) => format!("fd:{n}"),
                    _ => unreachable!("validated"),
                };
                let (protocol, acme_domains) =
                    listener_protocol(l);
                ListenerSummary {
                    address,
                    protocol,
                    acme_domains,
                }
            })
            .collect();

        let vhosts = config
            .vhosts
            .iter()
            .map(|v| VHostSummary {
                name: v.name.clone(),
                aliases: v.aliases.clone(),
                locations: v
                    .locations
                    .iter()
                    .map(|loc| LocationSummary {
                        path: loc.path.clone(),
                        handler: handler_type_name(&loc.handler)
                            .to_owned(),
                    })
                    .collect(),
            })
            .collect();

        let auth = config.server.auth.as_ref().map(|b| match b {
            AuthBackend::Pam { service } => {
                format!("pam:{service}")
            }
            AuthBackend::Ldap(c) => format!("ldap:{}", c.url),
        });

        ServerSummary {
            version: env!("CARGO_PKG_VERSION"),
            listeners,
            vhosts,
            auth,
        }
    }

    // Empty summary for tests that do not care about config data.
    pub fn default() -> Self {
        ServerSummary {
            version: env!("CARGO_PKG_VERSION"),
            listeners: Vec::new(),
            vhosts: Vec::new(),
            auth: None,
        }
    }
}

fn listener_protocol(
    l: &crate::config::ListenerConfig,
) -> (String, Vec<String>) {
    match (&l.tcp_proxy, &l.tls) {
        (Some(_), None) => ("TCP-proxy".into(), Vec::new()),
        (Some(_), Some(_)) => ("TLS-TCP-proxy".into(), Vec::new()),
        (None, None) => ("HTTP".into(), Vec::new()),
        (None, Some(tls)) => match &tls.cert {
            TlsConfig::Files { .. } => {
                ("HTTPS-file".into(), Vec::new())
            }
            TlsConfig::SelfSigned => {
                ("HTTPS-self-signed".into(), Vec::new())
            }
            TlsConfig::Acme { domains, .. } => {
                ("HTTPS-ACME".into(), domains.clone())
            }
        },
    }
}

fn handler_type_name(h: &HandlerConfig) -> &'static str {
    match h {
        HandlerConfig::Static { .. }  => "static",
        HandlerConfig::Proxy { .. }   => "proxy",
        HandlerConfig::Redirect { .. } => "redirect",
        HandlerConfig::FastCgi { .. } => "fastcgi",
        HandlerConfig::Scgi { .. }    => "scgi",
        HandlerConfig::Cgi { .. }     => "cgi",
        HandlerConfig::Status         => "status",
    }
}

// -- Handler -------------------------------------------------------

pub struct StatusHandler {
    metrics: Arc<Metrics>,
    summary: Arc<ServerSummary>,
}

impl StatusHandler {
    pub fn new(
        metrics: Arc<Metrics>,
        summary: Arc<ServerSummary>,
    ) -> Self {
        Self { metrics, summary }
    }

    pub async fn serve(
        &self,
        req: Request<Incoming>,
        _matched_prefix: &str,
    ) -> HttpResponse {
        let snap = self.metrics.snapshot();
        if accept_json(req.headers()) {
            render_json(&snap, &self.summary)
        } else {
            render_html(&snap, &self.summary)
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

fn render_json(s: &Snapshot, sum: &ServerSummary) -> HttpResponse {
    let listeners: Vec<_> = sum
        .listeners
        .iter()
        .map(|l| {
            serde_json::json!({
                "address":      l.address,
                "protocol":     l.protocol,
                "acme_domains": l.acme_domains,
            })
        })
        .collect();

    let vhosts: Vec<_> = sum
        .vhosts
        .iter()
        .map(|v| {
            let locs: Vec<_> = v
                .locations
                .iter()
                .map(|loc| {
                    serde_json::json!({
                        "path":    loc.path,
                        "handler": loc.handler,
                    })
                })
                .collect();
            serde_json::json!({
                "name":      v.name,
                "aliases":   v.aliases,
                "locations": locs,
            })
        })
        .collect();

    let body = serde_json::json!({
        "version":         sum.version,
        "pid":             std::process::id(),
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
        "listeners": listeners,
        "vhosts":    vhosts,
        "auth":      sum.auth,
    })
    .to_string();

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(bytes_body(Bytes::from(body)))
        .expect("known-valid response")
}

// -- HTML output ---------------------------------------------------

fn render_html(s: &Snapshot, sum: &ServerSummary) -> HttpResponse {
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
.info-table{{width:100%;border-collapse:collapse;font-size:.875rem}}
.info-table th{{text-align:left;color:var(--muted);font-weight:600;
  font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;
  padding:.3rem .5rem .5rem 0}}
.info-table td{{padding:.35rem .5rem .35rem 0;
  border-top:1px solid var(--border);word-break:break-all}}
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
.badge{{display:inline-block;font-size:.78rem;font-weight:600;
  background:var(--accent-bg);color:var(--accent);
  border-radius:4px;padding:.1rem .45rem}}
.note{{font-size:.75rem;color:var(--muted);text-align:right;
  margin-top:.5rem}}
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

{memory_section}
<div class="card sec">
  <h2>Server</h2>
  <table class="info-table">
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Version</td>
        <td><span class="badge">v{version}</span></td></tr>
    <tr><td>PID</td><td>{pid}</td></tr>
    <tr><td>Auth</td><td>{auth}</td></tr>
  </table>
</div>

{listeners_section}
{vhosts_section}
<p class="note">Page auto-refreshes every 10 s</p>
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
        latency_bars = latency_bars(&s.latency, total_lat),
        memory_section = memory_html(s.memory_kb),
        version      = sum.version,
        pid          = std::process::id(),
        auth         = sum.auth.as_deref().unwrap_or("none"),
        listeners_section = listeners_html(&sum.listeners),
        vhosts_section    = vhosts_html(&sum.vhosts),
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

fn listeners_html(ls: &[ListenerSummary]) -> String {
    if ls.is_empty() {
        return String::new();
    }
    let mut rows = String::new();
    for l in ls {
        let domains = if l.acme_domains.is_empty() {
            String::new()
        } else {
            l.acme_domains.join(", ")
        };
        rows.push_str(&format!(
            "<tr><td>{addr}</td><td>{proto}</td>\
             <td>{domains}</td></tr>",
            addr  = l.address,
            proto = l.protocol,
        ));
    }
    format!(
        "<div class=\"card sec\">\
<h2>Listeners</h2>\
<table class=\"info-table\">\
<tr><th>Address</th><th>Protocol</th><th>Domains</th></tr>\
{rows}\
</table></div>"
    )
}

fn vhosts_html(vs: &[VHostSummary]) -> String {
    if vs.is_empty() {
        return String::new();
    }
    let mut rows = String::new();
    for v in vs {
        let aliases = if v.aliases.is_empty() {
            String::new()
        } else {
            v.aliases.join(", ")
        };
        let locs = v
            .locations
            .iter()
            .map(|l| format!("{} ({})", l.path, l.handler))
            .collect::<Vec<_>>()
            .join(", ");
        rows.push_str(&format!(
            "<tr><td>{name}</td><td>{aliases}</td>\
             <td>{locs}</td></tr>",
            name = v.name,
        ));
    }
    format!(
        "<div class=\"card sec\">\
<h2>Virtual Hosts</h2>\
<table class=\"info-table\">\
<tr><th>Name</th><th>Aliases</th><th>Locations</th></tr>\
{rows}\
</table></div>"
    )
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
    use crate::config::Config;
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

    fn sample_summary() -> ServerSummary {
        ServerSummary {
            version: "0.0.0-test",
            listeners: vec![ListenerSummary {
                address: "0.0.0.0:80".into(),
                protocol: "HTTP".into(),
                acme_domains: Vec::new(),
            }],
            vhosts: vec![VHostSummary {
                name: "example.com".into(),
                aliases: vec!["www.example.com".into()],
                locations: vec![LocationSummary {
                    path: "/".into(),
                    handler: "static".into(),
                }],
            }],
            auth: None,
        }
    }

    // -- accept_json -----------------------------------------------

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

    // -- render_json -----------------------------------------------

    #[tokio::test]
    async fn render_json_contains_required_keys() {
        use http_body_util::BodyExt;
        let resp = render_json(&sample_snap(), &sample_summary());
        assert_eq!(resp.status(), 200);
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
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
        let resp = render_json(&sample_snap(), &sample_summary());
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("1100"));
    }

    #[tokio::test]
    async fn render_json_contains_version() {
        use http_body_util::BodyExt;
        let resp = render_json(&sample_snap(), &sample_summary());
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("\"version\""));
        assert!(text.contains("\"listeners\""));
        assert!(text.contains("\"vhosts\""));
        assert!(text.contains("\"pid\""));
    }

    #[tokio::test]
    async fn render_json_listener_count() {
        use http_body_util::BodyExt;
        let resp = render_json(&sample_snap(), &sample_summary());
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["listeners"].as_array().unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn render_json_auth_null_when_absent() {
        use http_body_util::BodyExt;
        let resp = render_json(&sample_snap(), &sample_summary());
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        assert!(v["auth"].is_null());
    }

    #[tokio::test]
    async fn render_json_auth_present() {
        use http_body_util::BodyExt;
        let mut sum = sample_summary();
        sum.auth = Some("pam:login".into());
        let resp = render_json(&sample_snap(), &sum);
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("pam:"));
    }

    // -- render_html -----------------------------------------------

    #[tokio::test]
    async fn render_html_contains_status_classes() {
        use http_body_util::BodyExt;
        let resp = render_html(&sample_snap(), &sample_summary());
        assert_eq!(resp.status(), 200);
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("2xx"), "missing 2xx label");
        assert!(html.contains("5xx"), "missing 5xx label");
        assert!(html.contains("Uptime"), "missing Uptime");
        assert!(
            html.contains("Request Rate"),
            "missing rates section"
        );
        assert!(html.contains("Latency"), "missing latency section");
        assert!(html.contains("Memory"), "missing memory section");
    }

    #[tokio::test]
    async fn render_html_no_memory_section_when_none() {
        use http_body_util::BodyExt;
        let mut s = sample_snap();
        s.memory_kb = None;
        let resp = render_html(&s, &sample_summary());
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !html.contains("Memory"),
            "memory section should be absent"
        );
    }

    #[tokio::test]
    async fn render_html_contains_listeners_section() {
        use http_body_util::BodyExt;
        let resp = render_html(&sample_snap(), &sample_summary());
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("Listeners"));
        assert!(html.contains("0.0.0.0:80"));
        assert!(html.contains("HTTP"));
    }

    #[tokio::test]
    async fn render_html_contains_vhosts_section() {
        use http_body_util::BodyExt;
        let resp = render_html(&sample_snap(), &sample_summary());
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("Virtual Hosts"));
        assert!(html.contains("example.com"));
    }

    #[tokio::test]
    async fn render_html_shows_version() {
        use http_body_util::BodyExt;
        let resp = render_html(&sample_snap(), &sample_summary());
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        // sample_summary uses "0.0.0-test" as version
        assert!(html.contains("0.0.0-test"));
    }

    #[tokio::test]
    async fn render_html_acme_domains_shown() {
        use http_body_util::BodyExt;
        let mut sum = ServerSummary::default();
        sum.listeners.push(ListenerSummary {
            address: "[::]:443".into(),
            protocol: "HTTPS-ACME".into(),
            acme_domains: vec![
                "example.com".into(),
                "www.example.com".into(),
            ],
        });
        let resp = render_html(&sample_snap(), &sum);
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("example.com"));
        assert!(html.contains("HTTPS-ACME"));
    }

    // -- ServerSummary::from_config --------------------------------

    fn summary_from(kdl: &str) -> ServerSummary {
        let cfg = Config::parse(kdl).unwrap();
        ServerSummary::from_config(&cfg)
    }

    #[test]
    fn summary_plain_http() {
        let s = summary_from(r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
        "#);
        assert_eq!(s.listeners[0].protocol, "HTTP");
        assert!(s.listeners[0].acme_domains.is_empty());
        assert!(s.auth.is_none());
    }

    #[test]
    fn summary_https_file() {
        let s = summary_from(r#"
            listener {
                bind "0.0.0.0:443"
                tls "file" {
                    cert "cert.pem"
                    key "key.pem"
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
        "#);
        assert_eq!(s.listeners[0].protocol, "HTTPS-file");
    }

    #[test]
    fn summary_https_self_signed() {
        let s = summary_from(r#"
            listener {
                bind "0.0.0.0:443"
                tls
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
        "#);
        assert_eq!(s.listeners[0].protocol, "HTTPS-self-signed");
    }

    #[test]
    fn summary_https_acme() {
        let s = summary_from(r#"
            server {
                state-dir "/tmp/t"
            }
            listener {
                bind "[::]:443"
                tls "acme" {
                    domain "example.com"
                    domain "www.example.com"
                }
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
        "#);
        assert_eq!(s.listeners[0].protocol, "HTTPS-ACME");
        assert_eq!(
            s.listeners[0].acme_domains,
            ["example.com", "www.example.com"]
        );
    }

    #[test]
    fn summary_tcp_proxy() {
        let s = summary_from(r#"
            listener {
                bind "[::]:5432"
                tcp-proxy {
                    upstream "db:5432"
                }
            }
        "#);
        assert_eq!(s.listeners[0].protocol, "TCP-proxy");
        assert!(s.listeners[0].acme_domains.is_empty());
    }

    #[test]
    fn summary_tls_tcp_proxy() {
        let s = summary_from(r#"
            listener {
                bind "[::]:443"
                tls "self-signed"
                tcp-proxy {
                    upstream "db:5432"
                }
            }
        "#);
        assert_eq!(s.listeners[0].protocol, "TLS-TCP-proxy");
    }

    #[test]
    fn summary_auth_pam() {
        let s = summary_from(r#"
            server {
                auth "pam" {
                    service "aloha"
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
        "#);
        assert_eq!(s.auth.as_deref(), Some("pam:aloha"));
    }

    #[test]
    fn summary_auth_ldap() {
        // The {user} placeholder in bind-dn is a literal string in KDL,
        // not a format specifier -- use a raw string literal to avoid
        // Rust format-macro interpretation.
        let s = summary_from(r#"
            server {
                auth "ldap" {
                    url "ldap://localhost:389"
                    bind-dn "uid={user},dc=example,dc=com"
                    base-dn "dc=example,dc=com"
                }
            }
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
        "#);
        let auth = s.auth.unwrap();
        assert!(
            auth.starts_with("ldap:ldap://"),
            "expected ldap: prefix, got {auth}"
        );
    }

    #[test]
    fn summary_auth_none() {
        let s = summary_from(r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
        "#);
        assert!(s.auth.is_none());
    }

    #[test]
    fn summary_vhost_locations() {
        let s = summary_from(r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/static/" {
                    static { root "."; }
                }
                location "/api/" {
                    proxy {
                        upstream "http://127.0.0.1:3000"
                    }
                }
            }
        "#);
        assert_eq!(s.vhosts[0].locations.len(), 2);
        assert_eq!(s.vhosts[0].locations[0].handler, "static");
        assert_eq!(s.vhosts[0].locations[1].handler, "proxy");
    }

    #[test]
    fn summary_version_matches_cargo() {
        let s = summary_from(r#"
            listener {
                bind "0.0.0.0:80"
            }
            vhost "h" {
                location "/" {
                    static { root "."; }
                }
            }
        "#);
        assert_eq!(s.version, env!("CARGO_PKG_VERSION"));
    }

    // -- fmt_num ---------------------------------------------------

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
