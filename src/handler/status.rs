// Built-in server status page: serves request counters, latency
// histogram, and uptime as HTML or JSON.
//
// HTML uses JavaScript polling (?format=json every 3 s) for live
// updates rather than a full-page meta-refresh.

use crate::cert_state::{CertState, SharedCertState};
use crate::config::{
    AuthBackend, Config, HandlerConfig, TlsConfig,
};
use crate::error::{bytes_body, HttpResponse};
use crate::metrics::{Metrics, Snapshot};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
    #[cfg(test)]
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
    cert_state: Option<SharedCertState>,
}

impl StatusHandler {
    pub fn new(
        metrics: Arc<Metrics>,
        summary: Arc<ServerSummary>,
    ) -> Self {
        Self { metrics, summary, cert_state: None }
    }

    pub fn with_cert_state(
        mut self,
        state: SharedCertState,
    ) -> Self {
        self.cert_state = Some(state);
        self
    }

    fn read_cert_states(&self) -> Vec<CertState> {
        self.cert_state.as_ref().map_or_else(Vec::new, |s| {
            s.read()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        })
    }

    pub async fn serve(
        &self,
        req: Request<Incoming>,
        _matched_prefix: &str,
    ) -> HttpResponse {
        let snap = self.metrics.snapshot();
        let certs = self.read_cert_states();
        if accept_json(req.headers()) || query_wants_json(req.uri()) {
            render_json(&snap, &self.summary, &certs)
        } else {
            render_html(&snap, &self.summary, &certs)
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

// True when the URL query contains format=json (used by JS polling).
fn query_wants_json(uri: &hyper::Uri) -> bool {
    uri.query()
        .unwrap_or("")
        .split('&')
        .any(|kv| kv == "format=json")
}

// -- JSON output ---------------------------------------------------

fn render_json(
    s: &Snapshot,
    sum: &ServerSummary,
    certs: &[CertState],
) -> HttpResponse {
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

    let cert_arr: Vec<serde_json::Value> = certs
        .iter()
        .map(|c| serde_json::json!({
            "domains":          c.domains,
            "expiry_ts":        c.expiry_ts,
            "next_renewal_ts":  c.next_renewal_ts,
        }))
        .collect();

    // Convert history slices to serde_json::Value to avoid relying
    // on the json! macro to handle Vec<Option<_>> directly.
    let rate_hist = serde_json::to_value(&s.rate_history)
        .unwrap_or(serde_json::Value::Array(vec![]));
    let mem_hist: serde_json::Value = s
        .memory_history
        .iter()
        .map(|v| v.map_or(serde_json::Value::Null, |n| {
            serde_json::Value::Number(n.into())
        }))
        .collect::<Vec<_>>()
        .into();
    let cpu_hist: serde_json::Value = s
        .cpu_history
        .iter()
        .map(|v| v.map_or(serde_json::Value::Null, |n| {
            serde_json::json!(n)
        }))
        .collect::<Vec<_>>()
        .into();

    let paths_1min: Vec<_> = s.top_paths_1min.iter()
        .map(|(p, c)| serde_json::json!([p, c]))
        .collect();
    let paths_5min: Vec<_> = s.top_paths_5min.iter()
        .map(|(p, c)| serde_json::json!([p, c]))
        .collect();
    let paths_15min: Vec<_> = s.top_paths_15min.iter()
        .map(|(p, c)| serde_json::json!([p, c]))
        .collect();
    let paths_total: Vec<_> = s.top_paths_total.iter()
        .map(|(p, c)| serde_json::json!([p, c]))
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
        "memory_kb":      s.memory_kb,
        "cpu_percent":    s.cpu_percent,
        "rate_history":   rate_hist,
        "memory_history": mem_hist,
        "cpu_history":    cpu_hist,
        "certs":          cert_arr,
        "top_paths": {
            "1min":  paths_1min,
            "5min":  paths_5min,
            "15min": paths_15min,
            "total": paths_total,
        },
        "listeners":      listeners,
        "vhosts":         vhosts,
        "auth":           sum.auth,
    })
    .to_string();

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(bytes_body(Bytes::from(body)))
        .expect("known-valid response")
}

// -- HTML output ---------------------------------------------------

// Inline JavaScript injected at the bottom of the status page.
// Polls ?format=json every 3 s and updates the DOM in place,
// avoiding full-page reloads.
const LIVE_JS: &str = r#"<script>
(function() {
  var POLL_MS = 3000;
  var lastData = null;
  var isOnline = true;

  function setText(id, v) {
    var el = document.getElementById(id);
    if (el) el.textContent = v;
  }

  function fmt(n) { return (+n).toLocaleString(); }

  function setOnline(online) {
    if (online === isOnline) return;
    isOnline = online;
    var dot1 = document.getElementById('live-dot');
    var lbl  = document.getElementById('live-label');
    var dot2 = document.getElementById('live-dot-note');
    var note = document.getElementById('live-note');
    if (online) {
      if (dot1) dot1.classList.remove('offline');
      if (dot2) dot2.classList.remove('offline');
      if (lbl)  { lbl.classList.remove('offline'); lbl.textContent = 'Live'; }
      if (note) note.textContent = 'Updating every 3 s';
    } else {
      if (dot1) dot1.classList.add('offline');
      if (dot2) dot2.classList.add('offline');
      if (lbl)  { lbl.classList.add('offline'); lbl.textContent = 'Offline'; }
      if (note) note.textContent = 'Server not responding';
    }
  }

  // Draw a sparkline into an SVG element using pixel coordinates.
  // No viewBox -- the SVG is sized by CSS; clientWidth gives real px.
  // fmtMax: optional function(maxVal) -> string for the y-axis label.
  function drawSparkline(id, data, color, fmtMax) {
    color = color || 'var(--spark-stroke)';
    var svg = document.getElementById(id);
    if (!svg) return;
    var W = svg.clientWidth || 200;
    var H = svg.clientHeight || 40;
    var n = data.length;
    if (n < 2) return;
    var vals = data.map(function(v) { return v == null ? 0 : +v; });
    var max = Math.max.apply(null, vals) || 1;
    var pad = 2;
    var pts = vals.map(function(v, i) {
      var x = ((i / (n - 1)) * W).toFixed(1);
      var y = (H - pad - (v / max) * (H - pad * 2)).toFixed(1);
      return x + ',' + y;
    });
    svg.innerHTML = '';
    var NS = 'http://www.w3.org/2000/svg';
    // Horizontal grid lines at 25 / 50 / 75 % of height.
    [0.25, 0.5, 0.75].forEach(function(f) {
      var line = document.createElementNS(NS, 'line');
      var y = (H * (1 - f)).toFixed(1);
      line.setAttribute('x1', '0');
      line.setAttribute('x2', String(W));
      line.setAttribute('y1', y);
      line.setAttribute('y2', y);
      line.setAttribute('stroke', 'var(--spark-grid)');
      line.setAttribute('stroke-width', '1');
      svg.appendChild(line);
    });
    // Area fill below the line.
    var area = document.createElementNS(NS, 'path');
    var fx = pts[0].split(',')[0];
    var lx = pts[n - 1].split(',')[0];
    area.setAttribute('d',
      'M' + fx + ',' + H + ' L' + pts.join(' L') +
      ' L' + lx + ',' + H + ' Z');
    area.setAttribute('fill', 'var(--spark-fill)');
    svg.appendChild(area);
    // Stroke.
    var pl = document.createElementNS(NS, 'polyline');
    pl.setAttribute('points', pts.join(' '));
    pl.setAttribute('fill', 'none');
    pl.setAttribute('stroke', color);
    pl.setAttribute('stroke-width', '1.5');
    pl.setAttribute('stroke-linejoin', 'round');
    svg.appendChild(pl);
    // Y-axis max label in the top-right corner.
    if (fmtMax) {
      var lbl = document.createElementNS(NS, 'text');
      lbl.setAttribute('x', String(W - 2));
      lbl.setAttribute('y', '9');
      lbl.setAttribute('text-anchor', 'end');
      lbl.setAttribute('font-size', '8');
      lbl.setAttribute('fill', 'var(--muted)');
      lbl.textContent = fmtMax(max);
      svg.appendChild(lbl);
    }
  }

  function countdown(ts) {
    var diff = ts - Math.floor(Date.now() / 1000);
    if (diff <= 0) return 'expired';
    var d = Math.floor(diff / 86400);
    var h = Math.floor((diff % 86400) / 3600);
    var m = Math.floor((diff % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm';
  }

  function certClass(ts) {
    var days = (ts - Math.floor(Date.now() / 1000)) / 86400;
    if (days < 7)  return 'cert-crit';
    if (days < 30) return 'cert-warn';
    return 'cert-ok';
  }

  function updateCerts(certs) {
    var sec = document.getElementById('certs-section');
    if (!sec) return;
    if (!certs || !certs.length) { sec.style.display = 'none'; return; }
    sec.style.display = '';
    var tbody = sec.querySelector('tbody');
    if (!tbody) return;
    tbody.innerHTML = certs.map(function(c) {
      var cls = certClass(c.expiry_ts);
      return '<tr><td>' + c.domains.join(', ') + '</td>' +
        '<td class="' + cls + ' countdown">' + countdown(c.expiry_ts) + '</td>' +
        '<td class="countdown">' + countdown(c.next_renewal_ts) + '</td></tr>';
    }).join('');
  }

  function updatePaths(data) {
    if (!data || !data.top_paths) return;
    var sel = document.getElementById('paths-window');
    var key = sel ? sel.value : '1min';
    var rows = data.top_paths[key] || [];
    var tbody = document.getElementById('paths-tbody');
    if (!tbody) return;
    if (!rows.length) {
      tbody.innerHTML =
        '<tr><td colspan="2" style="color:var(--muted);' +
        'font-style:italic">No data yet</td></tr>';
      return;
    }
    var maxHits = rows[0][1] || 1;
    tbody.innerHTML = rows.map(function(r) {
      var pct = (r[1] / maxHits * 100).toFixed(1);
      return '<tr>' +
        '<td style="font-family:ui-monospace,monospace;' +
        'font-size:.8rem;word-break:break-all">' + r[0] + '</td>' +
        '<td style="text-align:right;white-space:nowrap;' +
        'padding-left:.75rem">' +
          '<span style="display:inline-block;height:.6rem;' +
          'width:' + pct + 'px;max-width:60px;background:var(--accent);' +
          'border-radius:2px;vertical-align:middle;margin-right:.35rem">' +
          '</span>' + fmt(r[1]) + '</td></tr>';
    }).join('');
  }

  function poll() {
    fetch(location.pathname + '?format=json', {
      headers: { 'Accept': 'application/json' },
      cache: 'no-store'
    })
    .then(function(r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    })
    .then(function(d) {
      setOnline(true);
      lastData = d;
      setText('val-uptime', d.uptime_human);
      setText('val-active', d.requests_active);
      setText('val-total',  fmt(d.requests_total));
      setText('val-rate-cur', d.rates.current_per_sec.toFixed(2));
      setText('val-rate-1m',  d.rates.avg_1min.toFixed(2));
      setText('val-rate-5m',  d.rates.avg_5min.toFixed(2));
      setText('val-rate-15m', d.rates.avg_15min.toFixed(2));
      setText('val-2xx', fmt(d.status['2xx']));
      setText('val-3xx', fmt(d.status['3xx']));
      setText('val-4xx', fmt(d.status['4xx']));
      setText('val-5xx', fmt(d.status['5xx']));
      if (d.memory_kb != null)
        setText('val-mem', Math.round(d.memory_kb / 1024) + ' MiB');
      if (d.cpu_percent != null)
        setText('val-cpu', d.cpu_percent.toFixed(1) + '%');
      var lk = ['lt_1','lt_10','lt_50','lt_200','lt_1000','ge_1000'];
      var tot = lk.reduce(function(s, k) {
        return s + (d.latency_ms[k] || 0);
      }, 0);
      lk.forEach(function(k) {
        var c = d.latency_ms[k] || 0;
        var pct = tot > 0 ? (c / tot * 100).toFixed(1) : '0.0';
        var fill = document.querySelector(
          '.bar-fill[data-lat="' + k + '"]');
        var cnt = document.querySelector(
          '.bar-count[data-lat="' + k + '"]');
        if (fill) fill.style.width = pct + '%';
        if (cnt)  cnt.textContent = fmt(c);
      });
      if (d.rate_history && d.rate_history.length)
        drawSparkline('spark-rate', d.rate_history, null,
          function(v) { return v.toFixed(1) + ' req/s'; });
      if (d.memory_history && d.memory_history.length)
        drawSparkline('spark-mem', d.memory_history, null,
          function(v) { return Math.round(v / 1024) + ' MiB'; });
      if (d.cpu_history && d.cpu_history.length)
        drawSparkline('spark-cpu', d.cpu_history, 'var(--cpu-bar)',
          function(v) { return v.toFixed(1) + '%'; });
      updateCerts(d.certs);
      updatePaths(d);
    })
    .catch(function() { setOnline(false); });
  }

  // Re-render the paths table immediately when the window selector changes.
  var sel = document.getElementById('paths-window');
  if (sel) {
    sel.addEventListener('change', function() { updatePaths(lastData); });
  }

  poll();
  setInterval(poll, POLL_MS);
})();
</script>"#;

fn render_html(
    s: &Snapshot,
    sum: &ServerSummary,
    certs: &[CertState],
) -> HttpResponse {
    let total_lat: u64 = s.latency.iter().sum();
    let resource_sec = resource_section_html(
        s.memory_kb,
        s.cpu_percent,
    );
    let certs_sec = certs_section_html(certs);
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>aloha -- Status</title>
<style>
*,*::before,*::after{{box-sizing:border-box}}
:root{{
  --bg:#f5f7fa;--surface:#fff;--border:#dde3eb;
  --text:#1a2332;--muted:#5e6e82;--accent:#1e3a5f;
  --accent-bg:#edf2f8;--green:#16a34a;--green-bg:#dcfce7;
  --amber:#b45309;--amber-bg:#fef3c7;--red:#b91c1c;--red-bg:#fee2e2;
  --spark-stroke:#1e3a5f;--spark-fill:rgba(30,58,95,.12);
  --spark-grid:#dde3eb;--cpu-bar:#7c3aed;
  --cert-ok:#16a34a;--cert-warn:#b45309;--cert-crit:#b91c1c;
  --live-dot:#22c55e;
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
.live-dot{{display:inline-block;width:8px;height:8px;
  background:var(--live-dot);border-radius:50%;margin-right:.35rem;
  vertical-align:middle;animation:pulse 2s infinite}}
.live-dot.offline{{background:var(--red);animation:none}}
.live-label{{font-size:.78rem;color:rgba(255,255,255,.6)}}
.live-label.offline{{color:rgba(255,120,120,.9)}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.3}}}}
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
.sparkline{{display:block;width:100%;height:40px;margin-top:.75rem;
  overflow:hidden}}
.paths-win{{font-size:.8rem;font-weight:500;color:var(--muted);
  background:transparent;border:1px solid var(--border);
  border-radius:4px;padding:.1rem .35rem;margin-left:.5rem;
  vertical-align:middle;cursor:pointer}}
.note{{font-size:.75rem;color:var(--muted);text-align:right;
  margin-top:.5rem}}
.countdown{{font-variant-numeric:tabular-nums}}
.cert-ok{{color:var(--cert-ok)}}
.cert-warn{{color:var(--cert-warn)}}
.cert-crit{{color:var(--cert-crit);font-weight:700}}
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
  <span class="live-dot" id="live-dot"></span>
  <span class="live-label" id="live-label">Live</span>
  <a class="topbar-home" href="/">&larr; Home</a>
</header>
<main class="main">

<div class="grid-3">
  <div class="card">
    <div class="stat-label">Uptime</div>
    <div class="stat-val" id="val-uptime">{uptime}</div>
  </div>
  <div class="card">
    <div class="stat-label">Active Requests</div>
    <div class="stat-val" id="val-active">{active}</div>
  </div>
  <div class="card">
    <div class="stat-label">Total Requests</div>
    <div class="stat-val" id="val-total">{total}</div>
  </div>
</div>

<div class="grid-2">
  <div class="card sec">
    <h2>Request Rate</h2>
    <table class="rate-table">
      <tr><th>Window</th><th>req / s</th></tr>
      <tr><td>Last 5 s</td>
          <td id="val-rate-cur">{rate_cur:.2}</td></tr>
      <tr><td>1 min avg</td>
          <td id="val-rate-1m">{rate_1m:.2}</td></tr>
      <tr><td>5 min avg</td>
          <td id="val-rate-5m">{rate_5m:.2}</td></tr>
      <tr><td>15 min avg</td>
          <td id="val-rate-15m">{rate_15m:.2}</td></tr>
    </table>
    <svg id="spark-rate" class="sparkline" aria-hidden="true"></svg>
  </div>
  <div class="card sec">
    <h2>Status Codes</h2>
    <div class="sc-grid">
      <div class="sc sc-2xx">
        <div class="sc-val" id="val-2xx">{s2xx}</div>
        <div class="sc-label">2xx</div>
      </div>
      <div class="sc sc-3xx">
        <div class="sc-val" id="val-3xx">{s3xx}</div>
        <div class="sc-label">3xx</div>
      </div>
      <div class="sc sc-4xx">
        <div class="sc-val" id="val-4xx">{s4xx}</div>
        <div class="sc-label">4xx</div>
      </div>
      <div class="sc sc-5xx">
        <div class="sc-val" id="val-5xx">{s5xx}</div>
        <div class="sc-label">5xx</div>
      </div>
    </div>
  </div>
</div>

<div class="card sec">
  <h2>Latency Distribution</h2>
  {latency_bars}
</div>

{resource_sec}
{certs_sec}
<div class="card sec">
  <h2>Top Paths
    <select class="paths-win" id="paths-window">
      <option value="1min">1 minute</option>
      <option value="5min">5 minutes</option>
      <option value="15min">15 minutes</option>
      <option value="total">All time</option>
    </select>
  </h2>
  <table class="info-table">
    <thead>
      <tr><th>Path</th><th style="text-align:right">Hits</th></tr>
    </thead>
    <tbody id="paths-tbody">
      <tr><td colspan="2" style="color:var(--muted);font-style:italic"
        >Loading&hellip;</td></tr>
    </tbody>
  </table>
</div>

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
<p class="note">
  <span class="live-dot" id="live-dot-note"></span>
  <span id="live-note">Updating every 3 s</span>
</p>
</main>
{js}
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
        resource_sec = resource_sec,
        certs_sec    = certs_sec,
        version      = sum.version,
        pid          = std::process::id(),
        auth         = sum.auth.as_deref().unwrap_or("none"),
        listeners_section = listeners_html(&sum.listeners),
        vhosts_section    = vhosts_html(&sum.vhosts),
        js           = LIVE_JS,
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
    const KEYS: &[&str] =
        &["lt_1", "lt_10", "lt_50", "lt_200", "lt_1000", "ge_1000"];
    let mut out = String::new();
    for ((count, label), key) in
        counts.iter().zip(LABELS.iter()).zip(KEYS.iter())
    {
        let pct = if total > 0 {
            ((*count) as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        out.push_str(&format!(
            "<div class=\"bar-row\">\
<span class=\"bar-label\">{label}</span>\
<div class=\"bar-track\">\
<div class=\"bar-fill\" data-lat=\"{key}\" \
style=\"width:{pct:.1}%\"></div>\
</div>\
<span class=\"bar-count\" data-lat=\"{key}\">{count}</span>\
</div>",
        ));
    }
    out
}

fn resource_section_html(
    memory_kb: Option<u64>,
    cpu_percent: Option<f64>,
) -> String {
    let mem = match memory_kb {
        None => String::new(),
        Some(kb) => format!(
            "<div class=\"card sec\">\
<h2>Memory</h2>\
<div class=\"mem-val\" id=\"val-mem\">{} MiB</div>\
<div class=\"stat-label\">Resident set size</div>\
<svg id=\"spark-mem\" class=\"sparkline\" \
aria-hidden=\"true\"></svg>\
</div>",
            kb / 1024
        ),
    };
    let cpu = match cpu_percent {
        None => String::new(),
        Some(pct) => format!(
            "<div class=\"card sec\">\
<h2>CPU</h2>\
<div class=\"mem-val\" id=\"val-cpu\">{pct:.1}%</div>\
<div class=\"stat-label\">Process CPU usage</div>\
<svg id=\"spark-cpu\" class=\"sparkline\" \
aria-hidden=\"true\"></svg>\
</div>",
        ),
    };
    match (mem.is_empty(), cpu.is_empty()) {
        (true, true) => String::new(),
        (false, false) => {
            format!("<div class=\"grid-2\">{mem}{cpu}</div>")
        }
        _ => format!("{mem}{cpu}"),
    }
}

fn certs_section_html(certs: &[CertState]) -> String {
    let display = if certs.is_empty() {
        " style=\"display:none\""
    } else {
        ""
    };
    let rows = certs
        .iter()
        .map(|c| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let expiry_secs = c.expiry_ts - now;
            let renewal_secs = c.next_renewal_ts - now;
            let cls = if expiry_secs < 7 * 86400 {
                "cert-crit"
            } else if expiry_secs < 30 * 86400 {
                "cert-warn"
            } else {
                "cert-ok"
            };
            format!(
                "<tr><td>{domains}</td>\
<td class=\"{cls} countdown\">{expiry}</td>\
<td class=\"countdown\">{renewal}</td></tr>",
                domains = c.domains.join(", "),
                expiry  = fmt_countdown(expiry_secs),
                renewal = fmt_countdown(renewal_secs),
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<div id=\"certs-section\" class=\"card sec\"{display}>\
<h2>TLS Certificates</h2>\
<table class=\"info-table\">\
<tr><th>Domains</th>\
<th class=\"countdown\">Expires In</th>\
<th class=\"countdown\">Renewal In</th></tr>\
<tbody>{rows}</tbody>\
</table></div>"
    )
}

fn fmt_countdown(secs: i64) -> String {
    if secs <= 0 {
        return "expired".into();
    }
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

fn listeners_html(ls: &[ListenerSummary]) -> String {
    if ls.is_empty() {
        return String::new();
    }
    let mut rows = String::new();
    for l in ls {
        let domains = l.acme_domains.join(", ");
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
        let aliases = v.aliases.join(", ");
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
            uptime:           Duration::from_secs(3661),
            requests_total:   1234,
            requests_active:  3,
            status_2xx:       1100,
            status_3xx:       80,
            status_4xx:       50,
            status_5xx:       4,
            latency:          [800, 300, 100, 20, 10, 4],
            rate_current:     12.5,
            rate_1min:        10.2,
            rate_5min:        8.7,
            rate_15min:       7.1,
            memory_kb:        Some(32768),
            cpu_percent:      Some(5.2),
            rate_history:     vec![1.0; 30],
            memory_history:   vec![Some(32768); 30],
            cpu_history:      vec![Some(5.0); 30],
            top_paths_1min:   vec![("/".into(), 10), ("/api".into(), 5)],
            top_paths_5min:   vec![("/".into(), 50)],
            top_paths_15min:  vec![("/".into(), 150)],
            top_paths_total:  vec![("/".into(), 1000)],
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

    // -- query_wants_json ------------------------------------------

    #[test]
    fn query_wants_json_true_for_format_param() {
        let uri: hyper::Uri =
            "/status?format=json".parse().unwrap();
        assert!(query_wants_json(&uri));
    }

    #[test]
    fn query_wants_json_true_with_other_params() {
        let uri: hyper::Uri =
            "/status?foo=bar&format=json".parse().unwrap();
        assert!(query_wants_json(&uri));
    }

    #[test]
    fn query_wants_json_false_for_no_param() {
        let uri: hyper::Uri = "/status".parse().unwrap();
        assert!(!query_wants_json(&uri));
    }

    #[test]
    fn query_wants_json_false_for_other_format() {
        let uri: hyper::Uri =
            "/status?format=html".parse().unwrap();
        assert!(!query_wants_json(&uri));
    }

    // -- render_json -----------------------------------------------

    #[tokio::test]
    async fn render_json_contains_required_keys() {
        use http_body_util::BodyExt;
        let resp =
            render_json(&sample_snap(), &sample_summary(), &[]);
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
    async fn render_json_contains_top_paths() {
        use http_body_util::BodyExt;
        let resp =
            render_json(&sample_snap(), &sample_summary(), &[]);
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        assert!(v["top_paths"].is_object());
        assert!(v["top_paths"]["1min"].is_array());
        assert!(!v["top_paths"]["1min"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn render_json_contains_new_keys() {
        use http_body_util::BodyExt;
        let resp =
            render_json(&sample_snap(), &sample_summary(), &[]);
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("\"rate_history\""));
        assert!(text.contains("\"memory_history\""));
        assert!(text.contains("\"cpu_history\""));
        assert!(text.contains("\"cpu_percent\""));
        assert!(text.contains("\"certs\""));
    }

    #[tokio::test]
    async fn render_json_cert_state_included() {
        use http_body_util::BodyExt;
        let certs = vec![CertState {
            domains: vec!["test.example.com".into()],
            expiry_ts: 9_999_999_999,
            next_renewal_ts: 9_997_406_399,
        }];
        let resp =
            render_json(&sample_snap(), &sample_summary(), &certs);
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            v["certs"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            v["certs"][0]["expiry_ts"],
            9_999_999_999_i64
        );
    }

    #[tokio::test]
    async fn render_json_status_code_values() {
        use http_body_util::BodyExt;
        let resp =
            render_json(&sample_snap(), &sample_summary(), &[]);
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
        let resp =
            render_json(&sample_snap(), &sample_summary(), &[]);
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
        let resp =
            render_json(&sample_snap(), &sample_summary(), &[]);
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
        let resp =
            render_json(&sample_snap(), &sample_summary(), &[]);
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
        let resp = render_json(&sample_snap(), &sum, &[]);
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
    async fn render_html_no_meta_refresh() {
        use http_body_util::BodyExt;
        let resp = render_html(
            &sample_snap(), &sample_summary(), &[],
        );
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !html.contains("http-equiv"),
            "meta refresh must be removed"
        );
    }

    #[tokio::test]
    async fn render_html_has_live_indicator() {
        use http_body_util::BodyExt;
        let resp = render_html(
            &sample_snap(), &sample_summary(), &[],
        );
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(
            html.contains("live-dot"),
            "live indicator must be present"
        );
    }

    #[tokio::test]
    async fn render_html_contains_status_classes() {
        use http_body_util::BodyExt;
        let resp = render_html(
            &sample_snap(), &sample_summary(), &[],
        );
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
    async fn render_html_has_sparkline_ids() {
        use http_body_util::BodyExt;
        let resp = render_html(
            &sample_snap(), &sample_summary(), &[],
        );
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("id=\"spark-rate\""));
        assert!(html.contains("id=\"spark-mem\""));
        assert!(html.contains("id=\"spark-cpu\""));
    }

    #[tokio::test]
    async fn render_html_no_memory_section_when_none() {
        use http_body_util::BodyExt;
        let mut s = sample_snap();
        s.memory_kb = None;
        s.cpu_percent = None;
        let resp = render_html(&s, &sample_summary(), &[]);
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
    async fn render_html_certs_section_hidden_when_empty() {
        use http_body_util::BodyExt;
        let resp = render_html(
            &sample_snap(), &sample_summary(), &[],
        );
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(
            html.contains("certs-section"),
            "certs section must always be rendered"
        );
        assert!(
            html.contains("display:none"),
            "certs section should be hidden when no certs"
        );
    }

    #[tokio::test]
    async fn render_html_certs_section_visible_when_present() {
        use http_body_util::BodyExt;
        let certs = vec![CertState {
            domains: vec!["example.com".into()],
            expiry_ts: 9_999_999_999,
            next_renewal_ts: 9_997_406_399,
        }];
        let resp =
            render_html(&sample_snap(), &sample_summary(), &certs);
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !html.contains("certs-section\" class=\"card sec\" style=\"display:none\""),
            "certs section should not be hidden"
        );
        assert!(html.contains("TLS Certificates"));
    }

    #[tokio::test]
    async fn render_html_contains_listeners_section() {
        use http_body_util::BodyExt;
        let resp = render_html(
            &sample_snap(), &sample_summary(), &[],
        );
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
        let resp = render_html(
            &sample_snap(), &sample_summary(), &[],
        );
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
        let resp = render_html(
            &sample_snap(), &sample_summary(), &[],
        );
        let bytes = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let html = std::str::from_utf8(&bytes).unwrap();
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
        let resp = render_html(&sample_snap(), &sum, &[]);
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

    // -- fmt_countdown ---------------------------------------------

    #[test]
    fn fmt_countdown_expired() {
        assert_eq!(fmt_countdown(0), "expired");
        assert_eq!(fmt_countdown(-100), "expired");
    }

    #[test]
    fn fmt_countdown_minutes() {
        assert_eq!(fmt_countdown(300), "5m");
    }

    #[test]
    fn fmt_countdown_hours() {
        assert_eq!(fmt_countdown(3 * 3600 + 30 * 60), "3h 30m");
    }

    #[test]
    fn fmt_countdown_days() {
        assert_eq!(
            fmt_countdown(2 * 86400 + 3 * 3600 + 15 * 60),
            "2d 3h 15m"
        );
    }
}
