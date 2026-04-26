use crate::error::{bytes_body, response_502, HttpResponse};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── FastCGI constants ─────────────────────────────────────────────

const FCGI_VERSION: u8 = 1;
const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;
const FCGI_END_REQUEST: u8 = 3;
// Responder is the standard role for web-to-app-server requests.
const FCGI_RESPONDER: u16 = 1;
// We don't multiplex; a single request ID per connection is safe.
const REQUEST_ID: u16 = 1;

// ── Handler ───────────────────────────────────────────────────────

pub struct FcgiHandler {
    socket: String,
    root: String,
    index: Option<String>,
}

impl FcgiHandler {
    pub fn new(socket: &str, root: &str, index: Option<String>) -> Self {
        Self {
            socket: socket.to_owned(),
            root: root.to_owned(),
            index,
        }
    }

    pub async fn serve(
        &self,
        req: Request<Incoming>,
        matched_prefix: &str,
    ) -> HttpResponse {
        // Separate headers from body so we can collect the body without
        // losing the metadata needed for the CGI environment.
        let (parts, body) = req.into_parts();
        let body_bytes = match BodyExt::collect(body).await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                tracing::error!(
                    socket = %self.socket,
                    "fastcgi: failed to read request body: {e}"
                );
                return response_502();
            }
        };

        let env = build_cgi_env(
            &parts,
            &self.root,
            matched_prefix,
            &self.index,
            &body_bytes,
        );
        let request_bytes = build_fcgi_request(&env, &body_bytes);

        match self.execute(&request_bytes).await {
            Ok(raw) => match parse_fcgi_stdout(&raw) {
                Ok(stdout) => match parse_cgi_response(&stdout) {
                    Ok(resp) => resp,
                    Err(e) => {
                        tracing::error!(
                            socket = %self.socket,
                            "fastcgi: malformed CGI response: {e}"
                        );
                        response_502()
                    }
                },
                Err(e) => {
                    tracing::error!(
                        socket = %self.socket,
                        "fastcgi: protocol error: {e}"
                    );
                    response_502()
                }
            },
            Err(e) => {
                tracing::error!(
                    socket = %self.socket,
                    "fastcgi: connection error: {e}"
                );
                response_502()
            }
        }
    }

    async fn execute(&self, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        if let Some(path) = self.socket.strip_prefix("unix:") {
            let stream = tokio::net::UnixStream::connect(path).await?;
            let (mut reader, mut writer) = stream.into_split();
            writer.write_all(request).await?;
            writer.shutdown().await?;
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).await?;
            Ok(buf)
        } else if let Some(addr) = self.socket.strip_prefix("tcp:") {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            let (mut reader, mut writer) = stream.into_split();
            writer.write_all(request).await?;
            writer.shutdown().await?;
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).await?;
            Ok(buf)
        } else {
            anyhow::bail!(
                "unsupported fastcgi socket '{}'; \
                 use unix:/path or tcp:host:port",
                self.socket
            )
        }
    }
}

// ── Record encoding ───────────────────────────────────────────────

fn build_record(type_: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let padding = (8 - (len % 8)) % 8;
    let id = REQUEST_ID.to_be_bytes();
    let cl = (len as u16).to_be_bytes();
    let mut rec = Vec::with_capacity(8 + len + padding);
    rec.extend_from_slice(&[
        FCGI_VERSION, type_,
        id[0], id[1],
        cl[0], cl[1],
        padding as u8,
        0,
    ]);
    rec.extend_from_slice(content);
    rec.extend(std::iter::repeat(0u8).take(padding));
    rec
}

// FastCGI name-value length encoding: values < 128 use 1 byte,
// larger values use 4 bytes with the high bit set.
fn encode_length(out: &mut Vec<u8>, n: usize) {
    if n < 128 {
        out.push(n as u8);
    } else {
        let encoded = (n as u32) | 0x8000_0000;
        out.extend_from_slice(&encoded.to_be_bytes());
    }
}

pub fn encode_params<K: AsRef<str>, V: AsRef<str>>(
    vars: &[(K, V)],
) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in vars {
        let n = name.as_ref().as_bytes();
        let v = value.as_ref().as_bytes();
        encode_length(&mut out, n.len());
        encode_length(&mut out, v.len());
        out.extend_from_slice(n);
        out.extend_from_slice(v);
    }
    out
}

fn build_fcgi_request(env: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();

    // FCGI_BEGIN_REQUEST: role (2 BE bytes) + flags (1) + reserved (5)
    let role = FCGI_RESPONDER.to_be_bytes();
    let begin = [role[0], role[1], 0, 0, 0, 0, 0, 0];
    out.extend(build_record(FCGI_BEGIN_REQUEST, &begin));

    // FCGI_PARAMS: environment variables, then empty stream terminator
    out.extend(build_record(FCGI_PARAMS, &encode_params(env)));
    out.extend(build_record(FCGI_PARAMS, &[]));

    // FCGI_STDIN: request body, then empty stream terminator
    out.extend(build_record(FCGI_STDIN, body));
    out.extend(build_record(FCGI_STDIN, &[]));

    out
}

// ── CGI environment ───────────────────────────────────────────────

fn build_cgi_env(
    parts: &hyper::http::request::Parts,
    root: &str,
    _matched_prefix: &str,
    index: &Option<String>,
    body: &[u8],
) -> Vec<(String, String)> {
    let uri = &parts.uri;
    let path = uri.path();
    let query = uri.query().unwrap_or("");

    // For directory requests, append the configured index filename.
    let script_name = if path.ends_with('/') {
        match index {
            Some(idx) => format!("{path}{idx}"),
            None => path.to_owned(),
        }
    } else {
        path.to_owned()
    };

    // SCRIPT_FILENAME is the absolute filesystem path PHP-FPM uses to
    // locate the script.  PHP-FPM ignores SCRIPT_NAME and only uses this.
    let script_filename = format!(
        "{}/{}",
        root.trim_end_matches('/'),
        script_name.trim_start_matches('/'),
    );

    let request_uri = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };

    let host_hdr = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let (server_name, server_port) = split_host_port(host_hdr);

    let content_type = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    // Prefer the actual body length over the header value so that
    // the CGI app always sees a consistent CONTENT_LENGTH.
    let content_length = body.len().to_string();

    let mut env: Vec<(String, String)> = vec![
        ("GATEWAY_INTERFACE".into(), "CGI/1.1".into()),
        ("SERVER_SOFTWARE".into(),   "aloha/0.1.0".into()),
        ("SERVER_PROTOCOL".into(),   "HTTP/1.1".into()),
        ("REQUEST_METHOD".into(),    parts.method.as_str().into()),
        ("REQUEST_URI".into(),       request_uri),
        ("SCRIPT_NAME".into(),       script_name),
        ("SCRIPT_FILENAME".into(),   script_filename),
        ("PATH_INFO".into(),         "".into()),
        ("QUERY_STRING".into(),      query.to_owned()),
        ("CONTENT_TYPE".into(),      content_type),
        ("CONTENT_LENGTH".into(),    content_length),
        ("SERVER_NAME".into(),       server_name.to_owned()),
        ("SERVER_PORT".into(),       server_port.to_owned()),
        // REMOTE_ADDR: no peer address is available at handler level;
        // real IPs reach PHP via X-Forwarded-For in proxy deployments.
        ("REMOTE_ADDR".into(),       "0.0.0.0".into()),
    ];

    // Translate HTTP headers to HTTP_* CGI variables.
    // Skip Content-Type and Content-Length; they have dedicated vars.
    for (name, value) in &parts.headers {
        let lower = name.as_str();
        if lower == "content-type" || lower == "content-length" {
            continue;
        }
        if let Ok(v) = value.to_str() {
            let cgi_name = format!(
                "HTTP_{}",
                lower.to_ascii_uppercase().replace('-', "_")
            );
            env.push((cgi_name, v.to_owned()));
        }
    }

    env
}

// Split "host[:port]" → ("host", "port").  Handles IPv6 brackets.
fn split_host_port(host: &str) -> (&str, &str) {
    if host.starts_with('[') {
        if let Some(end) = host.find(']') {
            let port = host[end + 1..].strip_prefix(':').unwrap_or("80");
            return (&host[..=end], port);
        }
    }
    match host.rfind(':') {
        Some(i) => (&host[..i], &host[i + 1..]),
        None    => (host, "80"),
    }
}

// ── Response parsing ──────────────────────────────────────────────

// Concatenate FCGI_STDOUT record content from the raw response stream.
// Stops at FCGI_END_REQUEST.  FCGI_STDERR is logged and discarded.
pub fn parse_fcgi_stdout(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut stdout = Vec::new();
    let mut pos = 0;
    while pos + 8 <= data.len() {
        let type_        = data[pos + 1];
        let content_len =
            u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
        let padding_len  = data[pos + 6] as usize;
        let end = pos + 8 + content_len + padding_len;
        if end > data.len() {
            anyhow::bail!(
                "truncated fastcgi record at byte {pos}"
            );
        }
        let content = &data[pos + 8..pos + 8 + content_len];
        match type_ {
            FCGI_STDOUT => stdout.extend_from_slice(content),
            FCGI_STDERR => {
                if let Ok(msg) = std::str::from_utf8(content) {
                    let msg = msg.trim();
                    if !msg.is_empty() {
                        tracing::warn!("fastcgi stderr: {msg}");
                    }
                }
            }
            FCGI_END_REQUEST => break,
            _ => {}
        }
        pos = end;
    }
    Ok(stdout)
}

// Parse a CGI-format response into a hyper Response.
// The CGI Status header sets the status code (default 200).
// All other headers are forwarded verbatim.
pub fn parse_cgi_response(stdout: &[u8]) -> anyhow::Result<HttpResponse> {
    let (header_bytes, body) =
        find_header_boundary(stdout).ok_or_else(|| {
            anyhow::anyhow!("fastcgi response has no header/body separator")
        })?;

    let headers_str = std::str::from_utf8(header_bytes)
        .map_err(|_| anyhow::anyhow!("fastcgi headers are not UTF-8"))?;

    let mut status = StatusCode::OK;
    let mut builder = Response::builder();

    for line in headers_str.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (key, val) = line.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("malformed fastcgi header line: {line:?}")
        })?;
        let key = key.trim();
        let val = val.trim();
        if key.eq_ignore_ascii_case("status") {
            // "Status: 404 Not Found" — only the numeric portion matters.
            let code: u16 = val
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| {
                    anyhow::anyhow!("malformed Status header: {val:?}")
                })?;
            status = StatusCode::from_u16(code).map_err(|_| {
                anyhow::anyhow!("invalid HTTP status code {code}")
            })?;
        } else {
            builder = builder.header(key, val);
        }
    }

    Ok(builder
        .status(status)
        .body(bytes_body(bytes::Bytes::copy_from_slice(body)))
        .expect("known-valid response builder"))
}

fn find_header_boundary(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(i) = find_subsequence(data, b"\r\n\r\n") {
        return Some((&data[..i], &data[i + 4..]));
    }
    if let Some(i) = find_subsequence(data, b"\n\n") {
        return Some((&data[..i], &data[i + 2..]));
    }
    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_record_has_correct_header() {
        let rec = build_record(FCGI_PARAMS, b"hello");
        assert_eq!(rec[0], FCGI_VERSION);
        assert_eq!(rec[1], FCGI_PARAMS);
        assert_eq!(u16::from_be_bytes([rec[2], rec[3]]), REQUEST_ID);
        assert_eq!(u16::from_be_bytes([rec[4], rec[5]]), 5); // content len
        assert_eq!(rec[6], 3); // padding: (8 - 5%8) % 8 = 3
        assert_eq!(&rec[8..13], b"hello");
    }

    #[test]
    fn build_record_pads_to_8_bytes() {
        for len in 0usize..=16 {
            let content = vec![0u8; len];
            let rec = build_record(FCGI_STDOUT, &content);
            let padding = rec[6] as usize;
            assert_eq!((8 + len + padding) % 8, 0);
            assert_eq!(rec.len(), 8 + len + padding);
        }
    }

    #[test]
    fn encode_params_short_names() {
        let params = encode_params(&[("FOO", "bar")]);
        assert_eq!(params[0], 3); // name length
        assert_eq!(params[1], 3); // value length
        assert_eq!(&params[2..5], b"FOO");
        assert_eq!(&params[5..8], b"bar");
        assert_eq!(params.len(), 8);
    }

    #[test]
    fn encode_params_long_name() {
        let long_name = "X".repeat(200);
        let params = encode_params(&[(&long_name, "v")]);
        // 4-byte length with high bit set
        assert_eq!(params[0] & 0x80, 0x80);
        let name_len = u32::from_be_bytes([
            params[0] & 0x7f, params[1], params[2], params[3],
        ]) as usize;
        assert_eq!(name_len, 200);
        // value "v" → 1-byte length
        assert_eq!(params[4], 1);
    }

    #[test]
    fn encode_params_empty() {
        assert!(encode_params::<&str, &str>(&[]).is_empty());
    }

    #[test]
    fn parse_fcgi_stdout_collects_stdout_records() {
        let content = b"Content-Type: text/plain\r\n\r\nhello";
        let mut data = build_record(FCGI_STDOUT, content);
        data.extend(build_record(FCGI_END_REQUEST, &[0u8; 8]));
        assert_eq!(parse_fcgi_stdout(&data).unwrap(), content);
    }

    #[test]
    fn parse_fcgi_stdout_ignores_stderr() {
        let mut data = build_record(FCGI_STDERR, b"PHP Notice: foo");
        data.extend(build_record(
            FCGI_STDOUT,
            b"Content-Type: text/plain\r\n\r\nok",
        ));
        data.extend(build_record(FCGI_END_REQUEST, &[0u8; 8]));
        assert_eq!(
            parse_fcgi_stdout(&data).unwrap(),
            b"Content-Type: text/plain\r\n\r\nok"
        );
    }

    #[test]
    fn parse_fcgi_stdout_multiple_chunks() {
        // PHP-FPM may split STDOUT across several records.
        let mut data = build_record(FCGI_STDOUT, b"Content-Type: text/plain\r\n");
        data.extend(build_record(FCGI_STDOUT, b"\r\nbody"));
        data.extend(build_record(FCGI_END_REQUEST, &[0u8; 8]));
        assert_eq!(
            parse_fcgi_stdout(&data).unwrap(),
            b"Content-Type: text/plain\r\n\r\nbody"
        );
    }

    #[test]
    fn parse_cgi_response_defaults_to_200() {
        let stdout = b"Content-Type: text/html\r\n\r\n<h1>ok</h1>";
        assert_eq!(parse_cgi_response(stdout).unwrap().status(), 200);
    }

    #[test]
    fn parse_cgi_response_explicit_status() {
        let stdout =
            b"Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\nnope";
        assert_eq!(parse_cgi_response(stdout).unwrap().status(), 404);
    }

    #[test]
    fn parse_cgi_response_headers_copied() {
        let stdout = b"Content-Type: text/css\r\nX-Custom: yes\r\n\r\nbody";
        let resp = parse_cgi_response(stdout).unwrap();
        assert_eq!(resp.headers().get("content-type").unwrap(), "text/css");
        assert_eq!(resp.headers().get("x-custom").unwrap(), "yes");
    }

    #[test]
    fn parse_cgi_response_unix_newlines() {
        // Some FastCGI apps use \n\n instead of \r\n\r\n.
        let stdout = b"Content-Type: text/plain\n\nbody";
        assert_eq!(parse_cgi_response(stdout).unwrap().status(), 200);
    }

    #[test]
    fn split_host_port_plain() {
        assert_eq!(split_host_port("example.com:8080"), ("example.com", "8080"));
        assert_eq!(split_host_port("example.com"), ("example.com", "80"));
    }

    #[test]
    fn split_host_port_ipv6() {
        assert_eq!(split_host_port("[::1]:9000"), ("[::1]", "9000"));
        assert_eq!(split_host_port("[::1]"), ("[::1]", "80"));
    }
}
