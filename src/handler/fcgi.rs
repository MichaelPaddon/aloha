use super::cgi_util::{build_cgi_env, parse_cgi_response};
use crate::error::{response_502, HttpResponse};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::Request;
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

        let env =
            build_cgi_env(&parts, &self.root, matched_prefix, &self.index, &body_bytes);
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

// ── STDOUT parsing ────────────────────────────────────────────────

// Concatenate FCGI_STDOUT record content from the raw response stream.
// Stops at FCGI_END_REQUEST.  FCGI_STDERR is logged and discarded.
pub fn parse_fcgi_stdout(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut stdout = Vec::new();
    let mut pos = 0;
    while pos + 8 <= data.len() {
        let type_       = data[pos + 1];
        let content_len =
            u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
        let padding_len = data[pos + 6] as usize;
        let end = pos + 8 + content_len + padding_len;
        if end > data.len() {
            anyhow::bail!("truncated fastcgi record at byte {pos}");
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
        assert_eq!(u16::from_be_bytes([rec[4], rec[5]]), 5);
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
        assert_eq!(params[0], 3);
        assert_eq!(params[1], 3);
        assert_eq!(&params[2..5], b"FOO");
        assert_eq!(&params[5..8], b"bar");
        assert_eq!(params.len(), 8);
    }

    #[test]
    fn encode_params_long_name() {
        let long_name = "X".repeat(200);
        let params = encode_params(&[(&long_name, "v")]);
        assert_eq!(params[0] & 0x80, 0x80);
        let name_len = u32::from_be_bytes([
            params[0] & 0x7f, params[1], params[2], params[3],
        ]) as usize;
        assert_eq!(name_len, 200);
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
        let mut data = build_record(FCGI_STDOUT, b"Content-Type: text/plain\r\n");
        data.extend(build_record(FCGI_STDOUT, b"\r\nbody"));
        data.extend(build_record(FCGI_END_REQUEST, &[0u8; 8]));
        assert_eq!(
            parse_fcgi_stdout(&data).unwrap(),
            b"Content-Type: text/plain\r\n\r\nbody"
        );
    }
}
