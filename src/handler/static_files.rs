use crate::error::{
    bytes_body, response_400, response_403, response_404,
    response_416, response_500, HttpResponse,
};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use std::fs::Metadata;
use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::UNIX_EPOCH;
use tokio::fs::{self, File};
use tokio::io::{AsyncRead, AsyncSeekExt, ReadBuf};

pub struct StaticHandler {
    root: PathBuf,
    index_files: Vec<String>,
    strip_prefix: bool,
}

impl StaticHandler {
    pub fn new(
        root: &str,
        index_files: Vec<String>,
        strip_prefix: bool,
    ) -> Self {
        Self {
            root: PathBuf::from(root),
            index_files,
            strip_prefix,
        }
    }

    pub async fn serve(
        &self,
        req: &Request<Incoming>,
        matched_prefix: &str,
    ) -> HttpResponse {
        let uri_path = req.uri().path();

        let relative = if self.strip_prefix {
            uri_path
                .strip_prefix(matched_prefix)
                .unwrap_or(uri_path)
        } else {
            uri_path
        };

        let file_path = match safe_join(&self.root, relative) {
            Some(p) => p,
            None => return response_400(),
        };

        // Canonicalise both root and the requested path.
        // The starts_with check guards against symlinks that escape
        // the configured root directory.
        let canonical_root = match self.root.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    root = %self.root.display(),
                    error = %e,
                    "static root is not accessible"
                );
                return response_500();
            }
        };
        let canonical_path = match file_path.canonicalize() {
            Ok(p) => p,
            Err(_) => return response_404(),
        };
        if !canonical_path.starts_with(&canonical_root) {
            return response_403();
        }

        let metadata = match fs::metadata(&canonical_path).await {
            Ok(m) => m,
            Err(_) => return response_404(),
        };

        // Resolve index file for directory requests.
        let target = if metadata.is_dir() {
            match self.resolve_index(&canonical_path).await {
                Some(p) => p,
                // Directory exists but has no index — do not list.
                None => return response_403(),
            }
        } else {
            canonical_path
        };

        let metadata = match fs::metadata(&target).await {
            Ok(m) => m,
            Err(_) => return response_404(),
        };

        let etag = compute_etag(&metadata);
        if is_not_modified(req, &etag) {
            return Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header("ETag", &etag)
                .body(bytes_body(Bytes::new()))
                .unwrap();
        }

        let file_len = metadata.len();
        let content_type = mime_guess::from_path(&target)
            .first_raw()
            .unwrap_or("application/octet-stream");

        // Parse an optional Range header and build the response.
        match parse_range_header(req, file_len) {
            // Syntactically valid range that fits within the file.
            Some(Ok((start, end))) => {
                let mut file = match File::open(&target).await {
                    Ok(f) => f,
                    Err(_) => return response_500(),
                };
                if file.seek(SeekFrom::Start(start)).await.is_err() {
                    return response_500();
                }
                let length = end - start + 1;
                Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header("Content-Type", content_type)
                    .header("Content-Length", length)
                    .header("Content-Range", format!(
                        "bytes {start}-{end}/{file_len}"
                    ))
                    .header("ETag", &etag)
                    .header("Accept-Ranges", "bytes")
                    .body(
                        FileBody::new(file, Some(length))
                            .map_err(|e| {
                                tracing::warn!(
                                    "file read error: {e}"
                                );
                                e
                            })
                            .boxed(),
                    )
                    .unwrap()
            }
            // Range header present but out of bounds → 416.
            Some(Err(())) => response_416(file_len),
            // No Range header → full 200 response.
            None => {
                let file = match File::open(&target).await {
                    Ok(f) => f,
                    Err(_) => return response_500(),
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", content_type)
                    .header("Content-Length", file_len)
                    .header("ETag", &etag)
                    .header("Accept-Ranges", "bytes")
                    .body(
                        FileBody::new(file, None)
                            .map_err(|e| {
                                tracing::warn!(
                                    "file read error: {e}"
                                );
                                e
                            })
                            .boxed(),
                    )
                    .unwrap()
            }
        }
    }

    async fn resolve_index(&self, dir: &Path) -> Option<PathBuf> {
        for name in &self.index_files {
            let candidate = dir.join(name);
            if fs::metadata(&candidate).await.is_ok() {
                return Some(candidate);
            }
        }
        None
    }
}

// ── Range parsing ─────────────────────────────────────────────────
//
// Parses a single `Range: bytes=start-end` header value.
// Returns:
//   None          – no Range header (serve the full file)
//   Some(Ok(_))   – valid range within [0, file_len)
//   Some(Err(()))  – syntactically invalid or out-of-range (→ 416)
//
// Multi-range requests (e.g. `bytes=0-499,600-999`) are not supported;
// they are treated as absent and a 200 is returned instead.
fn parse_range_header(
    req: &Request<Incoming>,
    file_len: u64,
) -> Option<Result<(u64, u64), ()>> {
    let value = req
        .headers()
        .get("range")
        .and_then(|v| v.to_str().ok())?;

    let bytes = value.strip_prefix("bytes=")?;

    // Decline multi-range requests — return None so the caller sends 200.
    if bytes.contains(',') {
        return None;
    }

    let (start, end) = if let Some(suffix) = bytes.strip_prefix('-') {
        // Suffix range: bytes=-N → last N bytes.
        let n: u64 = suffix.parse().ok()?;
        if n == 0 || file_len == 0 {
            return Some(Err(()));
        }
        let start = file_len.saturating_sub(n);
        (start, file_len - 1)
    } else {
        let mut parts = bytes.splitn(2, '-');
        let start: u64 = parts.next()?.parse().ok()?;
        let end_str = parts.next()?;
        let end = if end_str.is_empty() {
            // Open-ended: bytes=N- → from N to EOF.
            if file_len == 0 {
                return Some(Err(()));
            }
            file_len - 1
        } else {
            end_str.parse().ok()?
        };
        (start, end)
    };

    if start > end || end >= file_len {
        return Some(Err(()));
    }
    Some(Ok((start, end)))
}

// ── FileBody ──────────────────────────────────────────────────────
//
// Streams a tokio File in 64 KB chunks without buffering the whole
// file in memory.  `limit` caps the number of bytes read, enabling
// Range responses without over-reading.

const CHUNK: usize = 65536;

struct FileBody {
    file: File,
    buf: Box<[u8; CHUNK]>,
    // Remaining bytes to deliver; None means "read until EOF".
    remaining: Option<u64>,
    done: bool,
}

impl FileBody {
    fn new(file: File, limit: Option<u64>) -> Self {
        Self {
            file,
            buf: Box::new([0u8; CHUNK]),
            remaining: limit,
            done: false,
        }
    }
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }

        // How many bytes to request in this read.
        let want = match self.remaining {
            Some(0) => {
                self.done = true;
                return Poll::Ready(None);
            }
            Some(rem) => (rem as usize).min(CHUNK),
            None => CHUNK,
        };

        let this = self.as_mut().get_mut();
        let mut rbuf = ReadBuf::new(&mut this.buf[..want]);
        match Pin::new(&mut this.file).poll_read(cx, &mut rbuf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                this.done = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(Ok(())) => {
                let n = rbuf.filled().len();
                if n == 0 {
                    this.done = true;
                    Poll::Ready(None)
                } else {
                    if let Some(rem) = this.remaining.as_mut() {
                        *rem -= n as u64;
                    }
                    let bytes =
                        Bytes::copy_from_slice(&this.buf[..n]);
                    Poll::Ready(Some(Ok(Frame::data(bytes))))
                }
            }
        }
    }
}

// ── Path helpers ──────────────────────────────────────────────────

/// Join `root` with the URI-decoded `uri_path`, blocking traversal.
///
/// Returns `None` if the path contains `..` segments or null bytes.
/// The caller must still verify the canonicalised result stays inside
/// `root` to defend against symlink escapes.
pub fn safe_join(root: &Path, uri_path: &str) -> Option<PathBuf> {
    if uri_path.contains('\0') {
        return None;
    }

    let decoded = percent_decode(uri_path);

    // Reject any ".." segment after decoding, before the filesystem
    // sees the path.  This stops both raw and percent-encoded traversal.
    for segment in decoded.split('/') {
        if segment == ".." {
            return None;
        }
    }

    let relative = decoded.trim_start_matches('/');
    Some(root.join(relative))
}

// Percent-decode a URI component.  Invalid sequences are passed through
// as-is rather than returning an error, matching common server behaviour.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                hex_nibble(bytes[i + 1]),
                hex_nibble(bytes[i + 2]),
            ) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ETag derived from mtime + file size.  Cheap to compute and stable
// across server restarts as long as the file is unchanged.
fn compute_etag(meta: &Metadata) -> String {
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("\"{}-{}\"", mtime, meta.len())
}

fn is_not_modified(req: &Request<Incoming>, etag: &str) -> bool {
    req.headers()
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == etag)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn safe_join_normal() {
        let root = Path::new("/var/www");
        assert_eq!(
            safe_join(root, "/index.html"),
            Some(PathBuf::from("/var/www/index.html"))
        );
    }

    #[test]
    fn safe_join_traversal_rejected() {
        let root = Path::new("/var/www");
        assert_eq!(safe_join(root, "/../etc/passwd"), None);
        assert_eq!(safe_join(root, "/foo/../../etc/passwd"), None);
    }

    #[test]
    fn safe_join_null_byte_rejected() {
        let root = Path::new("/var/www");
        assert_eq!(safe_join(root, "/foo\0bar"), None);
    }

    #[test]
    fn safe_join_percent_encoded_traversal_rejected() {
        let root = Path::new("/var/www");
        // %2e%2e decodes to ".." which must be caught after decoding.
        assert_eq!(safe_join(root, "/%2e%2e/etc/passwd"), None);
    }

    #[test]
    fn safe_join_encoded_slash_in_name_is_fine() {
        let root = Path::new("/var/www");
        // %2F → '/' → segments ["foo", "bar.txt"], neither is "..".
        let result = safe_join(root, "/foo%2Fbar.txt");
        assert!(result.is_some());
    }

    #[test]
    fn percent_decode_basics() {
        assert_eq!(
            percent_decode("/hello%20world"),
            "/hello world"
        );
        assert_eq!(percent_decode("/foo%2Fbar"), "/foo/bar");
    }

    fn parse(range_hdr: &str, file_len: u64)
        -> Option<Result<(u64, u64), ()>>
    {
        parse_range_header_str(range_hdr, file_len)
    }

    // Mirrors parse_range_header without needing a real Request<Incoming>.
    fn parse_range_header_str(
        hdr: &str,
        file_len: u64,
    ) -> Option<Result<(u64, u64), ()>> {
        let bytes = hdr.strip_prefix("bytes=")?;
        if bytes.contains(',') {
            return None;
        }
        let (start, end) =
            if let Some(suffix) = bytes.strip_prefix('-') {
                let n: u64 = suffix.parse().ok()?;
                if n == 0 || file_len == 0 {
                    return Some(Err(()));
                }
                (file_len.saturating_sub(n), file_len - 1)
            } else {
                let mut parts = bytes.splitn(2, '-');
                let start: u64 = parts.next()?.parse().ok()?;
                let end_str = parts.next()?;
                let end = if end_str.is_empty() {
                    if file_len == 0 {
                        return Some(Err(()));
                    }
                    file_len - 1
                } else {
                    end_str.parse().ok()?
                };
                (start, end)
            };
        if start > end || end >= file_len {
            return Some(Err(()));
        }
        Some(Ok((start, end)))
    }

    #[test]
    fn range_full_explicit() {
        assert_eq!(parse("bytes=0-99", 100), Some(Ok((0, 99))));
    }

    #[test]
    fn range_open_ended() {
        assert_eq!(parse("bytes=50-", 100), Some(Ok((50, 99))));
    }

    #[test]
    fn range_suffix() {
        assert_eq!(parse("bytes=-20", 100), Some(Ok((80, 99))));
    }

    #[test]
    fn range_out_of_bounds() {
        // end >= file_len
        assert_eq!(parse("bytes=0-100", 100), Some(Err(())));
    }

    #[test]
    fn range_inverted() {
        // start > end
        assert_eq!(parse("bytes=50-20", 100), Some(Err(())));
    }

    #[test]
    fn range_absent_returns_none() {
        assert_eq!(parse_range_header_str("bytes=0-49,50-99", 100), None);
    }

    #[test]
    fn range_single_byte() {
        assert_eq!(parse("bytes=0-0", 100), Some(Ok((0, 0))));
    }

    #[test]
    fn range_last_byte() {
        assert_eq!(parse("bytes=99-99", 100), Some(Ok((99, 99))));
    }
}
