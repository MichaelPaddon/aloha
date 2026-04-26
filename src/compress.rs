use crate::error::{bytes_body, HttpResponse};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header::{self, HeaderValue};
use hyper::Response;

// Responses smaller than this are not worth compressing.
const MIN_SIZE: usize = 1024;

#[derive(Clone, Copy)]
pub enum Encoding {
    Gzip,
    Brotli,
}

// Parse Accept-Encoding and return the best encoding we support.
// Prefers brotli over gzip; returns None if neither is accepted.
//
// q=0 ("not acceptable") is intentionally not handled — clients that
// explicitly opt out of gzip/brotli are rare enough not to complicate
// the hot path.
pub fn negotiate(accept_encoding: &str) -> Option<Encoding> {
    let mut brotli = false;
    let mut gzip = false;
    for entry in accept_encoding.split(',') {
        let token = entry.split(';').next().unwrap_or("").trim();
        if token.eq_ignore_ascii_case("br") {
            brotli = true;
        } else if token.eq_ignore_ascii_case("gzip") {
            gzip = true;
        }
    }
    if brotli {
        Some(Encoding::Brotli)
    } else if gzip {
        Some(Encoding::Gzip)
    } else {
        None
    }
}

// Returns true for content types that compress well.  Binary formats
// (images, video, audio, zip) are already compressed or incompressible.
fn is_compressible(content_type: &str) -> bool {
    let ct = content_type.split(';').next().unwrap_or("").trim();
    ct.starts_with("text/")
        || ct == "application/json"
        || ct == "application/javascript"
        || ct == "application/ecmascript"
        || ct == "application/xml"
        || ct == "application/xhtml+xml"
        || ct == "application/wasm"
        || ct == "application/manifest+json"
        || ct == "image/svg+xml"
}

// Compress the response body according to `encoding`.
//
// Returns the response unmodified when:
// - `encoding` is None
// - the response already carries Content-Encoding
// - the Content-Type is not compressible
// - the body is smaller than MIN_SIZE bytes
//
// The body is fully buffered before compression; large binary responses
// are excluded by the content-type filter above so peak memory is
// bounded to the size of compressible responses.
pub async fn maybe_compress(
    resp: HttpResponse,
    encoding: Option<Encoding>,
) -> HttpResponse {
    let Some(enc) = encoding else { return resp; };

    if resp.headers().contains_key(header::CONTENT_ENCODING) {
        return resp;
    }

    let compressible = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(is_compressible)
        .unwrap_or(false);
    if !compressible {
        return resp;
    }

    let (mut parts, body) = resp.into_parts();

    let data = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Response::from_parts(parts, bytes_body(Bytes::new()))
        }
    };

    if data.len() < MIN_SIZE {
        return Response::from_parts(parts, bytes_body(data));
    }

    let compressed = match enc {
        Encoding::Gzip => gzip_encode(&data),
        Encoding::Brotli => brotli_encode(&data),
    };

    let Ok(compressed) = compressed else {
        // Compression failed; send the original body unencoded.
        return Response::from_parts(parts, bytes_body(data));
    };

    let enc_name = match enc {
        Encoding::Gzip => "gzip",
        Encoding::Brotli => "br",
    };

    // Content-Length no longer matches; remove it so hyper recomputes
    // or uses chunked transfer encoding.
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static(enc_name),
    );
    // Caches must not serve this response to clients that sent a
    // different (or absent) Accept-Encoding.
    parts.headers.insert(
        header::VARY,
        HeaderValue::from_static("Accept-Encoding"),
    );

    Response::from_parts(parts, bytes_body(Bytes::from(compressed)))
}

fn gzip_encode(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)?;
    Ok(enc.finish()?)
}

fn brotli_encode(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::io::Write;
    let mut out = Vec::new();
    {
        // Quality 5: good balance between speed and ratio for dynamic
        // content.  Quality 11 is 3–4× slower for marginal gain.
        let mut enc =
            brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        enc.write_all(data)?;
    }
    Ok(out)
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::StatusCode;

    fn text_response(body: &str) -> HttpResponse {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Content-Length", body.len().to_string())
            .body(bytes_body(Bytes::from(body.to_owned())))
            .unwrap()
    }

    fn binary_response(body: &[u8]) -> HttpResponse {
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "image/png")
            .body(bytes_body(Bytes::from(body.to_owned())))
            .unwrap()
    }

    // ── negotiate ───────────────────────────────────────────────

    #[test]
    fn negotiate_prefers_brotli() {
        assert!(matches!(
            negotiate("gzip, br"),
            Some(Encoding::Brotli)
        ));
    }

    #[test]
    fn negotiate_falls_back_to_gzip() {
        assert!(matches!(
            negotiate("gzip, deflate"),
            Some(Encoding::Gzip)
        ));
    }

    #[test]
    fn negotiate_none_when_unsupported() {
        assert!(negotiate("deflate, identity").is_none());
    }

    #[test]
    fn negotiate_case_insensitive() {
        assert!(matches!(negotiate("BR"), Some(Encoding::Brotli)));
        assert!(matches!(negotiate("GZIP"), Some(Encoding::Gzip)));
    }

    #[test]
    fn negotiate_with_q_values_in_header() {
        // q-value parsing is not fully implemented; just verify we
        // don't panic and do find the tokens.
        assert!(matches!(
            negotiate("gzip;q=1.0, br;q=0.9"),
            Some(Encoding::Brotli)
        ));
    }

    // ── is_compressible ─────────────────────────────────────────

    #[test]
    fn compressible_types() {
        for ct in &[
            "text/html",
            "text/css",
            "text/plain",
            "application/json",
            "application/javascript",
            "application/xml",
            "image/svg+xml",
            "application/wasm",
        ] {
            assert!(is_compressible(ct), "{ct} should be compressible");
        }
    }

    #[test]
    fn incompressible_types() {
        for ct in &[
            "image/png",
            "image/jpeg",
            "image/webp",
            "video/mp4",
            "audio/mpeg",
            "application/zip",
            "application/gzip",
        ] {
            assert!(!is_compressible(ct), "{ct} should not be compressible");
        }
    }

    #[test]
    fn compressible_ignores_parameters() {
        assert!(is_compressible("text/html; charset=utf-8"));
        assert!(is_compressible("application/json; charset=utf-8"));
    }

    // ── maybe_compress ──────────────────────────────────────────

    #[tokio::test]
    async fn compresses_large_text_response_with_gzip() {
        let body = "hello world ".repeat(200); // well above MIN_SIZE
        let resp = text_response(&body);
        let out = maybe_compress(resp, Some(Encoding::Gzip)).await;

        assert_eq!(
            out.headers()
                .get("Content-Encoding")
                .unwrap()
                .to_str()
                .unwrap(),
            "gzip"
        );
        assert_eq!(
            out.headers()
                .get("Vary")
                .unwrap()
                .to_str()
                .unwrap(),
            "Accept-Encoding"
        );
        assert!(out.headers().get("Content-Length").is_none());
    }

    #[tokio::test]
    async fn compresses_large_text_response_with_brotli() {
        let body = "hello world ".repeat(200);
        let resp = text_response(&body);
        let out = maybe_compress(resp, Some(Encoding::Brotli)).await;

        assert_eq!(
            out.headers()
                .get("Content-Encoding")
                .unwrap()
                .to_str()
                .unwrap(),
            "br"
        );
    }

    #[tokio::test]
    async fn skips_compression_below_min_size() {
        let resp = text_response("small");
        let out = maybe_compress(resp, Some(Encoding::Gzip)).await;
        assert!(out.headers().get("Content-Encoding").is_none());
    }

    #[tokio::test]
    async fn skips_compression_for_binary_content() {
        let resp = binary_response(b"PNG\x89\x50\x4e\x47");
        let out = maybe_compress(resp, Some(Encoding::Gzip)).await;
        assert!(out.headers().get("Content-Encoding").is_none());
    }

    #[tokio::test]
    async fn skips_compression_when_already_encoded() {
        let body = "hello world ".repeat(200);
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .header("Content-Encoding", "gzip")
            .body(bytes_body(Bytes::from(body)))
            .unwrap();
        let out = maybe_compress(resp, Some(Encoding::Brotli)).await;
        assert_eq!(
            out.headers()
                .get("Content-Encoding")
                .unwrap()
                .to_str()
                .unwrap(),
            "gzip" // unchanged
        );
    }

    #[tokio::test]
    async fn skips_compression_when_encoding_is_none() {
        let body = "hello world ".repeat(200);
        let resp = text_response(&body);
        let out = maybe_compress(resp, None).await;
        assert!(out.headers().get("Content-Encoding").is_none());
    }

    #[tokio::test]
    async fn gzip_output_is_decompressible() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let body = "the quick brown fox ".repeat(100);
        let resp = text_response(&body);
        let out = maybe_compress(resp, Some(Encoding::Gzip)).await;

        let compressed = out.into_body().collect().await.unwrap().to_bytes();
        let mut dec = GzDecoder::new(compressed.as_ref());
        let mut decompressed = String::new();
        dec.read_to_string(&mut decompressed).unwrap();
        assert_eq!(decompressed, body);
    }

    #[tokio::test]
    async fn brotli_output_is_decompressible() {
        let body = "the quick brown fox ".repeat(100);
        let resp = text_response(&body);
        let out = maybe_compress(resp, Some(Encoding::Brotli)).await;

        let compressed = out.into_body().collect().await.unwrap().to_bytes();
        let mut dec =
            brotli::Decompressor::new(compressed.as_ref(), 4096);
        use std::io::Read;
        let mut decompressed = String::new();
        dec.read_to_string(&mut decompressed).unwrap();
        assert_eq!(decompressed, body);
    }
}
