// GeoIP country lookup using MaxMind MMDB databases (GeoLite2-Country,
// GeoLite2-City, or any MMDB that carries a country.iso_code field).

use maxminddb::{Reader, path};
use std::net::IpAddr;

/// In-memory MMDB reader.  `Send + Sync`, safe to share via `Arc`.
pub type CountryReader = Reader<Vec<u8>>;

/// Open an MMDB file and load it into memory.
pub fn open(path: &str) -> anyhow::Result<CountryReader> {
    Reader::open_readfile(path)
        .map_err(|e| anyhow::anyhow!("geoip: cannot open {path}: {e}"))
}

/// Return the ISO 3166-1 alpha-2 country code (e.g. "US") for `ip`.
///
/// Returns `None` for private/reserved ranges and IPs not present in the
/// database.  The returned code matches MaxMind capitalisation (uppercase).
pub fn lookup_country(reader: &CountryReader, ip: IpAddr) -> Option<String> {
    let result = reader.lookup(ip).ok()?;
    result.decode_path(&path!["country", "iso_code"]).ok()?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Attempting to open a nonexistent MMDB path returns an Err whose
    /// message contains the diagnostic prefix added by `open()`.
    #[test]
    fn open_returns_error_for_nonexistent_path() {
        let result = open("/nonexistent/path/missing.mmdb");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("geoip: cannot open"),
            "unexpected error: {msg}",
        );
    }
}
