// HAProxy PROXY protocol header builder (v1 text and v2 binary).
// Used by the TCP proxy listener to forward the real client address
// to backends that cannot see it directly through NAT or a load balancer.

use std::net::{IpAddr, SocketAddr};

use crate::config::ProxyProtocolVersion;

/// Build a PROXY protocol header to prepend to the backend connection.
///
/// `src` is the original client address; `dst` is aloha's local address
/// (what the client was connecting to).
pub fn build_header(
    version: ProxyProtocolVersion,
    src: SocketAddr,
    dst: SocketAddr,
) -> Vec<u8> {
    match version {
        ProxyProtocolVersion::V1 => build_v1(src, dst),
        ProxyProtocolVersion::V2 => build_v2(src, dst),
    }
}

// -- PROXY protocol v1 (text) --------------------------------------

// Format: "PROXY {TCP4|TCP6} {src_ip} {dst_ip} {src_port} {dst_port}\r\n"
fn build_v1(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let proto = match src.ip() {
        IpAddr::V4(_) => "TCP4",
        IpAddr::V6(_) => "TCP6",
    };
    format!(
        "PROXY {proto} {} {} {} {}\r\n",
        src.ip(),
        dst.ip(),
        src.port(),
        dst.port(),
    )
    .into_bytes()
}

// -- PROXY protocol v2 (binary) -----------------------------------

// Fixed 12-byte signature that marks a v2 PROXY header.
const V2_SIGNATURE: &[u8; 12] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

fn build_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + 36); // max size (IPv6)
    buf.extend_from_slice(V2_SIGNATURE);

    // Version (high nibble = 2) + command (low nibble = 1 = PROXY).
    buf.push(0x21);

    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            buf.push(0x11); // AF_INET + STREAM
            buf.extend_from_slice(&12u16.to_be_bytes()); // addr block length
            buf.extend_from_slice(&s.octets());
            buf.extend_from_slice(&d.octets());
            buf.extend_from_slice(&src.port().to_be_bytes());
            buf.extend_from_slice(&dst.port().to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            buf.push(0x21); // AF_INET6 + STREAM
            buf.extend_from_slice(&36u16.to_be_bytes()); // addr block length
            buf.extend_from_slice(&s.octets());
            buf.extend_from_slice(&d.octets());
            buf.extend_from_slice(&src.port().to_be_bytes());
            buf.extend_from_slice(&dst.port().to_be_bytes());
        }
        _ => {
            // Mixed address families -- emit UNSPEC/UNSPEC with no addresses.
            buf.push(0x00);
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
    }

    buf
}

// -- Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
    }

    fn v6(ip: [u8; 16], port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
    }

    // -- v1 --------------------------------------------------------

    #[test]
    fn v1_ipv4_format() {
        let header = build_v1(
            v4([192, 168, 1, 100], 54321),
            v4([10, 0, 0, 1], 3306),
        );
        let s = std::str::from_utf8(&header).unwrap();
        assert_eq!(s, "PROXY TCP4 192.168.1.100 10.0.0.1 54321 3306\r\n");
    }

    #[test]
    fn v1_ipv6_format() {
        let src = "::1".parse::<IpAddr>().unwrap();
        let dst = "::2".parse::<IpAddr>().unwrap();
        let header = build_v1(
            SocketAddr::new(src, 1234),
            SocketAddr::new(dst, 5432),
        );
        let s = std::str::from_utf8(&header).unwrap();
        assert_eq!(s, "PROXY TCP6 ::1 ::2 1234 5432\r\n");
    }

    #[test]
    fn v1_ends_with_crlf() {
        let h = build_v1(v4([1, 2, 3, 4], 100), v4([5, 6, 7, 8], 200));
        assert!(h.ends_with(b"\r\n"));
    }

    // -- v2 --------------------------------------------------------

    #[test]
    fn v2_starts_with_signature() {
        let h = build_v2(v4([1, 2, 3, 4], 100), v4([5, 6, 7, 8], 200));
        assert_eq!(&h[..12], V2_SIGNATURE);
    }

    #[test]
    fn v2_version_and_command() {
        let h = build_v2(v4([1, 2, 3, 4], 100), v4([5, 6, 7, 8], 200));
        assert_eq!(h[12], 0x21, "version=2, command=PROXY");
    }

    #[test]
    fn v2_ipv4_family_and_length() {
        let h = build_v2(v4([1, 2, 3, 4], 100), v4([5, 6, 7, 8], 200));
        assert_eq!(h[13], 0x11, "AF_INET + STREAM");
        let len = u16::from_be_bytes([h[14], h[15]]);
        assert_eq!(len, 12, "4+4+2+2 bytes for IPv4 address block");
        assert_eq!(h.len(), 28, "16 fixed + 12 address bytes");
    }

    #[test]
    fn v2_ipv4_addresses_and_ports() {
        let h = build_v2(
            v4([192, 168, 1, 100], 54321),
            v4([10, 0, 0, 1], 3306),
        );
        assert_eq!(&h[16..20], &[192, 168, 1, 100]); // src IP
        assert_eq!(&h[20..24], &[10, 0, 0, 1]);      // dst IP
        let src_port = u16::from_be_bytes([h[24], h[25]]);
        let dst_port = u16::from_be_bytes([h[26], h[27]]);
        assert_eq!(src_port, 54321);
        assert_eq!(dst_port, 3306);
    }

    #[test]
    fn v2_ipv6_family_and_length() {
        let h = build_v2(
            v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 1234),
            v6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2], 5432),
        );
        assert_eq!(h[13], 0x21, "AF_INET6 + STREAM");
        let len = u16::from_be_bytes([h[14], h[15]]);
        assert_eq!(len, 36, "16+16+2+2 bytes for IPv6 address block");
        assert_eq!(h.len(), 52, "16 fixed + 36 address bytes");
    }

    #[test]
    fn build_header_dispatches_to_correct_version() {
        let src = v4([1, 2, 3, 4], 1000);
        let dst = v4([5, 6, 7, 8], 2000);
        let v1 = build_header(ProxyProtocolVersion::V1, src, dst);
        let v2 = build_header(ProxyProtocolVersion::V2, src, dst);
        // v1 is text; v2 starts with the binary signature
        assert!(v1.starts_with(b"PROXY "));
        assert!(v2.starts_with(V2_SIGNATURE));
    }
}
