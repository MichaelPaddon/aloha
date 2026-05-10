// Transparent socket inheritance for seamless process upgrades.
//
// At startup, aloha scans all open file descriptors and collects those
// that are listening sockets (TCP or Unix domain).  bind_socket() checks
// this pool before calling bind(2): if an inherited fd matches the
// configured address it is adopted directly, preserving open connections
// across the upgrade.  Unmatched inherited fds remain open, so a
// subsequent bind() on the same address fails with EADDRINUSE — the
// intended loud failure when config and environment diverge.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

pub struct InheritedSockets {
    tcp: HashMap<SocketAddr, RawFd>,
    unix: HashMap<PathBuf, RawFd>,
}

impl InheritedSockets {
    /// Scan all open fds and collect listening sockets into the pool.
    /// Never fails: errors on individual fds are silently skipped.
    pub fn scan() -> Self {
        let mut tcp = HashMap::new();
        let mut unix = HashMap::new();

        for fd in open_fds() {
            classify_fd(fd, &mut tcp, &mut unix);
        }

        if !tcp.is_empty() || !unix.is_empty() {
            tracing::debug!(
                tcp = tcp.len(),
                unix = unix.len(),
                "inherited listening sockets found"
            );
        }
        InheritedSockets { tcp, unix }
    }

    /// Take the TCP fd bound to `addr`, if one was inherited.
    /// Removing it prevents the same fd from being claimed twice.
    pub fn take_tcp(&mut self, addr: SocketAddr) -> Option<RawFd> {
        self.tcp.remove(&addr)
    }

    /// Take the Unix fd bound to `path`, if one was inherited.
    pub fn take_unix(&mut self, path: &std::path::Path) -> Option<RawFd> {
        self.unix.remove(path)
    }

    /// Log a warning for each inherited socket that was never matched.
    /// These fds remain open, so bind() on the same address will fail
    /// with EADDRINUSE — alerting the operator to a config mismatch.
    pub fn warn_unclaimed(&self) {
        for (addr, fd) in &self.tcp {
            tracing::warn!(
                fd, %addr,
                "inherited listening socket not claimed by any listener \
                 (bind address mismatch?)"
            );
        }
        for (path, fd) in &self.unix {
            tracing::warn!(
                fd, path = %path.display(),
                "inherited listening unix socket not claimed by any listener \
                 (bind address mismatch?)"
            );
        }
    }
}

/// Classify one fd: if it's a listening TCP or Unix socket, insert it.
///
/// Uses std's socket wrappers via ManuallyDrop so the fd is never closed
/// by the probe.  SO_ACCEPTCONN filters out connected/unbound sockets.
fn classify_fd(
    fd: RawFd,
    tcp: &mut HashMap<SocketAddr, RawFd>,
    unix: &mut HashMap<PathBuf, RawFd>,
) {
    use nix::sys::socket::{getsockopt, sockopt::AcceptConn};
    use std::mem::ManuallyDrop;
    use std::os::unix::io::{BorrowedFd, FromRawFd};

    // SAFETY: fd is open for the duration of this call.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    if !getsockopt(&borrowed, AcceptConn).unwrap_or(false) {
        return;
    }

    // Probe as TCP (works for both IPv4 and IPv6).
    // ManuallyDrop ensures the fd is never closed by the probe.
    {
        let l = ManuallyDrop::new(unsafe {
            std::net::TcpListener::from_raw_fd(fd)
        });
        if let Ok(addr) = l.local_addr() {
            tcp.insert(addr, fd);
            return;
        }
    }

    // Probe as Unix domain socket.
    {
        let l = ManuallyDrop::new(unsafe {
            std::os::unix::net::UnixListener::from_raw_fd(fd)
        });
        if let Ok(addr) = l.local_addr()
            && let Some(path) = addr.as_pathname()
        {
            unix.insert(path.to_path_buf(), fd);
        }
    }
}

/// Enumerate all open file descriptors, excluding stdin/stdout/stderr.
fn open_fds() -> Vec<RawFd> {
    // On Linux, /proc/self/fd lists every open fd by name.
    #[cfg(target_os = "linux")]
    if let Ok(dir) = std::fs::read_dir("/proc/self/fd") {
        return dir
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<RawFd>().ok())
            .filter(|&fd| fd > 2)
            .collect();
    }

    // Fallback for other Unix: probe fds 3..4096 via F_GETFD.
    use nix::fcntl::{FcntlArg, fcntl};
    use std::os::unix::io::BorrowedFd;
    (3_i32..4096)
        .filter(|&fd| {
            // SAFETY: checking if fd is valid; no ownership transfer.
            let b = unsafe { BorrowedFd::borrow_raw(fd) };
            fcntl(b, FcntlArg::F_GETFD).is_ok()
        })
        .collect()
}
