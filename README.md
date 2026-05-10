<div align="center">
  <img src="docs/aloha-logo.svg" alt="aloha" width="320">
  <p>An HTTP server and reverse proxy written in Rust.<br>
  Single-file KDL configuration. No surprises.</p>
</div>

---

aloha is a HTTP server built on [hyper](https://hyper.rs/) and
[tokio](https://tokio.rs/). It is written in Rust for memory safety and handles
the common 80%: static files, reverse proxy, TLS with automatic certificates,
and access control — all from a single readable `aloha.kdl` file.

## Features

**TLS & serving**
- Automatic certificates via Let's Encrypt (ACME HTTP-01)
- Self-signed for development; PEM file for managed certificates
- HTTP/1.1 and HTTP/2 (ALPN negotiation) on all TLS listeners
- Static file serving: streaming, Range requests, ETag caching

**Routing & backends**
- Virtual hosts: exact and regex hostname matching
- Reverse proxy with connection pooling
- FastCGI, SCGI, and CGI backends
- TCP proxy with HAProxy PROXY protocol v1/v2
- HTTP redirects

**Security & access control**
- HTTP Basic authentication via PAM or LDAP
- Subrequest auth (nginx `auth_request` style)
- JWT session cookies (ES256, JWKS endpoint)
- Firewall-style policy blocks: IP ranges, users, groups, countries (GeoIP)
- Privilege drop — binds ports < 1024 as root, then runs unprivileged
- Per-location header injection with dynamic variables

**Operations**
- Response compression (gzip and brotli)
- Configurable per-listener connection and request timeouts
- Structured access logging via `RUST_LOG`
- Built-in status page (HTML and JSON metrics)
- Health check endpoints (`/healthz`, `/livez`, `/readyz`)
- Custom error pages per status code
- Systemd service and socket activation; `.deb` and `.rpm` packages

## Installation

**From package** — download the `.deb` or `.rpm` from the
[releases page](../../releases) and install with your package manager:

```
sudo systemctl enable --now aloha
```

**Container (Docker / Podman):**

```
docker run --rm -p 80:80 -p 443:443 ghcr.io/michaelpaddon/aloha:latest
```

The default config listens on ports 80 (HTTP) and 443 (HTTPS, self-signed).
Override the config or serve custom content with volume mounts:

```
docker run --rm -p 80:80 -p 443:443 \
    -v /path/to/my.kdl:/etc/aloha.kdl:ro \
    -v /path/to/webroot:/var/www/aloha:ro \
    ghcr.io/michaelpaddon/aloha:latest
```

For ACME certificates, persist the state directory across restarts:

```
docker run --rm -p 80:80 -p 443:443 \
    -v aloha-state:/var/lib/aloha \
    -v /path/to/acme.kdl:/etc/aloha.kdl:ro \
    ghcr.io/michaelpaddon/aloha:latest
```

Podman users: replace `docker` with `podman` and add `:Z` to volume mounts
on SELinux systems (RHEL, Fedora).

**From source:**

```
cargo build --release
cp target/release/aloha /usr/local/bin/
```

## Documentation

Full configuration reference:
**https://michaelpaddon.github.io/aloha/config.html**

## Building packages

```
cargo deb           # target/debian/aloha_<version>_<arch>.deb
cargo generate-rpm  # target/generate-rpm/aloha-<version>-1.<arch>.rpm
```

Requires `cargo-deb` and `cargo-generate-rpm`
(`cargo install cargo-deb cargo-generate-rpm`).

## Contributing

Issues and pull requests are welcome. Please open an issue before starting
work on a large change.

## License

BSD 2-Clause — see [LICENSE](LICENSE).
