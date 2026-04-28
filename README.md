<div align="center">
  <img src="html/aloha-logo.svg" alt="aloha" width="320">
  <p>A lightweight HTTP server and reverse proxy written in Rust that just works.</p>
</div>

---

- Virtual host routing -- exact and regex hostname matching
- Automatic TLS via Let's Encrypt (ACME HTTP-01)
- TLS with self-signed or PEM file certificates
- HTTP/1.1 and HTTP/2 on all TLS listeners (ALPN)
- Static file serving with streaming, ETag caching, and Range support
- HTTP reverse proxy with connection pooling
- FastCGI, SCGI, and CGI backends
- TCP proxy with optional TLS termination and HAProxy PROXY protocol
- HTTP Basic authentication via PAM or LDAP (including Unix socket)
- Firewall-style access control: IP ranges, authenticated users, and groups
- Per-location header injection -- add, override, or remove request and response headers with dynamic variables (`{client_ip}`, `{username}`, `{groups}`, `{scheme}`, ...)
- HTTP redirects
- Response compression (gzip and brotli)
- Built-in status page (HTML and JSON)
- Configurable per-listener connection and request timeouts
- Structured access logging via `RUST_LOG`
- Privilege drop -- binds privileged ports as root, then runs unprivileged
- Systemd socket activation

## Installation

### From package

Download the `.deb` or `.rpm` from the releases page and install with your
package manager. The package installs a systemd unit; enable it with:

```
sudo systemctl enable --now aloha
```

### From source

```
cargo build --release
cp target/release/aloha /usr/local/bin/
```

## Usage

```
aloha [OPTIONS]

Options:
  -c, --config <FILE>  Path to configuration file [default: aloha.kdl]
  -h, --help           Print help
```

Configuration defaults to `aloha.kdl` in the working directory.

## Configuration

Configuration is written in [KDL](https://kdl.dev).
See the **[Configuration Reference](CONFIGURATION.md)** for the full option
reference, or browse the annotated `aloha.kdl` for a quick overview.

Minimal example -- static files over plain HTTP:

```kdl
listener {
    bind "[::]:80"
}

vhost "example.com" {
    location "/" {
        static {
            root "/var/www/example"
            index-file "index.html"
        }
    }
}
```

### TLS

Self-signed (development):

```kdl
listener {
    bind "[::]:443"
    tls
}
```

PEM certificate (production):

```kdl
listener {
    bind "[::]:443"
    tls "file" {
        cert "/etc/aloha/cert.pem"
        key  "/etc/aloha/key.pem"
    }
}
```

Automatic certificate via Let's Encrypt (requires a port-80 listener for the
HTTP-01 challenge):

```kdl
server {
    state-dir "/var/lib/aloha"
}

listener { bind "[::]:80" }

listener {
    bind "[::]:443"
    tls "acme" {
        domain "example.com"
        email  "admin@example.com"
    }
}
```

### Reverse proxy

```kdl
location "/api/" {
    proxy {
        upstream     "http://127.0.0.1:3000"
        strip-prefix true
    }
}
```

### Authentication and access control

PAM authentication with group-based access:

```kdl
server {
    auth "pam" {
        service "login"
    }
}

vhost "example.com" {
    location "/admin/" {
        auth   { realm "Admin" }
        access {
            allow { group "admin" }
            deny  code=401
        }
        static { root "/var/www/admin" }
    }
}
```

LDAP authentication:

```kdl
server {
    auth "ldap" {
        url     "ldap://localhost:389"
        bind-dn "uid={user},ou=people,dc=example,dc=com"
        base-dn "ou=groups,dc=example,dc=com"
    }
}
```

### Header injection

Inject request metadata and authenticated identity into backend requests,
and enforce security headers on responses:

```kdl
location "/api/" {
    request-headers {
        set    "X-Client-IP"       "{client_ip}"
        set    "X-Auth-User"       "{username}"
        set    "X-Forwarded-Proto" "{scheme}"
        remove "Authorization"
    }
    response-headers {
        set    "X-Frame-Options" "DENY"
        remove "Server"
    }
    proxy { upstream "http://127.0.0.1:3000" }
}
```

Available variables: `{client_ip}`, `{username}`, `{groups}`, `{method}`,
`{path}`, `{host}`, `{scheme}`.

### Virtual hosts

Exact match:

```kdl
vhost "example.com" {
    alias "www.example.com"
    location "/" { static { root "/var/www/example" } }
}
```

Regex match (anchored at both ends):

```kdl
vhost "~.+\.example\.com" {
    location "/" { static { root "/var/www/wildcard" } }
}
```

Matching order per request: exact literal -> regex (declaration order) ->
listener `default-vhost` fallback.

### Privilege drop

Start as root to bind ports below 1024, then drop to an unprivileged user:

```kdl
server {
    user "aloha"
}
```

## Building packages

```
cargo deb           # target/debian/aloha_<version>_<arch>.deb
cargo generate-rpm  # target/generate-rpm/aloha-<version>-1.<arch>.rpm
```

Requires `cargo-deb` / `cargo-generate-rpm` (`cargo install cargo-deb cargo-generate-rpm`).

## License

BSD 2-Clause -- see [LICENSE](LICENSE).
