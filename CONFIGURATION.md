# Configuration Reference

Complete reference for `aloha.kdl`.

## Overview

aloha is configured via a single [KDL](https://kdl.dev) file. By default it
looks for `aloha.kdl` in the current working directory. Pass `--config
/path/to/file.kdl` (or `-c`) to use a different path.

A minimal configuration needs one `listener` and one `vhost`:

```kdl
listener {
    bind "[::]:8080"
}

vhost "localhost" {
    location "/" {
        static {
            root "./public"
        }
    }
}
```

## KDL quick primer

KDL nodes have the form `node-name arg prop="value" { child … }`.

- **Arguments** are positional values after the node name: `vhost "example.com"` or `tls "acme"`
- **Properties** are named `key=value` pairs after the node name
- **Children** live inside `{ }`, one per line: `bind "[::]:8080"`
- Line comments start with `//`
- The null literal is written `null`

---

## `server`

Global server settings. The entire node is optional.

```kdl
server {
    state-dir "/var/lib/aloha"
    tls {
        min-version "1.2"
    }
}
```

| Child node  | Type    | Default            | Description |
|-------------|---------|-------------------|-------------|
| `state-dir` | path    | —                 | Directory for persistent runtime state: ACME account keys and issued certificates. Required when any listener uses `tls "acme"`. |
| `user`      | string  | —                 | Unix username to switch to after all sockets are bound. Only effective when started as root; silently ignored otherwise. |
| `group`     | string  | user's primary group | Unix group to switch to. Defaults to the primary GID of `user` from `/etc/passwd`. |
| `tls`       | block   | —                 | Global TLS defaults inherited by every TLS listener. See [TLS protocol options](#tls-protocol-options). |

### Privilege drop

When aloha is started as root (needed to bind ports 80 and 443), set `user`
to drop privileges immediately after all sockets are bound, before accepting
any connections. The syscall sequence is `setgroups` → `setgid` → `setuid`.

```kdl
server { user "www-data" }               // group from /etc/passwd
server { user "aloha"; group "aloha" }   // explicit group
```

---

## `listener`

Opens a TCP socket and begins accepting connections. At least one is required.
Use separate listeners for plain HTTP and HTTPS.

```kdl
// Plain HTTP
listener {
    bind "[::]:80"
}

// HTTPS with an explicit default vhost
listener {
    bind          "[::]:443"
    default-vhost "example.com"
    tls "file" {
        cert "/etc/aloha/cert.pem"
        key  "/etc/aloha/key.pem"
    }
}

// null disables the fallback — unrecognised hosts get a 404
listener {
    bind          "[::]:80"
    default-vhost null
}

// systemd socket activation (fd 3 = first socket passed by systemd)
listener {
    fd 3
}
```

| Child node      | Type              | Default       | Description |
|-----------------|-------------------|---------------|-------------|
| `bind`          | string            | —             | Address and port to listen on, e.g. `"[::]:8080"`. Mutually exclusive with `fd`; exactly one must be present. |
| `fd`            | integer           | —             | Adopt an already-open file descriptor as the listening socket (systemd socket activation). Mutually exclusive with `bind`. |
| `default-vhost` | string \| `null`  | first vhost   | Vhost used when no `Host` header matches. Omit to fall back to the first vhost defined in the config. Set to `null` to return 404 for unrecognised hosts. |

### `timeouts` child node

Optional connection and request timeout settings. All values are whole seconds.
Omit any field (or the entire `timeouts` node) for no limit.

```kdl
listener {
    bind "[::]:8080"
    timeouts {
        request-header 30
        handler        60
        keepalive      75
    }
}
```

| Child node       | Type    | Default   | Description |
|------------------|---------|-----------|-------------|
| `request-header` | integer | unlimited | Maximum seconds to wait for a complete request line and headers. Protects against Slowloris-style attacks. |
| `handler`        | integer | unlimited | Maximum seconds a request handler may run before it is cancelled and `408 Request Timeout` is returned. |
| `keepalive`      | integer | unlimited | HTTP/1.1 keep-alive idle timeout. Set to `0` to disable keep-alive entirely. |

### `tls` — certificate mode

Add a `tls` child to make the listener speak HTTPS. Pass the certificate
source as the first argument; omit it for self-signed (inferred).

```kdl
// Self-signed — ephemeral, generated at startup (development only)
tls

// PEM files from disk
tls "file" {
    cert "/etc/aloha/cert.pem"
    key  "/etc/aloha/key.pem"
}

// ACME / Let's Encrypt
tls "acme" {
    domain "example.com"
    domain "www.example.com"
    email  "admin@example.com"
}
```

| Argument / child | Type | Default | Description |
|---|---|---|---|
| *(argument)* | `"self-signed"` \| `"file"` \| `"acme"` | inferred | Certificate source. Inferred when omitted: `"file"` if `cert` and `key` are present, `"self-signed"` otherwise. |
| `cert` | path | — | PEM certificate chain. Required for `"file"`. |
| `key`  | path | — | PEM private key. Required alongside `cert`. |

> **Warning:** The `"self-signed"` certificate is regenerated on every start
> and is not trusted by browsers. Use `"file"` or `"acme"` for production.

HTTP/1.1 and HTTP/2 are both supported on TLS listeners; protocol selection
is automatic via ALPN.

### ACME / Let's Encrypt

With `tls "acme"`, aloha obtains and renews a certificate automatically via
the ACME HTTP-01 challenge. A plain HTTP listener must be running to answer
challenge requests. Requires `state-dir` in the `server` block.

```kdl
listener {
    bind "[::]:443"
    tls "acme" {
        domain "example.com"
        domain "www.example.com"
        email  "admin@example.com"
    }
}
```

| Child node       | Type    | Default        | Description |
|------------------|---------|----------------|-------------|
| `domain`         | string  | —              | **Required.** Domain name to include as a Subject Alternative Name. Repeatable; at least one required. |
| `email`          | string  | —              | Contact address registered with the ACME provider. Recommended so Let's Encrypt can send expiry warnings. |
| `name`           | string  | first domain   | Storage subdirectory name under `state-dir` for this certificate's account key and cert files. |
| `staging`        | boolean | `false`        | Use the Let's Encrypt staging server (untrusted but no rate limits — useful for testing). |
| `server`         | URL     | Let's Encrypt  | Override the ACME directory URL. |
| `retry-interval` | integer | `3600`         | Seconds between retry attempts when certificate acquisition fails. |

### TLS protocol options

These child nodes can appear in any `tls` block — either inside a `listener`
or inside the global `server` block. Per-listener values override the global
defaults.

```kdl
server {
    tls {
        min-version "1.2"
        cipher "TLS13_AES_256_GCM_SHA384"
        cipher "TLS13_CHACHA20_POLY1305_SHA256"
    }
}
```

| Child node    | Type                   | Default            | Description |
|---------------|------------------------|--------------------|-------------|
| `min-version` | `"1.2"` \| `"1.3"`   | `"1.2"`            | Minimum TLS protocol version to accept. |
| `cipher`      | string (repeatable)    | provider defaults  | Restrict the allowed cipher suites by name. |

---

## `vhost`

Maps one or more hostnames to a set of URL routing rules. Requests are matched
against the `Host` header (port suffix stripped). At least one vhost is
required.

### Name matching

The first argument is the primary name; `alias` adds extra names. Both support
two matching modes:

- **Exact literal** — the default. The full hostname must match exactly.
- **Regex** — prefix the name with `~`. The remainder is compiled as a regular
  expression anchored at both ends (`^…$`). Invalid patterns are caught at startup.

Matching order per request:

1. Exact literal match — all literal names, O(1).
2. Regex patterns — in config declaration order; first match wins.
3. Listener `default-vhost` fallback.

```kdl
// Exact match for the bare domain and an alias
vhost "example.com" {
    alias "www.example.com"
    location "/" { static { root "/var/www/example" } }
}

// Regex — matches any subdomain of example.com
vhost "~.+\.example\.com" {
    location "/" { static { root "/var/www/wildcard" } }
}
```

| Child     | Argument   | Description |
|-----------|------------|-------------|
| `alias`   | name       | Additional hostname or regex pattern that maps to this vhost. Repeatable. |
| `location`| path prefix | URL routing rule. See [location](#location). |

---

## `location`

Maps a URL path prefix to a handler. Locations inside a vhost are tested in
declaration order — the first one whose prefix matches the request path wins.
Each location contains exactly one handler node.

### `auth` — access control

Add an `auth` block to require authentication before a location is served.

```kdl
location "/admin/" {
    auth {
        // Allow rules — OR semantics: any one satisfied rule grants access.
        group "admin" "superuser"  // in admin OR superuser
        user  "alice"              // OR: exactly alice

        // Deny rules — take precedence over allow rules.
        deny {
            group "suspended"      // blocked even if in admin
        }
    }
    static { root "/var/www/admin" }
}

location "/members/" {
    auth {
        authenticated              // any logged-in user
    }
    static { root "/var/www/members" }
}
```

#### Allow rules

| Node             | Arguments    | Description |
|------------------|--------------|-------------|
| `authenticated`  | —            | Any authenticated user is accepted. |
| `user`           | name …       | Accept if the username matches any of the listed names. |
| `group`          | name …       | Accept if the user is a member of any of the listed groups. |

Multiple arguments on `user` or `group` are OR-combined within that node.
Multiple rule nodes are also OR-combined: any one satisfied rule grants access.

#### Deny rules (optional)

Place a `deny { … }` child block to explicitly reject matching users even if
they would satisfy an allow rule. Deny takes precedence.

The same node types (`authenticated`, `user`, `group`) are valid inside `deny`.

```kdl
auth {
    authenticated           // allow any logged-in user
    deny {
        user "mallory"      // …except this one
        group "suspended"   // …and no suspended-group members
    }
}
```

#### Responses

- **401 Unauthorized** — request carries no credentials (anonymous).
- **403 Forbidden** — credentials present but the user is denied or not allowed.

> **Note:** Authentication mechanisms (HTTP Basic auth, OAuth, …) are not yet
> implemented. Until one is configured every request is treated as anonymous,
> so a location with `auth` will return 401 for all requests.

---

### Handler: `static`

Serves files from a local directory.

```kdl
location "/assets/" {
    static {
        root         "/var/www/assets"
        strip-prefix true
        index-file   "index.html"
        index-file   "index.htm"
    }
}
```

| Child node     | Type               | Default                          | Description |
|----------------|--------------------|----------------------------------|-------------|
| `root`         | path               | —                                | **Required.** Filesystem directory to serve. Path traversal outside `root` is blocked. |
| `strip-prefix` | boolean            | `false`                          | Remove the matched location prefix before resolving the file path. With `location "/assets/"` and `strip-prefix true`, `/assets/app.js` maps to `{root}/app.js`. |
| `index-file`   | string (repeatable)| `"index.html"`, `"index.htm"`    | Filenames tried in order for directory requests. Returns 403 if none exist. Supplying any `index-file` children replaces the defaults entirely. |

### Handler: `proxy` *(stub)*

Reverse-proxies requests to an upstream HTTP server. Not yet implemented — returns 502.

```kdl
location "/api/" {
    proxy {
        upstream "http://127.0.0.1:3000"
    }
}
```

| Child node | Type | Default | Description |
|---|---|---|---|
| `upstream` | URL | — | **Required.** Base URL of the upstream server. |

### Handler: `redirect`

Returns an HTTP redirect response.

```kdl
location "/old/" {
    redirect {
        to   "/new/"
        code 301
    }
}
```

| Child node | Type          | Default | Description |
|---|---|---|---|
| `to`   | URL or path   | —       | **Required.** Destination written to the `Location` header. |
| `code` | integer       | `301`   | HTTP status code: `301` (permanent) or `302` (temporary). |

### Handler: `fastcgi`

Forwards requests to a FastCGI application server such as PHP-FPM.

```kdl
location "/" {
    fastcgi {
        socket "unix:/run/php/fpm.sock"
        root   "/var/www/html"
        index  "index.php"
    }
}
```

| Child node | Type   | Default | Description |
|---|---|---|---|
| `socket` | string | —       | **Required.** FastCGI socket: `unix:/path` for a Unix domain socket or `tcp:host:port` for TCP. |
| `root`   | path   | —       | **Required.** Document root; combined with the request path to build `SCRIPT_FILENAME`. |
| `index`  | string | —       | Default script appended to directory requests (paths ending in `/`), e.g. `"index.php"`. |

aloha opens a new connection per request (no pooling). The full CGI/1.1
environment is sent, including `REQUEST_METHOD`, `QUERY_STRING`,
`CONTENT_TYPE`, `CONTENT_LENGTH`, and `HTTP_*` headers. `REMOTE_ADDR`
is set to `0.0.0.0`; use `X-Forwarded-For` in a proxy deployment.

---

## Full example

```kdl
// aloha.kdl

server {
    state-dir "/var/lib/aloha"
    user "aloha"
}

// Plain HTTP — required for ACME HTTP-01 challenges
listener {
    bind          "[::]:80"
    default-vhost "example.com"
}

// HTTPS with a Let's Encrypt certificate
listener {
    bind          "[::]:443"
    default-vhost "example.com"
    tls "acme" {
        domain "example.com"
        domain "www.example.com"
        email  "admin@example.com"
    }
}

// Main site
vhost "example.com" {
    alias "www.example.com"

    location "/old/" {
        redirect { to "/new/"; code 301 }
    }

    location "/api/" {
        proxy { upstream "http://127.0.0.1:3000" }
    }

    location "/" {
        static {
            root       "/var/www/example.com"
            index-file "index.html"
        }
    }
}

// Regex vhost — matches *.example.com
vhost "~.+\.example\.com" {
    location "/" {
        static { root "/var/www/wildcard" }
    }
}
```
