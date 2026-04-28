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

KDL nodes have the form `node-name arg prop="value" { child ... }`.

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
    user      "aloha"
    tls {
        min-version "1.2"
    }
}
```

| Child node  | Type    | Default              | Description |
|-------------|---------|----------------------|-------------|
| `state-dir` | path    | --                   | Directory for persistent runtime state: ACME account keys and issued certificates. Required when any listener uses `tls "acme"`. |
| `user`      | string  | --                   | Unix username to switch to after all sockets are bound. Only effective when started as root; silently ignored otherwise. |
| `group`     | string  | user's primary group | Unix group to switch to. Defaults to the primary GID of `user` from `/etc/passwd`. |
| `auth`      | block   | --                   | Authentication back-end. See [Authentication](#authentication). |
| `tls`       | block   | --                   | Global TLS defaults inherited by every TLS listener. See [TLS protocol options](#tls-protocol-options). |

### Privilege drop

When aloha is started as root (needed to bind ports 80 and 443), set `user`
to drop privileges immediately after all sockets are bound, before accepting
any connections. The syscall sequence is `setgroups` -> `setgid` -> `setuid`.

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

// null disables the fallback -- unrecognised hosts get a 404
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
| `bind`          | string            | --            | Address and port to listen on, e.g. `"[::]:8080"`. Mutually exclusive with `fd`; exactly one must be present. |
| `fd`            | integer           | --            | Adopt an already-open file descriptor as the listening socket (systemd socket activation). Mutually exclusive with `bind`. |
| `default-vhost` | string \| `null`  | first vhost   | Vhost used when no `Host` header matches. Omit to fall back to the first vhost defined in the config. Set to `null` to return 404 for unrecognised hosts. |

### `tcp-proxy` child node

Add a `tcp-proxy` child to make the listener forward raw TCP bytes to an
upstream address instead of speaking HTTP. All HTTP processing (virtual
hosts, handlers, auth) is bypassed.

Combine with a `tls` node to terminate TLS before forwarding -- aloha
decrypts the connection, then forwards the plaintext stream to the upstream.

```kdl
// Plain TCP tunnel to a PostgreSQL backend
listener {
    bind "[::]:5432"
    tcp-proxy {
        upstream       "db.internal:5432"
        proxy-protocol "v2"
    }
}

// TLS-terminating tunnel -- clients connect over TLS, backend gets plaintext
listener {
    bind "[::]:5433"
    tls "self-signed"
    tcp-proxy {
        upstream       "db.internal:5432"
        proxy-protocol "v2"
    }
}
```

| Child node       | Type             | Default | Description |
|------------------|------------------|---------|-------------|
| `upstream`       | `"host:port"`    | --      | **Required.** Address to forward connections to. |
| `proxy-protocol` | `"v1"` \| `"v2"` | --      | Send a HAProxy PROXY protocol header to the upstream so it can see the real client IP. `"v1"` is text; `"v2"` is binary and preferred. |

A config consisting entirely of `tcp-proxy` listeners is valid with no
`vhost` at all.

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

### `tls` -- certificate mode

Add a `tls` child to make the listener speak HTTPS. Pass the certificate
source as the first argument; omit it for self-signed (inferred).

```kdl
// Self-signed -- ephemeral, generated at startup (development only)
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
| `cert` | path | -- | PEM certificate chain. Required for `"file"`. |
| `key`  | path | -- | PEM private key. Required alongside `cert`. |

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
| `domain`         | string  | --             | **Required.** Domain name to include as a Subject Alternative Name. Repeatable; at least one required. |
| `email`          | string  | --             | Contact address registered with the ACME provider. Recommended so Let's Encrypt can send expiry warnings. |
| `name`           | string  | first domain   | Storage subdirectory name under `state-dir` for this certificate's account key and cert files. |
| `staging`        | boolean | `false`        | Use the Let's Encrypt staging server (untrusted but no rate limits -- useful for testing). |
| `server`         | URL     | Let's Encrypt  | Override the ACME directory URL. |
| `retry-interval` | integer | `3600`         | Seconds between retry attempts when certificate acquisition fails. |

### TLS protocol options

These child nodes can appear in any `tls` block -- either inside a `listener`
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

| Child node    | Type                   | Default           | Description |
|---------------|------------------------|-------------------|-------------|
| `min-version` | `"1.2"` \| `"1.3"`    | `"1.2"`           | Minimum TLS protocol version to accept. |
| `cipher`      | string (repeatable)    | provider defaults | Restrict the allowed cipher suites by name. |

---

## Authentication

aloha supports HTTP Basic authentication validated against the system PAM
stack or an LDAP directory. Configure a back-end once in the `server` block;
the chosen mechanism applies to every location that challenges users.

Once a back-end is configured, add an `auth` block inside any `location` to
issue a `WWW-Authenticate: Basic` challenge and an `access` block to enforce
who is allowed (see [Access control](#access-control)).

### PAM

```kdl
server {
    auth "pam" {
        service "login"    // PAM service name; defaults to "login"
    }
}
```

Credentials are validated by calling into libpam using the named service
(`/etc/pam.d/<service>`). After a successful authentication, the user's Unix
group memberships are resolved via `getgrouplist(3)` and become available for
`group` conditions in `access` blocks.

| Child node | Type   | Default   | Description |
|------------|--------|-----------|-------------|
| `service`  | string | `"login"` | PAM service name. Must correspond to a file in `/etc/pam.d/`. |

PAM authentication blocks in the calling thread while libpam runs; aloha
runs it on a dedicated blocking thread so the async runtime is not stalled.

### LDAP

```kdl
server {
    auth "ldap" {
        url      "ldap://localhost:389"
        bind-dn  "uid={user},ou=people,dc=example,dc=com"
        base-dn  "ou=groups,dc=example,dc=com"

        // Optional:
        group-filter "(memberUid={user})"
        group-attr   "cn"
        starttls     false
        timeout      5
    }
}
```

Authentication is performed as an LDAP simple bind. The `{user}` placeholder
in `bind-dn` (and in `group-filter`) is replaced with the escaped username at
request time. After a successful bind, a subtree search under `base-dn` finds
the user's group memberships.

Unix socket connections are supported via the `ldapi://` scheme:

```kdl
auth "ldap" {
    url     "ldapi:///var/run/slapd/ldapi"
    bind-dn "uid={user},ou=people,dc=example,dc=com"
    base-dn "ou=groups,dc=example,dc=com"
}
```

| Child node     | Type    | Default              | Description |
|----------------|---------|----------------------|-------------|
| `url`          | string  | --                   | **Required.** Server URL. Supported schemes: `ldap://` (plain), `ldaps://` (TLS), `ldapi://` (Unix socket). |
| `bind-dn`      | string  | --                   | **Required.** DN template for the simple bind. Must contain `{user}`, which is replaced with the RFC 4514-escaped username. |
| `base-dn`      | string  | --                   | **Required.** Base DN for the group membership search. |
| `group-filter` | string  | `(memberUid={user})` | LDAP filter template for finding a user's groups. `{user}` is replaced with the RFC 4515-escaped username. Default is RFC 2307 `posixGroup` style. |
| `group-attr`   | string  | `cn`                 | Entry attribute whose value is used as the group name. |
| `starttls`     | boolean | `false`              | Upgrade a plain `ldap://` connection to TLS using STARTTLS. |
| `timeout`      | integer | `5`                  | Seconds before an LDAP operation is abandoned. |

> **Security note:** Empty passwords are rejected before any bind attempt is
> made. Many LDAP servers accept an empty password as an anonymous bind,
> which would otherwise grant access to any username.

---

## `vhost`

Maps one or more hostnames to a set of URL routing rules. Requests are matched
against the `Host` header (port suffix stripped). At least one vhost is
required.

### Name matching

The first argument is the primary name; `alias` adds extra names. Both support
two matching modes:

- **Exact literal** -- the default. The full hostname must match exactly.
- **Regex** -- prefix the name with `~`. The remainder is compiled as a regular
  expression anchored at both ends (`^...$`). Invalid patterns are caught at startup.

Matching order per request:

1. Exact literal match -- all literal names, O(1).
2. Regex patterns -- in config declaration order; first match wins.
3. Listener `default-vhost` fallback.

```kdl
// Exact match for the bare domain and an alias
vhost "example.com" {
    alias "www.example.com"
    location "/" { static { root "/var/www/example" } }
}

// Regex -- matches any subdomain of example.com
vhost "~.+\.example\.com" {
    location "/" { static { root "/var/www/wildcard" } }
}
```

| Child     | Argument    | Description |
|-----------|-------------|-------------|
| `alias`   | name        | Additional hostname or regex pattern that maps to this vhost. Repeatable. |
| `location`| path prefix | URL routing rule. See [location](#location). |

---

## `location`

Maps a URL path prefix to a handler. The location with the **longest matching
prefix** wins -- declaration order does not matter. This means a catch-all
`location "/"` never masks a more specific `location "/_status"` regardless
of which appears first in the config. Each location contains exactly one
handler node.

In addition to a handler, a location can carry:

- An **`access`** block -- firewall-style rules controlling which clients and
  users may reach this location. See [Access control](#access-control).
- An **`auth`** block -- configures the HTTP Basic auth challenge realm.
  See [Authentication](#authentication).
- A **`request-headers`** and/or **`response-headers`** block -- inject or
  modify headers. See [Header injection](#header-injection).

---

## Access control

An `access` block inside a `location` enforces per-request allow/deny rules
using a combination of client IP and authenticated identity. Rules are
evaluated top to bottom; the first matching rule wins. If no rule matches,
the request is denied with 403.

```kdl
location "/admin/" {
    access {
        allow { ip "10.0.0.0/8"; group "admin" }
        deny  code=403
    }
    static { root "/var/www/admin" }
}
```

Each rule is one of `allow`, `deny`, or `redirect`. The child nodes inside a
rule are the conditions that must hold for the rule to fire.

### Rule types

| Node       | Properties            | Description |
|------------|-----------------------|-------------|
| `allow`    | --                    | Grant access. |
| `deny`     | `code=N` (default 403)| Deny with the given HTTP status code. Use `code=401` together with an `auth` block to issue a Basic auth challenge. |
| `redirect` | `to="..."`, `code=N` (default 302) | Redirect to the given URL. Useful for sending unauthenticated users to a login page. |

A rule with no conditions is a catch-all that always matches.

### Conditions

Conditions inside a rule are **AND**-ed across types: all types present must
match. Within the same type, conditions are **OR**-ed: any one match suffices.

| Condition       | Argument     | Description |
|-----------------|--------------|-------------|
| `ip`            | CIDR or IP   | Client IP address or range. `10.0.0.0/8`, `192.168.1.1`, `::1` are all valid. IPv4-mapped IPv6 addresses are normalised automatically. Repeatable -- multiple `ip` entries are OR-ed. |
| `authenticated` | --           | Any authenticated (non-anonymous) user. |
| `user`          | username     | A specific authenticated username. Repeatable. |
| `group`         | group name   | The authenticated user is a member of this group. Repeatable. |

### Examples

Restrict by IP:
```kdl
access {
    allow { ip "10.0.0.0/8" }
    deny  code=403
}
```

Allow admin group from any IP, deny everyone else:
```kdl
access {
    allow { group "admin" }
    deny  code=403
}
```

Require authentication (401 challenge), then allow only the `staff` group:
```kdl
auth {
    realm "Staff Portal"
}
access {
    allow { group "staff" }
    deny  code=401   // triggers WWW-Authenticate challenge
}
```

Redirect unauthenticated users to a login page:
```kdl
access {
    allow { authenticated }
    redirect to="/login/" code=302
}
```

Allow internal IPs without auth, require auth for external:
```kdl
access {
    allow { ip "10.0.0.0/8" }
    allow { authenticated }
    deny  code=401
}
```

---

## `auth` -- Basic auth realm

An `auth` block inside a `location` configures the `WWW-Authenticate` realm
sent in `401` responses. It does not by itself restrict access; pair it with
an `access` block containing a `deny code=401` rule.

```kdl
location "/members/" {
    auth {
        realm "Members Area"
    }
    access {
        allow { authenticated }
        deny  code=401
    }
    static { root "/var/www/members" }
}
```

| Child node | Type   | Default        | Description |
|------------|--------|----------------|-------------|
| `realm`    | string | `"Restricted"` | Realm string sent in the `WWW-Authenticate: Basic realm="..."` header. Displayed by browsers in the credential prompt. |

When a request arrives with no credentials and the access policy returns 401,
aloha responds with `401 Unauthorized` and a `WWW-Authenticate: Basic
realm="..."` header. The browser prompts the user for a username and password
and resends the request with an `Authorization: Basic` header.

A server-level `auth` back-end (PAM or LDAP) must be configured for
credentials to be validated. Without one, all requests are treated as
anonymous and `deny code=401` will always challenge.

---

## Header injection

The `request-headers` and `response-headers` blocks inside a `location`
add, replace, or remove HTTP headers before the request reaches the
backend and before the response reaches the client. This works for all
handler types: `proxy`, `fastcgi`, `scgi`, `cgi`, `static`, and `redirect`.

```kdl
location "/api/" {
    request-headers {
        set    "X-Client-IP"       "{client_ip}"
        set    "X-Auth-User"       "{username}"
        set    "X-Auth-Groups"     "{groups}"
        set    "X-Forwarded-Proto" "{scheme}"
        remove "Authorization"
    }
    response-headers {
        set    "X-Frame-Options"        "DENY"
        set    "X-Content-Type-Options" "nosniff"
        add    "Vary"                   "Accept-Encoding"
        remove "Server"
    }
    proxy { upstream "http://backend:8080" }
}
```

### Operations

| Operation | Arguments      | Description |
|-----------|----------------|-------------|
| `set`     | name, value    | Set the header to this value, replacing any existing value. Creates the header if absent. |
| `add`     | name, value    | Append a value without removing existing values. Useful for multi-valued headers such as `Vary`. |
| `remove`  | name           | Delete the header. A no-op if the header is absent. |

Operations are applied in declaration order.

### Variable substitution

Value strings can contain `{variable}` placeholders that are replaced at
request time. Unrecognised placeholders are passed through unchanged.

| Variable      | Value |
|---------------|-------|
| `{client_ip}` | Client IPv4 or IPv6 address |
| `{username}`  | Authenticated username; empty string if the request is anonymous |
| `{groups}`    | Authenticated user's groups, comma-joined; empty string if anonymous |
| `{method}`    | HTTP request method (`GET`, `POST`, ...) |
| `{path}`      | Request URI path |
| `{host}`      | Value of the `Host` request header |
| `{scheme}`    | `"https"` for TLS listeners, `"http"` for plain listeners |

Variables that reference the authenticated identity (`{username}`,
`{groups}`) cause the configured auth back-end to run even when there is no
`access` block. If no credentials are present the variables render as empty
strings.

### Notes

- **`{client_ip}` vs `REMOTE_ADDR`**: FastCGI, SCGI, and CGI handlers expose
  `REMOTE_ADDR = 0.0.0.0` because the real peer address is not available at
  the CGI environment level. Use a `request-headers` rule to inject the real
  address as an `HTTP_X_REAL_IP` or similar header:
  ```kdl
  request-headers {
      set "X-Real-IP" "{client_ip}"
  }
  ```
  The backend sees this as `HTTP_X_REAL_IP` in the CGI environment.

- **`X-Forwarded-For` and `X-Real-IP`**: The `proxy` handler sets these
  unconditionally after `request-headers` rules run. A `remove` rule in
  `request-headers` will be overwritten by the proxy's append. To fully
  control these headers, do not rely on `request-headers`; instead accept
  the proxy's appended value at the backend.

- **Invalid header values**: If a rendered value contains characters that
  are not valid in an HTTP header (e.g. control characters), the operation
  is silently skipped and a warning is logged. The connection is not aborted.

---

## Handlers

Each `location` block contains exactly one handler node.

### `static` -- file serving

Serves files from a local directory. Supports `Range` requests, `ETag`
conditional `GET`, and directory index files. Files are streamed in 64 KB
chunks without buffering the entire file in memory.

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

| Child node     | Type                | Default                        | Description |
|----------------|---------------------|--------------------------------|-------------|
| `root`         | path                | --                             | **Required.** Filesystem directory to serve. Path traversal outside `root` is blocked. |
| `strip-prefix` | boolean             | `false`                        | Remove the matched location prefix before resolving the file path. With `location "/assets/"` and `strip-prefix true`, `/assets/app.js` maps to `{root}/app.js`. |
| `index-file`   | string (repeatable) | `"index.html"`, `"index.htm"` | Filenames tried in order for directory requests. Returns 403 if none exist. Supplying any `index-file` children replaces the defaults entirely. |

### `proxy` -- HTTP reverse proxy

Reverse-proxies requests to an upstream HTTP server. Connections to the
upstream are pooled and reused across requests.

```kdl
location "/api/" {
    proxy {
        upstream     "http://127.0.0.1:3000"
        strip-prefix true
    }
}
```

| Child node     | Type    | Default | Description |
|----------------|---------|---------|-------------|
| `upstream`     | URL     | --      | **Required.** Base URL of the upstream server. Both `http` and `https` schemes are supported. HTTPS backends are verified against Mozilla's bundled root certificates. |
| `strip-prefix` | boolean | `false` | Remove the matched location prefix from the request path before forwarding. With `location "/api/"` and `strip-prefix true`, `/api/users` is forwarded as `/users`. |

The proxy unconditionally sets `X-Forwarded-For` (appending the client IP to
any existing chain), `X-Real-IP`, and overrides `Host` with the upstream
authority. Hop-by-hop headers are stripped from both the forwarded request
and the backend response.

### `fastcgi` -- FastCGI

Forwards requests to a FastCGI application server such as PHP-FPM using the
binary FastCGI record protocol.

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
|------------|--------|---------|-------------|
| `socket`   | string | --      | **Required.** FastCGI socket: `unix:/path` for a Unix domain socket or `tcp:host:port` for TCP. |
| `root`     | path   | --      | **Required.** Document root; combined with the request path to build `SCRIPT_FILENAME`. |
| `index`    | string | --      | Default script appended to directory requests (paths ending in `/`), e.g. `"index.php"`. |

A new connection is opened per request (no pooling). The full CGI/1.1
environment is sent including `HTTP_*` headers. `REMOTE_ADDR` is set to
`0.0.0.0`; use a `request-headers` rule with `{client_ip}` to pass the real
address.

### `scgi` -- SCGI

Forwards requests to an SCGI application server (Gunicorn, uWSGI, etc.)
using the netstring-framed SCGI protocol.

```kdl
location "/" {
    scgi {
        socket "unix:/run/myapp.sock"
        root   "/var/www/html"
        index  "index.py"
    }
}
```

| Child node | Type   | Default | Description |
|------------|--------|---------|-------------|
| `socket`   | string | --      | **Required.** SCGI socket: `unix:/path` or `tcp:host:port`. |
| `root`     | path   | --      | **Required.** Document root for `SCRIPT_FILENAME`. |
| `index`    | string | --      | Default script appended to directory requests. |

`REMOTE_ADDR` is `0.0.0.0`; use `request-headers` with `{client_ip}` to
inject the real address.

### `cgi` -- CGI

Executes a CGI script as a child process. One process is forked per request.
Unix only.

```kdl
location "/cgi-bin/" {
    cgi {
        root "/usr/lib/cgi-bin"
    }
}
```

| Child node | Type | Default | Description |
|------------|------|---------|-------------|
| `root`     | path | --      | **Required.** Directory containing CGI scripts. The request path is mapped directly to a file under this directory. Path traversal is blocked. |

`REMOTE_ADDR` is `0.0.0.0`; use `request-headers` with `{client_ip}`.

### `redirect` -- HTTP redirect

Returns an HTTP redirect response.

```kdl
location "/old/" {
    redirect {
        to   "/new/"
        code 301
    }
}
```

| Child node | Type         | Default | Description |
|------------|--------------|---------|-------------|
| `to`       | URL or path  | --      | **Required.** Destination written to the `Location` header. |
| `code`     | integer      | `301`   | HTTP status code: `301` (permanent) or `302` (temporary). |

### `status` -- built-in status page

Serves a live server status page. The page auto-refreshes every 10 seconds.

```kdl
location "/_status" {
    status
}
```

No child nodes. Protect with an `access` block to restrict visibility.

**HTML output** (default): a self-contained page showing:

- Uptime and total / active request counts
- Request rate (last 5 s, 1/5/15-minute rolling averages)
- Status code distribution (2xx / 3xx / 4xx / 5xx)
- Latency histogram (6 buckets from <1 ms to >=1 s)
- Resident memory in MiB (Linux only)
- Server version and process ID
- Listener table: address, protocol, ACME domain list
- Virtual host table: names, aliases, locations with handler types

**JSON output**: send `Accept: application/json`. The response is a JSON
object with all the same data:

```json
{
    "version":         "0.2.0",
    "pid":             12345,
    "uptime_secs":     3661,
    "uptime_human":    "1h 1m 1s",
    "requests_total":  98765,
    "requests_active": 3,
    "status":          { "2xx": 95000, "3xx": 1200, "4xx": 500, "5xx": 65 },
    "rates":           { "current_per_sec": 12.5, "avg_1min": 10.2, "avg_5min": 8.7, "avg_15min": 7.1 },
    "latency_ms":      { "lt_1": 40000, "lt_10": 50000, "lt_50": 5000, "lt_200": 500, "lt_1000": 200, "ge_1000": 65 },
    "memory_kb":       32768,
    "listeners": [
        { "address": "[::]:443", "protocol": "HTTPS-ACME", "acme_domains": ["example.com"] }
    ],
    "vhosts": [
        { "name": "example.com", "aliases": [], "locations": [{ "path": "/", "handler": "static" }] }
    ],
    "auth": "pam:login"
}
```

The `auth` field is `null` when no auth back-end is configured, or a string
of the form `"pam:service"` or `"ldap:url"`.

Rates are computed from a 15-minute ring buffer updated every 5 seconds and
converge to accurate values as the buffer fills.

---

## Response compression

aloha automatically compresses responses when the client sends an
`Accept-Encoding` header that includes `br` (brotli) or `gzip`. Brotli is
preferred when both are accepted.

Compression is applied to text-based content types: `text/*`,
`application/json`, `application/javascript`, `application/xml`,
`image/svg+xml`, and several others.

Responses smaller than 1 KB, responses that already carry a
`Content-Encoding` header, and binary formats (images, video, audio,
archives) are passed through unmodified.

When compression is applied, aloha removes `Content-Length` and adds:

```
Content-Encoding: gzip    (or br)
Vary: Accept-Encoding
```

There is no per-location configuration; compression is always active for
eligible responses.

---

## Full example

```kdl
// aloha.kdl

server {
    state-dir "/var/lib/aloha"
    user      "aloha"

    // Validate credentials via PAM (uses /etc/pam.d/login)
    auth "pam" {
        service "login"
    }
}

// Plain HTTP -- required for ACME HTTP-01 challenges
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

// Encrypted tunnel to an internal database
listener {
    bind "[::]:5433"
    tls "file" {
        cert "/etc/aloha/db-cert.pem"
        key  "/etc/aloha/db-key.pem"
    }
    tcp-proxy {
        upstream       "db.internal:5432"
        proxy-protocol "v2"
    }
}

// Main site
vhost "example.com" {
    alias "www.example.com"

    // Status page -- internal access only
    location "/_status" {
        access {
            allow { ip "10.0.0.0/8" }
            deny  code=403
        }
        status
    }

    // Admin area -- requires auth and group membership
    location "/admin/" {
        auth {
            realm "Admin"
        }
        access {
            allow { group "admin" }
            deny  code=401
        }
        // Pass identity to the backend
        request-headers {
            set "X-Auth-User"   "{username}"
            set "X-Auth-Groups" "{groups}"
        }
        proxy { upstream "http://127.0.0.1:3000" }
    }

    // API -- inject client info, strip auth header
    location "/api/" {
        request-headers {
            set    "X-Client-IP"       "{client_ip}"
            set    "X-Forwarded-Proto" "{scheme}"
            remove "Authorization"
        }
        response-headers {
            set    "X-Frame-Options"        "DENY"
            set    "X-Content-Type-Options" "nosniff"
            remove "Server"
        }
        proxy {
            upstream     "http://127.0.0.1:4000"
            strip-prefix true
        }
    }

    // PHP application
    location "/app/" {
        request-headers {
            set "X-Real-IP" "{client_ip}"
        }
        fastcgi {
            socket "unix:/run/php/fpm.sock"
            root   "/var/www/html"
            index  "index.php"
        }
    }

    // Old URL redirect
    location "/old/" {
        redirect { to "/new/"; code 301 }
    }

    // Static files
    location "/" {
        static {
            root       "/var/www/example.com"
            index-file "index.html"
        }
    }
}

// Wildcard subdomain -- regex match
vhost "~.+\.example\.com" {
    location "/" {
        static { root "/var/www/wildcard" }
    }
}
```
