#!/bin/bash
# Integration smoke tests for aloha.
# Runs inside the container built from tests/integration/Containerfile.
# Exercises all major handler types and the security access-control path.

set -euo pipefail

ALOHA=/usr/bin/aloha
PASS=0
FAIL=0
ALOHA_PID=""
BACKEND_PIDS=()
TMPDIR=$(mktemp -d)

cleanup() {
    stop_server
    for pid in "${BACKEND_PIDS[@]+"${BACKEND_PIDS[@]}"}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# --- assertion helpers ----------------------------------------------

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1  (${2:-})"; }

# assert_status <label> <expected-code> <url> [curl-flags...]
assert_status() {
    local label="$1" expected="$2" url="$3"
    shift 3
    local got
    got=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 5 "$@" "$url" 2>/dev/null) || got="000"
    if [ "$got" = "$expected" ]; then
        pass "$label"
    else
        fail "$label" "expected HTTP $expected, got $got"
    fi
}

# assert_header <label> <header-name> <pattern> <url> [curl-flags...]
# Pattern is matched case-insensitively against the header value.
assert_header() {
    local label="$1" header="$2" pattern="$3" url="$4"
    shift 4
    local hdrs
    hdrs=$(curl -s -D - -o /dev/null --max-time 5 "$@" "$url" \
        2>/dev/null) || hdrs=""
    if echo "$hdrs" | grep -qi "^${header}:.*${pattern}"; then
        pass "$label"
    else
        fail "$label" "no '${header}: *${pattern}' header"
    fi
}

# assert_body <label> <literal-text> <url> [curl-flags...]
assert_body() {
    local label="$1" text="$2" url="$3"
    shift 3
    local body
    body=$(curl -s --max-time 5 "$@" "$url" 2>/dev/null) || body=""
    if echo "$body" | grep -qF "$text"; then
        pass "$label"
    else
        fail "$label" "'$text' not found in body"
    fi
}

# --- server lifecycle -----------------------------------------------

# Start aloha with the given config and wait until it responds on port.
# Optional third arg "https" polls with TLS (--insecure).
start_server() {
    local config="$1" port="$2" proto="${3:-http}"
    "$ALOHA" "$config" >"$TMPDIR/aloha.out" 2>&1 &
    ALOHA_PID=$!
    local tries=0 code
    while true; do
        if [ "$proto" = "https" ]; then
            code=$(curl -sk -o /dev/null -w "%{http_code}" \
                --max-time 0.5 --connect-timeout 0.5 \
                "https://127.0.0.1:${port}/") || code=""
        else
            code=$(curl -s -o /dev/null -w "%{http_code}" \
                --max-time 0.5 --connect-timeout 0.5 \
                "http://127.0.0.1:${port}/") || code=""
        fi
        [ -n "${code}" ] && [ "${code}" != "000" ] && return 0
        if ! kill -0 "$ALOHA_PID" 2>/dev/null; then
            echo "  ERROR: aloha exited during startup (port $port):" >&2
            cat "$TMPDIR/aloha.out" >&2
            ALOHA_PID=""
            return 1
        fi
        tries=$((tries + 1))
        if [ $tries -ge 60 ]; then
            echo "  ERROR: timeout waiting for aloha on port $port" >&2
            cat "$TMPDIR/aloha.out" >&2
            stop_server
            return 1
        fi
        sleep 0.1
    done
}

stop_server() {
    if [ -n "${ALOHA_PID:-}" ]; then
        kill "$ALOHA_PID" 2>/dev/null || true
        wait "$ALOHA_PID" 2>/dev/null || true
        ALOHA_PID=""
    fi
}

# --- shared setup ---------------------------------------------------

setup_webroot() {
    mkdir -p /tmp/www
    printf '<html><body>Hello aloha</body></html>\n' \
        > /tmp/www/index.html
    printf 'hello\n' > /tmp/www/hello.txt
    # Large enough to trigger compression (>= compress threshold).
    python3 -c "print('aloha ' * 2000)" > /tmp/www/big.txt
}

# --- test suites ----------------------------------------------------

suite_static_files() {
    echo "=== Static files ==="
    cat >"$TMPDIR/static.kdl" <<'EOF'
listener {
    bind "127.0.0.1:8080"
}
vhost "localhost" {
    location "/" {
        static { root "/tmp/www"; index-file "index.html"; }
    }
}
EOF
    start_server "$TMPDIR/static.kdl" 8080 \
        || { fail "static/server_start" "aloha failed"; return; }

    assert_status "static/200_index"   200 "http://127.0.0.1:8080/"
    assert_status "static/200_file"    200 "http://127.0.0.1:8080/hello.txt"
    assert_status "static/404_missing" 404 "http://127.0.0.1:8080/nosuchfile"
    assert_body   "static/body"        "Hello aloha" "http://127.0.0.1:8080/"

    # Conditional GET: server must return 304 when ETag matches.
    local etag
    etag=$(curl -sI --max-time 5 "http://127.0.0.1:8080/hello.txt" \
           | grep -i '^etag:' | tr -d '\r' | sed 's/[Ee][Tt][Aa][Gg]: //') \
           || etag=""
    if [ -n "$etag" ]; then
        assert_status "static/304_etag" 304 \
            "http://127.0.0.1:8080/hello.txt" \
            -H "If-None-Match: ${etag}"
    else
        fail "static/etag_present" "no ETag header"
    fi

    # Range request must return 206 Partial Content.
    assert_status "static/206_range" 206 \
        "http://127.0.0.1:8080/hello.txt" -H "Range: bytes=0-2"

    stop_server
}

suite_redirect() {
    echo "=== Redirect ==="
    cat >"$TMPDIR/redirect.kdl" <<'EOF'
listener {
    bind "127.0.0.1:8081"
}
vhost "localhost" {
    location "/old" {
        redirect { to "/new"; code 301; }
    }
    location "/" {
        static { root "/tmp/www"; }
    }
}
EOF
    start_server "$TMPDIR/redirect.kdl" 8081 \
        || { fail "redirect/server_start" "aloha failed"; return; }

    # Default curl follows redirects; disable with --no-location.
    assert_status "redirect/301"           301 \
        "http://127.0.0.1:8081/old" --no-location
    assert_header "redirect/location_hdr"  "Location" "/new" \
        "http://127.0.0.1:8081/old" --no-location

    stop_server
}

suite_ip_access() {
    echo "=== IP access control ==="
    # Two vhosts on two listeners in one aloha process: one allows
    # loopback, the other denies it.
    cat >"$TMPDIR/access.kdl" <<'EOF'
listener {
    bind "127.0.0.1:8082"
    default-vhost "allow-site"
}
listener {
    bind "127.0.0.1:8089"
    default-vhost "deny-site"
}
vhost "allow-site" {
    location "/" {
        static { root "/tmp/www"; index-file "index.html"; }
        access {
            allow { ip "127.0.0.1/32" }
            deny
        }
    }
}
vhost "deny-site" {
    location "/" {
        static { root "/tmp/www"; index-file "index.html"; }
        access {
            deny { ip "127.0.0.1/32" }
            allow
        }
    }
}
EOF
    start_server "$TMPDIR/access.kdl" 8082 \
        || { fail "access/server_start" "aloha failed"; return; }

    assert_status "access/allow_loopback" 200 "http://127.0.0.1:8082/"
    assert_status "access/deny_loopback"  403 "http://127.0.0.1:8089/"

    stop_server
}

suite_auth() {
    echo "=== HTTP Basic auth ==="

    # Create a PAM-visible test user; skip if useradd is unavailable.
    if ! command -v useradd >/dev/null 2>&1; then
        echo "  SKIP: useradd not found"
        return
    fi
    useradd -M -s /usr/sbin/nologin alohatest 2>/dev/null || true
    if ! echo "alohatest:alohapass" | chpasswd 2>/dev/null; then
        echo "  SKIP: chpasswd failed"
        return
    fi

    cat >"$TMPDIR/auth.kdl" <<'EOF'
server {
    auth "pam"
}
listener {
    bind "127.0.0.1:8083"
}
vhost "localhost" {
    location "/" {
        static { root "/tmp/www"; index-file "index.html"; }
        auth { realm "Test Realm"; }
        access {
            allow { authenticated }
            deny code=401
        }
    }
}
EOF
    start_server "$TMPDIR/auth.kdl" 8083 \
        || { fail "auth/server_start" "aloha failed"; return; }

    # No credentials: must challenge with 401 + WWW-Authenticate.
    assert_status "auth/challenge_401"    401 "http://127.0.0.1:8083/"
    assert_header "auth/www_authenticate" "WWW-Authenticate" "Basic" \
        "http://127.0.0.1:8083/"
    assert_header "auth/realm"            "WWW-Authenticate" "Test Realm" \
        "http://127.0.0.1:8083/"

    # Correct credentials: must get 200.
    assert_status "auth/valid_creds" 200 "http://127.0.0.1:8083/" \
        -u "alohatest:alohapass"

    # Wrong credentials: must get 401 again.
    assert_status "auth/bad_creds" 401 "http://127.0.0.1:8083/" \
        -u "alohatest:wrongpassword"

    stop_server
}

suite_status_page() {
    echo "=== Status page ==="
    cat >"$TMPDIR/status.kdl" <<'EOF'
listener {
    bind "127.0.0.1:8084"
}
vhost "localhost" {
    location "/" {
        status
    }
}
EOF
    start_server "$TMPDIR/status.kdl" 8084 \
        || { fail "status/server_start" "aloha failed"; return; }

    assert_status "status/html_200"    200 "http://127.0.0.1:8084/"
    assert_body   "status/html_body"   "aloha" "http://127.0.0.1:8084/"
    assert_status "status/json_200"    200 "http://127.0.0.1:8084/" \
        -H "Accept: application/json"
    assert_body   "status/json_fields" "requests" \
        "http://127.0.0.1:8084/" -H "Accept: application/json"

    stop_server
}

suite_compression() {
    echo "=== Compression ==="
    cat >"$TMPDIR/compress.kdl" <<'EOF'
listener {
    bind "127.0.0.1:8085"
}
vhost "localhost" {
    location "/" {
        static { root "/tmp/www"; }
    }
}
EOF
    start_server "$TMPDIR/compress.kdl" 8085 \
        || { fail "compress/server_start" "aloha failed"; return; }

    assert_header "compress/gzip"   "Content-Encoding" "gzip" \
        "http://127.0.0.1:8085/big.txt" -H "Accept-Encoding: gzip"
    assert_header "compress/brotli" "Content-Encoding" "br" \
        "http://127.0.0.1:8085/big.txt" -H "Accept-Encoding: br"

    stop_server
}

suite_reverse_proxy() {
    echo "=== Reverse proxy ==="
    # python3 -m http.server as a backend.
    python3 -m http.server 9001 --directory /tmp/www \
        >/dev/null 2>&1 &
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/proxy.kdl" <<'EOF'
listener {
    bind "127.0.0.1:8086"
}
vhost "localhost" {
    location "/" {
        proxy { upstream "http://127.0.0.1:9001"; }
    }
}
EOF
    start_server "$TMPDIR/proxy.kdl" 8086 \
        || { fail "proxy/server_start" "aloha failed"; return; }

    assert_status "proxy/200"  200 "http://127.0.0.1:8086/"
    assert_body   "proxy/body" "Hello aloha" "http://127.0.0.1:8086/"

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}

suite_cgi() {
    echo "=== CGI ==="
    mkdir -p /tmp/cgi-bin
    # Minimal CGI script: emit headers then body.
    cat > /tmp/cgi-bin/hello.sh <<'SCRIPT'
#!/bin/sh
printf "Status: 200 OK\r\n"
printf "Content-Type: text/plain\r\n"
printf "\r\n"
printf "CGI works\r\n"
SCRIPT
    chmod +x /tmp/cgi-bin/hello.sh

    cat >"$TMPDIR/cgi.kdl" <<'EOF'
listener {
    bind "127.0.0.1:8087"
}
vhost "localhost" {
    location "/" {
        cgi { root "/tmp/cgi-bin"; }
    }
}
EOF
    start_server "$TMPDIR/cgi.kdl" 8087 \
        || { fail "cgi/server_start" "aloha failed"; return; }

    assert_status "cgi/200"             200 "http://127.0.0.1:8087/hello.sh"
    assert_body   "cgi/body"            "CGI works" \
        "http://127.0.0.1:8087/hello.sh"
    assert_status "cgi/404_missing"     404 \
        "http://127.0.0.1:8087/nosuchscript.sh"
    # Directory request (trailing slash) must return 404 per CgiHandler.
    assert_status "cgi/404_directory"   404 "http://127.0.0.1:8087/"

    stop_server
}

suite_tls() {
    echo "=== TLS (self-signed) ==="
    cat >"$TMPDIR/tls.kdl" <<'EOF'
listener {
    bind "127.0.0.1:8443"
    tls
}
vhost "localhost" {
    location "/" {
        static { root "/tmp/www"; index-file "index.html"; }
    }
}
EOF
    start_server "$TMPDIR/tls.kdl" 8443 "https" \
        || { fail "tls/server_start" "aloha failed"; return; }

    assert_status "tls/200"  200 "https://127.0.0.1:8443/" -k
    assert_body   "tls/body" "Hello aloha" "https://127.0.0.1:8443/" -k

    stop_server
}

suite_tcp_proxy() {
    echo "=== TCP proxy ==="
    # A minimal HTTP/1.1 backend implemented in Python.
    python3 - <<'PYEOF' >/dev/null 2>&1 &
import socket, threading
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9002))
srv.listen(10)
def handle(conn):
    try:
        conn.recv(4096)
        conn.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 6\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"tcp-ok"
        )
    finally:
        conn.close()
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF
    local backend_pid=$!
    BACKEND_PIDS+=("$backend_pid")
    sleep 0.3

    cat >"$TMPDIR/tcp.kdl" <<'EOF'
listener {
    bind "127.0.0.1:8088"
    tcp-proxy {
        upstream "127.0.0.1:9002"
    }
}
EOF
    # TCP proxy has no HTTP layer to poll; give it time to bind.
    "$ALOHA" "$TMPDIR/tcp.kdl" >"$TMPDIR/aloha.out" 2>&1 &
    ALOHA_PID=$!
    sleep 0.5
    if ! kill -0 "$ALOHA_PID" 2>/dev/null; then
        fail "tcp_proxy/server_start" "aloha exited"
        cat "$TMPDIR/aloha.out" >&2
        ALOHA_PID=""
        return
    fi

    assert_status "tcp_proxy/200"  200 "http://127.0.0.1:8088/"
    assert_body   "tcp_proxy/body" "tcp-ok" "http://127.0.0.1:8088/"

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}

# --- main -----------------------------------------------------------

setup_webroot

suite_static_files
suite_redirect
suite_ip_access
suite_auth
suite_status_page
suite_compression
suite_reverse_proxy
suite_cgi
suite_tls
suite_tcp_proxy

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
