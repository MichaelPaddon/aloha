#!/bin/bash
# Integration smoke tests for aloha.
# Runs inside the container built from tests/integration/Containerfile.
# Exercises all major handler types and the security access-control path.

set -euo pipefail

ALOHA=/usr/bin/aloha
PASS=0
FAIL=0
ALOHA_PID=""
SLAPD_PID=""
BACKEND_PIDS=()
TMPDIR=$(mktemp -d)

cleanup() {
    stop_server
    teardown_ldap
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
    "$ALOHA" --config "$config" >"$TMPDIR/aloha.out" 2>&1 &
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
            allow { ip "127.0.0.1/32"; }
            deny
        }
    }
}
vhost "deny-site" {
    location "/" {
        static { root "/tmp/www"; index-file "index.html"; }
        access {
            deny { ip "127.0.0.1/32"; }
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
            allow { authenticated; }
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
    "$ALOHA" --config "$TMPDIR/tcp.kdl" >"$TMPDIR/aloha.out" 2>&1 &
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

# --- LDAP helpers ---------------------------------------------------

# Start a local OpenLDAP server with two test users and one group.
# Returns 1 (and prints a SKIP message) if slapd is unavailable.
setup_ldap() {
    if ! command -v slapd >/dev/null 2>&1; then
        echo "  SKIP: slapd not found"
        return 1
    fi

    mkdir -p /tmp/ldap-db

    # Old-style slapd.conf; still accepted by OpenLDAP 2.5+ via -f.
    cat >/tmp/slapd.conf <<'SLAPD_CONF'
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
include /etc/ldap/schema/nis.schema
# In Debian packages the MDB backend is a loadable module.
modulepath /usr/lib/ldap
moduleload back_mdb
pidfile /tmp/slapd.pid
database mdb
maxsize 1073741824
suffix "dc=test,dc=local"
rootdn "cn=admin,dc=test,dc=local"
rootpw secret
directory /tmp/ldap-db
SLAPD_CONF

    # Generate SSHA password hashes at runtime.
    local alice_pw bob_pw
    alice_pw=$(slappasswd -s alicepass 2>/dev/null) || {
        echo "  SKIP: slappasswd failed"
        return 1
    }
    bob_pw=$(slappasswd -s bobpass 2>/dev/null)

    # Seed the directory: two users, one group (alice is a member; bob is not).
    cat >/tmp/ldap-init.ldif <<EOF
dn: dc=test,dc=local
objectClass: dcObject
objectClass: organization
dc: test
o: Test

dn: ou=people,dc=test,dc=local
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=test,dc=local
objectClass: organizationalUnit
ou: groups

dn: uid=alice,ou=people,dc=test,dc=local
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: Test
userPassword: $alice_pw

dn: uid=bob,ou=people,dc=test,dc=local
objectClass: inetOrgPerson
uid: bob
cn: Bob
sn: Test
userPassword: $bob_pw

dn: cn=testgroup,ou=groups,dc=test,dc=local
objectClass: posixGroup
cn: testgroup
gidNumber: 2000
memberUid: alice
EOF

    slapadd -f /tmp/slapd.conf -l /tmp/ldap-init.ldif \
        >/tmp/slapadd.log 2>&1 || {
        echo "  ERROR: slapadd failed:" >&2
        cat /tmp/slapadd.log >&2
        return 1
    }

    slapd -f /tmp/slapd.conf -h "ldap://127.0.0.1:3890/" \
        >/tmp/slapd.log 2>&1 &
    SLAPD_PID=$!

    # Wait until slapd is accepting connections.
    local tries=0
    while ! ldapsearch -x -H "ldap://127.0.0.1:3890" \
            -b "dc=test,dc=local" -s base "(objectClass=*)" \
            >/dev/null 2>&1; do
        if ! kill -0 "$SLAPD_PID" 2>/dev/null; then
            echo "  ERROR: slapd exited during startup:" >&2
            cat /tmp/slapd.log >&2
            SLAPD_PID=""
            return 1
        fi
        tries=$((tries + 1))
        if [ $tries -ge 50 ]; then
            echo "  ERROR: timeout waiting for slapd" >&2
            cat /tmp/slapd.log >&2
            return 1
        fi
        sleep 0.1
    done
}

teardown_ldap() {
    if [ -n "${SLAPD_PID:-}" ]; then
        kill "$SLAPD_PID" 2>/dev/null || true
        wait "$SLAPD_PID" 2>/dev/null || true
        SLAPD_PID=""
    fi
    rm -rf /tmp/ldap-db /tmp/slapd.conf /tmp/ldap-init.ldif \
        /tmp/slapd.pid /tmp/slapd.log /tmp/slapadd.log
}

suite_ldap_auth() {
    echo "=== LDAP authentication ==="

    setup_ldap || return

    # Single aloha process with two listeners, each backed by a
    # different vhost: one tests credential validation, the other
    # tests group-based access control.
    cat >"$TMPDIR/ldap.kdl" <<'EOF'
server {
    auth "ldap" {
        url "ldap://127.0.0.1:3890"
        bind-dn "uid={user},ou=people,dc=test,dc=local"
        base-dn "ou=groups,dc=test,dc=local"
    }
}
listener {
    bind "127.0.0.1:8090"
    default-vhost "ldap-auth"
}
listener {
    bind "127.0.0.1:8091"
    default-vhost "ldap-group"
}
vhost "ldap-auth" {
    location "/" {
        static { root "/tmp/www"; index-file "index.html"; }
        auth { realm "LDAP Test"; }
        access {
            allow { authenticated; }
            deny code=401
        }
    }
}
vhost "ldap-group" {
    location "/" {
        static { root "/tmp/www"; index-file "index.html"; }
        auth { realm "LDAP Group Test"; }
        access {
            allow { group "testgroup"; }
            deny code=403
        }
    }
}
EOF
    start_server "$TMPDIR/ldap.kdl" 8090 \
        || { fail "ldap/server_start" "aloha failed"; teardown_ldap; return; }

    # -- Credential validation (port 8090) ---------------------------

    # No credentials: must challenge with 401 + WWW-Authenticate.
    assert_status "ldap/challenge_401"    401 "http://127.0.0.1:8090/"
    assert_header "ldap/www_authenticate" "WWW-Authenticate" "LDAP Test" \
        "http://127.0.0.1:8090/"

    # Correct credentials: must pass LDAP bind and return 200.
    assert_status "ldap/valid_creds"    200 "http://127.0.0.1:8090/" \
        -u "alice:alicepass"

    # Wrong password: LDAP bind fails → stays anonymous → 401.
    assert_status "ldap/wrong_password" 401 "http://127.0.0.1:8090/" \
        -u "alice:badpass"

    # Empty password: aloha rejects before attempting any LDAP bind.
    # (prevents accidental anonymous bind on LDAP servers that allow it)
    assert_status "ldap/empty_password" 401 "http://127.0.0.1:8090/" \
        -u "alice:"

    # -- Group-based access control (port 8091) ----------------------

    # alice is in testgroup → allow.
    assert_status "ldap/group_allowed" 200 "http://127.0.0.1:8091/" \
        -u "alice:alicepass"

    # bob is not in testgroup → deny 403.
    assert_status "ldap/group_denied"  403 "http://127.0.0.1:8091/" \
        -u "bob:bobpass"

    stop_server
    teardown_ldap
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
suite_ldap_auth

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
