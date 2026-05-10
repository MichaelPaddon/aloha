#!/bin/bash
# Shared helpers for aloha integration tests.
# Sourced by run.sh; not executed directly.
# All functions operate on global variables declared in run.sh.

# --- assertion helpers -----------------------------------------------

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

# --- server lifecycle ------------------------------------------------

# start_server <config-path> <port> [https]
# Starts aloha with the given config and waits until it responds.
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

# --- cleanup ---------------------------------------------------------

cleanup() {
    stop_server
    teardown_ldap
    for pid in "${BACKEND_PIDS[@]+"${BACKEND_PIDS[@]}"}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
}

# --- shared setup ----------------------------------------------------

setup_webroot() {
    mkdir -p /tmp/www
    printf '<html><body>Hello aloha</body></html>\n' \
        > /tmp/www/index.html
    printf 'hello\n' > /tmp/www/hello.txt
    # Large enough to trigger compression (>= compress threshold).
    python3 -c "print('aloha ' * 2000)" > /tmp/www/big.txt
}

# --- LDAP helpers ----------------------------------------------------

# Start a local OpenLDAP server with two test users and one group.
# Returns 1 (and prints a SKIP message) if slapd is unavailable.
setup_ldap() {
    if ! command -v slapd >/dev/null 2>&1; then
        echo "  SKIP: slapd not found"
        return 1
    fi

    mkdir -p /tmp/ldap-db

    cat >/tmp/slapd.conf <<'SLAPD_CONF'
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
include /etc/ldap/schema/nis.schema
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

    local alice_pw bob_pw
    alice_pw=$(slappasswd -s alicepass 2>/dev/null) || {
        echo "  SKIP: slappasswd failed"
        return 1
    }
    bob_pw=$(slappasswd -s bobpass 2>/dev/null)

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
