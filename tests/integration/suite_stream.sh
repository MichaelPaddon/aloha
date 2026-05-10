#!/bin/bash
# Suite: TCP and Unix socket stream proxies.

suite_stream_proxy() {
    echo "=== Stream proxy (TCP) ==="
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

    cat >"$TMPDIR/stream.kdl" <<'EOF'
listener "127.0.0.1:8088" {
    proxy "127.0.0.1:9002"
}
EOF
    # Stream listener has no HTTP layer to poll; give it time to bind.
    "$ALOHA" --config "$TMPDIR/stream.kdl" >"$TMPDIR/aloha.out" 2>&1 &
    ALOHA_PID=$!
    sleep 0.5
    if ! kill -0 "$ALOHA_PID" 2>/dev/null; then
        fail "stream_proxy/server_start" "aloha exited"
        cat "$TMPDIR/aloha.out" >&2
        ALOHA_PID=""
        return
    fi

    assert_status "stream_proxy/200"  200 "http://127.0.0.1:8088/"
    assert_body   "stream_proxy/body" "tcp-ok" "http://127.0.0.1:8088/"

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}

suite_stream_proxy_unix() {
    echo "=== Stream proxy (Unix socket) ==="
    local sock="$TMPDIR/stream_backend.sock"
    python3 - "$sock" <<'PYEOF' >/dev/null 2>&1 &
import socket, sys, threading
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(sys.argv[1])
srv.listen(10)
def handle(conn):
    try:
        conn.recv(4096)
        conn.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 7\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"unix-ok"
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

    cat >"$TMPDIR/stream_unix.kdl" <<EOF
listener "127.0.0.1:8089" {
    proxy "unix:$sock"
}
EOF
    "$ALOHA" --config "$TMPDIR/stream_unix.kdl" >"$TMPDIR/aloha.out" 2>&1 &
    ALOHA_PID=$!
    sleep 0.5
    if ! kill -0 "$ALOHA_PID" 2>/dev/null; then
        fail "stream_proxy_unix/server_start" "aloha exited"
        cat "$TMPDIR/aloha.out" >&2
        ALOHA_PID=""
        return
    fi

    assert_status "stream_proxy_unix/200"  200 "http://127.0.0.1:8089/"
    assert_body   "stream_proxy_unix/body" "unix-ok" "http://127.0.0.1:8089/"

    stop_server
    kill "$backend_pid" 2>/dev/null || true
    wait "$backend_pid" 2>/dev/null || true
    BACKEND_PIDS=("${BACKEND_PIDS[@]/$backend_pid}")
}
