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

# Load shared helpers (assert_*, start_server, stop_server, cleanup,
# setup_webroot, setup_ldap, teardown_ldap).
TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
source "$TESTS_DIR/lib.sh"

trap cleanup EXIT

# Source all suite files.
# shellcheck source=suite_static.sh
source "$TESTS_DIR/suite_static.sh"
# shellcheck source=suite_access.sh
source "$TESTS_DIR/suite_access.sh"
# shellcheck source=suite_auth.sh
source "$TESTS_DIR/suite_auth.sh"
# shellcheck source=suite_status.sh
source "$TESTS_DIR/suite_status.sh"
# shellcheck source=suite_proxy.sh
source "$TESTS_DIR/suite_proxy.sh"
# shellcheck source=suite_cgi.sh
source "$TESTS_DIR/suite_cgi.sh"
# shellcheck source=suite_gateways.sh
source "$TESTS_DIR/suite_gateways.sh"
# shellcheck source=suite_tls.sh
source "$TESTS_DIR/suite_tls.sh"
# shellcheck source=suite_stream.sh
source "$TESTS_DIR/suite_stream.sh"
# shellcheck source=suite_routing.sh
source "$TESTS_DIR/suite_routing.sh"
# shellcheck source=suite_headers.sh
source "$TESTS_DIR/suite_headers.sh"
# shellcheck source=suite_jwt.sh
source "$TESTS_DIR/suite_jwt.sh"
# shellcheck source=suite_subrequest_auth.sh
source "$TESTS_DIR/suite_subrequest_auth.sh"
# shellcheck source=suite_auth_request.sh
source "$TESTS_DIR/suite_auth_request.sh"
# shellcheck source=suite_http3.sh
source "$TESTS_DIR/suite_http3.sh"
# shellcheck source=suite_proxy_h3.sh
source "$TESTS_DIR/suite_proxy_h3.sh"
# shellcheck source=suite_proxy_trust.sh
source "$TESTS_DIR/suite_proxy_trust.sh"

# --- main -----------------------------------------------------------

setup_webroot

suite_static_files
suite_redirect
suite_ip_access
suite_auth
suite_status_page
suite_compression
suite_reverse_proxy
suite_reverse_proxy_unix
suite_cgi
suite_tls
suite_stream_proxy
suite_stream_proxy_unix
suite_ldap_auth
suite_health_endpoint
suite_multi_vhost
suite_vhost_aliases
suite_regex_vhost
suite_response_headers
suite_request_headers
suite_custom_error_pages
suite_access_redirect
suite_scgi
suite_fastcgi
suite_static_mime_types
suite_redirect_variables
suite_proxy_x_forwarded_for
suite_proxy_strip_prefix
suite_jwt
suite_subrequest_auth
suite_auth_request
suite_http3_basic
suite_http3_alt_svc
suite_http3_middleware
suite_proxy_h3_forced
suite_proxy_h3_autoupgrade
suite_proxy_h3_altsvc_expires
suite_proxy_skip_verify
suite_proxy_connect_timeout

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
