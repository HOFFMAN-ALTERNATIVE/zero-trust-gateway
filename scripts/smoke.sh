#!/usr/bin/env bash
# End-to-end walkthrough against the docker-compose demo. Used by CI.
# shellcheck disable=SC2015  # pass() never fails
set -euo pipefail
GW=${GW:-http://localhost:8080}
IDP=${IDP:-http://localhost:9000}
ADMIN=${ADMIN:-http://localhost:9090}

pass() { printf '  \033[32m✔\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✘\033[0m %s\n' "$1"; exit 1; }
token() { curl -fsS "$IDP/dev/token?user=$1" | jq -r .access_token; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
expect() { local want=$1 desc=$2; shift 2; local got; got=$(code "$@"); [[ $got == "$want" ]] && pass "$desc → $got" || fail "$desc: want $want got $got"; }

echo "waiting for gateway readiness"
for _ in $(seq 1 60); do [[ $(code "$ADMIN/readyz") == 200 ]] && break; sleep 1; done
expect 200 "gateway ready" "$ADMIN/readyz"

ALICE=$(token alice); BOB=$(token bob); CAROL=$(token carol)

echo "deny by default"
expect 401 "anonymous API call"               "$GW/"
expect 302 "anonymous browser → login"        -H 'Accept: text/html' "$GW/"
expect 200 "public route, anonymous"          "$GW/public/status"
expect 401 "forged token"                     -H "Authorization: Bearer eyJhbGciOiJub25lIn0.e30." "$GW/"

echo "policy"
expect 200 "alice (example.com) → app"        -H "Authorization: Bearer $ALICE" "$GW/"
expect 403 "carol (example.org) → app"        -H "Authorization: Bearer $CAROL" "$GW/"
expect 200 "carol (finance) → /finance"       -H "Authorization: Bearer $CAROL" "$GW/finance/q3"
expect 200 "alice (admins) POST /admin"       -X POST -H "Authorization: Bearer $ALICE" "$GW/admin/users"
expect 200 "bob (engineering) GET /admin"     -H "Authorization: Bearer $BOB" "$GW/admin/users"
expect 403 "bob (engineering) POST /admin"    -X POST -H "Authorization: Bearer $BOB" "$GW/admin/users"
expect 405 "PUT not allowed on /admin"        -X PUT -H "Authorization: Bearer $ALICE" "$GW/admin/users"

echo "identity propagation over mTLS"
body=$(curl -fsS -H "Authorization: Bearer $BOB" -H 'X-Auth-Request-Groups: admins' "$GW/hello")
jq -e '.mtls_peer == "gateway" and .tls_version == "TLS 1.3" and .user == "u-1002" and .groups == "engineering"' <<<"$body" >/dev/null \
  && pass "upstream sees gateway client cert, TLS 1.3, real identity (spoofed header stripped)" || fail "propagation: $body"

echo "browser login (authorization code + PKCE)"
jar=$(mktemp)
body=$(curl -fsS -L -c "$jar" -b "$jar" "$GW/_ztg/login?rd=/dashboard&login_hint=alice")
jq -e '.authn == "session" and .path == "/dashboard" and .email == "alice@example.com"' <<<"$body" >/dev/null \
  && pass "session cookie issued, redirected back to /dashboard" || fail "login: $body"
expect 200 "whoami with session"              -b "$jar" "$GW/_ztg/whoami"

echo "signing-key rotation"
curl -fsS -X POST "$IDP/rotate" >/dev/null
sleep 3 # unknown-kid refetches are rate-limited to one per jwks_min_refresh (2s in the demo)
expect 200 "token from rotated key"           -H "Authorization: Bearer $(token alice)" "$GW/"
expect 200 "token from previous key"          -H "Authorization: Bearer $ALICE" "$GW/"

echo "observability"
curl -fsS "$ADMIN/metrics" | grep -q 'ztg_requests_total{code="403",decision="deny",route="app"}' && pass "prometheus metrics" || fail "metrics"
curl -fsS "$ADMIN/metrics" | grep -q 'ztg_jwks_refresh_total{result="ok"}' && pass "jwks refresh metric" || fail "jwks metric"
rm -f "$jar"
echo "all checks passed"
