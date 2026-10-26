#!/usr/bin/env bash
# Starts ShieldGate for the conformance and load tests: builds the server,
# generates a throwaway RS256 signing key, runs the server against
# DATABASE_URL and seeds the test tenant, users and clients
# (tests/conformance/seed).
#
#   DATABASE_URL=postgres://... scripts/conformance/serve.sh
#
# Environment:
#   DATABASE_URL  (required) a database used only for testing
#   SERVER_URL    issuer and public URL (default http://127.0.0.1:18100); its
#                 host becomes the tenant's domain
#   PORT          listen port (default: the port of SERVER_URL)
#   WORK_DIR      where the binary, key, log and pid file go
#                 (default: a new temporary directory)
#
# The server keeps running in the background; stop it with
#   kill "$(cat "$WORK_DIR/server.pid")"
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL must point at a test database}"
SERVER_URL=${SERVER_URL:-http://127.0.0.1:18100}
hostport=${SERVER_URL#*://}
hostport=${hostport%%/*}
host=${hostport%:*}
PORT=${PORT:-${hostport##*:}}
WORK_DIR=${WORK_DIR:-$(mktemp -d)}
repo=$(cd "$(dirname "$0")/../.." && pwd)

mkdir -p "$WORK_DIR"
cd "$repo"
go build -o "$WORK_DIR/auth-server" ./cmd/auth-server/main.go
if [ ! -f "$WORK_DIR/signing.pem" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK_DIR/signing.pem" 2>/dev/null
  chmod 600 "$WORK_DIR/signing.pem"
fi

# Rate limits are raised: the conformance suite and the load tests send far
# more requests from one address than a real client would
DATABASE_URL=$DATABASE_URL REDIS_URL='' PORT=$PORT SERVER_URL=$SERVER_URL GIN_MODE=release LOG_LEVEL=${LOG_LEVEL:-warn} \
  METRICS_ADDR=${METRICS_ADDR:-} JWT_SECRET=${JWT_SECRET:-conformance-only-secret-0123456789abcdef} \
  JWT_SIGNING_ALG=RS256 JWT_SIGNING_KEY_FILE="$WORK_DIR/signing.pem" \
  RATE_LIMIT_REQUESTS_PER_MINUTE=${RATE_LIMIT_REQUESTS_PER_MINUTE:-1000000} \
  "$WORK_DIR/auth-server" >"$WORK_DIR/server.log" 2>&1 &
echo $! >"$WORK_DIR/server.pid"

for _ in $(seq 1 60); do
  if curl -sf "http://127.0.0.1:$PORT/health" >/dev/null; then
    break
  fi
  if ! kill -0 "$(cat "$WORK_DIR/server.pid")" 2>/dev/null; then
    echo "server exited; see $WORK_DIR/server.log" >&2
    tail -5 "$WORK_DIR/server.log" >&2
    exit 1
  fi
  sleep 0.5
done
curl -sf "http://127.0.0.1:$PORT/health" >/dev/null || { echo "server did not become healthy" >&2; exit 1; }

go run ./tests/conformance/seed -database-url "$DATABASE_URL" -domain "$host"
echo "server: $SERVER_URL (pid $(cat "$WORK_DIR/server.pid"), log $WORK_DIR/server.log)"
