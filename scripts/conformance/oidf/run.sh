#!/usr/bin/env bash
# Runs the OpenID Foundation conformance suite against ShieldGate:
#   1. starts the suite in Docker (compose.yml)
#   2. starts a throwaway PostgreSQL and a seeded ShieldGate on $PORT whose
#      issuer is https://shieldgate.test, the TLS proxy the suite reaches it
#      through (see compose.yml)
#   3. runs the test plan with run_plan.py and prints a summary
#
#   scripts/conformance/oidf/run.sh
#
# Environment:
#   PLAN          test plan (default oidcc-basic-certification-test-plan)
#   VARIANT       plan variant JSON (default discovery + static client)
#   CONFIG        suite configuration (default oidcc-basic.json)
#   RESULTS       where to write the JSON results (default: the work dir)
#   KEEP_SUITE=1  leave the suite running afterwards (to look at the logs
#                 at https://localhost.emobix.co.uk:8443)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
PORT=${PORT:-18101}
PLAN=${PLAN:-oidcc-basic-certification-test-plan}
VARIANT=${VARIANT:-'{"server_metadata":"discovery","client_registration":"static_client"}'}
CONFIG=${CONFIG:-$here/oidcc-basic.json}
SUITE=https://localhost.emobix.co.uk:8443/
export PORT SHIELDGATE_PORT=$PORT
export SERVER_URL=https://shieldgate.test
export WORK_DIR=${WORK_DIR:-$(mktemp -d)}
RESULTS=${RESULTS:-$WORK_DIR/results.json}
pg=shieldgate-oidf-pg-$$

cleanup() {
  if [ -f "$WORK_DIR/server.pid" ]; then
    kill "$(cat "$WORK_DIR/server.pid")" 2>/dev/null || true
  fi
  docker rm -f "$pg" >/dev/null 2>&1 || true
  if [ "${KEEP_SUITE:-}" != 1 ]; then
    docker compose -f "$here/compose.yml" down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker compose -f "$here/compose.yml" up -d
pg_port=${PG_PORT:-55433}
docker run -d --rm --name "$pg" -e POSTGRES_PASSWORD=conformance -p "127.0.0.1:$pg_port:5432" postgres:16-alpine >/dev/null
for _ in $(seq 1 60); do
  docker exec "$pg" psql -U postgres -c 'select 1' >/dev/null 2>&1 && break
  sleep 0.5
done
export DATABASE_URL="postgres://postgres:conformance@127.0.0.1:$pg_port/postgres?sslmode=disable"
"$repo/scripts/conformance/serve.sh"

echo "waiting for the conformance suite..."
for _ in $(seq 1 120); do
  [ "$(curl -sk -o /dev/null -w '%{http_code}' "${SUITE}api/runner/available")" = 200 ] && break
  sleep 5
done

sed "s|{ISSUER}|$SERVER_URL|g" "$CONFIG" >"$WORK_DIR/config.json"
python3 -I "$here/run_plan.py" "$SUITE" "$PLAN" "$VARIANT" "$WORK_DIR/config.json" "$RESULTS"
