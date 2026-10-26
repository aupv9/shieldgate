#!/usr/bin/env bash
# Runs the black-box conformance tests (tests/conformance) end to end: a
# throwaway PostgreSQL container, a seeded server (serve.sh), the tests, then
# cleanup.
#
#   scripts/conformance/run.sh
#
# Set DATABASE_URL to use an existing test database instead of a container.
# Extra arguments are passed to `go test` (e.g. -run TestRefresh -v).
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
PORT=${PORT:-18100}
export SERVER_URL=${SERVER_URL:-http://127.0.0.1:$PORT}
export WORK_DIR=${WORK_DIR:-$(mktemp -d)}
container=""

cleanup() {
  if [ -f "$WORK_DIR/server.pid" ]; then
    kill "$(cat "$WORK_DIR/server.pid")" 2>/dev/null || true
  fi
  if [ -n "$container" ]; then
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [ -z "${DATABASE_URL:-}" ]; then
  container=shieldgate-conformance-$$
  pg_port=${PG_PORT:-55432}
  docker run -d --rm --name "$container" -e POSTGRES_PASSWORD=conformance \
    -p "127.0.0.1:$pg_port:5432" postgres:16-alpine >/dev/null
  for _ in $(seq 1 60); do
    docker exec "$container" pg_isready -U postgres >/dev/null 2>&1 && break
    sleep 0.5
  done
  # pg_isready can succeed before the init scripts finish; wait for a query
  for _ in $(seq 1 60); do
    docker exec "$container" psql -U postgres -c 'select 1' >/dev/null 2>&1 && break
    sleep 0.5
  done
  export DATABASE_URL="postgres://postgres:conformance@127.0.0.1:$pg_port/postgres?sslmode=disable"
fi

"$repo/scripts/conformance/serve.sh"
cd "$repo"
SHIELDGATE_CONFORMANCE_URL=$SERVER_URL go test -tags conformance -count 1 "$@" ./tests/conformance/
