#!/usr/bin/env bash
# Runs the k6 load test (tests/load/token_endpoint.js) in Docker against a
# server prepared by scripts/conformance/serve.sh.
#
#   scripts/load/run.sh                         # all scenarios, 200 req/s, 60s each
#   RATE=500 DURATION=30s SCENARIOS=client_credentials scripts/load/run.sh
#
# BASE_URL is the server as seen from the host (default
# http://127.0.0.1:18100); inside the container it is reached through
# host.docker.internal, and the script names the tenant with X-Tenant-ID
# (TENANT_ID, default: the seeded tenant). The JSON summary is written to
# $SUMMARY (default tests/load/results/summary-<timestamp>.json; the
# directory must be shared with Docker).
set -euo pipefail

BASE_URL=${BASE_URL:-http://127.0.0.1:18100}
K6_IMAGE=${K6_IMAGE:-grafana/k6:0.54.0}
repo=$(cd "$(dirname "$0")/../.." && pwd)
SUMMARY=${SUMMARY:-$repo/tests/load/results/summary-$(date +%Y%m%d-%H%M%S).json}

hostport=${BASE_URL#*://}
hostport=${hostport%%/*}
port=${hostport##*:}
mkdir -p "$(dirname "$SUMMARY")"
out_dir=$(cd "$(dirname "$SUMMARY")" && pwd)

docker run --rm -i --user "$(id -u):$(id -g)" \
  --add-host "host.docker.internal:host-gateway" \
  -v "$repo/tests/load:/scripts:ro" -v "$out_dir:/out" \
  -e BASE_URL="http://host.docker.internal:$port" -e TENANT_ID="${TENANT_ID:-}" \
  -e RATE="${RATE:-200}" -e DURATION="${DURATION:-60s}" -e SCENARIOS="${SCENARIOS:-}" \
  "$K6_IMAGE" run --summary-export "/out/$(basename "$SUMMARY")" /scripts/token_endpoint.js
