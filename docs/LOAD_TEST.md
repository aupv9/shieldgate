# Load testing

The k6 script `tests/load/token_endpoint.js` loads the endpoints every client
and resource server calls: the token endpoint, introspection, discovery and
JWKS. It runs against a server prepared by `scripts/conformance/serve.sh`,
which seeds the clients the script uses.

```bash
DATABASE_URL=postgres://... scripts/conformance/serve.sh   # seeded server on :18100
make load-test                                              # all scenarios, 200 req/s, 60 s each
RATE=1000 DURATION=30s SCENARIOS=client_credentials scripts/load/run.sh
```

`scripts/load/run.sh` runs k6 in Docker (`grafana/k6:0.54.0`) and writes the
JSON summary to `tests/load/results/` (ignored by git).

| Scenario | Request | Pass criteria |
|---|---|---|
| `client_credentials` | `POST /oauth/token`, `grant_type=client_credentials`, HTTP Basic | p95 < 250 ms, < 1% errors, < 1% dropped |
| `refresh` | `POST /oauth/token`, `grant_type=refresh_token` (rotating) | p95 < 250 ms, < 1% errors |
| `introspect` | `POST /oauth/introspect` of a live token | p95 < 250 ms, < 1% errors, < 1% dropped |
| `discovery` | discovery document + JWKS | p95 < 50 ms, < 1% errors, < 1% dropped |

Every scenario uses a constant arrival rate (`RATE` per second), so a slow
server shows up as latency and dropped iterations instead of a lower request
rate. In the refresh scenario, each of `REFRESH_VUS` (default 100) virtual
users logs in once and then follows its own chain of rotated refresh tokens
(presenting a token twice would be reuse and revoke the grant). Refreshes in
the first `WARMUP` seconds (default 10), while the logins run, are not
measured.

## Results

Measured on 2026-10-26 on one machine (Apple M4, 10 cores). The server ran on
the host and PostgreSQL 16 and k6 ran in Docker Desktop (6 CPUs), with RS256
signing and no Redis. Each run used a fresh database. Other workloads were
running on the machine during these runs, and repeated runs varied by about
2× in p95. Treat the numbers as a comparison between builds on the same
machine, not as production capacity.

`main` (before 4.6) against this branch, 30 s per row:

| Scenario | Rate | `main` p50 / p95 | This branch p50 / p95 |
|---|---|---|---|
| client_credentials | 100/s | 63 ms / 108 ms | 3.2 ms / 5.2 ms |
| client_credentials | 200/s | **overloaded**: only 134 req/s served, p95 5.2 s | 3.0 ms / 5.0 ms |
| client_credentials | 1000/s | — | 18 ms / 134 ms, 0 errors, 0 dropped |
| introspect | 100/s | 58 ms / 72 ms | 2.1 ms / 9.6 ms |
| introspect | 1000/s | — | 1.2 ms / 7.2 ms |
| refresh | 100/s | 76 ms / 567 ms (fails) | 7.0 ms / 9.8 ms |
| refresh | 300/s | — | 7.3 ms / 49 ms |
| discovery + JWKS | 1000/s | — | 0.23 ms / 0.89 ms |

Saturation on this machine: client_credentials served about 1,650 req/s
(an offered 2,000/s dropped requests; p95 was 231 ms at 1,500/s). Refresh
served about 770 req/s at an offered 800/s with p95 149 ms. At 1,000 req/s the
server itself used only about 1.5 of 10 cores. The limit is the test setup
(PostgreSQL commits in the Docker VM, Docker Desktop networking, k6 on the
same machine).

## What the load test found

1. **bcrypt on every client authentication capped the token endpoint at
   ~130 req/s.** Every confidential client request (token, introspection,
   revocation) ran a full bcrypt comparison (cost 10, 50 ms of CPU). Client
   secrets are server-generated 256-bit random values, so bcrypt's slowness
   protects nothing there. `ClientService.ValidateClient` now remembers
   successful verifications for 10 minutes
   (`internal/services/client_secret_cache.go`):
   - the cache holds an HMAC of the secret under a random per-process key,
     keyed by client and stored hash, so rotating a secret invalidates it;
   - failed attempts are never cached, so guessing still costs a bcrypt each;
   - the client row is still loaded on every request, so deleting a client
     takes effect immediately.
2. **GORM logged every SQL statement.** `database.Initialize` hard-coded
   GORM's Info level, so every statement was written to stdout (74 MB of log
   in a few minutes, and about 30% of the server's CPU under load). GORM now
   follows `LOG_LEVEL`: statements only at `debug`; otherwise only errors and
   queries slower than 200 ms. "Record not found" is no longer logged as an
   error.
3. **Without Redis, the rate limiter logged a warning on every request**
   (144,000 lines in one run). It now warns once that rate limiting is
   disabled.
4. **Refresh token rotation was not atomic.** Designing the refresh scenario
   showed that concurrent requests with the same refresh token each received
   a new token chain (see [CONFORMANCE.md](CONFORMANCE.md)). This is fixed.
   Because of strict rotation, a client that sends the same refresh token
   twice at once (for example from two browser tabs) now loses the grant.

## Where the remaining cost is

- **RS256 signing**: about half of the server's CPU per token at 1,000 req/s
  (one signature per access token, two when an ID token is issued).
- **Writes per token**: each issued token inserts an `access_tokens` row
  (7 indexes) and an `audit_logs` row (6 indexes) in separate commits; a
  refresh also updates the old refresh token and inserts a new one. With
  PostgreSQL in Docker Desktop, commit fsync latency (`WALSync`) is what
  requests wait on. In production, PostgreSQL on its own host with fast
  storage moves this limit much higher. If the audit write becomes the
  bottleneck, batching audit events is an option, at the cost of losing
  events still in a batch if the process crashes.
- Tables grow by one access token and one audit row per request. Long runs
  against the same database get slower until the cleanup job removes expired
  tokens; audit retention is not automatic.
