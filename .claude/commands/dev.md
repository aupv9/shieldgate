Start the full ShieldGate development stack (PostgreSQL, Redis, auth-server) via Docker Compose:

```bash
# Ensure .env exists
[ -f .env ] || cp .env.example .env

# Start all services
make start

# Verify health
make health
```

After startup, tail the logs:
```bash
make logs
```

The auth-server will be available at http://localhost:8080.
Health endpoint: GET http://localhost:8080/health
OIDC discovery: GET http://localhost:8080/.well-known/openid-configuration

To stop: `make stop`
