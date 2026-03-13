Run a security scan of the ShieldGate codebase using gosec:

```bash
# Install gosec if not present
which gosec || go install github.com/securego/gosec/v2/cmd/gosec@latest

# Run the scan
gosec ./...
```

After the scan, summarize:
1. Total issues found
2. Any HIGH severity findings — show file, line, and description
3. Any MEDIUM severity findings — show file, line, and description
4. LOW severity issues can be briefly listed or counted

Focus attention on:
- SQL injection risks (G201, G202)
- Hardcoded credentials (G101)
- Weak cryptography (G401, G402, G501)
- JWT handling issues
- HTTP server configuration (G114)
