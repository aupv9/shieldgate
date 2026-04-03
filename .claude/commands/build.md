Build the ShieldGate auth-server binary:

```bash
mkdir -p bin
go build -o bin/auth-server ./cmd/auth-server/main.go
```

If the build succeeds, confirm the binary location (`bin/auth-server`) and its size.
If the build fails, show the full compiler error and suggest a fix.
