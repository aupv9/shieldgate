Run all code quality checks for the ShieldGate project:

```bash
# 1. Format code
go fmt ./...

# 2. Static analysis
go vet ./...

# 3. Linter (if golangci-lint is installed)
golangci-lint run 2>/dev/null || echo "golangci-lint not installed, skipping"
```

Report any issues found. For formatting changes, list which files were modified.
For vet or lint errors, show the file path, line number, and error message.
