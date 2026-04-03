Run the full Go test suite with verbose output and coverage:

```bash
go test -v -cover ./...
```

After running, report:
1. Any failing tests with their error messages
2. Per-package coverage percentages
3. Packages with coverage below 80% (the project minimum)

If a specific package is given as an argument, run tests only for that package:
```bash
go test -v -cover ./$ARGUMENTS/...
```
