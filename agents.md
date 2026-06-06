# Go conventions

## Always
- Check every error. Wrap with `%w`: `fmt.Errorf("ctx: %w", err)`
- `gofumpt` before commit, `goimports` for import ordering
- `any` not `interface{}`; guard clauses, no `else` after `return`

## Testing
- Table-driven: `[{name, input, want}, ...]`
- `testify/assert`, `testify/require` when must stop
- `-race`, `t.Parallel()` in CI

## Naming
- Short lowercase packages. `Owner()` not `GetOwner()`. `-er` for 1-method interfaces

## Concurrency
- `ctx context.Context` always first param. `errgroup` for bounded parallel work

## Structure
- `cmd/name/main.go` for each binary. `internal/` for private packages

## Comments
- Short doc comment on exported funcs only when the signature isn't enough.
- No inline comments mid-code.

## Commits
- **English only.** Conventional: `type: description` (`feat`, `fix`, `chore`, ...)

## Tooling
```bash
make fmt    # gofumpt + goimports (masterdns/ excluded)
make lint   # golangci-lint
make test   # tests with -race
make build  # compile
make check  # all of above
```
