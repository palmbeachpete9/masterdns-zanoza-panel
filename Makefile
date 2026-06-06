.PHONY: lint fmt test build check

# ── Configuration ─────────────────────────────────────────────
GO        := go
GOLANGCI  := golangci-lint
GOFUMPT   := gofumpt

# ── lint ──────────────────────────────────────────────────────
lint:
	$(GOLANGCI) run ./...

# ── fmt ───────────────────────────────────────────────────────
fmt:
	find . -name '*.go' -not -path './masterdns/*' -print0 | xargs -0 $(GOFUMPT) -l -w -extra

# ── test ──────────────────────────────────────────────────────
test:
	-$(GO) test -race -count=1 ./...

# ── build ─────────────────────────────────────────────────────
build:
	$(GO) build -o zanoza-panel ./cmd/zanoza-panel

# ── check ─────────────────────────────────────────────────────
# Full CI pipeline: fmt → lint → test → build.
check: fmt lint test build
	@echo "✅ All checks passed."
