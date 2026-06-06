//go:build tools

// Package tools tracks development-only dependencies (linters, formatters)
// so their versions are pinned in go.mod. These are never compiled into
// production binaries.
package tools

import (
	_ "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"
	_ "mvdan.cc/gofumpt"
)
