# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Tanner Nicol

# Build, test and verify targets for restoregap. `make help` lists them.
#
# Everything a contributor needs is defined below and needs only Go (plus
# bash, jq and sqlite3 for the hook test, node for the site check, and the
# optional tools named in `make help`). Nothing is downloaded by a target.
#
# The maintainer's machine can add its own extra checks: if the file named by
# PLATFORM_MK exists, it is included in place of the portable block below. It
# is private tooling, absent from every clone, and nothing here depends on it.
PLATFORM_MK ?= $(HOME)/homelab/mk/verify.mk
COVER_MIN ?= 0

ifneq ($(wildcard $(PLATFORM_MK)),)
include $(PLATFORM_MK)
else
# ---- Portable targets (used whenever the optional private file is absent) --
.DEFAULT_GOAL := help

.PHONY: help build test test-race vet fmt-check lint packaging-test site-check verify
help:
	@echo "restoregap -- available targets:"
	@echo "  build           build ./cmd/restoregap to ./restoregap"
	@echo "  test            go test ./..."
	@echo "  test-race       go test -race ./..."
	@echo "  vet             go vet ./..."
	@echo "  fmt-check       fail if gofmt would change any file"
	@echo "  lint            staticcheck and govulncheck, each only if installed (never fetched)"
	@echo "  hook-test       end-to-end check of the example PreToolUse hook (needs bash, jq, sqlite3)"
	@echo "  packaging-test  check the installer and release packaging (bash scripts/tests/packaging.sh)"
	@echo "  reuse-lint      REUSE/SPDX license check (skipped if 'reuse' is not installed)"
	@echo "  site-check      check the landing page is in sync with its source (needs node)"
	@echo "  verify          fmt-check vet test-race hook-test packaging-test reuse-lint site-check"
	@echo "  release-status  is the newest release lined up to publish? (tags, export, assets, installed build, bar)"
	@echo "  clean           remove build artifacts"

build:
	go build -trimpath -o restoregap ./cmd/restoregap

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

# gofmt -l prints the name of every file it would rewrite; any output fails.
fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "fmt-check: these files need gofmt:"; echo "$$out"; exit 1; \
	fi

# Static analysis. Each tool runs only if it is already on PATH; this target
# never downloads anything.
lint:
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "lint: SKIP staticcheck -- not on PATH (install: go install honnef.co/go/tools/cmd/staticcheck@latest)"; \
	fi
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "lint: SKIP govulncheck -- not on PATH (install: go install golang.org/x/vuln/cmd/govulncheck@latest)"; \
	fi

# Installer and release-packaging checks.
packaging-test:
	bash scripts/tests/packaging.sh

# The landing page (site/index.html) is generated; --check fails if it drifted.
site-check:
	@if command -v node >/dev/null 2>&1; then \
		node scripts/build-site.mjs --check; \
	else \
		echo "site-check: SKIP -- node not on PATH"; \
	fi

verify: fmt-check vet test-race hook-test packaging-test reuse-lint site-check
endif

.PHONY: clean
clean:
	rm -f coverage.out
	rm -f restoregap

# One screen: is VERSION lined up to publish? Exit 0 iff every probe is green.
.PHONY: release-status
release-status:
	scripts/release-status.sh

# Re-record the README demo (needs vhs, ttyd, ffmpeg, sqlite3). See demo/demo.tape.
.PHONY: demo
demo:
	demo/setup.sh /tmp/rg-demo
	go build -trimpath -o /tmp/rg-demo/bin/restoregap ./cmd/restoregap
	vhs demo/demo.tape

# End-to-end check of the example PreToolUse hook against a fresh demo
# fixture (needs bash, jq, sqlite3, go). See docs/examples/preflight-hook.test.sh.
.PHONY: hook-test
hook-test:
	bash docs/examples/preflight-hook.test.sh

# SPDX compliance (REUSE spec): every tracked file carries license + copyright,
# either as in-file SPDX tags (hand-authored source) or via REUSE.toml
# (generated, golden, binary and no-comment-syntax files — see its comments for
# why each group cannot be annotated in place). License text: LICENSES/MIT.txt.
#
# Guarded by binary presence: a check must never fetch a tool. reuse is a
# Python tool, so a machine without it skips with a notice instead of failing
# or downloading anything. Install it into a virtualenv, never system-wide
# (the charset-normalizer extra is needed where libmagic is absent, e.g. macOS):
#
#   python3 -m venv ~/.venvs/reuse && ~/.venvs/reuse/bin/pip install 'reuse[charset-normalizer]==6.2.0'
#   PATH="$HOME/.venvs/reuse/bin:$PATH" make reuse-lint
#
# (bump the pin with `pip index versions reuse`; keep this line and the version
# in lockstep)
.PHONY: reuse-lint
reuse-lint:
	@if command -v reuse >/dev/null 2>&1; then \
		reuse lint; \
	else \
		echo "reuse-lint: SKIP — reuse not on PATH (see install note in Makefile)"; \
	fi
