# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Tanner Nicol

# restoregap-oss — on the shared platform gauntlet (reference-not-copy: the gate is
# defined once in ~/homelab/mk/verify.mk; this repo carries no copy).
#
# TIER 0 (PLATFORM.md §3, "internal/simple"): fmt, vet, lint, -race,
# govulncheck and CI are all enforced; the coverage floor is soft. Raising this
# to Tier 1 is a coverage investment, not a config change.
PLATFORM_MK ?= $(HOME)/homelab/mk/verify.mk
COVER_MIN ?= 0

# The private gauntlet is optional: a clone that does not have PLATFORM_MK
# (e.g. the public export, or any machine other than the maintainer's) still
# gets a working build/test/vet/clean loop from the fallback block below.
# On the maintainer's machine this resolves true and behaves exactly as the
# old unconditional `include` did — same file, same targets, same `verify`.
ifneq ($(wildcard $(PLATFORM_MK)),)
include $(PLATFORM_MK)
else
# ---- Stranger fallback (no private platform gauntlet present) ------------
# PLATFORM_MK below provides `verify`, `vet`, `test-race`, etc. on the
# maintainer's machine; without it, these targets give a contributor a
# working build/test/vet loop instead of a hard failure on `make`.
.DEFAULT_GOAL := help

.PHONY: help build test vet
help:
	@echo "restoregap — available targets:"
	@echo "  build       build ./cmd/restoregap to ./restoregap"
	@echo "  test        go test ./..."
	@echo "  vet         go vet ./..."
	@echo "  reuse-lint  REUSE/SPDX license check (skips if 'reuse' is not installed)"
	@echo "  release-status  is the newest release lined up to publish? (tags, export, assets, installed build, bar)"
	@echo "  clean       remove build artifacts"
	@echo
	@echo "note: the full internal verification gauntlet (make verify) needs"
	@echo "the maintainer's private platform tooling and is not available here."

build:
	go build -trimpath -o restoregap ./cmd/restoregap

test:
	go test ./...

vet:
	go vet ./...
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
# (platform-managed, generated, golden and binary files — see its comments for
# why each group cannot be annotated in place). License text: LICENSES/MIT.txt.
#
# Guarded by binary presence (PLATFORM.md §3: a gate must never fetch a tool).
# reuse is a Python tool, not a `go install` one, so unlike the gauntlet tools
# it is NOT on $(HOME)/go/bin — a machine without it skips with a notice
# instead of failing or downloading anything. Install, never system-wide:
#
#   python3 -m venv ~/.venvs/reuse && ~/.venvs/reuse/bin/pip install reuse==6.2.0
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
