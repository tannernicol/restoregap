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
include $(PLATFORM_MK)

.PHONY: clean
clean:
	rm -f coverage.out

# Re-record the README demo (needs vhs, ttyd, ffmpeg, sqlite3). See demo/demo.tape.
.PHONY: demo
demo:
	demo/setup.sh /tmp/rg-demo
	go build -trimpath -o /tmp/rg-demo/bin/restoregap ./cmd/restoregap
	vhs demo/demo.tape

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
