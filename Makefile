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
