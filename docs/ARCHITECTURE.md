# restoregap (Go) — Target Architecture

Status: draft v1 (2026-07-16). This is the design for the ground-up Go rewrite of the
Python scanner. The Python implementation at `../scanner` is FROZEN as the behavioral
reference until the cutover gate passes; it is not refactored further.

## Why a rewrite

- Distribution: a single static binary (`restoregap`) replaces "requires Python + uv" —
  the right install story for a commercial CLI. Trivial cross-compile for mac/linux.
- Architecture reset: the Python tree accreted a 6.5k-line CLI god module, four disjoint
  inline-CSS regimes, rule functions called by name, and `dict[str, object]` attribute
  bags. The rewrite fixes these by design, not by refactor.
- UI reset: one design system for every HTML artifact (see §UI).

## Compatibility stance: clean slate (decided by Tanner, 2026-07-16)

No backwards/forwards compatibility is required. Schemas, ledger format, and CLI
may be redesigned freely. What MUST carry over is **semantics**, not bytes:

1. **Fail-closed decisions.** Everything the Python engine blocks, v2 must still
   block on equivalent input — asserted by the semantic reference cases in
   `testdata/golden/` (inputs → verdicts/risk classes, captured from Python).
2. **Zero-config safety.** `preflight` with NO context file still BLOCKs
   lifeline-shaped intents (SSH keys, recovery bundles). Protected behavior.
3. **Exit-code convention kept by choice** (it's good, and callers key off it):
   0 pass, 1 block / --fail-on-warn warning, 2 usage/internal error.
4. **Ledger v2 (Go-native):** append-only JSONL, hash-chained — entry hash =
   SHA-256 over the RFC 8785 (JCS) canonical form of the entry minus its hash
   field; `prev` links the chain; entry ids are ULIDs. The old Python ledger is
   ARCHIVED read-only at cutover (kept for history, verified by the old tool if
   ever needed); the Go ledger starts fresh.

   In-place repair of a corrupted entry is impossible by design: `prev` is
   part of every entry's hashed content, so rewriting one entry would cascade
   and change every hash after it. For the rare case of a known, owner-approved
   historical mismatch (e.g. a pre-union payload edited after writing, with
   the original bytes unrecoverable), `restoregap ledger anchor <ledger.jsonl>
   <entry-id> --reason "..." --approved-by <who>` appends a `chain_anchor`
   entry — never rewrites — that `Verify` honors only when the anchor's
   recorded `stored_hash` matches the target entry's claimed hash and the
   anchor appears later in the file than the entry it vouches for. A passing
   verify with anchors present is reported as `OK — N entries (K anchored
   anomalies: <ids>)`, not silently as a clean chain.
5. **Context schema v2 — unified guard model.** Python's change_guards /
   update_guards / command_guards / assurance_contracts / lifeline_artifacts
   collapse into one concept:

   ```yaml
   version: 2
   guards:
     - id: portable-recovery-kit
       kind: lifeline            # lifeline | guard (kind drives default risk class)
       match:                    # any matcher may appear on any guard
         paths: ["recovery-usb/**", "runbooks/**"]
         commands: []            # exact or glob command matchers
         packages: ["nvidia*", "kernel*"]
         actions: [delete_file, modify_file]
         actors: ["agent/*"]     # formerly assurance_contract.applies_to
         context_windows: [git-commit]
       required_for: [cold-metal-recovery]
       requires: {proofs: [kit-restore-drill], facts: [kit-location]}
       enforcement: block        # block | warn
       max_proof_age_hours: 24
   facts: [...]                  # unchanged in spirit: statement + provenance + expiry
   proofs: [...]                 # unchanged in spirit: status + hashes + optional ed25519
   ```

   Tanner's real `~/.config/restoregap/restoregap.local.yml` is hand-converted at
   cutover; a `migrate` command is optional later, not v1 scope.
6. **MCP:** same 7 tool *capabilities* (preflight intent/diff, acknowledge_risk,
   explain_decision, required_proof, ledger_query, story); schemas may be cleaned up.

### Cutover checklist (we own updating every caller)

- `~/bin/restoregap` wrapper → Go binary.
- Guarded-update wrappers in `~/bin` + `~/infra-config/bin` (restoregap-run-guarded-*,
  restoregap-preflight-os-update, weekly-patch, crash-*-readiness,
  restoregap-clean-zram-after-upgrade, restoregap-apply-post-upgrade-root-fixes).
- Git hooks `.githooks/restoregap-git-guard` (pre-commit/pre-push).
- MCP client configs; `~/CLAUDE.md`/`AGENTS.md`/`GEMINI.md` invocation snippets.
- Hand-convert the live local context YAML to v2; archive the old ledger.

Cutover gate = semantic reference cases green + git hooks and one guarded-update
wrapper exercised end-to-end against the Go binary.

## Module layout

```
scanner-go/
├── cmd/restoregap/           main.go — thin: build root command, exit-code mapping
├── internal/
│   ├── cli/                  cobra command tree; one file per command; NO business logic
│   ├── intent/               ChangeIntent domain type + intent YAML / diff / tf-plan parsers
│   ├── contextspec/          restoregap.yml schema: typed structs, validation, proof/fact
│   │                         freshness, host identity, Ed25519 proof signatures
│   ├── rules/                Rule interface + registry; one file per rule
│   │                         (changeguard, updateguard, commandguard, lifeline, sshd,
│   │                          caddyroute, recoverykit, tailnet, zeroconfig)
│   ├── engine/               decision core: RiskClass, ProofStatus, Verdict enums;
│   │                         assurance-contract matching; override resolution;
│   │                         Finding type. Pure — no I/O.
│   ├── ledger/               JSONL append/read/verify/checkpoint/anchor; canonical JSON
│   │                         (Python-compatible); file locking (flock) for safe append
│   ├── adapters/
│   │   ├── local/            wires diff/intent → rules for the local machine
│   │   ├── github/           org/repo scan, findings
│   │   └── aws/              RDS/S3/KMS discovery, recovery preflight
│   ├── policy/               scan → plan → fix → evidence flow; graph store (SQLite)
│   ├── report/               all artifact rendering: html/template + embedded UI bundle,
│   │                         markdown, JSON, CSV. One renderer per artifact type,
│   │                         one shared page shell.
│   ├── mcpserver/            JSON-RPC stdio server exposing the 7 tools
│   └── release/              public-boundary + oss-mirror-gate
├── ui/                       TypeScript design system (see §UI)
│   ├── src/tokens.css        design tokens (dark-first)
│   ├── src/components/       chips, tables, folds, graph, layout
│   └── dist/                 vite build output → go:embed'd by internal/report
├── testdata/golden/          captured Python contract fixtures (parity harness)
└── docs/
```

Rules for the tree:
- `internal/engine` is pure logic: takes normalized `[]ChangeIntent` + `contextspec.Context`
  + ledger overrides, returns `[]Finding`. Every rule is a type implementing
  `rules.Rule` and self-registers with typed match results — no string-keyed attribute
  bags anywhere.
- `internal/cli` maps flags → a request struct → calls one entry function per command.
  No rendering, no rule logic. (Anti-goal: recreating cli.py.)
- Errors are one-line human messages on stderr + exit 2; no stack traces (Python parity).
- Dependencies: stdlib-first. Allowed: cobra (CLI), gopkg.in/yaml.v3, modernc.org/sqlite
  (pure-Go, keeps cross-compile trivial), golang.org/x/crypto (ed25519 helpers if
  needed beyond stdlib). PDF export stays out of v1 (Python kept it optional too);
  print-quality HTML replaces it until there's demand.

## Decision engine (the core)

```
verdict(risk RiskClass, proof ProofStatus, enforcement Enforcement) Verdict
  proof ∈ {missing, stale, contradicted}            → block (or warn if enforcement=warn)
  proof ∈ {present, validated} & fresh              → pass (risk recorded)
  risk = none, no contract applies                  → pass
  cannot classify / cannot prove safe               → block  // fail-closed, zero-config path
```

Single `proofcheck` component owns ALL freshness/signature/host-identity validation
(Python scattered this across context_validation + proof matching). Overrides come from
the ledger (`active_override_for_finding`) with expiry; an override never deletes
history — it appends.

## UI (design system + inlined bundle)

Decision (Tanner, 2026-07-16): professional artifact UI, NOT walls of text; dark-first,
calm (no motion/shimmer/flashing — durable preference); artifacts stay SELF-CONTAINED
single HTML files (offline, emailable, archivable — that's the evidence-product promise).

- `ui/` is a Vite + TypeScript workspace building to exactly two files:
  `dist/restoregap.css` + `dist/restoregap.js` (no framework runtime in v1 —
  design tokens, components as classes + small vanilla-TS behaviors: theme boot,
  fold/expand, table sort/filter, copy buttons, severity chips, recovery graph).
- Go embeds `ui/dist` via `go:embed` and inlines both assets into every artifact head.
  One page shell (`report.PageShell`) used by ALL surfaces: report, status, preflight,
  evidence packet, vendor-limits, ledger/story. This kills the four-CSS-regimes problem
  structurally — a surface cannot ship without the shell.
- Information design per surface: verdict banner first (BLOCK/WARN/PASS chip + required
  next step), then evidence tables with severity chips and collapsible proof detail.
  Dense prose only inside folds. Light theme exists for print/evidence-recipient use;
  dark is default.
- The interactive recovery graph (`recovery_graph.js`, 928 lines, dependency-free) is
  PORTED AS-IS into `ui/src/components/graph.ts` — it already works and the marketing
  site syncs from it; keep the sync contract.
- Playwright `scripts/ui_check` (desktop + mobile, console-error-clean, overflow checks)
  is a release gate like in the site repo.

## What is NOT ported

- `src/restoregap/dev/` labs, chaos/demo generators (28k LOC): only `agent-demo`,
  `dev github-demo`, `dev demo-ready` (minimal), `dev public-boundary`,
  `dev oss-mirror-gate` are rebuilt because release gates and hooks invoke them.
- `rest_api.py`-style speculative surfaces: nothing hosted in v1.
- WeasyPrint PDF: replaced by print-grade HTML.

## Phases

0. Architecture doc (this file) + golden fixtures + scaffold.        ← current
1. Preflight vertical slice (intent + diff + zero-config + ledger).  Parity: fixtures.
2. policy scan/plan/fix/evidence, status, ledger cmds, MCP server.
3. UI design system + all artifact surfaces + vendor-limits.
4. GitHub/AWS adapters, release gates, agent/github demos.
5. Cutover gate → repoint ~/bin/restoregap → archive Python as reference.

Repo stays PRIVATE (Gitea origin; no GitHub until the existing scanner-kkr
publish-approval flow says otherwise).
