# Restore Gap

**Prove your recovery works. Then make the change.**

[![ci](https://github.com/tannernicol/restoregap/actions/workflows/ci.yml/badge.svg)](https://github.com/tannernicol/restoregap/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/tannernicol/restoregap?include_prereleases&label=release)](https://github.com/tannernicol/restoregap/releases)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![go](https://img.shields.io/github/go-mod/go-version/tannernicol/restoregap)](go.mod)

Your coding agent is about to delete a database. Restore Gap is the hook it
hits first: a read-only gate that checks the proposed change against your
recovery rules and answers with a reason the agent can act on. It never
executes the change, and it never runs a recovery to make itself pass.

One command wires it into the agent as a pre-tool hook and an MCP server:

```console
$ restoregap agent install claude     # or: gemini
wrote ~/.claude/settings.json: hooks.PreToolUse[restoregap], mcpServers.restoregap
```

When the agent then proposes `rm app.db`, the hook answers in the agent's own
decision format. From the [disposable SQLite demo](docs/walkthrough.md), paths
shortened:

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse",
  "permissionDecision": "deny",
  "permissionDecisionReason": "BLOCK delete_file app.db: Restore Gap preflight could not prove the declared recovery path survives this change. Required proof: app-db-recovery. Run: restoregap drill --context restoregap.local.yml --proof app-db-recovery"}}
```

After `restoregap drill` restores the database in a sandbox and passes its
checks, the same call is allowed and the decision lands in a local ledger:

```console
$ restoregap ledger show --limit 1
proposed: delete_file · app.db
proof: app-db-recovery · validated and fresh; recipe-bound
Restore Gap did not execute the change.
```

The same evaluator is an MCP server (`preflight_intent`, `required_proof`,
`explain_decision`, …) and a plain CLI for CI. One MIT-licensed binary.
Local, offline, no account. [Watch the terminal recording](demo/demo.gif).

## Quick start

Install the v0.11.5 release, then run the isolated demo fixture. The demo needs
`sqlite3` because its fixture is a real SQLite database.

```console
$ curl -sSfLO https://raw.githubusercontent.com/tannernicol/restoregap/v0.11.5/scripts/install.sh
$ less install.sh
$ RESTOREGAP_VERSION=v0.11.5 sh install.sh
$ export PATH="$HOME/.local/bin:$PATH"   # use /usr/local/bin when installing as root
$ git clone --depth 1 --branch v0.11.5 https://github.com/tannernicol/restoregap.git
$ cd restoregap
$ demo/run.sh
```

`demo/run.sh` creates a fresh temporary fixture, points `RESTOREGAP_CONTEXT`,
`RESTOREGAP_LEDGER`, and `XDG_STATE_HOME` into it, then runs the real flow:
drift check, missing-proof block, drill, fresh-proof pass, expiry block, and
ledger verification. Pass a fresh empty directory to keep the fixture for
inspection: `demo/run.sh /tmp/restoregap-demo`.

The installer supports Linux and macOS on amd64 and arm64. It verifies the
selected archive against the matching entry in `checksums.txt` before it
extracts or installs anything. As a normal user it installs to
`~/.local/bin`; as root it installs to `/usr/local/bin`. It never asks for
sudo. The release also includes SBOM documents and reproducible build settings.

Or choose an archive from the [releases page](https://github.com/tannernicol/restoregap/releases),
or build from source with `go install github.com/tannernicol/restoregap/cmd/restoregap@latest`
(Go 1.25+).

## The local gate

The smallest useful loop is:

| Rung | Command | What it establishes |
|---|---|---|
| Drift | `restoregap check <live> <recovery>` | Which entries exist in exactly one place or differ today. |
| Proof | `restoregap drill` | Whether a declared recovery source can reconstruct the artifact and pass its checks. |
| Gate | `restoregap preflight` | Whether a supplied intent or diff satisfies the recovery requirements for the guards it touches. |

`drill propose` measures a live artifact and writes a draft context. You review
that context, then run the drill. A proof expires; an expired proof does not
clear a guard. The ledger records decisions, drill results, and owner
overrides. Read it with `restoregap ledger show`; check its chain with
`restoregap ledger verify`.

For agent workflows, enable `preflight --require-coverage`: every supplied
path, destination, package and command must match declared coverage. Use
`require_bound: true` with `require_verified: true` on guards that require a
tested, unchanged recovery recipe. A proposed change to a declared recovery
dependency invalidates the affected proof for that decision. See the
[agent gate](docs/agent-gate.md) and the [restic recipe](docs/examples/restic.md).

The built-in policy covers SSH keys and recovery bundles even without a custom
context. For an agent integration, `restoregap mcp serve` exposes the same
preflight decision surface. The example hook in
[docs/examples/preflight-hook.sh](docs/examples/preflight-hook.sh) shows how a
narrow set of destructive command shapes can be translated into intents; it is
an example integration, not universal command interception.

## The ledger explains the decision

`restoregap ledger show --limit 10` answers: **What change was proposed? Why
did it pass or block? What evidence was used? What should happen next?**
It also shows recorded drills, owner overrides and chain integrity. JSON output
is available with `--format json` for agents. The dashboard presents the latest
decision using the same recorded data; older entries remain readable and are
labelled when proposal details were not recorded.

The ledger is a local audit trail, not an execution log or a count of incidents
prevented. A hash chain detects changes against its recorded chain; an owner
who can replace the whole ledger can replace that history. Keep trusted copies
and signing keys outside the agent's writable scope when assurance matters.

For a review handoff, `bundle export --summary-only` produces a signed JSON
summary of test outcomes, freshness, binding and ledger integrity without raw
paths, commands or configuration. Verification requires an independently trusted
key. It establishes who signed the record and whether it changed; it does not
certify compliance, insurance acceptance or universal recoverability.
[Create and verify a review summary](docs/evidence-handoff.md).

## Five words

- **proof** — a recorded observation or test result; a verified drill proof states which recovery checks passed and when.
- **drill** — the declared recovery run that produces a proof.
- **guard** — a rule naming what must be proven before a matching change is allowed.
- **intent** — the proposed change under evaluation, supplied as an intent file or diff.
- **ledger** — the decision history: what was evaluated, why it passed or blocked, and which tests or owner exceptions were recorded. A decision does not establish that a change was executed.

## What it does not claim

Restore Gap checks the recovery process and change scope you declare. It does not inspect inside
every backup product, make an undeclared recovery path safe, provide an OS-level
sandbox, or turn an agent into a generally safe operator. Your backup tooling,
host isolation, permissions, and agent controls remain responsible for those
parts. There is no provider-aware AWS, GitHub, or Terraform-plan adapter in this
release. Model relevant files, commands, packages and recovery dependencies
explicitly. For restic, borg, or ZFS targets, see the
[comparators issue](https://github.com/tannernicol/restoregap/issues/2).

## A possible hosted layer

The binary is complete and stays free, local, offline, and MIT licensed. A
future hosted service is only a proposal: optional evidence retention and
custody, expected-proof monitoring over time, and private links for sharing a
recovery record. It does not exist yet, and no hosted feature is required to
use the CLI. If that would help, describe the workflow on the
[interest-check issue](https://github.com/tannernicol/restoregap/issues/1).

## FAQ

**I already have restic, borg, or ZFS snapshots.**

Good. Restore Gap sits beside scheduled verification and custom recovery
scripts as a local evidence and gate layer. `restoregap drill` records whether
the declared path worked and how long it took, then the guard ties that fresh
evidence to the local change it protects.

**My agent already has deny rules.**

Deny rules remain useful. Restore Gap adds a proof-based decision for the
specific guarded change you wire into it.

**Isn't this just `diff`?**

`diff` compares files. A drill performs the declared restore and records which
checks passed at that time. It cannot guarantee a future restore will succeed.

**Does it phone home?**

No account or telemetry is required. Evaluation and offline evidence verification
make no network calls. Explicit recovery commands and validation probes may use
the network you configure.

## Docs

[Walkthrough](docs/walkthrough.md) · [Why not a script?](docs/why-not-a-script.md) ·
[Authoring drills](docs/drill-authoring.md) · [Discover](docs/DISCOVER.md) ·
[Agent gate](docs/agent-gate.md) · [GitHub Action](docs/github-action.md) ·
[Schema](docs/SCHEMA.md) · [The recovery story](docs/recovery-story.md) ·
[Architecture](docs/ARCHITECTURE.md) · [Contributing](CONTRIBUTING.md) ·
[Security](SECURITY.md) · [Changelog](CHANGELOG.md) · MIT.

## See also

- [deadman](https://github.com/tannernicol/deadman) — the off-property half: a GitHub-Actions-only dead-man switch that opens an issue when your box stops committing its hourly heartbeat. A watcher that lives inside the blast radius cannot report the outage; this one lives on GitHub.
