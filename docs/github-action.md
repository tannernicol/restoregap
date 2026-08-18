# GitHub Action

`action.yml` at the repo root wraps `restoregap preflight` for a pull
request: it diffs `HEAD` against `diff-base`, evaluates it against your
declared guards, and writes the rendered verdict to the job summary. The
check fails the same way a local preflight gate does — a `block` verdict
(or `warn`, if you set `fail-on: warn`) exits non-zero.

It gates the diff, not the repo: files the PR never touches produce no
findings, same as running `preflight --diff` locally.

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: tannernicol/restoregap@v0.9.1
  with:
    diff-base: origin/${{ github.base_ref }}
```

It needs a context declared in the repo — `restoregap.yml` or
`restoregap.local.yml` at the root, or a path passed via `context` (one per
line for more than one file) — the same discovery `preflight`/`status` use
locally. With no context anywhere, the action still runs, but only the
built-in zero-config guards (SSH keys, recovery bundles) apply.

Inputs: `version` (release tag, default `latest`), `context` (optional path
list), `diff-base` (default `origin/${{ github.base_ref }}`), `fail-on`
(`block` or `warn`, default `block`).
