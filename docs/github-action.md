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
- uses: tannernicol/restoregap@v0.12.1
  with:
    version: v0.12.1
    diff-base: origin/${{ github.base_ref }}
```

Declare guards in a context file — `restoregap.yml` or
`restoregap.local.yml` at the root, or a path passed via `context` (one per
line for more than one file) — for this check to evaluate the repository's
recovery requirements. Without a discovered context, preflight can still pass
with no findings; that result does not establish recovery coverage for the
repository.

Inputs: `version` (release tag, default `latest`), `context` (optional path
list), `diff-base` (default `origin/${{ github.base_ref }}`), `fail-on`
(`block` or `warn`, default `block`).

This action evaluates the pull request diff against the guards you declare. It
does not intercept other commands, provide an operating-system sandbox, or
replace the repository's own permissions and CI controls.
