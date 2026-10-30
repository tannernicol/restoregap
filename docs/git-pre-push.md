# Gate outgoing Git refs with RestoreGap

`scripts/git-pre-push-restoregap.py` adapts Git's provider-neutral `pre-push`
hook input to the existing RestoreGap preflight CLI. It reads every ref update
from standard input and checks both the ref operation and the resulting tree
change before Git sends the update.

The adapter does not contact the remote or execute a push. It uses the local
object IDs supplied by Git. Its policy context and policy directories must be
explicitly configured outside the repository whose refs are being pushed, so
the outgoing refs cannot rewrite the rules used to evaluate them. Branch
creation compares the empty tree with the published tip; branch update
compares the remote tip with the outgoing tip; branch deletion compares the
old tip with the empty tree. Non-fast-forward branch updates are classified as
rewrites. Existing tag replacements are classified as rewrites too. Tags must
peel to a tree (including annotated tags); unsupported ref namespaces or
objects fail closed.

Changed paths come from Git's NUL-delimited name-status output, independent of
repository diff formatting settings. Adds, modifications, type changes and
deletions are sent as grouped path intents; parseable text patches are also
checked as supplementary content intents. Gitlink changes are included even
when repository configuration asks Git to ignore submodules.

## Add it to an existing hook

First inspect the repository's existing hook path:

```sh
git config --show-origin --get core.hooksPath || true
```

Add the adapter call to that repository's existing `pre-push` hook, keeping
its current path and behavior. If the existing hook also reads standard input,
capture it once in a private temporary file and replay the same bytes to each
hook. For example, inside the existing hook:

```sh
set -eu
umask 077
input="$(mktemp "${TMPDIR:-/tmp}/restoregap-pre-push.XXXXXX")"
trap 'rm -f "$input"' EXIT HUP INT TERM
cat > "$input"

# Keep the existing hook here, if it has one, and feed it the captured input:
# /path/to/existing-pre-push "$@" < "$input"

python3 /opt/restoregap/scripts/git-pre-push-restoregap.py "$@" < "$input"
```

Use the script's installed absolute path in place of the example. Do not
replace an existing `core.hooksPath` setting or discard a hook already at that
path. The adapter itself does not install or alter Git hooks.

## Declare the policy

The adapter always requests strict resource coverage and treats warnings as a
stop. Every ref operation must match a `commands` guard, and every changed path
must match a path guard. The normalized command forms are:

```text
git push create refs/heads/<ref>
git push update refs/heads/<ref>
git push rewrite refs/heads/<ref>
git push delete refs/heads/<ref>
git push create refs/tags/<ref>
git push rewrite refs/tags/<ref>
git push delete refs/tags/<ref>
```

An example policy has separate path and command guards so both kinds of
resource are covered. Replace the repo path and proof ID with the real values:

```yaml
version: 2
guards:
  - id: repo-recovery
    kind: lifeline
    match:
      paths:
        - /srv/project
        - /srv/project/**
    requires:
      proofs: [repo-recovery]
    require_verified: true
    require_bound: true
  - id: outgoing-refs
    kind: guard
    match:
      commands:
        - "git push create refs/heads/*"
        - "git push update refs/heads/*"
        - "git push rewrite refs/heads/*"
        - "git push delete refs/heads/*"
        - "git push create refs/tags/*"
        - "git push rewrite refs/tags/*"
        - "git push delete refs/tags/*"
    requires:
      proofs: [repo-recovery]
    require_verified: true
    require_bound: true
```

Declare the corresponding `drills` entry and run `restoregap drill --context
<context-file>` to produce the verified, recipe-bound proof. Set an explicit
external path (or colon-separated list) in `RESTOREGAP_CONTEXT` in the hook's
environment; any `RESTOREGAP_POLICY_DIRS` entries must also be outside the
repository. Missing or unreadable policy, uncovered paths or commands, stale
or unbound proof, malformed hook input, missing executables, unresolved Git
objects, and failed preflight all stop the push. The policy can match multiple
ref components because command globs treat `/` as an ordinary character.

The adapter runs locally and offline. It never sends ref names, repository
contents, policy or proof data to a hosting service. Git's remote URL argument
is not used or logged. Optional hosted retention is not required or used as a
feature gate.

## Verify

`make hook-test` exercises the adapter against real temporary Git repositories
and the built RestoreGap binary, including branch create/update/rewrite/delete,
annotated tag creation and replacement, proof-backed pass and block, malformed
input, missing binary, hostile ref text, unusual binary filenames, symlinks,
mode/type changes, gitlinks and hostile diff configuration. The test writes
only under a temporary directory.
