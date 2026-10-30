# Hand over recovery evidence

Use a signed summary to answer a narrow question: **What recovery evidence did
this operator record, as of this time, under this policy?** It is useful input
to an engineering, compliance or insurance review. It is not a certification,
coverage decision or promise that every change can be undone.

## Produce the summary

First run the declared drill and record a preflight decision using your normal
context and ledger. Export explicitly; nothing is uploaded:

```sh
restoregap bundle export --summary-only \
  --context restoregap.yml --ledger ledger.jsonl \
  --signing-key "$RESTOREGAP_SIGNING_SEED" \
  --out recovery-summary.json
```

The signing seed is an Ed25519 seed encoded as hex, the same format used by
`drill --signing-key`. Keep it outside an untrusted agent's writable scope.
`--label` optionally adds an operator-supplied label; its text is included in
the handoff. `--env`, `--system` and `--host` select proofs using their declared
scope. `--as-of` chooses the evidence evaluation time. An export records both
that time and its generation time. These declarations are not independently
discovered facts. `--since` applies only to full archives, not summaries.

The signed scope says whether all proofs or a filtered subset was selected.
Selected environment/system/host values are represented by SHA-256 digests,
so the handoff does not expose their names. Give the reviewer the scope mapping
through an appropriate separate channel when those names matter.

The summary contains opaque proof identifiers, outcome and assurance enums,
observation/expiry times, recipe/dependency digests, finite measurements,
check types/results, policy digest and ledger chain counts/tail. It excludes
raw context, resource paths, commands, URLs, actors and free-form check output.
Digests are identifiers, not encryption; do not use them to conceal low-entropy
secrets. Missing or broken requested ledgers cause export to fail. The output
is a new private file; an existing destination is never overwritten.

## Verify independently

Get the public key through a channel you already trust, separately from the
file. On another machine, with no access to the original system:

```sh
restoregap bundle verify recovery-summary.json \
  --expected-key "$TRUSTED_RESTOREGAP_PUBLIC_KEY"
```

The command validates the schema and bounds, rejects altered content, unknown
or duplicate fields, and checks that the signature matches that expected key.
Exit zero establishes integrity and the expected signer. It does not establish
that the signer recorded truthful inputs or that the recovery will work later.

Read three things separately:

| Question | Evidence |
|---|---|
| What was tested? | Recorded method, checks and measurements; scope is limited to supplied declarations. |
| Is that evidence current for this recipe? | Outcome as of the stated time, expiry, recipe/dependency binding and assurance version. |
| Who stands behind this handoff? | Summary signature verified against the independently trusted public key. |

Legacy unbound proofs remain identifiable. Signing a summary does not upgrade
the assurance of its underlying evidence. An anchored ledger explicitly retains
the count of owner-acknowledged historical anomalies. The summary includes fixed
signed limitations; retain them with the record.

## When you need the detailed record

`restoregap ledger show --format json` reads the local proposal, findings,
evidence explanations and next steps. A decision records evaluation;
Restore Gap did not execute the proposed change.

The existing `bundle export` without `--summary-only` creates a full tar.gz
archive containing raw context and a ledger slice. Treat that archive as private
operational data. `bundle verify archive.tgz --expected-key "$TRUSTED_RESTOREGAP_PUBLIC_KEY"`
adds expected-signer checking; omitting the key checks the archive's internal
integrity against its embedded key only. `bundle inspect` displays content
without verifying it. Neither form performs a network request.
