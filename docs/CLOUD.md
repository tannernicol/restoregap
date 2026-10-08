# Restore Gap Cloud — the operated layer

Restore Gap Cloud is the hosted half of Restore Gap: a small service that
receives the signed bundles your hosts already export, keeps them, and
answers the three questions one binary structurally cannot answer on its own:

1. **Time.** How has each proof's state moved over weeks and months, host by
   host? Which proofs regressed since the last bundle?
2. **Breadth.** What does the whole estate look like right now, merged, without
   anyone running `bundle merge` by hand?
3. **Absence.** Which host stopped sending? A proof that silently stops
   arriving is a gap nobody is looking at.

Plus one thing a laptop cannot do credibly: a **share link** a third party
(an auditor, a customer's security reviewer, a board member) can open to see
the current recovery record and verify its signatures without shelling into
any of your machines.

The local tool stays free, MIT, offline and complete. Cloud never unlocks a
recovery check you need; it operates the retention, monitoring and sharing
around the checks you already run. Cloud's own source is in this repository
under the same MIT license, so you can run it yourself.

## What leaves your host, and what never does

The only thing Cloud ever sees is a bundle you pushed. A bundle
(`docs/SCHEMA.md` §6) carries the context files in force, a `--since`-bounded
ledger slice, and proof-evidence **metadata** (path, size, hash) — never an
evidence file's bytes and never a path under a secret store. Cloud has no
agent, no credentials to your machines, and no way to request more than a
bundle contains.

The binary never pushes on its own initiative. `restoregap bundle push` is an
explicit command you put in a cron line, a timer or a CI step; nothing else
in the binary opens a network connection to Cloud.

## Signing in

Sign-in is by emailed link, valid for 15 minutes and usable once. Opening the
link shows a page with one **Sign in** button; pressing it starts the session.
(Fetching the link alone, as mail scanners and link previewers do, does not use
it up.) With no SMTP relay configured the link is written to the log instead
(dev mode), and `restoregap-cloud admin workspace create` prints one.

## Push a bundle

```sh
restoregap bundle push \
  --to https://cloud.restoregap.com \
  --token "$RESTOREGAP_PUSH_TOKEN" \
  --context restoregap.yml --ledger ledger.jsonl \
  --signing-key "$RESTOREGAP_SIGNING_SEED" --since 168h
```

`push` builds the same signed archive `bundle export` builds (same `--context`,
`--ledger`, `--signing-key`, `--since`, `--env`, `--system`, `--host`; `--summary-only`
is not supported), sends it, and prints the host, host id, generation time and
dashboard URL the service answered with. Pass an existing archive instead of
export flags: `bundle push --to … --token … host.tgz`.

- `--to` is the service's base URL and must be `https://`. Plain `http://` is
  accepted only for `localhost`, `127.0.0.1` and `::1`, or with `--insecure-http`.
- The token comes from `--token` or `RESTOREGAP_PUSH_TOKEN` (prefer the
  environment variable; flags show up in the process list). It is sent only as
  a bearer header and is never printed.
- One request, 30 second timeout, no retries, redirects are not followed.
- Exit 0 on acceptance (`pushed: …`, HTTP 201) and when the service already
  holds that exact archive (`already stored: …`, HTTP 200); 1 when the service
  refused the bundle (the reason is printed); 2 on a usage error, a network
  error or any other response.

`bundle push` only runs when you invoke it. No other command contacts Cloud and
nothing runs in the background; schedule it yourself if you want it recurring.

Tokens are per workspace, created and revoked in **Settings → Tokens**. A
token can push; it cannot read, delete or change anything.

## Trust on first use

The first bundle from a host pins that host's signing public key to its
host id. A later bundle for the same host id signed with a different key is
refused with `409 key mismatch` until an owner rotates the pinned key in the
host's settings. Every stored bundle keeps its original signature, so a
reviewer can re-verify any bundle with `restoregap bundle verify
--expected-key`.

## Monitoring

Each host has an **expected cadence** (default: none). When a host with a
cadence has not sent a bundle for 1.5× that interval, Cloud records a
`lapsed` alert and notifies the workspace's email and webhook; the next
bundle records `recovered`. Between consecutive bundles from one host, a
proof whose state moved from healthy (`restored`, `observed`, `accepted`) to
anything else records a `proof_regressed` alert: `expired` (stale evidence),
`unreachable` (missing), `disputed` (failed or contradicted), `lapsed` or
`unreviewed`. A bundle that regresses many proofs at once raises the first 25
alerts and one roll-up alert.

Alerts are facts about bundles arriving or not, and about declared proof
state. They are not uptime monitoring and not a claim about the host.

## Share links

A share link is a random, revocable URL that renders the current fleet view
(or one host) read-only, with each contributing bundle's host, generation
time, signing public key and signature so the reader can verify it
independently. It never exposes raw context files or the ledger slice. Links
can carry an expiry.

A reader can download each contributing bundle's signed `manifest.json` and
`manifest.sig`, and nothing else from the archive. That manifest carries the
signed metadata every bundle manifest holds: the host name, the names of the
context files, and the path and size of each piece of proof evidence. It never
carries context file contents or the ledger slice. Because those paths and
names are visible to anyone with the link, do not give a share link to someone
who must not see them.

## Plans

Early access is free: one workspace per person, no host limit, no payment
method, no time limit. The point of early access is feedback on whether
retention, monitoring and share links are worth operating at all, and for
whom. If a paid tier is ever introduced, existing early-access workspaces
get at least 30 days' notice and a way to export everything first.

The service carries dormant Stripe support (a three-plan table keyed by hosts
and retention) so that a paid tier would not need a rewrite. It is inert
unless the operator sets the Stripe variables below; the operated service
does not set them.

## API

`POST /api/v1/bundles` — `Authorization: Bearer <token>`, body is the
`.tgz` (`Content-Type: application/gzip`, 8 MiB limit). Responses:

| Status | Body |
|---|---|
| 201 | `{"bundle_id","host","host_id","generated_at","url"}` |
| 200 | the same body, for an archive this host already pushed (nothing changes) |
| 401 | `{"error":"unknown or revoked token"}` |
| 402 | `{"error":"workspace is not active"}` — only possible when billing is enabled |
| 409 | `{"error":"key mismatch …"}` or `{"error":"host limit reached …"}` |
| 413 | `{"error":"bundle too large"}` |
| 422 | `{"error":"bundle failed verification: …"}` |

`GET /api/v1/fleet.json` — same token, returns the merged latest-per-host
fleet in the `fleet.json` shape `bundle merge` writes.

## Run it yourself

```sh
go build -o restoregap-cloud ./cmd/restoregap-cloud
RESTOREGAP_CLOUD_DATA=/var/lib/restoregap-cloud \
RESTOREGAP_CLOUD_BASE_URL=https://cloud.example.com \
./restoregap-cloud serve --listen 127.0.0.1:8080
```

Put a TLS-terminating proxy in front. State is one SQLite database plus the
bundle archives under the data directory; back them up like anything else
(and drill the restore — `examples/` has a SQLite drill).

Configuration is environment only:

| Variable | Meaning |
|---|---|
| `RESTOREGAP_CLOUD_DATA` | data directory (default `./data`) |
| `RESTOREGAP_CLOUD_BASE_URL` | public URL, used in emails and share links |
| `RESTOREGAP_CLOUD_SMTP_URL` | `smtp://user:pass@host:587?from=cloud@example.com`; unset logs magic links to stdout |
| `RESTOREGAP_CLOUD_STRIPE_SECRET` | Stripe secret key; unset (the default, and early access) disables billing |
| `RESTOREGAP_CLOUD_STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret; required when the Stripe secret is set |
| `RESTOREGAP_CLOUD_PRICE_SOLO` / `_TEAM` / `_FLEET` | Stripe price ids |
| `RESTOREGAP_CLOUD_ALLOW_SIGNUP` | `false` to refuse new workspaces |

`serve` also takes `--monitor-every` (default `1m`): how often the monitor
checks for lapsed hosts, delivers alerts and enforces retention. Logs go to
stdout.

`restoregap-cloud admin …` manages workspaces from the shell on the host
(create, list, set plan) for self-hosters without Stripe:

```sh
restoregap-cloud admin workspace create --email you@example.com   # prints a sign-in link
restoregap-cloud admin workspace list
restoregap-cloud admin workspace set-plan <workspace-id> solo
restoregap-cloud admin token create <workspace-id> --name web-1   # prints the token once
```

## Terms, privacy, hosting

The operated service runs under the [terms](https://restoregap.com/terms.html)
and [privacy policy](https://restoregap.com/privacy.html) on restoregap.com.
Hosting provider for the operated service: not yet chosen (early access);
this line is updated when it is. Early access is free; see Plans.

## What it is not

- Not uptime monitoring, not a backup product, not a storage target for
  evidence files, and not a certification.
- Not a daemon on your hosts: you push, it listens.
- Not required: everything in `restoregap` works with Cloud absent.
