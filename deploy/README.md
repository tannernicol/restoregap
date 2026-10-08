# Deploying Restore Gap Cloud

Everything the service needs is one static binary, one directory, and a
TLS-terminating proxy in front of it. This page is the operator's runbook for
the operated service at `cloud.restoregap.com`; a self-hoster can follow the
same steps on their own hostname.

## 1. Pick a host

Any Linux box with a persistent disk works. The service is a single process
with SQLite; it does not need a managed database, a queue, or more than one
instance. Do not host the operated service on a home network: a paying
customer's bundles should not depend on a residential connection or a box
that also runs a media server.

A 1 vCPU / 1 GB VPS with a 20 GB disk is enough for the first hundred hosts.
Bundles are kilobytes to low megabytes each; retention × hosts × cadence is
the disk budget (Team plan: 25 hosts × 365 days × 1 bundle/day × ~100 KB ≈
1 GB).

## 2. Build or pull

From a checkout at the release tag:

```sh
docker build -t restoregap-cloud:v0.12.0 --build-arg VERSION=v0.12.0 .
```

or without Docker:

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/tannernicol/restoregap/internal/cli.Version=v0.12.0" -o /usr/local/bin/restoregap-cloud ./cmd/restoregap-cloud
```

## 3. Configure

Copy `deploy/cloud.env.example` to `/etc/restoregap-cloud.env` (mode 0600,
owned by root) and fill in:

| Variable | Operated service value |
|---|---|
| `RESTOREGAP_CLOUD_BASE_URL` | `https://cloud.restoregap.com` |
| `RESTOREGAP_CLOUD_DATA` | `/var/lib/restoregap-cloud` |
| `RESTOREGAP_CLOUD_SMTP_URL` | a transactional provider's SMTP URL, from address `cloud@restoregap.com` |
| `RESTOREGAP_CLOUD_STRIPE_SECRET` | the live secret key |
| `RESTOREGAP_CLOUD_STRIPE_WEBHOOK_SECRET` | from the webhook endpoint created in step 5 |
| `RESTOREGAP_CLOUD_PRICE_SOLO/TEAM/FLEET` | the three recurring price ids |

Leave `RESTOREGAP_CLOUD_ALLOW_SIGNUP` unset (open) for early access.

## 4. Run it as a service

`deploy/restoregap-cloud.service` is a hardened systemd unit (dynamic user,
private tmp, read-only root, state directory). Install, enable and start it:

```sh
install -m 0644 deploy/restoregap-cloud.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now restoregap-cloud
journalctl -u restoregap-cloud -f
```

Put Caddy or nginx in front with a certificate for the hostname, proxying to
`127.0.0.1:8080`. With Caddy the whole config is:

```
cloud.restoregap.com {
    reverse_proxy 127.0.0.1:8080
}
```

Point the `cloud` DNS record at the box (Cloudflare proxied is fine; the
service reads no client IPs for decisions).

## 5. Stripe

In the Stripe dashboard, in live mode:

1. Create one product "Restore Gap Cloud" with three recurring monthly
   prices: Solo $19, Team $79, Fleet $249. Copy the three `price_…` ids.
2. Add a webhook endpoint `https://cloud.restoregap.com/webhooks/stripe`
   subscribed to `checkout.session.completed`,
   `customer.subscription.created`, `customer.subscription.updated`,
   `customer.subscription.deleted`. Copy its signing secret.
3. Enable the customer portal with "cancel subscription" and "update payment
   method" allowed.
4. Restart the service after filling the env file. `journalctl` shows
   `billing=true` on the listening line.

Test with a 100%-off promotion code before announcing; `allow_promotion_codes`
is on in Checkout.

## 6. Back it up and drill it

The state is `/var/lib/restoregap-cloud/cloud.db` (plus `-wal`) and
`bundles/`. Snapshot the directory daily with the host's tooling, and declare
a Restore Gap drill for it: the obvious dogfood is a `restoregap.yml` with a
sqlite check against the restored `cloud.db` and a `bundle push` of its own
proof into a workspace on the same service.

## 7. Day-2

- Logs are stdout, JSON-free key=value lines; `level=ERROR` is worth a look.
- `restoregap-cloud admin workspace list` on the box shows every workspace,
  plan, status and host count.
- Upgrades: replace the binary, restart. Schema migrations run on start and
  are forward-only; keep the backup from step 6 before the first start of a
  new version.
- Retention pruning and alert delivery run inside the process every
  `--monitor-every` (default 1m); nothing else is scheduled.

## The early-access instance (maintainer notes)

cloud.restoregap.com currently runs on the NAS as two containers on a
dedicated Docker network, `restoregap-cloud` (the static binary bind-mounted
into `gcr.io/distroless/static-debian12:nonroot`, data under
`Container/restoregap-cloud/data`, signup closed, billing off) and
`restoregap-cloud-tunnel` (`cloudflare/cloudflared` with the token stored in
`pass cloudflare/restoregap-cloud-tunnel-token`). The Cloudflare tunnel is
named `restoregap-cloud` and is separate from the homelab tunnel; the DNS
record is a proxied CNAME `cloud` → `<tunnel-id>.cfargotunnel.com`.

Create a workspace for someone: `docker exec restoregap-cloud /restoregap-cloud
admin workspace create --email them@example.com` prints a single-use sign-in
link valid 24 hours. Tear it all down: remove the two containers and the
network, delete the DNS record and the tunnel in Cloudflare, remove the
`Container/restoregap-cloud` directory.
