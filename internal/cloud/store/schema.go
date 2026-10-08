// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package store

// migrations[i] upgrades schema version i to i+1. Never edit a shipped entry;
// append a new one.
var migrations = []string{
	// v1
	`
CREATE TABLE workspaces (
	id                     TEXT PRIMARY KEY,
	name                   TEXT NOT NULL,
	plan                   TEXT NOT NULL CHECK (plan IN ('solo','team','fleet','unlimited')),
	billing_status         TEXT NOT NULL CHECK (billing_status IN ('trialing','active','past_due','canceled','unlimited')),
	stripe_customer_id     TEXT NOT NULL DEFAULT '',
	stripe_subscription_id TEXT NOT NULL DEFAULT '',
	trial_ends_at          TEXT,
	notify_email           TEXT NOT NULL DEFAULT '',
	notify_webhook_url     TEXT NOT NULL DEFAULT '',
	notify_webhook_secret  TEXT NOT NULL DEFAULT '',
	created_at             TEXT NOT NULL
);
CREATE UNIQUE INDEX workspaces_stripe_customer
	ON workspaces (stripe_customer_id) WHERE stripe_customer_id <> '';

CREATE TABLE users (
	id         TEXT PRIMARY KEY,
	email      TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL
);

CREATE TABLE memberships (
	workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
	user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	role         TEXT NOT NULL CHECK (role IN ('owner','member')),
	PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX memberships_user ON memberships (user_id);

CREATE TABLE api_tokens (
	id           TEXT PRIMARY KEY,
	workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
	name         TEXT NOT NULL,
	prefix       TEXT NOT NULL,
	token_hash   TEXT NOT NULL UNIQUE,
	created_at   TEXT NOT NULL,
	last_used_at TEXT,
	revoked_at   TEXT
);
CREATE INDEX api_tokens_workspace ON api_tokens (workspace_id);

CREATE TABLE hosts (
	id               TEXT PRIMARY KEY,
	workspace_id     TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
	host_id          TEXT NOT NULL,
	name             TEXT NOT NULL,
	epoch            TEXT NOT NULL DEFAULT '',
	public_key_hex   TEXT NOT NULL,
	expected_every_ns INTEGER NOT NULL DEFAULT 0,
	first_seen_at    TEXT NOT NULL,
	last_seen_at     TEXT NOT NULL,
	lapsed_at        TEXT,
	UNIQUE (workspace_id, host_id)
);

CREATE TABLE bundles (
	id              TEXT PRIMARY KEY,
	workspace_id    TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
	host_row_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
	generated_at    TEXT NOT NULL,
	received_at     TEXT NOT NULL,
	epoch           TEXT NOT NULL DEFAULT '',
	policy_revision TEXT NOT NULL DEFAULT '',
	public_key_hex  TEXT NOT NULL,
	signature_hex   TEXT NOT NULL,
	guards          INTEGER NOT NULL DEFAULT 0,
	proofs          INTEGER NOT NULL DEFAULT 0,
	ledger_entries  INTEGER NOT NULL DEFAULT 0,
	size_bytes      INTEGER NOT NULL DEFAULT 0,
	sha256          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX bundles_host_time ON bundles (workspace_id, host_row_id, generated_at DESC);

CREATE TABLE proof_rows (
	bundle_id    TEXT NOT NULL REFERENCES bundles(id) ON DELETE CASCADE,
	workspace_id TEXT NOT NULL,
	host_row_id  TEXT NOT NULL,
	proof        TEXT NOT NULL,
	layer        TEXT NOT NULL DEFAULT '',
	category     TEXT NOT NULL DEFAULT '',
	state        TEXT NOT NULL DEFAULT '',
	level        TEXT NOT NULL DEFAULT '',
	why          TEXT NOT NULL DEFAULT '',
	host         TEXT NOT NULL DEFAULT '',
	epoch        TEXT NOT NULL DEFAULT '',
	environment  TEXT NOT NULL DEFAULT '',
	system       TEXT NOT NULL DEFAULT '',
	artifact     TEXT NOT NULL DEFAULT '',
	generated_at TEXT NOT NULL,
	PRIMARY KEY (bundle_id, proof)
);
CREATE INDEX proof_rows_history ON proof_rows (workspace_id, host_row_id, proof, generated_at DESC);

CREATE TABLE alerts (
	id             TEXT PRIMARY KEY,
	workspace_id   TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
	host_row_id    TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
	kind           TEXT NOT NULL CHECK (kind IN ('lapsed','recovered','proof_regressed')),
	message        TEXT NOT NULL,
	created_at     TEXT NOT NULL,
	delivered_at   TEXT,
	delivery_error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX alerts_workspace ON alerts (workspace_id, created_at DESC);
CREATE INDEX alerts_undelivered ON alerts (created_at) WHERE delivered_at IS NULL;

CREATE TABLE share_links (
	id           TEXT PRIMARY KEY,
	workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
	token_hash   TEXT NOT NULL UNIQUE,
	scope        TEXT NOT NULL,
	created_at   TEXT NOT NULL,
	expires_at   TEXT,
	revoked_at   TEXT
);
CREATE INDEX share_links_workspace ON share_links (workspace_id);

CREATE TABLE login_tokens (
	token_hash TEXT PRIMARY KEY,
	email      TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	used_at    TEXT
);

CREATE TABLE sessions (
	id           TEXT PRIMARY KEY,
	token_hash   TEXT NOT NULL UNIQUE,
	user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
	created_at   TEXT NOT NULL,
	expires_at   TEXT NOT NULL
);
`,
}
