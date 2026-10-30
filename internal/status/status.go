// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package status summarizes the recovery chain: declared guards, proof
// freshness, and ledger health — the "am I still recoverable?" view.
package status

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/hostid"
	"github.com/tannernicol/restoregap/internal/ledger"
	"github.com/tannernicol/restoregap/internal/policy"
	"github.com/tannernicol/restoregap/internal/report"
)

// Request mirrors the status CLI flags. ContextPaths is repeatable: real
// deployments keep one context file per drill (its proof-writing timer
// rewrites that file, so co-mingling several drills in one file fights the
// timer that owns it) — status needs to see all of them to show the whole
// machine in one view. Zero paths means the built-in default policy, same
// as today.
type Request struct {
	ContextPaths []string
	LedgerPath   string
	Format       string // text | html
	AsOf         string
}

// ProofState is one proof's freshness line.
type ProofState struct {
	ID     string
	Status string
	Detail string
}

// Summary is the gathered status.
type Summary struct {
	Verdict string // pass | warn | block posture
	Origin  string
	// GeneratedAt is the evaluation time Gather ran at (req.AsOf when given,
	// else time.Now().UTC()) — printed as the HTML dashboard's "generated
	// at" timestamp so a fixed --as-of run reproduces byte-identical output.
	GeneratedAt  time.Time
	Lifelines    int
	Guards       int
	Proofs       []ProofState
	ExpiringSoon int
	// Restored counts proofs whose contextspec.LevelOf reaches at least
	// LevelRestores (restores/data-valid/serves) — provably restorable.
	// The remaining LevelDeclared proofs split three ways: Observed (both
	// observed_at and expires_at declared, still inside that observation's
	// own TTL window — actively kept fresh, not a gap), Accepted (an owner
	// acceptance is recorded AND its review_by is still in the future), and
	// Unreviewed (everything else at declared: no expiry declared, an
	// expiry that fell out of its own TTL window, never observed, or an
	// attention-state record — including a lapsed acceptance, which is
	// just a gap that learned to hide). Restored+Observed+Accepted+
	// Unreviewed always equals len(Proofs).
	Restored      int
	Observed      int
	Accepted      int
	Unreviewed    int
	LedgerEntries int
	LedgerOK      bool
	LedgerDetail  string
	LastDecision  string
	// PolicyFindings are ignored guard-loosening attempts from the layered
	// policy merge (docs/SCHEMA.md §Layered policy) — a later (host) layer
	// tried to weaken or drop an earlier (org) layer's guard. The attempt
	// never took effect; these exist so it is never silent. Each entry is
	// already the rendered "policy/loosened <id> in <file>" line.
	PolicyFindings []string
	// NextExpiryID/NextExpiryAt are the soonest future proof expiry — the
	// "Green. Next expiry: …" line the HTML dashboard's to-green panel
	// shows when there is nothing left to do. Zero values when no proof
	// declares a future expiry.
	NextExpiryID string
	NextExpiryAt time.Time
	// ActiveOverrides are the owner exceptions still masking a finding. Every
	// new override has an explicit expiry; LegacyNoExpiry marks the bounded
	// 30-day read-migration path for entries written by older binaries.
	ActiveOverrides []ledger.OverrideState
	// DecisionHistory keeps gate execution failures separate from policy
	// blocks. Both make a caller stop, but only a block says a check ran and
	// found a recovery gap.
	GateBroken []DecisionSummary
	Blocked    []DecisionSummary
	Last       *DecisionSummary
	// Inventory is one row per declared drill, plus one row per proof that
	// has no matching drill (an attestation — evidence ingested, never
	// drilled), sorted weakest recovery level first — the gaps are the
	// headline, not the wins.
	Inventory []InventoryRow
	// InventorySummary is the "N of M provably restorable" line printed
	// under the table. Empty when Inventory is empty.
	InventorySummary string
	// Context is the merged (or built-in default) context Gather evaluated
	// against — carried so the taxonomy tree (BuildLayerTree, Classify) and
	// scope-based filtering/roll-ups can be computed from a Summary alone,
	// without re-loading or re-merging context files.
	Context contextspec.Context
	// DiscoverLine is the one-line coverage summary shown under the
	// headline, read from discover's latest on-disk snapshot (never
	// computed by running a scan here — status stays fast and
	// side-effect-free). Always non-empty: either a real coverage line or
	// the "not scanned" line when no fresh snapshot exists. Kept alongside
	// Discover (below) for the plain-text renderer's one-liner; Discover
	// carries the richer view the HTML page's coverage block needs.
	DiscoverLine string
	// Discover is status's whole view of discover's on-disk snapshot —
	// state (fresh/stale/absent), the top uncovered candidates by
	// consequence, and the shared remediation prompt — gathered once here
	// (gatherDiscoverCoverage) so DiscoverLine and the HTML page can never
	// disagree about what was found.
	Discover DiscoverCoverage
}

// DecisionSummary is the report-first view of one ledger decision. It keeps
// the durable version/duration/check metadata beside the verdict instead of
// reducing a failed gate to the indistinguishable word "block".
type DecisionSummary struct {
	EntryID      string
	When         time.Time
	EvaluatedAt  *time.Time
	Actor        string
	Verdict      string
	GateState    string
	BrokenReason string
	Operation    string
	Executed     *bool
	Intents      []ledger.IntentRecord
	Findings     []ledger.FindingRecord
	Legacy       bool
	DurationMS   int64
	ToolVersion  string
	Checks       []ledger.DecisionCheckRecord
	// PolicyRevision/HostName/HostID/Epoch are the portability stamps the
	// decision entry recorded (docs/SCHEMA.md): which policy text was in
	// force and on which machine/install the verdict was made. Empty for
	// entries written before stamping existed.
	PolicyRevision string
	HostName       string
	HostID         string
	Epoch          string
}

// InventoryRow is one declared drill's earned recovery level
// (contextspec.RecoveryLevel — the ONE derivation this is read from, never
// re-computed here) plus what it measured. RPO/RTO/ProofAge are pre-
// formatted display strings ("—" when absent) so both renderers (text
// table, HTML section) print identically.
type InventoryRow struct {
	Level    string
	Proof    string
	RPO      string
	RTO      string
	ProofAge string
	// IsDrilled is true when this row came from a declared drill (the
	// buildInventory drill loop), false when it is an attestation-only
	// proof with no matching drill at all. The HTML dashboard uses this to
	// tell "never even tried" from "tried and hasn't proven yet" — the text
	// renderer never reads it.
	IsDrilled bool
	// LevelRank is contextspec.RecoveryLevel.Rung() for Level — the raw
	// 1-4 rung, kept alongside the display string so the HTML dashboard can
	// pick a badge color class by number instead of string-matching Level.
	LevelRank int
	// History is this proof's last drill runs from the ledger (oldest to
	// newest, capped at maxHistoryTicks, pin_check entries excluded) — the
	// HTML dashboard's heartbeat tick strip and RTO sparkline. Empty when no
	// ledger path was given or no matching drill entries exist; the text
	// renderer never reads it.
	History []RunTick

	// The fields below feed the HTML dashboard's expandable row detail card
	// only — the text renderer never reads any of them.

	// SourceFile is the context file this drill was declared in (empty for
	// an attestation-only row, or the built-in zero-config default, which
	// never declares drills) — the "next step" command's --context value.
	SourceFile string
	// RecoverCmd, RecoverySource, PinCheckCmd, BudgetRTO, and BudgetRPO are
	// the drill's own declaration (contextspec.Drill), not what it last
	// measured — set for IsDrilled rows regardless of current proof
	// validity, since "what would run" is relevant even for a row that
	// never got a proof or whose last run failed. BudgetRTO/BudgetRPO are
	// emDash when that budget was not declared.
	RecoverCmd     string
	RecoverySource string
	PinCheckCmd    string
	BudgetRTO      string
	BudgetRPO      string
	// Checks is the last verified run's per-check breakdown, in declared
	// order. Populated only when the row is currently good (same rule as
	// RPO/RTO) — a check outcome from before the proof expired would be
	// exactly the stale-measurement false confidence LevelOf's reason
	// collapse exists to prevent.
	Checks []CheckResult

	// Evidence — populated whenever a proof record exists, regardless of
	// current validity (an expired proof's observed_at/signature are still
	// facts about what was recorded).
	ObservedAtDisplay string // RFC3339, emDash when absent
	ExpiresAtDisplay  string // RFC3339, emDash when absent
	ExpiresInDisplay  string // "expires in Nd" / "expired Nd ago", emDash when no expiry
	// IsObserved is isObservedProof's verdict for this proof — both
	// observed_at and expires_at declared, and now still inside the
	// freshness window (freshnessWindow: max(48h, TTL/7)) that timestamp
	// pair earns. status.classifyProofState reads this directly rather
	// than re-deriving it from the display strings or raw timestamps, so
	// the taxonomy's "observed" state and the headline's Observed count
	// (Summary.Observed, via partitionCounts) never disagree.
	IsObserved       bool
	SignaturePresent bool
	SigPubKeyPrefix  string // first 8 hex chars of the Ed25519 public key, "" when unsigned
	// Binding is the recovery recipe assurance label: bound, unbound legacy
	// evidence, or invalid when only part of a binding was recorded.
	Binding string
	// PreviousEpoch is true when the proof's recorded epoch differs from
	// this machine's current one (see previousEpoch) — evidence from a
	// different world: it carries the unreviewed state with the "from a
	// previous epoch — re-drill" reason and is excluded from green no
	// matter what it claims to have verified.
	PreviousEpoch bool

	// Acceptance — populated from the proof's accepted: block when one is
	// recorded. AcceptedReason is set only while the acceptance is still
	// active (review_by in the future); AcceptanceLapsedOn is set instead
	// once it has passed, so renderers and the next-steps ladder can tell
	// "deliberately carried" from "acceptance that expired into a gap"
	// without re-deriving dates.
	AcceptedReason   string // the recorded reason, "" when no active acceptance
	AcceptedBy       string // who accepted, "" when no active acceptance
	AcceptedReviewBy string // YYYY-MM-DD, "" when no active acceptance
	// AcceptanceLapsedOn is the review_by date (YYYY-MM-DD) of a recorded
	// acceptance whose window has passed — the proof counts as unreviewed
	// again, with the lapse visible. "" when nothing lapsed.
	AcceptanceLapsedOn string

	// The fields below are set only for attestation-only (!IsDrilled) rows.
	AttestCommand     string // the verifier command the attestation asserts, emDash when none
	AttestEvidenceURL string // emDash when none
	// ProposeArtifact is a best-effort artifact path for the "convert to a
	// real drill" hint, inferred from a guard that requires this proof and
	// names one concrete (non-glob) path. Empty when no such guard/path
	// exists — the dashboard falls back to a generic placeholder.
	ProposeArtifact string
}

// CheckResult is one drill validate: check's outcome, decoupled from
// contextspec.CheckOutcome so the HTML dashboard's row shape never depends
// directly on contextspec's internal type.
type CheckResult struct {
	Type   string
	Pass   bool
	Detail string
}

// RunTick is one ledger drill entry reduced to what the HTML dashboard's
// history tick strip and RTO sparkline need to draw one point.
type RunTick struct {
	When     time.Time
	Verified bool
	RTOMs    int64
}

// Gather builds the status summary. Posture: block if the ledger chain is
// broken; warn if any required proof is stale/expiring within 7 days or the
// context is the zero-config default; pass otherwise.
func Gather(req Request) (*Summary, error) {
	now, err := getEvalTime(req.AsOf)
	if err != nil {
		return nil, err
	}

	loaded, err := getContexts(req.ContextPaths)
	if err != nil {
		return nil, err
	}
	merged, policyFindings, err := loadMerged(req.ContextPaths)
	if err != nil {
		return nil, err
	}

	s := &Summary{Verdict: "pass", Origin: merged.Origin, GeneratedAt: now, LedgerOK: true}
	s.Lifelines, s.Guards = countLifelinesAndGuards(merged)

	if len(req.ContextPaths) == 0 {
		s.Verdict = "warn" // running on the built-in default: nothing is provable yet
	}
	for _, f := range policyFindings {
		s.PolicyFindings = append(s.PolicyFindings, f.String())
	}
	if len(s.PolicyFindings) > 0 {
		// A later policy layer tried to loosen or remove a guard an earlier
		// (org) layer declared — the attempt was ignored (docs/SCHEMA.md
		// §Layered policy), but it needs an owner's eyes, so it never sits
		// silently at "pass".
		s.Verdict = worst(s.Verdict, "warn")
	}

	epoch := hostid.Current().Epoch
	s.Proofs = getProofs(merged, now, epoch, &s.Verdict, &s.ExpiringSoon)
	s.Restored, s.Observed, s.Accepted, s.Unreviewed = partitionCounts(merged, now, epoch)
	if s.Unreviewed > 0 {
		// A proof nobody has drilled OR accepted is the one posture this
		// tool exists to surface: converge on it by drilling what can be
		// drilled and accepting, with a reason, what cannot.
		s.Verdict = worst(s.Verdict, "warn")
	}
	s.NextExpiryID, s.NextExpiryAt = nextExpiry(merged.Proofs, now)
	s.Inventory = buildInventory(merged, &sourceFiles{drills: drillSourceFiles(loaded), proofs: proofSourceFiles(loaded)}, now, epoch)
	s.InventorySummary = inventorySummaryLine(s.Inventory)
	s.Context = merged

	if req.LedgerPath != "" {
		if err := processLedger(req.LedgerPath, s, now); err != nil {
			return nil, err
		}
	}
	s.Discover = gatherDiscoverCoverage(now)
	s.DiscoverLine = s.Discover.Line

	return s, nil
}

func getEvalTime(asOf string) (time.Time, error) {
	now := time.Now().UTC()
	if asOf != "" {
		t, err := time.Parse(time.RFC3339, asOf)
		if err != nil {
			return now, fmt.Errorf("status: --as-of must be RFC3339: %w", err)
		}
		now = t.UTC()
	}
	return now, nil
}

// loadedContext pairs a parsed context with the path it came from (empty
// for the built-in default), so mergeContexts can name which file a
// duplicate id was last seen in.
type loadedContext struct {
	path string
	ctx  contextspec.Context
}

// getContexts loads every declared path in order. Zero paths is the
// zero-config default policy, exactly as a single empty ContextPath used to
// mean — that single-element result is what keeps the zero- and
// one-context paths byte-identical to pre-multi-context behavior.
func getContexts(paths []string) ([]loadedContext, error) {
	if len(paths) == 0 {
		return []loadedContext{{ctx: contextspec.Default()}}, nil
	}
	out := make([]loadedContext, 0, len(paths))
	for _, p := range paths {
		ctx, err := contextspec.Load(p)
		if err != nil {
			return nil, fmt.Errorf("status: %w", err)
		}
		out = append(out, loadedContext{path: p, ctx: ctx})
	}
	return out, nil
}

// loadMerged loads and merges every declared context path via policy.Merge
// — facts/proofs/drills merge by union exactly as contextspec.LoadAll always
// did (a duplicate id across files is an error naming both), but guards
// merge tighten-only by id (docs/SCHEMA.md §Layered policy): a file later in
// paths (the host tier of discovery.PolicyDirs, when in play) may add a
// guard or make an existing one stricter, never weaker — a weakening
// attempt is ignored and returned as a Finding rather than applied or
// erroring. Falls back to the built-in zero-config default when no paths
// are declared. getContexts's own per-path loop stays separate: it exists
// for drillSourceFiles's per-file provenance, which a merged Context
// deliberately does not carry.
func loadMerged(paths []string) (contextspec.Context, []policy.Finding, error) {
	if len(paths) == 0 {
		return contextspec.Default(), nil, nil
	}
	ctx, findings, err := policy.Merge(paths)
	if err != nil {
		return contextspec.Context{}, nil, fmt.Errorf("status: %w", err)
	}
	return ctx, findings, nil
}

// drillSourceFiles maps each declared drill's proof id to the context file
// path it came from (last-loaded wins on a duplicate id, mirroring
// mergeContexts's own rule for drills) — a separate read-only pass over the
// per-file loaded contexts, computed before they are merged into one
// contextspec.Context and that per-file provenance is lost. Empty string
// for the built-in zero-config default, which never declares drills.
func drillSourceFiles(loaded []loadedContext) map[string]string {
	sources := make(map[string]string)
	for _, lc := range loaded {
		for _, d := range lc.ctx.Drills {
			sources[d.Proof] = lc.path
		}
	}
	return sources
}

// proofSourceFiles maps each PROOF id to the context file path it came
// from (last-loaded wins on a duplicate id, mirroring drillSourceFiles's
// own rule) — an attestation-only proof has no drill to name a source
// file, so this is what fills its InventoryRow.SourceFile (and, via
// Classify, ProofClassification.ContextFile / the taxonomy/next/JSON
// context_file field) instead. Empty string for the built-in zero-config
// default, which never declares proofs.
func proofSourceFiles(loaded []loadedContext) map[string]string {
	sources := make(map[string]string)
	for _, lc := range loaded {
		for _, p := range lc.ctx.Proofs {
			sources[p.ID] = lc.path
		}
	}
	return sources
}

func countLifelinesAndGuards(ctx contextspec.Context) (int, int) {
	lifelines, guards := 0, 0
	for _, g := range ctx.Guards {
		if g.Kind == contextspec.GuardKindLifeline {
			lifelines++
		} else {
			guards++
		}
	}
	return lifelines, guards
}

// expiringSoonCutoff is when a proof starts counting as "expiring".
//
// This used to be a flat 7 days, which made the warning permanent for any
// proof with a shorter life than that: the context-control-plane proofs are
// re-attested on a timer with a 48h TTL, so they were ALWAYS "expiring soon"
// no matter how healthy the refresh was. A warning that cannot clear is a
// warning nobody reads, and it sat in the fixit queue for weeks doing exactly
// that.
//
// "Soon" is now relative to the proof's OWN lifetime: it means "this has used
// up most of its life and nothing has renewed it", which is the question the
// warning is actually asking. A proof with no ObservedAt has no measurable
// lifetime, so it keeps the flat window.
func expiringSoonCutoff(p contextspec.Proof, now time.Time) time.Time {
	const flat = 7 * 24 * time.Hour
	if p.ObservedAt == nil || p.ExpiresAt == nil {
		return now.Add(flat)
	}
	lifetime := p.ExpiresAt.Sub(*p.ObservedAt)
	if lifetime <= 0 {
		return now.Add(flat)
	}
	// Warn in the last third of the proof's life: long enough that a missed
	// refresh cycle is visible before the proof dies, short enough that a
	// healthy refresh loop never trips it.
	window := lifetime / 3
	if window > flat {
		window = flat
	}
	return now.Add(window)
}

func getProofs(ctx contextspec.Context, now time.Time, currentEpoch string, verdict *string, expiringSoon *int) []ProofState {
	var proofs []ProofState
	for _, p := range ctx.Proofs {
		state, detail, expired, expiringHit := proofExpiryState(p, now)
		binding := ctx.CheckProof(p.ID, 0, false, now)
		if binding.State == contextspec.StateContradicted {
			state, detail, expired, expiringHit = "contradicted", binding.Detail, false, false
		}
		if previousEpoch(p, currentEpoch) {
			// Evidence from a different install of this machine (or another
			// machine entirely) says nothing about THIS machine's recoverability
			// — it counts as unreviewed and is excluded from green until
			// re-drilled here and now.
			state, detail = "unreviewed", "from a previous epoch — re-drill"
			expired = false
		}
		if expired {
			*verdict = worst(*verdict, "warn")
		}
		if state == "contradicted" || state == "unreachable" || state == "stale" {
			*verdict = worst(*verdict, "warn")
		}
		if expiringHit {
			*expiringSoon++
		}
		if os, od, override := terminalStatusOverride(p.Status); override {
			state, detail = os, od
			*verdict = worst(*verdict, "warn")
		}
		proofs = append(proofs, ProofState{ID: p.ID, Status: state, Detail: detail})
	}
	sort.Slice(proofs, func(i, j int) bool { return proofs[i].ID < proofs[j].ID })
	return proofs
}

// proofExpiryState derives a proof's state/detail from its own
// expires_at/observed_at declarations, before any terminal-status override.
// expired and expiringHit flag which of the caller's counters to update.
func proofExpiryState(p contextspec.Proof, now time.Time) (state, detail string, expired, expiringHit bool) {
	intrinsic := contextspec.EvaluateProof(p, now)
	switch intrinsic.State {
	case contextspec.StateUnreachable:
		return "unreachable", intrinsic.Detail, false, false
	case contextspec.StateContradicted:
		return "contradicted", intrinsic.Detail, false, false
	case contextspec.StateStale:
		if p.Status == contextspec.ProofRecordStale {
			return "stale", intrinsic.Detail, false, false
		}
		return "expired", intrinsic.Detail, true, false
	}
	state, detail = "present", "no expiry declared"
	switch {
	case p.ExpiresAt != nil && p.ExpiresAt.Before(now):
		state = "expired"
		detail = "expired " + p.ExpiresAt.Format(time.RFC3339)
		expired = true
	case p.ExpiresAt != nil && p.ExpiresAt.Before(expiringSoonCutoff(p, now)):
		// Counted and shown ("E expiring soon" in the headline, its own
		// footer tile on the dashboard) but no longer a verdict-warn on
		// its own: warn is reserved for proofs that are actually bad
		// (expired/disputed/unreachable/stale) or actually unreviewed.
		// An about-to-expire proof that is still inside its own TTL is
		// information, not a failure.
		state = "expiring"
		detail = "expires " + p.ExpiresAt.Format(time.RFC3339)
		expiringHit = true
	case p.ExpiresAt != nil && p.ObservedAt != nil && withinFreshnessWindow(*p.ObservedAt, *p.ExpiresAt, now):
		// Both observed_at and expires_at declared, still inside its
		// freshness window (see freshnessWindow): this is exactly the
		// taxonomy's "observed" state — something keeps re-observing
		// it recently enough to trust, not merely "hasn't technically
		// expired yet".
		state = "observed"
		detail = fmt.Sprintf("refreshed %s ago · valid until %s", formatAgo(now.Sub(*p.ObservedAt)), p.ExpiresAt.Format(time.RFC3339))
	case p.ExpiresAt != nil:
		// Has an expiry, but the last observation has fallen outside
		// its own freshness window (or there was never one at all) —
		// a gap again, even though the proof record has not
		// technically expired: a one-off attestation with a long
		// declared TTL and nothing re-checking it is not the same
		// claim as an actively re-observed one.
		state = "unreviewed"
		if p.ObservedAt == nil {
			detail = "never observed"
		} else {
			window := freshnessWindow(*p.ObservedAt, *p.ExpiresAt)
			detail = fmt.Sprintf("last observed %s ago (window %s)", formatAgo(now.Sub(*p.ObservedAt)), formatAgo(window))
		}
	}
	return state, detail, expired, expiringHit
}

// terminalStatusOverride reports the state/detail a proof's terminal status
// (stale/disputed/unreachable) forces over whatever proofExpiryState
// computed. The two drill-failure statuses carry their own remediation
// instead of an expiry line: they read differently because they MEAN
// different things — unreachable is "could not even try" (no data loss
// implied), disputed is "tried and it did not verify" (investigate the
// copy).
func terminalStatusOverride(status contextspec.ProofRecordStatus) (state, detail string, override bool) {
	if status != contextspec.ProofRecordStale && status != contextspec.ProofRecordDisputed && status != contextspec.ProofRecordUnreachable {
		return "", "", false
	}
	state = string(status)
	switch status {
	case contextspec.ProofRecordUnreachable:
		detail = "the recovery source was not reachable when this ran; re-run the drill once the source is reachable"
	case contextspec.ProofRecordDisputed:
		detail = "the recovery ran and did not verify; investigate the copy"
	}
	return state, detail, true
}

// partitionCounts partitions ctx.Proofs into "restored" (LevelOf reaches
// LevelRestores or better — the recovery was actually proven, at least
// once, byte-identical or stronger), "accepted" (still at LevelDeclared,
// but an owner acceptance is recorded and its review_by is in the future),
// and "unreviewed" (every other declared proof: never verified, or
// currently stale/disputed/expired/unreachable so the earlier verification
// no longer counts — including an acceptance whose review date has passed,
// which is a gap again, not a decision). It is the same
// contextspec.LevelOf the inventory rows use, summed across every declared
// proof, so Restored+Accepted+Unreviewed always equals len(ctx.Proofs).
func partitionCounts(ctx contextspec.Context, now time.Time, currentEpoch string) (restored, observed, accepted, unreviewed int) {
	for _, p := range ctx.Proofs {
		if previousEpoch(p, currentEpoch) {
			unreviewed++ // a previous epoch's proof is never green here (docs/SCHEMA.md §Identity & epoch)
			continue
		}
		binding := ctx.CheckProof(p.ID, 0, false, now)
		if binding.State != contextspec.StatePresent {
			unreviewed++
			continue
		}
		level, _ := contextspec.LevelOf(p, now)
		if level != contextspec.LevelDeclared {
			restored++
			continue
		}
		switch {
		case p.Accepted.Active(now):
			accepted++
		case isObservedProof(ctx, p, now):
			observed++
		default:
			unreviewed++
		}
	}
	return restored, observed, accepted, unreviewed
}

// isObservedProof reports whether a still-declared-level proof is being
// actively kept fresh: it carries both an observed_at and an expires_at,
// and now falls within that observation's own TTL window — i.e.
// now - observed_at <= expires_at - observed_at, which (given expires_at
// is in the future) is simply "has not expired". An attention-state
// record (disputed/unreachable/stale) or an already-expired proof is never
// "observed" — those are gaps (or worse), not fresh evidence, regardless
// of what timestamps happen to be on file.
func isObservedProof(ctx contextspec.Context, p contextspec.Proof, now time.Time) bool {
	if ctx.CheckProof(p.ID, 0, false, now).State != contextspec.StatePresent {
		return false
	}
	switch p.Status {
	case contextspec.ProofRecordDisputed, contextspec.ProofRecordUnreachable, contextspec.ProofRecordStale:
		return false
	}
	if p.ObservedAt == nil || p.ExpiresAt == nil {
		return false
	}
	if !p.ExpiresAt.After(now) {
		return false // already expired — an attention state, not observed
	}
	return withinFreshnessWindow(*p.ObservedAt, *p.ExpiresAt, now)
}

// minFreshnessWindow floors every freshness window at 48h regardless of a
// short-TTL proof's own math (a proof with a 6h TTL would otherwise get an
// under-an-hour window, which is noise, not signal).
const minFreshnessWindow = 48 * time.Hour

// freshnessWindow is how recently a proof must have been (re-)observed to
// still count as "observed" rather than "unreviewed": max(48h, TTL/7).
// "Within its own TTL" (the original, simpler rule) let a one-off
// attestation with a long declared TTL — recovery-usb-bootstrap observed
// once with a 30-day expiry — read as "observed" for nearly a month with
// nothing re-checking it, which is exactly the false confidence this state
// exists to distinguish from. Dividing by 7 means an hourly/daily-
// refreshed proof (short TTL relative to its refresh cadence) stays
// observed continuously, while a one-off with a 30-day TTL falls back to
// unreviewed after about 4.3 days — the SAME 48h/window text this
// function's result feeds directly into getProofs' and
// status.classifyProofState's row text.
func freshnessWindow(observedAt, expiresAt time.Time) time.Duration {
	ttl := expiresAt.Sub(observedAt)
	window := ttl / 7
	if window < minFreshnessWindow {
		window = minFreshnessWindow
	}
	return window
}

// withinFreshnessWindow reports whether now is still inside observedAt's
// freshness window (see freshnessWindow) relative to expiresAt.
func withinFreshnessWindow(observedAt, expiresAt, now time.Time) bool {
	return now.Sub(observedAt) <= freshnessWindow(observedAt, expiresAt)
}

// formatAgo renders a duration the way the freshness-window row text
// wants: hours for anything under a day (an hourly/daily-refreshed proof's
// "refreshed 3h ago" would otherwise round down to a meaningless "0d"),
// contextspec.FormatAge's day grain beyond that.
func formatAgo(d time.Duration) string {
	if d < 24*time.Hour {
		hours := int(d.Hours())
		return fmt.Sprintf("%dh", hours)
	}
	return contextspec.FormatAge(d)
}

// nextExpiry finds the soonest proof expiry still in the future — the
// "Green. Next expiry: …" answer for a machine with nothing left to do.
// Zero values when no proof declares a future expiry.
func nextExpiry(proofs []contextspec.Proof, now time.Time) (id string, at time.Time) {
	for _, p := range proofs {
		if p.ExpiresAt == nil || !p.ExpiresAt.After(now) {
			continue
		}
		if id == "" || p.ExpiresAt.Before(at) {
			id, at = p.ID, *p.ExpiresAt
		}
	}
	return id, at
}

// dateOnly is the day-grain date format acceptance review dates render in:
// a review date is a deadline a human plans around, not a timestamp.
const dateOnly = "2006-01-02"

// emDash marks an absent RPO/RTO measurement — never "0" or blank, which
// would read as "measured, and it was zero".
const emDash = "—"

// buildInventory returns one row per declared drill, PLUS one row per proof
// that has no matching drill — an attestation: evidence ingested (or
// hand-authored) but never actually drilled. Omitting those would invert
// the section's whole purpose, since in a real deployment the undrilled
// mass of attestation-only proofs (rung declared/restores) is usually the
// majority and IS the headline the inventory exists to show. Sorted
// weakest recovery level first (ties broken by proof id for a stable,
// readable order). The level and the reason a proof isn't currently good
// both come from contextspec.LevelOf — this function only formats, it
// never re-derives the level -> rung mapping.
// sourceFiles is buildInventory's provenance input: which context file
// declared each drill's proof, and which declared each proof directly (for
// an attestation-only row, which has no drill of its own to name a file).
// A *sourceFiles (rather than two separate map parameters, or one map
// reused for both) keeps buildInventory's call shape unchanged for every
// existing caller that passes nil (Go allows nil for a pointer exactly as
// it did for a map) and not care about source-file provenance at all.
type sourceFiles struct {
	drills map[string]string
	proofs map[string]string
}

func (s *sourceFiles) drill(proofID string) string {
	if s == nil {
		return ""
	}
	return s.drills[proofID]
}

func (s *sourceFiles) proof(proofID string) string {
	if s == nil {
		return ""
	}
	return s.proofs[proofID]
}

func buildInventory(ctx contextspec.Context, sources *sourceFiles, now time.Time, currentEpoch string) []InventoryRow {
	proofByID := make(map[string]contextspec.Proof, len(ctx.Proofs))
	for _, p := range ctx.Proofs {
		proofByID[p.ID] = p
	}
	hasDrill := make(map[string]bool, len(ctx.Drills))
	for _, d := range ctx.Drills {
		hasDrill[d.Proof] = true
	}
	bc := rowBuildContext{context: ctx, proofByID: proofByID, guards: ctx.Guards, sources: sources, now: now, epoch: currentEpoch}

	type leveled struct {
		level contextspec.RecoveryLevel
		row   InventoryRow
	}
	entries := make([]leveled, 0, len(ctx.Drills)+len(ctx.Proofs))
	for i := range ctx.Drills {
		d := ctx.Drills[i]
		level, row := inventoryRow(&d, d.Proof, true, bc)
		entries = append(entries, leveled{level, row})
	}
	for _, p := range ctx.Proofs {
		if hasDrill[p.ID] {
			continue // already covered by the drill loop above
		}
		level, row := inventoryRow(nil, p.ID, false, bc)
		entries = append(entries, leveled{level, row})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].level != entries[j].level {
			return entries[i].level < entries[j].level
		}
		return entries[i].row.Proof < entries[j].row.Proof
	})

	rows := make([]InventoryRow, len(entries))
	for i, e := range entries {
		e.row.LevelRank = e.level.Rung()
		rows[i] = e.row
	}
	return rows
}

// contextualLevelOf credits a proof's recovery level only when its intrinsic
// evidence and any recorded recipe/dependency binding still match the current
// context. A recipe edit therefore moves the row back to declared instead of
// leaving stale measurements looking restored.
func contextualLevelOf(ctx contextspec.Context, p contextspec.Proof, now time.Time) (contextspec.RecoveryLevel, string) {
	if result := ctx.CheckProof(p.ID, 0, false, now); result.State != contextspec.StatePresent {
		return contextspec.LevelDeclared, result.Detail
	}
	return contextspec.LevelOf(p, now)
}

// rowBuildContext bundles the read-only lookups inventoryRow needs beyond
// the one proof/drill it is building a row for — a parameter object rather
// than four positional maps/slices/times, all of which are the same across
// every call within one buildInventory pass.
type rowBuildContext struct {
	context   contextspec.Context
	proofByID map[string]contextspec.Proof
	guards    []contextspec.Guard
	sources   *sourceFiles
	now       time.Time
	epoch     string
}

// previousEpoch reports whether p was recorded under an epoch other than the
// current one — a different install of this machine, or a different machine
// whose context file was copied here. An unstamped proof (epoch "") is
// legacy, not foreign: it was written before stamps existed and is never
// marked, because the machine could not have said at the time.
func previousEpoch(p contextspec.Proof, currentEpoch string) bool {
	return p.Epoch != "" && currentEpoch != "" && p.Epoch != currentEpoch
}

// inventoryRow derives one row, for either a declared drill (d non-nil,
// isDrilled true) or a drill-less attestation proof (d nil, isDrilled
// false). Level/Proof/RPO/RTO/ProofAge — the text renderer's only inputs —
// are computed exactly as before; every other field is additive, feeding
// only the HTML dashboard's expandable row detail card.
//
// RPO/RTO/measured age/Checks are only shown when the proof is currently
// good (LevelOf returned no reason) — a measurement from before a proof
// expired or was disputed would read as current when it no longer is, which
// is exactly the false confidence this inventory exists to prevent. The
// drill's own declaration (recover/pin_check/recovery_source/budgets) is
// NOT gated on that: what a drill would run is relevant even when it has
// never produced a proof, or its last run failed.
func inventoryRow(d *contextspec.Drill, proofID string, isDrilled bool, bc rowBuildContext) (contextspec.RecoveryLevel, InventoryRow) {
	row := InventoryRow{Proof: proofID, IsDrilled: isDrilled, RPO: emDash, RTO: emDash}
	if d != nil {
		row.SourceFile = bc.sources.drill(proofID)
		row.RecoverCmd = d.Recover
		row.RecoverySource = d.RecoverySource
		row.PinCheckCmd = d.PinCheck
		row.BudgetRTO = formatBudget(d.Budgets.RTO, contextspec.FormatRTO)
		row.BudgetRPO = formatBudget(d.Budgets.RPO, contextspec.FormatRPO)
	}

	p, ok := bc.proofByID[proofID]
	if !ok {
		// Only reachable for a declared drill: an attestation-only row is
		// only ever built from an id that IS in proofByID (see buildInventory).
		row.Level = contextspec.LevelDeclared.String()
		row.ProofAge = "no proof recorded yet"
		return contextspec.LevelDeclared, row
	}

	row.ObservedAtDisplay = formatTimestamp(p.ObservedAt)
	row.ExpiresAtDisplay = formatTimestamp(p.ExpiresAt)
	row.ExpiresInDisplay = formatExpiresIn(p.ExpiresAt, bc.now)
	row.IsObserved = isObservedProof(bc.context, p, bc.now)
	row.SignaturePresent = p.Signature != nil
	row.Binding = proofBinding(p)
	if p.Signature != nil {
		row.SigPubKeyPrefix = prefixHex(p.Signature.PublicKeyHex, 8)
	}
	if !isDrilled {
		populateAttestationRow(&row, p, proofID, bc)
	}

	level, reason := contextualLevelOf(bc.context, p, bc.now)
	reason = applyProofStatus(&row, p, level, reason, isDrilled, bc)
	row.Level = level.String()
	row.ProofAge = reason
	if reason != "" {
		return level, row
	}
	populateMeasurements(&row, p, bc.now)
	return level, row
}

func proofBinding(p contextspec.Proof) string {
	switch {
	case p.RecipeDigest != "" && p.Dependencies != nil:
		return "bound"
	case p.RecipeDigest != "" || p.Dependencies != nil:
		return "invalid binding"
	default:
		return "unbound evidence"
	}
}

func populateAttestationRow(row *InventoryRow, p contextspec.Proof, proofID string, bc rowBuildContext) {
	row.AttestCommand = orEmDash(p.Command)
	row.AttestEvidenceURL = orEmDash(p.EvidenceURL)
	row.ProposeArtifact = inferArtifactPath(proofID, bc.guards)
	// An attestation has no drill to name its own source file — the file that
	// declared the proof is the closest thing to a next-step --context value.
	row.SourceFile = bc.sources.proof(proofID)
}

func applyProofStatus(row *InventoryRow, p contextspec.Proof, level contextspec.RecoveryLevel, reason string, isDrilled bool, bc rowBuildContext) string {
	if previousEpoch(p, bc.epoch) {
		row.PreviousEpoch = true
		reason = fmt.Sprintf("from a previous epoch — re-drill (recorded under epoch %s, this machine is %s)", p.Epoch, bc.epoch)
	}
	if !isDrilled && reason == "not verified" {
		reason = "attested, no drill"
	}
	if p.Accepted == nil {
		return reason
	}
	if p.Accepted.Active(bc.now) {
		row.AcceptedReason = p.Accepted.Reason
		row.AcceptedBy = p.Accepted.By
		row.AcceptedReviewBy = p.Accepted.ReviewBy.Format(dateOnly)
		if level == contextspec.LevelDeclared {
			return fmt.Sprintf("attested · accepted: %s (review by %s)", p.Accepted.Reason, row.AcceptedReviewBy)
		}
		return reason
	}
	row.AcceptanceLapsedOn = p.Accepted.ReviewBy.Format(dateOnly)
	return fmt.Sprintf("%s · acceptance lapsed %s", reason, row.AcceptanceLapsedOn)
}

func populateMeasurements(row *InventoryRow, p contextspec.Proof, now time.Time) {
	if p.ObservedAt != nil {
		row.ProofAge = contextspec.FormatAge(now.Sub(*p.ObservedAt))
	}
	if p.Measurements == nil {
		return
	}
	row.RTO = contextspec.FormatRTO(p.Measurements.RTOSeconds)
	if p.Measurements.RPOSeconds != nil {
		row.RPO = contextspec.FormatRPO(*p.Measurements.RPOSeconds)
	}
	row.Checks = convertChecks(p.Measurements.Checks)
}

// formatBudget renders a declared RTO/RPO budget using the same formatter
// (contextspec.FormatRTO or FormatRPO) the measured column already uses, so
// "declared vs measured" reads as the same unit/rounding on both sides. A
// zero duration means the budget was not declared (contextspec.DrillBudgets
// doc comment), never a real zero-time budget.
func formatBudget(d time.Duration, format func(seconds float64) string) string {
	if d <= 0 {
		return emDash
	}
	return format(d.Seconds())
}

// formatTimestamp renders an optional evidence timestamp, RFC3339 to match
// every other timestamp already printed on this page (proof expiry, ledger
// last-decision).
func formatTimestamp(t *time.Time) string {
	if t == nil {
		return emDash
	}
	return t.UTC().Format(time.RFC3339)
}

// formatExpiresIn renders the plain-language expiry countdown the detail
// card shows next to ExpiresAtDisplay: how long until (or since) expiry, at
// the same day granularity contextspec.FormatAge uses everywhere else.
func formatExpiresIn(expires *time.Time, now time.Time) string {
	if expires == nil {
		return emDash
	}
	if expires.After(now) {
		return "expires in " + contextspec.FormatAge(expires.Sub(now))
	}
	return "expired " + contextspec.FormatAge(now.Sub(*expires)) + " ago"
}

// prefixHex returns the first n characters of a hex string, unchanged if it
// is already that short or shorter — the detail card shows just enough of a
// signing key to recognize it without printing the whole public key.
func prefixHex(hex string, n int) string {
	if len(hex) <= n {
		return hex
	}
	return hex[:n]
}

// orEmDash renders an optional free-text proof field (Command, EvidenceURL)
// as emDash rather than an empty table/detail-card cell.
func orEmDash(s string) string {
	if s == "" {
		return emDash
	}
	return s
}

// inferArtifactPath finds a guard that requires proofID and returns the
// first concrete (non-glob) path in that guard's Match.Paths — the
// dashboard's best-effort artifact hint for an attestation-only proof's
// "convert to a real drill" propose command. Empty when no guard requires
// this proof, or every declared path is a glob pattern (nothing concrete to
// hand `drill propose` as a single artifact) — the dashboard falls back to
// a generic placeholder in that case.
func inferArtifactPath(proofID string, guards []contextspec.Guard) string {
	for _, g := range guards {
		for _, want := range g.Requires.Proofs {
			if want != proofID {
				continue
			}
			for _, path := range g.Match.Paths {
				if !strings.ContainsAny(path, "*?[") {
					return path
				}
			}
		}
	}
	return ""
}

// convertChecks reduces a proof's typed check outcomes to the dashboard's
// decoupled CheckResult shape, preserving declared order.
func convertChecks(checks []contextspec.CheckOutcome) []CheckResult {
	if len(checks) == 0 {
		return nil
	}
	out := make([]CheckResult, len(checks))
	for i, c := range checks {
		out[i] = CheckResult{Type: c.Type, Pass: c.Pass, Detail: c.Detail}
	}
	return out
}

// inventorySummaryLine renders the one-line rollup shown under the
// inventory table: how many of the declared+attested proofs are provably
// restorable at all, and how many clear the top rung.
func inventorySummaryLine(rows []InventoryRow) string {
	if len(rows) == 0 {
		return ""
	}
	restorable, serving := 0, 0
	for _, r := range rows {
		if r.Level != contextspec.LevelDeclared.String() {
			restorable++
		}
		if r.Level == contextspec.LevelServes.String() {
			serving++
		}
	}
	return fmt.Sprintf("%d of %d provably restorable (restores or better) · %d boot and serve", restorable, len(rows), serving)
}

func processLedger(ledgerPath string, s *Summary, now time.Time) error {
	if _, err := os.Stat(ledgerPath); err == nil {
		entries, err := ledger.ReadAll(ledgerPath)
		if err != nil {
			return fmt.Errorf("status: %w", err)
		}
		s.LedgerEntries = len(entries)
		res := ledger.VerifyEntries(entries)
		s.LedgerOK = res.OK
		s.LedgerDetail = res.Reason
		if !res.OK {
			s.Verdict = "block"
		}
		s.GateBroken, s.Blocked, s.Last = decisionHistory(entries)
		if s.Last != nil {
			s.LastDecision = formatLastDecision(*s.Last)
		}
		s.ActiveOverrides = ledger.ActiveOverrideStates(entries, now)
		for _, override := range s.ActiveOverrides {
			if override.LegacyNoExpiry || overrideDaysLeft(override.ExpiresAt, now) <= 7 {
				s.Verdict = worst(s.Verdict, "warn")
			}
		}
		attachDrillHistory(s.Inventory, entries)
	} else {
		s.LedgerDetail = "no ledger yet at " + ledgerPath
	}
	return nil
}

// overrideDaysLeft rounds a partial day up: an override that expires in one
// second is still one day away, and it must be prominent rather than shown as
// zero days left while it still applies.
func overrideDaysLeft(expiresAt, now time.Time) int {
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		return 0
	}
	return int((remaining + 24*time.Hour - time.Nanosecond) / (24 * time.Hour))
}

// maxHistoryTicks caps how many past drill runs the HTML dashboard's
// heartbeat tick strip draws per proof — the ledger a real deployment
// accumulates over months of frequent drills is far longer than a single
// glance-able row.
const maxHistoryTicks = 20

// attachDrillHistory fills each inventory row's History from the ledger's
// drill entries, in place. Only proof ids already present in rows are
// considered — a drill entry for some id no longer in the current inventory
// (a retired proof) is silently ignored rather than growing the table.
func attachDrillHistory(rows []InventoryRow, entries []ledger.Entry) {
	known := make(map[string]bool, len(rows))
	for _, r := range rows {
		known[r.Proof] = true
	}
	byProof := drillHistoryByProof(entries, known)
	for i := range rows {
		rows[i].History = byProof[rows[i].Proof]
	}
}

// drillHistoryByProof reduces a ledger's entries to each known proof id's
// run history, oldest to newest (ReadAll already returns file/append
// order), pin_check entries excluded, capped at the last maxHistoryTicks per
// proof. A drill entry naming a proof id not in known is ignored.
func drillHistoryByProof(entries []ledger.Entry, known map[string]bool) map[string][]RunTick {
	out := make(map[string][]RunTick)
	for _, e := range entries {
		if e.EntryType != ledger.EntryDrill || e.Payload.Drill == nil {
			continue
		}
		d := e.Payload.Drill
		if d.Mode != "drill" || !known[d.ProofID] {
			continue
		}
		out[d.ProofID] = append(out[d.ProofID], RunTick{When: e.CreatedAt, Verified: d.Verified, RTOMs: d.RTOMs})
	}
	for id, ticks := range out {
		if len(ticks) > maxHistoryTicks {
			out[id] = ticks[len(ticks)-maxHistoryTicks:]
		}
	}
	return out
}

func decisionHistory(entries []ledger.Entry) (broken, blocked []DecisionSummary, last *DecisionSummary) {
	views := ledger.Decisions(entries)
	viewByID := make(map[string]ledger.DecisionView, len(views))
	for _, view := range views {
		viewByID[view.EntryID] = view
	}
	for _, e := range entries {
		if e.EntryType != ledger.EntryDecision || e.Payload.Decision == nil {
			continue
		}
		view, ok := viewByID[e.ID]
		if !ok {
			continue
		}
		d := e.Payload.Decision
		summary := DecisionSummary{
			EntryID: view.EntryID, When: view.CreatedAt, EvaluatedAt: view.EvaluatedAt, Actor: view.Actor, Verdict: view.Verdict, GateState: view.GateState,
			BrokenReason: view.BrokenReason, Operation: view.Operation, Executed: view.Executed,
			Intents:  append([]ledger.IntentRecord(nil), view.Intents...),
			Findings: append([]ledger.FindingRecord(nil), view.Findings...), Legacy: view.Legacy,
			DurationMS:  d.DurationMS,
			ToolVersion: d.ToolVersion, Checks: append([]ledger.DecisionCheckRecord(nil), d.Checks...),
		}
		if e.Policy != nil {
			summary.PolicyRevision = e.Policy.Revision
		}
		if e.Host != nil {
			summary.HostName, summary.HostID = e.Host.Name, e.Host.ID
		}
		summary.Epoch = e.Epoch
		if summary.GateState == "broken" {
			broken = append(broken, summary)
		} else if summary.Verdict == "block" {
			blocked = append(blocked, summary)
		}
		copy := summary
		last = &copy
	}
	return broken, blocked, last
}

func formatLastDecision(d DecisionSummary) string {
	state := strings.ToUpper(d.Verdict)
	if d.GateState == "broken" {
		state = "GATE BROKEN"
	}
	return fmt.Sprintf("%s (%s)", state, d.When.Format("2006-01-02"))
}

func worst(a, b string) string {
	rank := map[string]int{"pass": 0, "warn": 1, "block": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func (s *Summary) sections() []report.KVSection {
	sections := []report.KVSection{recoveryChainSection(s)}
	if recent, ok := recentDecisionSection(s.Last); ok {
		sections = append(sections, recent)
	}
	if overrides, ok := overrideSection(s); ok {
		sections = append(sections, overrides)
	}
	if proofs, ok := proofSection(s.Proofs); ok {
		sections = append(sections, proofs)
	}
	if policy, ok := policyFindingSection(s.PolicyFindings); ok {
		sections = append(sections, policy)
	}
	return sections
}

func recoveryChainSection(s *Summary) report.KVSection {
	rows := []report.KVRow{
		{Key: "Context", Value: s.Origin},
		{Key: "Guards declared", Value: fmt.Sprintf("%d (%d lifelines, %d guards)", s.Lifelines+s.Guards, s.Lifelines, s.Guards)},
	}
	if s.LedgerEntries > 0 || s.LedgerDetail != "" {
		value := s.LedgerDetail
		if s.LedgerEntries > 0 {
			state := "BROKEN: " + s.LedgerDetail
			if s.LedgerOK {
				state = "verified"
			}
			value = fmt.Sprintf("%d entries · chain %s", s.LedgerEntries, state)
		}
		rows = append(rows, report.KVRow{Key: "Ledger", Value: value})
	}
	if s.LastDecision != "" {
		rows = append(rows, report.KVRow{Key: "Last decision", Value: s.LastDecision})
	}
	return report.KVSection{Title: "Recovery chain", Rows: rows}
}

func recentDecisionSection(d *DecisionSummary) (report.KVSection, bool) {
	if d == nil {
		return report.KVSection{}, false
	}
	rows := []report.KVRow{
		{Key: "Outcome", Value: formatDecisionOutcome(*d)},
		{Key: "Recorded", Value: d.When.Local().Format("2006-01-02 15:04")},
	}
	if d.EvaluatedAt != nil {
		rows = append(rows, report.KVRow{Key: "Evaluated as of", Value: d.EvaluatedAt.Local().Format(time.RFC3339)})
	}
	if d.Legacy {
		rows = append(rows, report.KVRow{Key: "Proposed change", Value: "legacy record — details were not recorded"})
	} else {
		rows = append(rows, report.KVRow{Key: "Proposed change", Value: formatDecisionIntents(d.Intents)})
		for _, f := range d.Findings {
			rows = append(rows, report.KVRow{Key: "Finding " + f.FindingID, Value: formatFindingRecord(f)})
		}
	}
	return report.KVSection{Title: "Recent decision", Rows: rows}, true
}

func overrideSection(s *Summary) (report.KVSection, bool) {
	if len(s.ActiveOverrides) == 0 {
		return report.KVSection{}, false
	}
	section := report.KVSection{Title: "Active overrides"}
	for _, override := range s.ActiveOverrides {
		daysLeft := overrideDaysLeft(override.ExpiresAt, s.GeneratedAt)
		value := fmt.Sprintf("%d days left · approved by %s", daysLeft, override.ApprovedBy)
		if override.LegacyNoExpiry {
			value = fmt.Sprintf("WARN: override %s has no expiry — re-approve with --expires-in (%s)", override.EntryID, value)
		} else if daysLeft <= 7 {
			value = "WARN: expires soon · " + value
		}
		section.Rows = append(section.Rows, report.KVRow{Key: "override " + override.EntryID, Value: value})
	}
	return section, true
}

func proofSection(proofs []ProofState) (report.KVSection, bool) {
	if len(proofs) == 0 {
		return report.KVSection{}, false
	}
	section := report.KVSection{Title: "Proofs"}
	for _, p := range proofs {
		section.Rows = append(section.Rows, report.KVRow{Key: p.ID, Value: p.Status + " · " + p.Detail})
	}
	return section, true
}

func policyFindingSection(findings []string) (report.KVSection, bool) {
	if len(findings) == 0 {
		return report.KVSection{}, false
	}
	section := report.KVSection{Title: "Policy (ignored loosening attempts)"}
	for _, finding := range findings {
		section.Rows = append(section.Rows, report.KVRow{Key: "WARN", Value: finding})
	}
	return section, true
}

func formatDecisionOutcome(d DecisionSummary) string {
	if d.GateState == "broken" {
		if d.BrokenReason != "" {
			return "GATE BROKEN — " + d.BrokenReason
		}
		return "GATE BROKEN"
	}
	return strings.ToUpper(d.Verdict)
}

func formatDecisionIntents(intents []ledger.IntentRecord) string {
	if len(intents) == 0 {
		return "no proposed intents recorded"
	}
	parts := make([]string, 0, len(intents))
	for _, in := range intents {
		value := in.Action
		paths := append(append([]string(nil), in.Paths...), in.TargetPaths...)
		if len(paths) > 0 {
			value += " " + strings.Join(paths, ", ")
		}
		if in.Description != "" {
			value += " — " + in.Description
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, "; ")
}

func formatFindingRecord(f ledger.FindingRecord) string {
	parts := []string{f.Verdict}
	if f.Resource != "" {
		parts = append(parts, "resource: "+f.Resource)
	}
	if f.Proof != "" {
		parts = append(parts, "proof: "+f.Proof)
	}
	if f.RequiredNextStep != "" {
		parts = append(parts, "next: "+f.RequiredNextStep)
	}
	if f.Override != nil {
		parts = append(parts, "override by "+f.Override.ApprovedBy+": "+f.Override.Reason)
	}
	return strings.Join(parts, " · ")
}

func (s *Summary) summaryLine() string {
	parts := []string{fmt.Sprintf("%d guards", s.Lifelines+s.Guards)}
	if len(s.Proofs) > 0 {
		parts = append(parts, fmt.Sprintf("%d proofs (%d restored · %d observed · %d accepted · %d unreviewed · %d expiring soon)",
			len(s.Proofs), s.Restored, s.Observed, s.Accepted, s.Unreviewed, s.ExpiringSoon))
	} else {
		parts = append(parts, "no proofs declared")
	}
	if !s.LedgerOK {
		parts = append(parts, "LEDGER CHAIN BROKEN")
	}
	if len(s.ActiveOverrides) > 0 {
		parts = append(parts, fmt.Sprintf("%d active overrides", len(s.ActiveOverrides)))
	}
	return strings.Join(parts, " · ")
}

// Render produces the requested format. Text leads with the posture verdict,
// mirroring the report banner rule.
func (s *Summary) Render(format string) ([]byte, error) {
	if format == "html" {
		return s.RenderHTML()
	}
	if format == "json" {
		return s.RenderJSON()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s — %s\n", strings.ToUpper(s.Verdict), s.summaryLine())
	if s.DiscoverLine != "" {
		fmt.Fprintf(&b, "%s\n", s.DiscoverLine)
	}
	renderTreeText(&b, s, TreeFilter{})
	renderDecisionHeadings(&b, s.GateBroken, s.Blocked)
	for _, sec := range s.sections() {
		fmt.Fprintf(&b, "\n%s\n", sec.Title)
		for _, r := range sec.Rows {
			fmt.Fprintf(&b, "  %-18s %s\n", r.Key, r.Value)
		}
	}
	return []byte(b.String()), nil
}

// RenderLast emits the newest decision in the same verdict-first order as a
// gauntlet report: verdict, durable run metadata, then ordered check timings.
func (s *Summary) RenderLast() []byte {
	if s.Last == nil {
		return []byte("No recorded preflight decision.\n")
	}
	d := *s.Last
	var b strings.Builder
	if d.GateState == "broken" {
		b.WriteString("GATE BROKEN\n")
		if d.BrokenReason != "" {
			fmt.Fprintf(&b, "could not run: %s\n", d.BrokenReason)
		}
	} else {
		fmt.Fprintf(&b, "%s\n", strings.ToUpper(d.Verdict))
	}
	fmt.Fprintf(&b, "recorded: %s\n", d.When.Local().Format("2006-01-02 15:04"))
	if d.EvaluatedAt != nil {
		fmt.Fprintf(&b, "evaluated as of: %s\n", d.EvaluatedAt.Local().Format(time.RFC3339))
	}
	if d.ToolVersion != "" {
		fmt.Fprintf(&b, "tool version: %s\n", d.ToolVersion)
	}
	if d.PolicyRevision != "" {
		fmt.Fprintf(&b, "policy revision: %s\n", d.PolicyRevision)
	}
	if d.HostName != "" || d.Epoch != "" {
		stamp := d.HostName
		if d.HostID != "" {
			stamp += fmt.Sprintf(" (%s)", d.HostID)
		}
		if d.Epoch != "" {
			stamp += " · epoch " + d.Epoch
		}
		fmt.Fprintf(&b, "host: %s\n", stamp)
	}
	fmt.Fprintf(&b, "duration: %dms\n", d.DurationMS)
	for _, c := range d.Checks {
		fmt.Fprintf(&b, "  %-7s %s (%dms)\n", strings.ToUpper(c.Outcome), c.ID, c.DurationMS)
	}
	return []byte(b.String())
}

func renderDecisionHeadings(b *strings.Builder, broken, blocked []DecisionSummary) {
	if len(broken) > 0 {
		fmt.Fprintf(b, "\nGATE BROKEN (%d)\n", len(broken))
		for _, d := range broken {
			fmt.Fprintf(b, "  %s — %s\n", d.When.Local().Format("2006-01-02 15:04"), d.BrokenReason)
		}
	}
	if len(blocked) > 0 {
		fmt.Fprintf(b, "\nBLOCKED (%d)\n", len(blocked))
		for _, d := range blocked {
			fmt.Fprintf(b, "  %s — policy evaluation blocked (%dms)\n", d.When.Local().Format("2006-01-02 15:04"), d.DurationMS)
		}
	}
}
