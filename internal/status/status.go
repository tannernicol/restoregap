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
	"github.com/tannernicol/restoregap/internal/ledger"
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
	GeneratedAt   time.Time
	Lifelines     int
	Guards        int
	Proofs        []ProofState
	ExpiringSoon  int
	LedgerEntries int
	LedgerOK      bool
	LedgerDetail  string
	LastDecision  string
	// Inventory is one row per declared drill, plus one row per proof that
	// has no matching drill (an attestation — evidence ingested, never
	// drilled), sorted weakest recovery level first — the gaps are the
	// headline, not the wins.
	Inventory []InventoryRow
	// InventorySummary is the "N of M provably restorable" line printed
	// under the table. Empty when Inventory is empty.
	InventorySummary string
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
	SignaturePresent  bool
	SigPubKeyPrefix   string // first 8 hex chars of the Ed25519 public key, "" when unsigned

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
	merged, err := loadMerged(req.ContextPaths)
	if err != nil {
		return nil, err
	}

	s := &Summary{Verdict: "pass", Origin: merged.Origin, GeneratedAt: now, LedgerOK: true}
	s.Lifelines, s.Guards = countLifelinesAndGuards(merged)

	if len(req.ContextPaths) == 0 {
		s.Verdict = "warn" // running on the built-in default: nothing is provable yet
	}

	soon := now.Add(7 * 24 * time.Hour)
	s.Proofs = getProofs(merged, now, soon, &s.Verdict, &s.ExpiringSoon)
	s.Inventory = buildInventory(merged, drillSourceFiles(loaded), now)
	s.InventorySummary = inventorySummaryLine(s.Inventory)

	if req.LedgerPath != "" {
		if err := processLedger(req.LedgerPath, s); err != nil {
			return nil, err
		}
	}

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

// loadMerged loads and merges every declared context path via
// contextspec.LoadAll — the single source of truth for cross-file merge
// semantics (union of guards/facts/proofs/drills; a duplicate id across
// files is an error naming both, never a silent last-loaded-wins) — or the
// built-in zero-config default when none are declared. getContexts's own
// per-path loop stays separate: it exists for drillSourceFiles's per-file
// provenance, which a merged Context deliberately does not carry.
func loadMerged(paths []string) (contextspec.Context, error) {
	if len(paths) == 0 {
		return contextspec.Default(), nil
	}
	ctx, err := contextspec.LoadAll(paths)
	if err != nil {
		return contextspec.Context{}, fmt.Errorf("status: %w", err)
	}
	return ctx, nil
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

func getProofs(ctx contextspec.Context, now, soon time.Time, verdict *string, expiringSoon *int) []ProofState {
	var proofs []ProofState
	for _, p := range ctx.Proofs {
		state := "present"
		detail := "no expiry declared"
		switch {
		case p.ExpiresAt != nil && p.ExpiresAt.Before(now):
			state = "expired"
			detail = "expired " + p.ExpiresAt.Format(time.RFC3339)
			*verdict = worst(*verdict, "warn")
		case p.ExpiresAt != nil && p.ExpiresAt.Before(soon):
			state = "expiring"
			detail = "expires " + p.ExpiresAt.Format(time.RFC3339)
			*expiringSoon++
			*verdict = worst(*verdict, "warn")
		case p.ExpiresAt != nil:
			detail = "valid until " + p.ExpiresAt.Format(time.RFC3339)
		}
		if p.Status == contextspec.ProofRecordStale || p.Status == contextspec.ProofRecordDisputed {
			state = string(p.Status)
			*verdict = worst(*verdict, "warn")
		}
		proofs = append(proofs, ProofState{ID: p.ID, Status: state, Detail: detail})
	}
	sort.Slice(proofs, func(i, j int) bool { return proofs[i].ID < proofs[j].ID })
	return proofs
}

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
func buildInventory(ctx contextspec.Context, drillSources map[string]string, now time.Time) []InventoryRow {
	proofByID := make(map[string]contextspec.Proof, len(ctx.Proofs))
	for _, p := range ctx.Proofs {
		proofByID[p.ID] = p
	}
	hasDrill := make(map[string]bool, len(ctx.Drills))
	for _, d := range ctx.Drills {
		hasDrill[d.Proof] = true
	}
	bc := rowBuildContext{proofByID: proofByID, guards: ctx.Guards, drillSource: drillSources, now: now}

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

// rowBuildContext bundles the read-only lookups inventoryRow needs beyond
// the one proof/drill it is building a row for — a parameter object rather
// than four positional maps/slices/times, all of which are the same across
// every call within one buildInventory pass.
type rowBuildContext struct {
	proofByID   map[string]contextspec.Proof
	guards      []contextspec.Guard
	drillSource map[string]string
	now         time.Time
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
		row.SourceFile = bc.drillSource[proofID]
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
	row.SignaturePresent = p.Signature != nil
	if p.Signature != nil {
		row.SigPubKeyPrefix = prefixHex(p.Signature.PublicKeyHex, 8)
	}
	if !isDrilled {
		row.AttestCommand = orEmDash(p.Command)
		row.AttestEvidenceURL = orEmDash(p.EvidenceURL)
		row.ProposeArtifact = inferArtifactPath(proofID, bc.guards)
	}

	level, reason := contextspec.LevelOf(p, bc.now)
	if !isDrilled && reason == "not verified" {
		// "not verified" implies a drill ran and didn't produce a verified
		// result; an attestation with no drill behind it at all never had
		// one to run, so that phrasing would be actively misleading here.
		reason = "attested, no drill"
	}
	row.Level = level.String()
	row.ProofAge = reason
	if reason != "" {
		return level, row
	}
	if p.ObservedAt != nil {
		row.ProofAge = contextspec.FormatAge(bc.now.Sub(*p.ObservedAt))
	}
	if p.Measurements != nil {
		row.RTO = contextspec.FormatRTO(p.Measurements.RTOSeconds)
		if p.Measurements.RPOSeconds != nil {
			row.RPO = contextspec.FormatRPO(*p.Measurements.RPOSeconds)
		}
		row.Checks = convertChecks(p.Measurements.Checks)
	}
	return level, row
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
	return fmt.Sprintf("%d of %d provably restorable (level >= restores); %d serve", restorable, len(rows), serving)
}

func processLedger(ledgerPath string, s *Summary) error {
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
		s.LastDecision = getLastDecision(entries)
		attachDrillHistory(s.Inventory, entries)
	} else {
		s.LedgerDetail = "no ledger yet at " + ledgerPath
	}
	return nil
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

func getLastDecision(entries []ledger.Entry) string {
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].EntryType == ledger.EntryDecision && entries[i].Payload.Decision != nil {
			return fmt.Sprintf("%s (%s, %s)",
				entries[i].Payload.Decision.Verdict, entries[i].Actor,
				entries[i].CreatedAt.Format("2006-01-02"))
		}
	}
	return ""
}

func worst(a, b string) string {
	rank := map[string]int{"pass": 0, "warn": 1, "block": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func (s *Summary) sections() []report.KVSection {
	over := report.KVSection{Title: "Recovery chain", Rows: []report.KVRow{
		{Key: "Context", Value: s.Origin},
		{Key: "Guards declared", Value: fmt.Sprintf("%d (%d lifelines, %d guards)", s.Lifelines+s.Guards, s.Lifelines, s.Guards)},
	}}
	if s.LedgerEntries > 0 || s.LedgerDetail != "" {
		v := s.LedgerDetail
		if s.LedgerEntries > 0 {
			v = fmt.Sprintf("%d entries · chain %s", s.LedgerEntries, map[bool]string{true: "verified", false: "BROKEN: " + s.LedgerDetail}[s.LedgerOK])
		}
		over.Rows = append(over.Rows, report.KVRow{Key: "Ledger", Value: v})
	}
	if s.LastDecision != "" {
		over.Rows = append(over.Rows, report.KVRow{Key: "Last decision", Value: s.LastDecision})
	}
	sections := []report.KVSection{over}
	if len(s.Proofs) > 0 {
		ps := report.KVSection{Title: "Proofs"}
		for _, p := range s.Proofs {
			ps.Rows = append(ps.Rows, report.KVRow{Key: p.ID, Value: p.Status + " · " + p.Detail})
		}
		sections = append(sections, ps)
	}
	return sections
}

func (s *Summary) summaryLine() string {
	parts := []string{fmt.Sprintf("%d guards", s.Lifelines+s.Guards)}
	if len(s.Proofs) > 0 {
		parts = append(parts, fmt.Sprintf("%d proofs (%d expiring soon)", len(s.Proofs), s.ExpiringSoon))
	} else {
		parts = append(parts, "no proofs declared")
	}
	if !s.LedgerOK {
		parts = append(parts, "LEDGER CHAIN BROKEN")
	}
	return strings.Join(parts, " · ")
}

// renderInventoryText prints the recovery inventory as its own aligned
// table, followed by the summary rollup line. It is deliberately NOT folded
// into the generic %-18s two-column section dump below: a level/proof/
// RPO/RTO/age row has five columns of real meaning, and cramming them into
// one Value string would read worse than computing per-column widths from
// the actual data.
func renderInventoryText(b *strings.Builder, rows []InventoryRow, summary string) {
	if len(rows) == 0 {
		return
	}
	table := make([][]string, 0, len(rows)+1)
	table = append(table, []string{"LEVEL", "PROOF", "RPO", "RTO", "PROOF AGE"})
	for _, r := range rows {
		table = append(table, []string{r.Level, r.Proof, r.RPO, r.RTO, r.ProofAge})
	}
	widths := make([]int, len(table[0]))
	for _, row := range table {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	fmt.Fprintf(b, "\nRecovery inventory — what provably comes back, and to what point\n")
	for _, row := range table {
		b.WriteString("  ")
		for i, cell := range row {
			if i == len(row)-1 {
				b.WriteString(cell)
				continue
			}
			fmt.Fprintf(b, "%-*s  ", widths[i], cell)
		}
		b.WriteString("\n")
	}
	if summary != "" {
		fmt.Fprintf(b, "\n  %s\n", summary)
	}
}

// Render produces the requested format. Text leads with the posture verdict,
// mirroring the report banner rule.
func (s *Summary) Render(format string) ([]byte, error) {
	if format == "html" {
		return s.RenderHTML()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s — %s\n", strings.ToUpper(s.Verdict), s.summaryLine())
	renderInventoryText(&b, s.Inventory, s.InventorySummary)
	for _, sec := range s.sections() {
		fmt.Fprintf(&b, "\n%s\n", sec.Title)
		for _, r := range sec.Rows {
			fmt.Fprintf(&b, "  %-18s %s\n", r.Key, r.Value)
		}
	}
	return []byte(b.String()), nil
}
