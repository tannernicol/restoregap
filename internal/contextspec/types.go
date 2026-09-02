// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package contextspec implements the restoregap.yml / restoregap.local.yml
// v2 schema: a single unified `guards` concept (lifeline | guard) replacing
// the Python schema's five separate guard/contract lists, plus `facts` and
// `proofs`. It owns typed parsing, one-line-error validation, and ALL
// proof/fact freshness and Ed25519 signature checking (the "proofcheck"
// component named in docs/ARCHITECTURE.md) — no other package validates
// proof state. contextspec performs no guard-to-intent matching; that's
// internal/rules.
package contextspec

import "time"

// GuardKind drives a guard's default risk posture. Lifeline guards protect
// resources whose loss is unrecoverable by definition (SSH keys, recovery
// bundles, backup manifests); a lifeline match with nothing proving safety
// defaults to blocked. Plain guards are informational unless they declare
// their own requirements.
type GuardKind string

// The GuardKind values.
const (
	GuardKindLifeline GuardKind = "lifeline"
	GuardKindGuard    GuardKind = "guard"
)

// Enforcement is a guard's declared strictness when its requirements are
// unsatisfied. contextspec keeps its own copy of this vocabulary (rather
// than importing internal/engine) so contextspec has zero dependency on the
// decision engine; internal/rules maps between the two.
type Enforcement string

// The Enforcement values.
const (
	EnforcementBlock Enforcement = "block"
	EnforcementWarn  Enforcement = "warn"
)

// Matcher is the set of ways a guard can match a change intent. Any subset
// of fields may be populated; populated fields are ANDed together (a guard
// with both Paths and Actors set requires both to match), while multiple
// entries within one field are ORed (any pattern matching is enough). An
// empty field means "not constrained by this dimension".
type Matcher struct {
	Paths          []string // doublestar-style path globs
	Commands       []string // single-segment globs matched against the full command string
	Packages       []string // single-segment globs matched against each declared package
	Actions        []string // exact match against intent.Action
	Actors         []string // single-segment globs matched against intent.Actor
	ContextWindows []string // exact match against intent.ContextWindow
}

// Empty reports whether the matcher constrains nothing, which would make a
// guard match every intent — callers reject this at validation time.
func (m Matcher) Empty() bool {
	return len(m.Paths) == 0 && len(m.Commands) == 0 && len(m.Packages) == 0 &&
		len(m.Actions) == 0 && len(m.Actors) == 0 && len(m.ContextWindows) == 0
}

// Requirement lists the proof and fact IDs a guard needs satisfied.
type Requirement struct {
	Proofs []string
	Facts  []string
}

// Empty reports whether nothing is required to satisfy this guard.
func (r Requirement) Empty() bool {
	return len(r.Proofs) == 0 && len(r.Facts) == 0
}

// Guard is the unified replacement for Python's change_guards / update_guards
// / command_guards / assurance_contracts / lifeline_artifacts
// (docs/ARCHITECTURE.md §5).
type Guard struct {
	ID               string
	Kind             GuardKind
	Match            Matcher
	RequiredFor      []string
	Requires         Requirement
	Enforcement      Enforcement
	MaxProofAgeHours int // 0 = unbounded (only each proof's own ExpiresAt applies)
	RecoveryCopy     string
	AlternatePaths   []string
	// RequireVerified restricts this guard to proofs produced by a real drill
	// (Proof.Verified). An attestation that someone looked is not the same
	// claim as a recovery that was reconstructed and compared, and for the
	// artifacts you cannot afford to lose, only the second one is worth
	// blocking on.
	RequireVerified bool
	// Layer is this guard's recovery-domain classification (see the Layer*
	// constants) — empty when never classified. A proof this guard requires
	// inherits Layer as its own effective layer when the proof declares
	// none itself (EffectiveProofLayer).
	Layer string
	// Category is a free-form subgroup within Layer (e.g. "ssh-keys" within
	// identity-secrets). Optional; never validated against a fixed
	// vocabulary the way Layer is.
	Category string
	// Scope carries this guard's organizational axes (environment/system/
	// host/owner/tags), overriding the declaring context file's Scope
	// default field by field.
	Scope Scope
}

// Fact is a reviewed, provenanced statement of ground truth a guard may
// require. IDs are required so guards can reference facts the same way they
// reference proofs (the v2 schema sketch in ARCHITECTURE.md shows facts as
// statement+provenance+expiry only; contextspec adds a stable `id` field so
// `requires.facts` can name one — the same shape proofs already need).
type Fact struct {
	ID         string
	Statement  string
	Provenance string
	ExpiresAt  *time.Time
	MaxAgeDays *int
}

// ProofRecordStatus is the raw status a proof record declares in YAML.
type ProofRecordStatus string

// The ProofRecord source values.
const (
	ProofRecordObserved  ProofRecordStatus = "observed"
	ProofRecordValidated ProofRecordStatus = "validated"
	ProofRecordStale     ProofRecordStatus = "stale"
	ProofRecordDisputed  ProofRecordStatus = "disputed"
	// ProofRecordUnreachable records that the recovery SOURCE could not be
	// reached when the drill or pin_check ran (missing mount, connection
	// refused, permission denied on the source, timeout) — so nothing was
	// proven either way. It is deliberately NOT "disputed": disputed means a
	// recovery was performed and its verification genuinely failed. Both
	// statuses fail closed for gating identically; only the report differs
	// ("could not try" must never read as "your copy is corrupt").
	ProofRecordUnreachable ProofRecordStatus = "unreachable"
)

// Signature is an optional Ed25519 signature over a proof record, verified
// by CheckProof.
type Signature struct {
	PublicKeyHex string
	SignatureHex string
}

// Acceptance is an owner's reasoned decision to stop carrying a proof as a
// gap: this one will not be drilled (or re-drilled) within the review
// window, and that is accepted WITH a reason rather than left as silence.
// It is recorded on the proof itself so it travels with the context file
// the proof lives in, and it always carries a review date — an acceptance
// that never comes up for review is a gap that learned to hide.
type Acceptance struct {
	By       string    // who accepted, e.g. owner/tanner
	At       time.Time // when the acceptance was recorded
	Reason   string    // why this proof will not be drilled — required, never blank
	ReviewBy time.Time // when the acceptance lapses and the proof counts as unreviewed again
}

// Active reports whether the acceptance still applies at now. A lapsed
// acceptance is not an error state to hide: the proof simply returns to the
// unreviewed bucket, with the lapse visible in the inventory.
func (a *Acceptance) Active(now time.Time) bool {
	return a != nil && now.Before(a.ReviewBy)
}

// Proof is a declared piece of evidence a guard's Requires.Proofs may name.
type Proof struct {
	ID          string
	Status      ProofRecordStatus
	ObservedAt  *time.Time
	ExpiresAt   *time.Time
	SHA256      string
	EvidenceURL string
	Signature   *Signature
	// Verified is true only when a drill reconstructed the artifact from its
	// recovery source and the bytes matched. Guards with RequireVerified
	// accept nothing less.
	Verified bool
	// Command is the verifier a drill or evidence ingest actually ran, kept so
	// a proof says how it was obtained rather than merely asserting it.
	Command string
	// Measurements is set only for proofs a drill produced with typed
	// validate checks; nil for byte-identical-only and non-drill proofs.
	Measurements *Measurements
	// Accepted records an owner's reasoned acceptance that this proof will
	// not be drilled within its review window — the deliberate alternative
	// to leaving an undrillable proof as a permanent gap. Nil when no
	// acceptance is recorded.
	Accepted *Acceptance
	// Layer is this proof's own recovery-domain classification, if declared
	// directly on the proof. Empty means "not set here" — EffectiveProofLayer
	// then falls back to the guard(s) requiring this proof, then "unfiled".
	Layer string
	// Category is a free-form subgroup within Layer, own-declared only (no
	// fixed vocabulary).
	Category string
	// Scope carries this proof's own organizational axes, overriding the
	// declaring context file's Scope default field by field.
	Scope Scope
	// Host is the durable machine identity that recorded this proof
	// (internal/hostid): name plus a stable machine-id-derived id. Nil on
	// proofs written before host stamping, or hand-authored ones.
	Host *ProofHost
	// Epoch is the epoch id (machine id + root filesystem UUID) the proof
	// was recorded under. Empty means unstamped; status treats a non-empty
	// epoch that differs from the current machine's as "from a previous
	// epoch — re-drill".
	Epoch string
}

// ProofHost is the host block a proof record carries: {name, id}. A separate
// type from hostid.Identity so contextspec keeps its zero-dependency stance —
// the shape is the portability contract (docs/SCHEMA.md), the derivation
// lives in internal/hostid.
type ProofHost struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// DrillFreshness names the sqlite column a drill reads to measure RPO: how
// old the newest row is, as of the moment the drill ran.
type DrillFreshness struct {
	Table  string
	Column string
}

// DrillProbe is one liveness probe a "serve" check runs against the booted
// artifact. Type "http" reads Path/ExpectStatus/ExpectBody; type "command"
// reads Run.
type DrillProbe struct {
	Type         string // "http" | "command"
	Path         string // http: URL path; full URL is http://127.0.0.1:$RG_PORT<Path>
	ExpectStatus int    // http: default 200
	ExpectBody   string // http: optional response-body substring
	Run          string // command: sh -c, env RG_PORT/RG_TARGET/RG_SANDBOX; exit 0 = pass
}

// DrillCheck is one typed validation a drill runs against the recovered
// artifact, beyond "the bytes match". Fields are grouped by which Type reads
// them; a check declares only the fields its type uses.
type DrillCheck struct {
	Type string // "byte_identical" | "sqlite" | "git" | "file_tree" | "command" | "serve" | "key_fingerprint"

	// sqlite
	Integrity bool              // run PRAGMA integrity_check, require "ok"
	Tables    map[string]string // table name -> count constraint, e.g. ">= 12000"
	Freshness *DrillFreshness   // optional; feeds the RPO measurement

	// git
	Refs string // optional ref-count constraint, same grammar as Tables values

	// file_tree
	Files     string   // optional file-count constraint, same grammar
	MustExist []string // paths relative to the recovered root that must exist and be non-empty

	// command
	Run string // sh -c, env RG_TARGET/RG_SANDBOX/RG_RECOVERY_SOURCE; exit 0 = pass

	// serve — the L4 rung: boot the recovered artifact and require it to
	// answer. Run (above, reused) is the serve command, sh -c, additionally
	// given RG_PORT. This is process-level isolation only — an isolated
	// throwaway process plus the drill's own sandbox dir, never a container;
	// a user's serve command MAY shell out to docker itself, but the engine
	// has no container dependency and must never claim it does.
	ReadyTimeout time.Duration // default 30s; max wait for the first probe to pass
	Probes       []DrillProbe  // required, at least one; probes[0] also gates readiness

	// key_fingerprint — proves recovered key material is the RIGHT key
	// material, by fingerprint, never by reading, decrypting, or printing
	// the key itself (Wall-1: see internal/drill/keys.go). Keys selects the
	// fingerprinting scheme and is required for this type; at least one of
	// ExpectFrom, Expect, or a positive MinKeys must be declared — parse.go
	// rejects a check that would assert nothing.
	Keys       string   // "ssh" | "gpg" — required for this type
	ExpectFrom string   // optional: a LIVE path whose key fingerprints must ALL appear in the recovered set
	Expect     []string // optional: explicit fingerprints that must appear in the recovered set
	// MinKeys is the minimum number of keys required in the recovered set.
	// Unlike ReadyTimeout, 0 is a legitimate, meaningful value here — "don't
	// enforce a minimum, rely on ExpectFrom/Expect instead" — so it is NOT
	// re-defaulted by the engine the way a zero ReadyTimeout is. Only
	// parse.go's YAML path defaults an OMITTED min_keys: to 1
	// (DefaultKeyFingerprintMinKeys); a DrillCheck built directly in Go
	// (as tests do) gets exactly the MinKeys it was given, including a
	// bare zero value.
	MinKeys int
}

// DrillBudgets are the RTO/RPO ceilings a drill is measured against. A zero
// value on either field means that budget was not declared, not that it was
// met.
type DrillBudgets struct {
	RTO time.Duration
	RPO time.Duration
}

// Drill declares how one artifact is reconstructed from its recovery source.
// It is the only thing in the schema that produces a verified proof, because it
// is the only one that performs the recovery instead of describing it.
type Drill struct {
	Proof          string
	Artifact       string
	Recover        string
	RecoverySource string
	// Validate lists the typed checks run against the recovered artifact. An
	// empty list means the implicit, backward-compatible single
	// byte_identical check: recover, then compare bytes to the live artifact.
	Validate []DrillCheck
	Budgets  DrillBudgets
	// PinCheck is an optional command that only proves the pinned recovery
	// source still exists (exit 0), without performing a recovery. It backs
	// `restoregap drill --pins-only`, the cheap-and-frequent check between
	// full drills.
	PinCheck string
}

// CheckOutcome is the recorded result of one DrillCheck, in declared order.
type CheckOutcome struct {
	Type   string
	Pass   bool
	Detail string // human-readable measurement, e.g. "transactions=12431 (>= 12000)"
}

// Measurements is what a drill run actually measured, recorded onto the
// proof alongside verified/observed_at so a guard's evidence carries numbers,
// not only a pass/fail bit.
type Measurements struct {
	RTOSeconds float64
	RPOSeconds *float64 // nil when no freshness source was declared
	Checks     []CheckOutcome
}

// Scope carries the organizational axes of a recovery estate — "N users, X
// systems, M environments" — orthogonal to Layer (the recovery-domain axis).
// Every field is a free-form string except Tags. A context file's own Scope
// sets the default for every guard/proof it declares; a guard or proof may
// override any individual field (EffectiveScope merges field by field, never
// wholesale). Host defaults to the current hostname when a proof is written
// by drill/attest and declares no host of its own — the seam a later
// machine-id stamp (bead tanner-jyzp) will harden.
type Scope struct {
	Environment string   `json:"environment"`
	System      string   `json:"system"`
	Host        string   `json:"host"`
	Owner       string   `json:"owner"`
	Tags        []string `json:"tags,omitempty"`
}

// Context is a fully parsed and validated restoregap context document.
type Context struct {
	Version int
	Guards  []Guard
	Facts   []Fact
	Proofs  []Proof
	Drills  []Drill
	// Origin describes where this context came from, for evidence
	// rendering: "built-in default local lifeline policy" or a file path.
	Origin string
	// Scope is this file's default organizational scope, applied to every
	// guard/proof it declares that does not override a given field.
	Scope Scope
}

// GuardByID returns a guard by id, if declared.
func (c Context) GuardByID(id string) (Guard, bool) {
	for _, g := range c.Guards {
		if g.ID == id {
			return g, true
		}
	}
	return Guard{}, false
}
