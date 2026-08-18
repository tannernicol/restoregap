// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package drill proves a recovery by performing it.
//
// Every other signal in this tool is an assertion that someone looked. A drill
// is the one that cannot be faked: it reconstructs the artifact from its
// declared recovery source inside a throwaway sandbox and checks the result
// against typed, measurable outcomes — byte-identity by default, or explicit
// checks (sqlite table shape and integrity, git repo health, a file tree's
// shape, an arbitrary invariant command, or booting the artifact as a real
// service and probing it — see serve.go, the L4 rung) declared by the
// drill. It also measures how long recovery took (RTO) and how stale the
// recovered data was (RPO) against any declared budgets. Only a drill
// produces verified: true, and only that satisfies a guard marked
// require_verified.
//
// It fails closed on purpose. A recovery command that "succeeds" while
// restoring garbage, a source that has quietly gone missing, a sandbox that
// cannot be created, and a budget that was declared but nothing measures are
// all failures — because each of them, believed, would cost you the artifact
// at the exact moment you needed it.
package drill

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// Spec is one declared drill: reconstruct Artifact from RecoverySource by
// running Recover, and check the result against Validate (or, if empty, the
// implicit single byte_identical check). Fields mirror contextspec.Drill.
type Spec struct {
	Proof          string `yaml:"proof"`
	Artifact       string `yaml:"artifact"`
	Recover        string `yaml:"recover"`
	RecoverySource string `yaml:"recovery_source"`
	Validate       []contextspec.DrillCheck
	Budgets        contextspec.DrillBudgets
	PinCheck       string
}

// Result is the outcome of running one Spec.
type Result struct {
	Proof      string
	Verified   bool
	PreHash    string // hash of the live artifact; set only when a byte_identical check ran
	PostHash   string // hash of what the recovery reconstructed; set only when a byte_identical check ran
	Detail     string
	Err        error
	Checks     []contextspec.CheckOutcome // declared checks, in order, plus any synthetic budget_rto/budget_rpo failures
	RTOSeconds float64
	RPOSeconds *float64 // nil when no check measured freshness
}

// Runner executes drills. Now is injectable so callers can pin drill time for
// deterministic runs; the zero value measures real elapsed time.
type Runner struct {
	Now func() time.Time

	// SandboxDir is the parent directory throwaway sandboxes are created in.
	// Empty means the OS temp dir, which on most Linux systems is tmpfs —
	// that is, RAM. Restoring a multi-gigabyte artifact there quietly spends
	// memory the machine may need, and a large enough restore can take the
	// box down during the very exercise meant to prove it survives. Point
	// this at disk for anything big.
	SandboxDir string
}

func (r Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Run performs one drill. The recover command is handed three variables:
//
//	RG_SANDBOX          a private empty directory it may write into freely
//	RG_TARGET           the path it must write the reconstructed artifact to
//	RG_RECOVERY_SOURCE  the declared recovery source
//
// Writing to RG_TARGET rather than stdout means a command can emit a derived
// manifest (a restored database queried for table shape, a secret store
// enumerated by ciphertext hash) instead of raw bytes — which is what makes a
// drill possible for artifacts that must never be printed. RG_TARGET may be a
// single file (byte_identical, sqlite) or a directory (git, file_tree, serve
// — whatever the serve command itself expects); which checks run determines
// what shape it must take.
func (r Runner) Run(spec Spec) Result {
	res := Result{Proof: spec.Proof}

	if spec.Proof == "" || spec.Artifact == "" || spec.Recover == "" {
		res.Err = fmt.Errorf("drill: proof, artifact and recover are all required")
		return res
	}

	checks := spec.Validate
	if len(checks) == 0 {
		checks = []contextspec.DrillCheck{{Type: "byte_identical"}}
	}

	// PreHash is only meaningful — and only computed — when byte_identical is
	// actually running. Other check types must work against a live artifact
	// that is a changing dataset or a directory, neither of which hashFile
	// can read.
	var preHash string
	if hasCheckType(checks, "byte_identical") {
		h, err := hashFile(spec.Artifact)
		if err != nil {
			res.Err = fmt.Errorf("drill %s: cannot read the live artifact %s: %w", spec.Proof, spec.Artifact, err)
			return res
		}
		preHash = h
		res.PreHash = h
	}

	sandbox, err := os.MkdirTemp(r.SandboxDir, "restoregap-drill-")
	if err != nil {
		res.Err = fmt.Errorf("drill %s: cannot create sandbox: %w", spec.Proof, err)
		return res
	}
	defer func() { _ = os.RemoveAll(sandbox) }()

	target := filepath.Join(sandbox, "recovered")

	// The RTO clock runs from just before recovery starts to just after the
	// last check finishes — it measures the whole "how long until I know the
	// data is back and good", not merely the recovery command's exit.
	start := r.now()

	cmd := exec.Command("sh", "-c", spec.Recover)
	cmd.Env = append(os.Environ(),
		"RG_SANDBOX="+sandbox,
		"RG_TARGET="+target,
		"RG_RECOVERY_SOURCE="+spec.RecoverySource,
	)
	out, runErr := cmd.CombinedOutput()
	if runErr != nil {
		res.Err = fmt.Errorf("drill %s: recovery command failed: %w — %s", spec.Proof, runErr, firstLine(out))
		return res
	}

	// A command that exits 0 without producing anything is the most dangerous
	// shape of all: it looks like a successful recovery. This only applies
	// when some declared check actually needs RG_TARGET (everything but a
	// command-only drill, whose invariant script may validate purely through
	// side effects it inspects itself).
	if requiresTarget(checks) {
		if _, err := os.Lstat(target); err != nil {
			res.Err = fmt.Errorf("drill %s: recovery command exited 0 but wrote nothing to RG_TARGET", spec.Proof)
			return res
		}
	}

	env := checkEnv{
		Target:         target,
		Sandbox:        sandbox,
		RecoverySource: spec.RecoverySource,
		PreHash:        preHash,
		Now:            r.now,
		Artifact:       spec.Artifact,
	}

	outcomes := make([]contextspec.CheckOutcome, 0, len(checks))
	candidates := make([]*freshnessCandidate, 0, len(checks))
	allPassed := true
	for _, c := range checks {
		cr := runCheck(c, env)
		outcomes = append(outcomes, cr.outcome)
		if !cr.outcome.Pass {
			allPassed = false
		}
		if cr.postHash != "" {
			res.PostHash = cr.postHash
		}
		candidates = append(candidates, cr.rpo)
	}

	res.RTOSeconds = r.now().Sub(start).Seconds()
	res.RPOSeconds = selectRPO(candidates, spec.Budgets.RPO > 0)

	outcomes, budgetsMet := applyBudgets(spec.Budgets, res.RTOSeconds, res.RPOSeconds, freshnessDeclared(checks), outcomes)

	res.Checks = outcomes
	res.Verified = allPassed && budgetsMet
	res.Detail = summarizeDetail(res.Verified, outcomes)
	return res
}

// applyBudgets evaluates declared RTO/RPO budgets against what was measured
// and appends a synthetic check outcome for each one that fails — a budget
// declared but never met must be as visible in the scorecard as a failing
// check, never a silent pass. Declaring an rpo budget with nothing capable of
// measuring freshness is itself a hard failure (loud, not silent).
func applyBudgets(budgets contextspec.DrillBudgets, rtoSeconds float64, rpoSeconds *float64, freshnessAvailable bool, outcomes []contextspec.CheckOutcome) ([]contextspec.CheckOutcome, bool) {
	met := true

	if budgets.RTO > 0 && rtoSeconds > budgets.RTO.Seconds() {
		met = false
		outcomes = append(outcomes, contextspec.CheckOutcome{
			Type: "budget_rto", Pass: false,
			Detail: fmt.Sprintf("RTO %s exceeds budget %s", time.Duration(rtoSeconds*float64(time.Second)).Round(time.Millisecond), budgets.RTO),
		})
	}

	if budgets.RPO > 0 {
		switch {
		case rpoSeconds == nil && !freshnessAvailable:
			met = false
			outcomes = append(outcomes, contextspec.CheckOutcome{
				Type: "budget_rpo", Pass: false,
				Detail: "rpo budget declared but nothing measures freshness",
			})
		case rpoSeconds != nil && *rpoSeconds > budgets.RPO.Seconds():
			met = false
			outcomes = append(outcomes, contextspec.CheckOutcome{
				Type: "budget_rpo", Pass: false,
				Detail: fmt.Sprintf("RPO %s exceeds budget %s", time.Duration(*rpoSeconds*float64(time.Second)).Round(time.Second), budgets.RPO),
			})
		}
	}

	return outcomes, met
}

// hasCheckType reports whether any declared check is of the given type.
func hasCheckType(checks []contextspec.DrillCheck, t string) bool {
	for _, c := range checks {
		if c.Type == t {
			return true
		}
	}
	return false
}

// requiresTarget reports whether any declared check needs RG_TARGET to exist
// as a readable file or directory. Only a command-only drill can legitimately
// leave RG_TARGET unwritten.
func requiresTarget(checks []contextspec.DrillCheck) bool {
	for _, c := range checks {
		if c.Type != "command" {
			return true
		}
	}
	return false
}

// freshnessDeclared reports whether any declared check is CAPABLE of
// measuring RPO: a sqlite check with an explicit freshness block, or a
// git/file_tree check (whose freshness is auto-derived). It distinguishes "a
// source exists but its own measurement failed at runtime" — already visible
// as that check's failure — from "no rpo budget declared here could ever be
// met", which needs its own loud synthetic failure.
func freshnessDeclared(checks []contextspec.DrillCheck) bool {
	for _, c := range checks {
		switch c.Type {
		case "sqlite":
			if c.Freshness != nil {
				return true
			}
		case "git", "file_tree":
			return true
		}
	}
	return false
}

// selectRPO applies cross-check RPO precedence: sqlite's explicit freshness
// declaration always wins; git and file_tree mtime are fallbacks, used only
// when autoOK (an RPO budget was declared, making the extra measurement
// worth taking). Within a rank, the first declared check wins.
func selectRPO(candidates []*freshnessCandidate, autoOK bool) *float64 {
	var best *freshnessCandidate
	for _, c := range candidates {
		if c == nil {
			continue
		}
		if c.rank != freshnessRankSQLite && !autoOK {
			continue
		}
		if best == nil || c.rank < best.rank {
			best = c
		}
	}
	if best == nil {
		return nil
	}
	seconds := best.seconds
	return &seconds
}

// summarizeDetail renders the CLI-facing one-line summary. A verified drill
// lists every check's detail in declared order; a failed one names the
// failing checks first so the cause is visible before anything else.
func summarizeDetail(verified bool, outcomes []contextspec.CheckOutcome) string {
	if verified {
		parts := make([]string, 0, len(outcomes))
		for _, o := range outcomes {
			parts = append(parts, o.Detail)
		}
		return strings.Join(parts, "; ")
	}
	var failing, passing []string
	for _, o := range outcomes {
		if o.Pass {
			passing = append(passing, o.Detail)
		} else {
			failing = append(failing, fmt.Sprintf("%s: %s", o.Type, o.Detail))
		}
	}
	return strings.Join(append(failing, passing...), "; ")
}

func truncate(h string) string {
	if len(h) > 21 {
		return h[:21]
	}
	return h
}

func firstLine(b []byte) string {
	s := string(b)
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
