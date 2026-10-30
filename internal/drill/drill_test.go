// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package drill

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// twoPointClock returns start on its first call and start+delta on every call
// after that — enough to control RTO measurement (one call before recovery,
// one after the last check) without a check that itself reads the clock.
func twoPointClock(start time.Time, delta time.Duration) func() time.Time {
	calls := 0
	return func() time.Time {
		calls++
		if calls == 1 {
			return start
		}
		return start.Add(delta)
	}
}

// TestDrillVerifiesFaithfulRecovery: the happy path must produce verified: true
// only when the reconstructed bytes match exactly.
func TestDrillVerifiesFaithfulRecovery(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "table|rows|schema\n")
	src := writeFile(t, dir, "source", "table|rows|schema\n")

	res := Runner{}.Run(Spec{
		Proof:    "faithful",
		Artifact: artifact,
		Recover:  "cat " + src + " > \"$RG_TARGET\"",
	})
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if !res.Verified {
		t.Errorf("identical bytes must verify; detail=%q", res.Detail)
	}
	if res.PreHash != res.PostHash {
		t.Errorf("hashes should match: %s vs %s", res.PreHash, res.PostHash)
	}
}

// TestDrillRejectsAlteredRecovery is the case the whole package exists for: a
// recovery that runs cleanly but restores different content. money.db drifting
// by one row and a password store missing one entry both land here.
func TestDrillRejectsAlteredRecovery(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "entry-a\nentry-b\n")
	src := writeFile(t, dir, "source", "entry-a\n")

	res := Runner{}.Run(Spec{
		Proof:    "altered",
		Artifact: artifact,
		Recover:  "cat " + src + " > \"$RG_TARGET\"",
	})
	if res.Err != nil {
		t.Fatalf("a mismatch is a verdict, not an error: %v", res.Err)
	}
	if res.Verified {
		t.Error("different bytes must NOT verify")
	}
	if !strings.Contains(res.Detail, "do NOT match") {
		t.Errorf("detail should name the mismatch, got %q", res.Detail)
	}
}

// TestDrillRejectsSilentNoOp: a recovery command that exits 0 without writing
// anything is the most dangerous shape — it reads as success. It must fail.
func TestDrillRejectsSilentNoOp(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "content\n")

	res := Runner{}.Run(Spec{Proof: "noop", Artifact: artifact, Recover: "true"})
	if res.Verified {
		t.Fatal("a command that produced nothing must never verify")
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "wrote nothing") {
		t.Errorf("want an explicit empty-output error, got %v", res.Err)
	}
}

// TestDrillRejectsFailedRecoveryCommand: a non-zero recovery command fails
// closed, carrying its own output so the cause is visible.
func TestDrillRejectsFailedRecoveryCommand(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "content\n")

	res := Runner{}.Run(Spec{
		Proof:    "broken",
		Artifact: artifact,
		Recover:  "echo 'recovery source is gone' >&2; exit 3",
	})
	if res.Verified {
		t.Fatal("a failed recovery command must never verify")
	}
	if res.Err == nil || !strings.Contains(res.Err.Error(), "recovery source is gone") {
		t.Errorf("error should carry the command's own output, got %v", res.Err)
	}
}

// TestDrillRejectsMissingArtifact: with no live original there is nothing to
// compare against, so nothing can be proven.
func TestDrillRejectsMissingArtifact(t *testing.T) {
	res := Runner{}.Run(Spec{
		Proof:    "absent",
		Artifact: filepath.Join(t.TempDir(), "does-not-exist"),
		Recover:  "echo x > \"$RG_TARGET\"",
	})
	if res.Verified || res.Err == nil {
		t.Fatalf("missing artifact must fail closed; verified=%v err=%v", res.Verified, res.Err)
	}
}

// TestDrillSandboxIsPrivateAndCleanedUp: the recover command gets an empty
// directory of its own, and it does not survive the run.
func TestDrillSandboxIsPrivateAndCleanedUp(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "ok\n")
	marker := filepath.Join(dir, "sandbox-path")

	res := Runner{}.Run(Spec{
		Proof:    "sandbox",
		Artifact: artifact,
		Recover:  "printf '%s' \"$RG_SANDBOX\" > " + marker + "; [ -z \"$(ls -A \"$RG_SANDBOX\")\" ] || exit 9; echo ok > \"$RG_TARGET\"",
	})
	if res.Err != nil {
		t.Fatalf("sandbox should start empty: %v", res.Err)
	}
	if !res.Verified {
		t.Fatalf("expected verification, detail=%q", res.Detail)
	}
	used, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("recover command did not report its sandbox: %v", err)
	}
	if _, err := os.Stat(string(used)); !os.IsNotExist(err) {
		t.Errorf("sandbox %s should be removed after the drill", used)
	}
}

// TestDrillRequiresCompleteSpec: an incomplete declaration is a config error,
// not a silent pass.
func TestDrillRequiresCompleteSpec(t *testing.T) {
	if res := (Runner{}).Run(Spec{Proof: "x", Artifact: "y"}); res.Err == nil {
		t.Error("a spec with no recover command must error")
	}
}

// ---- typed validate checks, end to end ------------------------------------

// TestDrillWithSQLiteCheckVerifies runs a full drill through Run() with a
// typed sqlite validate check rather than the implicit byte_identical one,
// checking the whole engine wiring: recover, dispatch, Checks, PreHash left
// empty (no byte_identical check ran).
func TestDrillWithSQLiteCheckVerifies(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.db")
	db := createTestDB(t, src)
	if _, err := db.Exec("INSERT INTO transactions (id, date) VALUES (1, '2026-08-10')"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	res := Runner{}.Run(Spec{
		Proof:    "money-db",
		Artifact: filepath.Join(dir, "live.db"), // deliberately does not exist
		Recover:  "cp " + src + " \"$RG_TARGET\"",
		Validate: []contextspec.DrillCheck{{Type: "sqlite", Integrity: true, Tables: map[string]string{"transactions": ">= 1"}}},
	})
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if !res.Verified {
		t.Fatalf("expected verified, detail=%q", res.Detail)
	}
	if res.PreHash != "" {
		t.Errorf("PreHash must stay empty when no byte_identical check ran, got %q", res.PreHash)
	}
	if len(res.Checks) != 1 || res.Checks[0].Type != "sqlite" || !res.Checks[0].Pass {
		t.Errorf("unexpected Checks: %+v", res.Checks)
	}
}

// TestDrillCommandOnlyDoesNotRequireTarget: a command-only validate list may
// leave RG_TARGET unwritten (its invariant script validates through side
// effects it inspects itself) — this must not trip the "wrote nothing" guard
// that protects byte_identical/sqlite/git/file_tree.
func TestDrillCommandOnlyDoesNotRequireTarget(t *testing.T) {
	dir := t.TempDir()
	res := Runner{}.Run(Spec{
		Proof:    "side-effect-only",
		Artifact: filepath.Join(dir, "live"), // deliberately does not exist; PreHash must not be attempted
		Recover:  "true",                     // writes nothing to RG_TARGET
		Validate: []contextspec.DrillCheck{{Type: "command", Run: "echo checked"}},
	})
	if res.Err != nil {
		t.Fatalf("a command-only drill must not require RG_TARGET to exist: %v", res.Err)
	}
	if !res.Verified {
		t.Errorf("expected verified, detail=%q", res.Detail)
	}
}

// ---- budgets ----------------------------------------------------------

func TestApplyBudgetsRTOExceeded(t *testing.T) {
	outcomes, met := applyBudgets(contextspec.DrillBudgets{RTO: time.Second}, 5.0, nil, false, nil)
	if met {
		t.Error("RTO exceeding its budget must not be met")
	}
	if len(outcomes) != 1 || outcomes[0].Type != "budget_rto" || outcomes[0].Pass {
		t.Errorf("expected one failing budget_rto outcome, got %+v", outcomes)
	}
}

func TestApplyBudgetsRTOWithinBudgetIsSilent(t *testing.T) {
	outcomes, met := applyBudgets(contextspec.DrillBudgets{RTO: time.Minute}, 5.0, nil, false, nil)
	if !met {
		t.Error("RTO within budget must be met")
	}
	if len(outcomes) != 0 {
		t.Errorf("a met budget must not add a synthetic outcome, got %+v", outcomes)
	}
}

func TestApplyBudgetsRPOExceeded(t *testing.T) {
	rpo := 100.0
	outcomes, met := applyBudgets(contextspec.DrillBudgets{RPO: time.Second}, 0, &rpo, true, nil)
	if met {
		t.Error("RPO exceeding its budget must not be met")
	}
	if len(outcomes) != 1 || outcomes[0].Type != "budget_rpo" || outcomes[0].Pass {
		t.Errorf("expected one failing budget_rpo outcome, got %+v", outcomes)
	}
}

func TestApplyBudgetsRPOWithinBudgetIsSilent(t *testing.T) {
	rpo := 1.0
	outcomes, met := applyBudgets(contextspec.DrillBudgets{RPO: time.Hour}, 0, &rpo, true, nil)
	if !met {
		t.Error("RPO within budget must be met")
	}
	if len(outcomes) != 0 {
		t.Errorf("a met budget must not add a synthetic outcome, got %+v", outcomes)
	}
}

// TestApplyBudgetsRPONoFreshnessSourceIsHardFailure: declaring an rpo budget
// with nothing anywhere capable of measuring freshness must never pass
// silently — this is the "never a silent pass" rule from the spec.
func TestApplyBudgetsRPONoFreshnessSourceIsHardFailure(t *testing.T) {
	outcomes, met := applyBudgets(contextspec.DrillBudgets{RPO: time.Hour}, 0, nil, false, nil)
	if met {
		t.Error("an rpo budget with no freshness source anywhere must never be met")
	}
	if len(outcomes) != 1 || !strings.Contains(outcomes[0].Detail, "nothing measures freshness") {
		t.Errorf("expected a loud budget_rpo failure naming the gap, got %+v", outcomes)
	}
}

// TestApplyBudgetsRPOSourceDeclaredButMeasurementFailed: when a freshness
// source WAS declared but its own measurement failed at runtime (e.g. an
// unparseable timestamp), that failure already shows up on the underlying
// check — applyBudgets must not double up with a second, misleading "nothing
// measures freshness" outcome.
func TestApplyBudgetsRPOSourceDeclaredButMeasurementFailed(t *testing.T) {
	outcomes, met := applyBudgets(contextspec.DrillBudgets{RPO: time.Hour}, 0, nil, true, nil)
	if !met {
		t.Error("applyBudgets must not itself fail the run when a declared source's own check already reported the failure")
	}
	if len(outcomes) != 0 {
		t.Errorf("expected no synthetic outcome, got %+v", outcomes)
	}
}

// TestRunEndToEndRTOBudgetExceeded exercises the full Run() wiring (not just
// applyBudgets) with an injected clock, confirming the measured RTOSeconds
// and the synthetic budget_rto outcome both reach Result.
func TestRunEndToEndRTOBudgetExceeded(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "same\n")
	clock := twoPointClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 10*time.Second)

	res := Runner{Now: clock}.Run(Spec{
		Proof:    "p",
		Artifact: artifact,
		Recover:  "cat " + artifact + " > \"$RG_TARGET\"",
		Budgets:  contextspec.DrillBudgets{RTO: time.Second},
	})
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if res.Verified {
		t.Fatal("RTO exceeding its budget must not verify, even though the byte_identical check itself passed")
	}
	if res.RTOSeconds != 10 {
		t.Errorf("RTOSeconds = %v, want 10", res.RTOSeconds)
	}
	found := false
	for _, c := range res.Checks {
		if c.Type == "budget_rto" && !c.Pass {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a failing budget_rto outcome in Checks, got %+v", res.Checks)
	}
}

// TestRunEndToEndRPOBudgetWithNoFreshnessSource: a drill that declares an
// rpo budget but only a command check (nothing measures freshness) must fail
// closed even though the command itself passes.
func TestRunEndToEndRPOBudgetWithNoFreshnessSource(t *testing.T) {
	dir := t.TempDir()
	res := Runner{}.Run(Spec{
		Proof:    "p",
		Artifact: filepath.Join(dir, "live"),
		Recover:  "true",
		Validate: []contextspec.DrillCheck{{Type: "command", Run: "echo ok"}},
		Budgets:  contextspec.DrillBudgets{RPO: time.Hour},
	})
	if res.Err != nil {
		t.Fatalf("unexpected error: %v", res.Err)
	}
	if res.Verified {
		t.Fatal("an rpo budget nothing can measure must fail, not verify")
	}
	if res.RPOSeconds != nil {
		t.Errorf("RPOSeconds should stay nil, got %v", *res.RPOSeconds)
	}
}

// ---- RPO precedence across check types -------------------------------

// TestSelectRPOPrecedence pins the cross-check precedence rule directly:
// sqlite's explicit freshness always wins; git and file_tree mtime are
// fallbacks gated by whether an rpo budget makes the extra measurement worth
// taking; ties within a rank go to the first-declared candidate.
func TestSelectRPOPrecedence(t *testing.T) {
	sqlite := &freshnessCandidate{rank: freshnessRankSQLite, seconds: 10}
	git := &freshnessCandidate{rank: freshnessRankGit, seconds: 20}
	fileTree := &freshnessCandidate{rank: freshnessRankFileTree, seconds: 30}

	if got := selectRPO([]*freshnessCandidate{fileTree, git, sqlite}, false); got == nil || *got != 10 {
		t.Errorf("sqlite must win regardless of declared order or autoOK, got %v", got)
	}
	if got := selectRPO([]*freshnessCandidate{fileTree, git}, false); got != nil {
		t.Errorf("git/file_tree must be gated by autoOK (no rpo budget declared), got %v", *got)
	}
	if got := selectRPO([]*freshnessCandidate{fileTree, git}, true); got == nil || *got != 20 {
		t.Errorf("git must win over file_tree once gated open, got %v", got)
	}
	if got := selectRPO([]*freshnessCandidate{fileTree}, true); got == nil || *got != 30 {
		t.Errorf("file_tree mtime is the last-resort fallback, got %v", got)
	}
	if got := selectRPO(nil, true); got != nil {
		t.Errorf("no candidates at all must select nothing, got %v", *got)
	}

	gitFirst := &freshnessCandidate{rank: freshnessRankGit, seconds: 5}
	gitSecond := &freshnessCandidate{rank: freshnessRankGit, seconds: 99}
	if got := selectRPO([]*freshnessCandidate{gitFirst, gitSecond}, true); got == nil || *got != 5 {
		t.Errorf("the first declared candidate within a rank must win, got %v", got)
	}
}

// TestRunSandboxDir proves the sandbox is created under SandboxDir when set.
// It matters because the default OS temp dir is tmpfs (RAM) on most Linux
// systems: a multi-gigabyte restore there spends memory the machine may need
// during the very exercise meant to prove it survives.
func TestRunSandboxDir(t *testing.T) {
	live := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(live, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	sandboxRoot := t.TempDir()

	res := Runner{SandboxDir: sandboxRoot}.Run(Spec{
		Proof:    "sandbox-dir",
		Artifact: live,
		// Record where the engine actually put the sandbox, then satisfy the
		// default byte_identical check.
		Recover: `printf %s "$RG_SANDBOX" > "$RG_SANDBOX/../where"; cp "` + live + `" "$RG_TARGET"`,
	})
	if !res.Verified {
		t.Fatalf("drill did not verify: %+v", res)
	}

	where, err := os.ReadFile(filepath.Join(sandboxRoot, "where"))
	if err != nil {
		t.Fatalf("sandbox was not created under SandboxDir: %v", err)
	}
	if got := string(where); !strings.HasPrefix(got, sandboxRoot+string(os.PathSeparator)) {
		t.Errorf("sandbox %q is not under SandboxDir %q", got, sandboxRoot)
	}
}

// ---- source-unreachable classification (B16) ----------------------------
//
// "The source could not be reached" and "the recovery ran and did not
// verify" must never collapse into one status: the first means the NAS was
// asleep, the second means the copy is bad. These tests pin which engine
// failures land on which side, per the tiebreak rule: unreachable only when
// no recovery/verification was attempted at all, or when the failure output
// carries a source-reachability signature; everything else stays disputed.

func TestLooksLikeUnreachableSource(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{"cat: /backups/nas-host/creds.tar.gz.gpg: No such file or directory", true},
		{"rsync: [Receiver] mkdir /backups/nas-host failed: Permission denied (13)", true},
		{"ssh: connect to host nas port 22: Connection refused", true},
		{"curl: (28) Connection timed out after 30001 milliseconds", true},
		{"ssh: Could not resolve hostname nas.lan: Name or service not known", true},
		{"mount.nfs: mount point /mnt/backups does not exist", true},
		{"cp: cannot stat '/mnt/backups/x': Stale file handle", true},
		{"gpg: decryption failed: Bad session key", false},
		{"restore script: checksum mismatch after unpack", false},
		{"some totally unrelated crash", false},
		{"", false},
	}
	for _, c := range cases {
		if got := looksLikeUnreachableSource([]byte(c.out)); got != c.want {
			t.Errorf("looksLikeUnreachableSource(%q) = %v, want %v", c.out, got, c.want)
		}
	}
}

func TestDrillClassifiesSourceUnreachable(t *testing.T) {
	dir := t.TempDir()
	artifact := writeFile(t, dir, "artifact", "content\n")

	// A recovery command that fails while reporting the source missing —
	// the exact NAS-outage shape — is unreachable: the drill could not even
	// try, so nothing was proven.
	res := Runner{}.Run(Spec{
		Proof:    "nas-source",
		Artifact: artifact,
		Recover:  "cat /nonexistent/recovery/source.gpg > \"$RG_TARGET\"",
	})
	if res.Verified || res.Err == nil {
		t.Fatalf("must fail closed, verified=%v err=%v", res.Verified, res.Err)
	}
	if !res.SourceUnreachable {
		t.Errorf("a recover failure naming the source missing must classify unreachable, err=%v", res.Err)
	}

	// A recovery command that fails for a non-reachability reason (a broken
	// script, a bad key) was ATTEMPTED — it stays on the disputed side.
	res = Runner{}.Run(Spec{
		Proof:    "bad-decrypt",
		Artifact: artifact,
		Recover:  "echo 'gpg: decryption failed: Bad session key' >&2; exit 2",
	})
	if res.Verified || res.Err == nil {
		t.Fatalf("must fail closed, verified=%v err=%v", res.Verified, res.Err)
	}
	if res.SourceUnreachable {
		t.Error("a recover failure with no source-reachability signature must NOT classify unreachable")
	}

	// A command that exits 0 but produces nothing ran a "recovery" and got
	// garbage back — disputed, never unreachable.
	res = Runner{}.Run(Spec{Proof: "silent-noop", Artifact: artifact, Recover: "true"})
	if res.Verified || res.Err == nil {
		t.Fatalf("must fail closed, verified=%v err=%v", res.Verified, res.Err)
	}
	if res.SourceUnreachable {
		t.Error("an exited-0-but-empty recovery is a bad artifact, not an unreachable source")
	}

	// Failures before any recovery is attempted (unreadable live artifact,
	// unusable sandbox) proved nothing either — unreachable.
	res = Runner{}.Run(Spec{
		Proof:    "no-artifact",
		Artifact: filepath.Join(dir, "does-not-exist"),
		Recover:  "true",
	})
	if res.Err == nil || !res.SourceUnreachable {
		t.Errorf("a pre-recovery failure proves nothing; want unreachable, err=%v", res.Err)
	}
	res = Runner{SandboxDir: filepath.Join(dir, "no-such-parent-dir")}.Run(Spec{
		Proof:    "bad-sandbox",
		Artifact: artifact,
		Recover:  "true",
	})
	if res.Err == nil {
		t.Fatal("an unusable sandbox parent must fail closed")
	}
	if !res.SourceUnreachable {
		t.Errorf("a sandbox-creation failure attempts no recovery; want unreachable, err=%v", res.Err)
	}
}
