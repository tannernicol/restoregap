package contextspec

import (
	"strings"
	"testing"
	"time"
)

func TestRecoveryLevelString(t *testing.T) {
	cases := []struct {
		level RecoveryLevel
		want  string
	}{
		{LevelDeclared, "declared"},
		{LevelRestores, "restores"},
		{LevelDataValid, "data-valid"},
		{LevelServes, "serves"},
		{RecoveryLevel(99), "declared"}, // unknown value fails closed to the weakest claim
	}
	for _, c := range cases {
		if got := c.level.String(); got != c.want {
			t.Errorf("RecoveryLevel(%d).String() = %q, want %q", c.level, got, c.want)
		}
	}
}

func TestLevelOf(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	observed := now.Add(-time.Hour)
	future := now.Add(24 * time.Hour)
	expired := now.Add(-18 * 24 * time.Hour)

	passing := func(types ...string) []CheckOutcome {
		out := make([]CheckOutcome, 0, len(types))
		for _, t := range types {
			out = append(out, CheckOutcome{Type: t, Pass: true})
		}
		return out
	}

	cases := []struct {
		name       string
		proof      Proof
		wantLevel  RecoveryLevel
		wantReason string // substring; "" means don't check
	}{
		{
			name:       "disputed proof",
			proof:      Proof{Status: ProofRecordDisputed, ObservedAt: &observed, Verified: false},
			wantLevel:  LevelDeclared,
			wantReason: "disputed",
		},
		{
			name:       "stale proof",
			proof:      Proof{Status: ProofRecordStale, ObservedAt: &observed, Verified: true, Measurements: &Measurements{Checks: passing("byte_identical")}},
			wantLevel:  LevelDeclared,
			wantReason: "stale",
		},
		{
			name:       "expired proof",
			proof:      Proof{Status: ProofRecordValidated, ObservedAt: &observed, ExpiresAt: &expired, Verified: true, Measurements: &Measurements{Checks: passing("serve")}},
			wantLevel:  LevelDeclared,
			wantReason: "expired 18d ago",
		},
		{
			name:      "not expired yet",
			proof:     Proof{Status: ProofRecordValidated, ObservedAt: &observed, ExpiresAt: &future, Verified: true, Measurements: &Measurements{Checks: passing("byte_identical")}},
			wantLevel: LevelRestores,
		},
		{
			name:       "observed but never verified",
			proof:      Proof{Status: ProofRecordObserved, ObservedAt: &observed, Verified: false},
			wantLevel:  LevelDeclared,
			wantReason: "not verified",
		},
		{
			name:      "verified, no measurements (legacy/hand-authored proof)",
			proof:     Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true},
			wantLevel: LevelRestores,
		},
		{
			name:      "byte_identical only -> restores",
			proof:     Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{Checks: passing("byte_identical")}},
			wantLevel: LevelRestores,
		},
		{
			name:      "file_tree only -> restores",
			proof:     Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{Checks: passing("file_tree")}},
			wantLevel: LevelRestores,
		},
		{
			name:      "command only -> restores",
			proof:     Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{Checks: passing("command")}},
			wantLevel: LevelRestores,
		},
		{
			name:      "sqlite -> data-valid",
			proof:     Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{Checks: passing("sqlite")}},
			wantLevel: LevelDataValid,
		},
		{
			name:      "git -> data-valid",
			proof:     Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{Checks: passing("git")}},
			wantLevel: LevelDataValid,
		},
		{
			name:      "key_fingerprint -> data-valid",
			proof:     Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{Checks: passing("key_fingerprint")}},
			wantLevel: LevelDataValid,
		},
		{
			name:      "sqlite + command -> data-valid (max rung wins)",
			proof:     Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{Checks: passing("command", "sqlite")}},
			wantLevel: LevelDataValid,
		},
		{
			name:      "serve -> serves",
			proof:     Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{Checks: passing("serve")}},
			wantLevel: LevelServes,
		},
		{
			name:      "serve + sqlite -> serves (max rung, order independent)",
			proof:     Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{Checks: passing("sqlite", "serve")}},
			wantLevel: LevelServes,
		},
		{
			name: "a failing budget_rpo alongside a passing serve check still earns serves",
			proof: Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{
				Checks: []CheckOutcome{{Type: "serve", Pass: true}, {Type: "budget_rpo", Pass: false}},
			}},
			wantLevel: LevelServes,
		},
		{
			name: "a hypothetically-passing budget check never raises the level on its own",
			proof: Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{
				Checks: []CheckOutcome{{Type: "budget_rto", Pass: true}},
			}},
			wantLevel: LevelDeclared,
		},
		{
			name: "a passing check of an unrecognized type never raises the level",
			proof: Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{
				Checks: []CheckOutcome{{Type: "future_check_type", Pass: true}},
			}},
			wantLevel: LevelDeclared,
		},
		{
			name: "only failing checks -> declared (should not happen for Verified:true in practice, but must fail closed)",
			proof: Proof{Status: ProofRecordValidated, ObservedAt: &observed, Verified: true, Measurements: &Measurements{
				Checks: []CheckOutcome{{Type: "serve", Pass: false}},
			}},
			wantLevel: LevelDeclared,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			level, reason := LevelOf(c.proof, now)
			if level != c.wantLevel {
				t.Errorf("level = %s, want %s (reason %q)", level, c.wantLevel, reason)
			}
			if c.wantReason != "" && !strings.Contains(reason, c.wantReason) {
				t.Errorf("reason = %q, want substring %q", reason, c.wantReason)
			}
		})
	}
}

func TestFormatAge(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0d"},
		{23 * time.Hour, "0d"},
		{24 * time.Hour, "1d"},
		{18 * 24 * time.Hour, "18d"},
	}
	for _, c := range cases {
		if got := FormatAge(c.d); got != c.want {
			t.Errorf("FormatAge(%s) = %q, want %q", c.d, got, c.want)
		}
	}
}
