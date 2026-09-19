// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package drill

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

func TestRunContextHungValidatorFailsClosed(t *testing.T) {
	artifact := t.TempDir() + "/artifact"
	if err := os.WriteFile(artifact, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := Runner{Timeout: 80 * time.Millisecond}
	started := time.Now()
	res := runner.RunContext(context.Background(), Spec{
		Proof:    "hung-validator",
		Artifact: artifact,
		Recover:  ":",
		Validate: []contextspec.DrillCheck{{Type: "command", Run: "sleep 30"}},
	})
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("hung validator was not bounded: %s", elapsed)
	}
	if res.Verified {
		t.Fatalf("hung validator returned verified result: %+v", res)
	}
	if len(res.Checks) != 1 || res.Checks[0].Pass {
		t.Fatalf("hung validator check = %+v", res.Checks)
	}
}
