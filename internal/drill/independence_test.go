package drill

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunRejectsRecoverySourceAlias(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "live")
	if err := os.WriteFile(artifact, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "source")
	if err := os.Symlink(artifact, alias); err != nil {
		t.Fatal(err)
	}
	res := (Runner{}).RunContext(context.Background(), Spec{
		Proof: "same", Artifact: artifact, RecoverySource: alias, Recover: "exit 0",
	})
	if res.Verified || res.Err == nil {
		t.Fatalf("alias source must fail closed: %+v", res)
	}
}
