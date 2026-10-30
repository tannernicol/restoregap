// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Restore Gap contributors

package contextspec

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadAllUnionsScopedCommandCoverage(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	org := write("org.yml", "version: 2\ncoverage:\n  commands: [\"ssh nas *\"]\n")
	host := write("host.yml", "version: 2\ncoverage:\n  commands: [\"ssh nas *\", \"ssh router *\"]\n")
	ctx, err := LoadAll([]string{org, host})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"ssh nas *", "ssh router *"}; !reflect.DeepEqual(ctx.Coverage.Commands, want) {
		t.Fatalf("coverage commands = %v, want %v", ctx.Coverage.Commands, want)
	}
}
