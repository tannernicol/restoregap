// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package intent

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		want    ChangeIntent
		wantErr bool
	}{
		{
			name: "delete_file with singular path",
			yaml: "version: 1\naction: delete_file\npath: ~/.ssh/id_ed25519\ndescription: rm key\n",
			want: ChangeIntent{Action: ActionDeleteFile, Paths: []string{"~/.ssh/id_ed25519"}, Description: "rm key", Source: "action-intent"},
		},
		{
			name: "run_command",
			yaml: "version: 1\naction: run_command\ncommand: openclaw update\n",
			want: ChangeIntent{Action: ActionRunCommand, Command: "openclaw update", Source: "action-intent"},
		},
		{
			name: "package_update",
			yaml: "version: 1\naction: package_update\npackages: [nvidia-driver]\n",
			want: ChangeIntent{Action: ActionPackageUpdate, Packages: []string{"nvidia-driver"}, Source: "action-intent"},
		},
		{
			name:    "missing version",
			yaml:    "action: delete_file\npath: /tmp/x\n",
			wantErr: true,
		},
		{
			name:    "unknown action",
			yaml:    "version: 1\naction: nuke_everything\npath: /tmp/x\n",
			wantErr: true,
		},
		{
			name:    "delete_file without path",
			yaml:    "version: 1\naction: delete_file\n",
			wantErr: true,
		},
		{
			name:    "run_command without command",
			yaml:    "version: 1\naction: run_command\n",
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(c.yaml))
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Action != c.want.Action || got.Command != c.want.Command || got.Description != c.want.Description {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
			if !stringsEqual(got.Paths, c.want.Paths) || !stringsEqual(got.Packages, c.want.Packages) {
				t.Errorf("got paths=%v packages=%v, want paths=%v packages=%v", got.Paths, got.Packages, c.want.Paths, c.want.Packages)
			}
		})
	}
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
