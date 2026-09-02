package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain gives every test in this package an isolated XDG_CONFIG_HOME for
// the whole run. ContextPaths' final tier reads the user config directory,
// so without this a "nothing discoverable" test on a machine with a real
// ~/.config/restoregap (this homelab has one) would find it. RESTOREGAP_CONTEXT
// is cleared so no test result depends on the outer shell's environment.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "restoregap-discovery-test-config-*")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("XDG_CONFIG_HOME", dir)
	_ = os.Unsetenv("RESTOREGAP_CONTEXT")
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestContextPathsEnvVarColonList(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.yml")
	pathB := filepath.Join(dir, "b.yml")
	t.Setenv("RESTOREGAP_CONTEXT", pathA+":"+pathB)
	t.Chdir(t.TempDir())

	got := ContextPaths()
	if len(got) != 2 || got[0] != pathA || got[1] != pathB {
		t.Errorf("got %v, want [%q %q]", got, pathA, pathB)
	}
}

func TestContextPathsEnvVarSingleValueNoColon(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "/some/path.yml")
	t.Chdir(t.TempDir())

	got := ContextPaths()
	if len(got) != 1 || got[0] != "/some/path.yml" {
		t.Errorf("got %v, want [/some/path.yml]", got)
	}
}

func TestContextPathsPrefersLocalOverPlain(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "")
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("restoregap.local.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("restoregap.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ContextPaths()
	if len(got) != 1 || got[0] != "restoregap.local.yml" {
		t.Errorf("got %v, want [restoregap.local.yml]", got)
	}
}

func TestContextPathsFallsBackToPlainYml(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "")
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("restoregap.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ContextPaths()
	if len(got) != 1 || got[0] != "restoregap.yml" {
		t.Errorf("got %v, want [restoregap.yml]", got)
	}
}

func TestContextPathsNothingDiscoverable(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "")
	t.Chdir(t.TempDir())

	if got := ContextPaths(); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// writeConfigContext writes a minimal valid context document into a config
// directory laid out under cfgHome/restoregap/ and returns its full path.
func writeConfigContext(t *testing.T, cfgHome, name, body string) string {
	t.Helper()
	path := filepath.Join(cfgHome, "restoregap", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// newConfigHome returns an empty config-directory root the test can populate
// and points XDG_CONFIG_HOME at it, so no test ever reads the real
// ~/.config/restoregap.
func newConfigHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return dir
}

func TestContextPathsConfigDirUsedWhenCwdHasNoContext(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "")
	cfgHome := newConfigHome(t)
	// Written out of sorted order to prove the result is sorted, not
	// insertion- or glob-ordered.
	c := writeConfigContext(t, cfgHome, "c-drill.yml", "version: 2\n")
	a := writeConfigContext(t, cfgHome, "a-drill.yml", "version: 2\n")
	b := writeConfigContext(t, cfgHome, "b-drill.yml", "version: 2\n")
	t.Chdir(t.TempDir())

	got := ContextPaths()
	want := []string{a, b, c}
	if len(got) != 3 || got[0] != a || got[1] != b || got[2] != c {
		t.Errorf("got %v, want %v (sorted, deterministic)", got, want)
	}
}

func TestContextPathsCwdLocalWinsOverConfigDir(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "")
	cfgHome := newConfigHome(t)
	writeConfigContext(t, cfgHome, "a-drill.yml", "version: 2\n")
	writeConfigContext(t, cfgHome, "b-drill.yml", "version: 2\n")
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("restoregap.local.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ContextPaths()
	if len(got) != 1 || got[0] != "restoregap.local.yml" {
		t.Errorf("got %v, want [restoregap.local.yml] — the cwd tier outranks the config dir", got)
	}
}

func TestContextPathsEnvVarWinsOverCwdAndConfigDir(t *testing.T) {
	envPath := filepath.Join(t.TempDir(), "from-env.yml")
	if err := os.WriteFile(envPath, []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RESTOREGAP_CONTEXT", envPath)
	cfgHome := newConfigHome(t)
	writeConfigContext(t, cfgHome, "a-drill.yml", "version: 2\n")
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile("restoregap.local.yml", []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := ContextPaths()
	if len(got) != 1 || got[0] != envPath {
		t.Errorf("got %v, want [%q] — $RESTOREGAP_CONTEXT outranks every other tier", got, envPath)
	}
}

func TestContextPathsConfigDirExcludesNonContextFiles(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "")
	cases := []struct {
		name string
		want bool // want included in the discovery result
	}{
		{name: "drill-a.yml", want: true},
		{name: "notes.bak.yml", want: false},
		{name: "weekly.bak.20260818.yml", want: false},
		{name: "old.archive.yml", want: false},
		{name: "drill-sealed.yml", want: false},
		{name: "nas-access-sealed.yml", want: false},
		// Near-miss keep side: shares the surface word but not the
		// pattern, so it must stay discoverable.
		{name: "unsealed-notes.yml", want: true},
	}
	cfgHome := newConfigHome(t)
	var want []string
	for _, tc := range cases {
		path := writeConfigContext(t, cfgHome, tc.name, "version: 2\n")
		if tc.want {
			want = append(want, path)
		}
	}
	t.Chdir(t.TempDir())

	got := ContextPaths()
	if len(got) != len(want) {
		t.Errorf("got %v, want %v", got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
			return
		}
	}
}

func TestContextPathsConfigDirSkipsUnparseableYmlWithWarning(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "")
	cfgHome := newConfigHome(t)
	good := writeConfigContext(t, cfgHome, "drill-a.yml", "version: 2\n")
	broken := writeConfigContext(t, cfgHome, "broken.yml", "version: 3\n") // not a v2 context document
	t.Chdir(t.TempDir())

	var warnings []string
	orig := warnf
	warnf = func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	}
	t.Cleanup(func() { warnf = orig })

	got := ContextPaths()
	if len(got) != 1 || got[0] != good {
		t.Errorf("got %v, want [%q] — the unparseable file must be skipped, not fatal", got, good)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], broken) {
		t.Errorf("expected exactly one warning naming %q, got %v", broken, warnings)
	}
}

func TestPolicyDirsDefaultIsOrgThenHost(t *testing.T) {
	t.Setenv("RESTOREGAP_POLICY_DIRS", "")
	cfgHome := newConfigHome(t)

	got := PolicyDirs()
	want := []string{"/etc/restoregap", filepath.Join(cfgHome, "restoregap")}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPolicyDirsEnvVarColonList(t *testing.T) {
	t.Setenv("RESTOREGAP_POLICY_DIRS", "/org/a:/org/b:/host/c")
	got := PolicyDirs()
	want := []string{"/org/a", "/org/b", "/host/c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestLayeredConfigFilesGroupsByDirectoryInOrder(t *testing.T) {
	orgDir := t.TempDir()
	hostDir := t.TempDir()
	t.Setenv("RESTOREGAP_POLICY_DIRS", orgDir+":"+hostDir)

	orgFile := filepath.Join(orgDir, "org.yml")
	if err := os.WriteFile(orgFile, []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostFile := filepath.Join(hostDir, "host.yml")
	if err := os.WriteFile(hostFile, []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	groups := LayeredConfigFiles()
	if len(groups) != 2 {
		t.Fatalf("expected one group per policy dir, got %d: %v", len(groups), groups)
	}
	if len(groups[0]) != 1 || groups[0][0] != orgFile {
		t.Errorf("expected org group %v, got %v", []string{orgFile}, groups[0])
	}
	if len(groups[1]) != 1 || groups[1][0] != hostFile {
		t.Errorf("expected host group %v, got %v", []string{hostFile}, groups[1])
	}
}

func TestLayeredConfigFilesMissingOrgDirIsEmptyNotError(t *testing.T) {
	hostDir := t.TempDir()
	t.Setenv("RESTOREGAP_POLICY_DIRS", "/does/not/exist/restoregap-org:"+hostDir)
	hostFile := filepath.Join(hostDir, "host.yml")
	if err := os.WriteFile(hostFile, []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	groups := LayeredConfigFiles()
	if len(groups) != 2 {
		t.Fatalf("expected two groups, got %d", len(groups))
	}
	if len(groups[0]) != 0 {
		t.Errorf("expected the missing org dir to contribute no files, got %v", groups[0])
	}
	if len(groups[1]) != 1 || groups[1][0] != hostFile {
		t.Errorf("expected host group %v, got %v", []string{hostFile}, groups[1])
	}
}

func TestContextPathsUnchangedWithNoOrgDir(t *testing.T) {
	// The default RESTOREGAP_POLICY_DIRS org tier (/etc/restoregap) does not
	// exist on a normal dev/test box, so ContextPaths' final tier must
	// resolve to exactly the same files the pre-layering single-directory
	// discovery returned.
	t.Setenv("RESTOREGAP_CONTEXT", "")
	t.Setenv("RESTOREGAP_POLICY_DIRS", "")
	cfgHome := newConfigHome(t)
	a := writeConfigContext(t, cfgHome, "a-drill.yml", "version: 2\n")
	b := writeConfigContext(t, cfgHome, "b-drill.yml", "version: 2\n")
	t.Chdir(t.TempDir())

	got := ContextPaths()
	want := []string{a, b}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestContextPathsIncludesOrgLayerFilesBeforeHost(t *testing.T) {
	t.Setenv("RESTOREGAP_CONTEXT", "")
	orgDir := t.TempDir()
	hostDir := t.TempDir()
	t.Setenv("RESTOREGAP_POLICY_DIRS", orgDir+":"+hostDir)
	orgFile := filepath.Join(orgDir, "org.yml")
	if err := os.WriteFile(orgFile, []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostFile := filepath.Join(hostDir, "host.yml")
	if err := os.WriteFile(hostFile, []byte("version: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())

	got := ContextPaths()
	if len(got) != 2 || got[0] != orgFile || got[1] != hostFile {
		t.Errorf("got %v, want [%q %q] (org before host)", got, orgFile, hostFile)
	}
}
