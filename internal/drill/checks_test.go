package drill

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

func fixedEnv(target, sandbox string, now time.Time) checkEnv {
	return checkEnv{Target: target, Sandbox: sandbox, Now: func() time.Time { return now }}
}

// ---- byte_identical ---------------------------------------------------

func TestRunByteIdenticalPassAndFail(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "recovered")
	writeFile(t, dir, "recovered", "same bytes\n")

	pre, err := hashFile(target)
	if err != nil {
		t.Fatalf("hashFile: %v", err)
	}

	res := runCheck(contextspec.DrillCheck{Type: "byte_identical"}, checkEnv{Target: target, PreHash: pre, Now: time.Now})
	if !res.outcome.Pass {
		t.Errorf("identical bytes should pass, got %+v", res.outcome)
	}
	if res.postHash != pre {
		t.Errorf("postHash = %q, want %q", res.postHash, pre)
	}

	res = runCheck(contextspec.DrillCheck{Type: "byte_identical"}, checkEnv{Target: target, PreHash: "sha256:different", Now: time.Now})
	if res.outcome.Pass {
		t.Error("mismatched bytes must not pass")
	}
	if !strings.Contains(res.outcome.Detail, "do NOT match") {
		t.Errorf("detail should name the mismatch, got %q", res.outcome.Detail)
	}
}

// ---- sqlite -------------------------------------------------------------

func createTestDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec("CREATE TABLE transactions (id INTEGER PRIMARY KEY, date TEXT)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func TestRunSQLitePass(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "money.db")
	db := createTestDB(t, path)
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	for i, ts := range []string{"2026-08-09T00:00:00Z", "2026-08-10T00:00:00Z"} {
		if _, err := db.Exec("INSERT INTO transactions (id, date) VALUES (?, ?)", i, ts); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	c := contextspec.DrillCheck{
		Type:      "sqlite",
		Integrity: true,
		Tables:    map[string]string{"transactions": ">= 2"},
		Freshness: &contextspec.DrillFreshness{Table: "transactions", Column: "date"},
	}
	res := runCheck(c, fixedEnv(path, dir, now))
	if !res.outcome.Pass {
		t.Fatalf("expected pass, got %+v", res.outcome)
	}
	if !strings.Contains(res.outcome.Detail, "integrity ok") || !strings.Contains(res.outcome.Detail, "transactions=2 (>= 2)") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}
	if res.rpo == nil {
		t.Fatal("expected an RPO candidate from freshness")
	}
	wantSeconds := 12 * time.Hour.Seconds() // now (12:00) - newest row (2026-08-10T00:00:00Z)
	if res.rpo.seconds != wantSeconds {
		t.Errorf("rpo seconds = %v, want %v (now - newest date)", res.rpo.seconds, wantSeconds)
	}
	if res.rpo.rank != freshnessRankSQLite {
		t.Errorf("rpo rank = %d, want sqlite rank", res.rpo.rank)
	}
}

func TestRunSQLiteFailTableCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "money.db")
	db := createTestDB(t, path)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	c := contextspec.DrillCheck{Type: "sqlite", Tables: map[string]string{"transactions": ">= 1"}}
	res := runCheck(c, fixedEnv(path, dir, time.Now()))
	if res.outcome.Pass {
		t.Error("an empty table failing its count constraint must not pass")
	}
	if !strings.Contains(res.outcome.Detail, "transactions=0 (>= 1)") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}
}

func TestRunSQLiteFailMissingTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "money.db")
	createTestDB(t, path)

	c := contextspec.DrillCheck{Type: "sqlite", Tables: map[string]string{"nonexistent_table": ">= 0"}}
	res := runCheck(c, fixedEnv(path, dir, time.Now()))
	if res.outcome.Pass {
		t.Error("a query against a missing table must not pass")
	}
	if !strings.Contains(res.outcome.Detail, "query failed") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}
}

func TestRunSQLiteFailUnparseableFreshness(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "money.db")
	db := createTestDB(t, path)
	if _, err := db.Exec("INSERT INTO transactions (id, date) VALUES (1, 'not-a-timestamp')"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	c := contextspec.DrillCheck{Type: "sqlite", Freshness: &contextspec.DrillFreshness{Table: "transactions", Column: "date"}}
	res := runCheck(c, fixedEnv(path, dir, time.Now()))
	if res.outcome.Pass {
		t.Error("an unparseable freshness value must not pass")
	}
	if res.rpo != nil {
		t.Error("an unparseable freshness value must not produce an RPO candidate")
	}
	if !strings.Contains(res.outcome.Detail, "not-a-timestamp") {
		t.Errorf("detail should name the offending value (it's a date column, not a secret), got %q", res.outcome.Detail)
	}
}

func TestRunSQLiteFreshnessEmptyTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "money.db")
	createTestDB(t, path) // table exists, zero rows

	c := contextspec.DrillCheck{Type: "sqlite", Freshness: &contextspec.DrillFreshness{Table: "transactions", Column: "date"}}
	res := runCheck(c, fixedEnv(path, dir, time.Now()))
	if res.outcome.Pass {
		t.Error("freshness against an empty table has nothing to measure and must not pass")
	}
	if res.rpo != nil {
		t.Error("an empty table must not produce an RPO candidate")
	}
}

// TestRunSQLiteFailIntegrity corrupts a valid database's page bytes (past
// the 100-byte header, so it still opens) and expects PRAGMA
// integrity_check to report something other than "ok".
func TestRunSQLiteFailIntegrity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "money.db")
	db := createTestDB(t, path)
	for i := 0; i < 50; i++ {
		if _, err := db.Exec("INSERT INTO transactions (id, date) VALUES (?, ?)", i, "2026-08-10"); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read db file: %v", err)
	}
	if len(raw) < 4096 {
		t.Fatalf("db file too small to corrupt reliably: %d bytes", len(raw))
	}
	for i := 200; i < 4096; i++ { // past the header and first page's schema
		raw[i] ^= 0xFF
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write corrupted db: %v", err)
	}

	res := runCheck(contextspec.DrillCheck{Type: "sqlite", Integrity: true}, fixedEnv(path, dir, time.Now()))
	if res.outcome.Pass {
		t.Fatalf("a corrupted database must fail integrity_check, got %+v", res.outcome)
	}
}

func TestRunSQLiteFailNotADatabase(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "not-a-db", "hello\n")
	res := runCheck(contextspec.DrillCheck{Type: "sqlite", Integrity: true}, fixedEnv(path, dir, time.Now()))
	if res.outcome.Pass {
		t.Error("a non-sqlite file must not pass")
	}
}

// ---- git ------------------------------------------------------------------

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found on PATH")
	}
}

func gitInit(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q")
	writeFile(t, dir, "a.txt", "hello\n")
	run("add", "a.txt")
	run("commit", "-q", "-m", "initial")
}

func TestRunGitPass(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitInit(t, dir)

	res := runCheck(contextspec.DrillCheck{Type: "git", Refs: ">= 1"}, fixedEnv(dir, dir, time.Now()))
	if !res.outcome.Pass {
		t.Fatalf("expected pass, got %+v", res.outcome)
	}
	if !strings.Contains(res.outcome.Detail, "fsck ok") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}
	if res.rpo == nil || res.rpo.rank != freshnessRankGit {
		t.Errorf("expected a git-ranked RPO candidate, got %+v", res.rpo)
	}
}

func TestRunGitFailNotARepo(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	res := runCheck(contextspec.DrillCheck{Type: "git"}, fixedEnv(dir, dir, time.Now()))
	if res.outcome.Pass {
		t.Error("a plain directory is not a git repository")
	}
}

func TestRunGitFailRefsConstraint(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	gitInit(t, dir)

	res := runCheck(contextspec.DrillCheck{Type: "git", Refs: ">= 5"}, fixedEnv(dir, dir, time.Now()))
	if res.outcome.Pass {
		t.Error("a repo with 1 ref must not satisfy >= 5")
	}
}

func TestRunGitFailNoGitBinary(t *testing.T) {
	dir := t.TempDir()
	empty := t.TempDir() // an empty dir has no git executable in it
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	if err := os.Setenv("PATH", empty); err != nil {
		t.Fatalf("Setenv: %v", err)
	}

	res := runCheck(contextspec.DrillCheck{Type: "git"}, fixedEnv(dir, dir, time.Now()))
	if res.outcome.Pass {
		t.Fatal("a git check must fail closed when git itself is missing, never skip")
	}
	if !strings.Contains(res.outcome.Detail, "git not found") {
		t.Errorf("unexpected detail: %q", res.outcome.Detail)
	}
}

// ---- file_tree --------------------------------------------------------

func TestRunFileTreePass(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.txt", "x")
	writeFile(t, dir, "b.txt", "y")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFile(t, dir, "sub/c.txt", "z")

	c := contextspec.DrillCheck{Type: "file_tree", Files: ">= 3", MustExist: []string{"a.txt", "sub/c.txt"}}
	res := runCheck(c, fixedEnv(dir, dir, time.Now()))
	if !res.outcome.Pass {
		t.Fatalf("expected pass, got %+v", res.outcome)
	}
	if res.rpo == nil || res.rpo.rank != freshnessRankFileTree {
		t.Errorf("expected a file_tree-ranked RPO candidate, got %+v", res.rpo)
	}
}

func TestRunFileTreeFailMustExist(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "present.txt", "x")
	writeFile(t, dir, "empty.txt", "")

	c := contextspec.DrillCheck{Type: "file_tree", MustExist: []string{"present.txt", "empty.txt", "missing.txt"}}
	res := runCheck(c, fixedEnv(dir, dir, time.Now()))
	if res.outcome.Pass {
		t.Error("missing/empty must_exist entries must fail the check")
	}
	if !strings.Contains(res.outcome.Detail, "missing.txt (missing)") || !strings.Contains(res.outcome.Detail, "empty.txt (empty)") {
		t.Errorf("detail should name each failing path, got %q", res.outcome.Detail)
	}
}

func TestRunFileTreeFailNotADirectory(t *testing.T) {
	dir := t.TempDir()
	file := writeFile(t, dir, "notadir", "x")
	res := runCheck(contextspec.DrillCheck{Type: "file_tree"}, fixedEnv(file, dir, time.Now()))
	if res.outcome.Pass {
		t.Error("a file target must not pass a file_tree check")
	}
}

// ---- command ------------------------------------------------------------

func TestRunCommandPassAndFail(t *testing.T) {
	dir := t.TempDir()
	res := runCheck(contextspec.DrillCheck{Type: "command", Run: "echo all good"}, fixedEnv(dir, dir, time.Now()))
	if !res.outcome.Pass || res.outcome.Detail != "all good" {
		t.Errorf("unexpected result: %+v", res.outcome)
	}

	res = runCheck(contextspec.DrillCheck{Type: "command", Run: "echo nope >&2; exit 1"}, fixedEnv(dir, dir, time.Now()))
	if res.outcome.Pass {
		t.Error("a nonzero exit must fail the check")
	}
	if !strings.Contains(res.outcome.Detail, "nope") {
		t.Errorf("detail should carry the command's own output, got %q", res.outcome.Detail)
	}
}

func TestRunCommandReceivesEnv(t *testing.T) {
	dir := t.TempDir()
	res := runCheck(contextspec.DrillCheck{Type: "command", Run: `[ -n "$RG_TARGET" ] && [ -n "$RG_SANDBOX" ] && echo ok`},
		fixedEnv(filepath.Join(dir, "target"), dir, time.Now()))
	if !res.outcome.Pass || res.outcome.Detail != "ok" {
		t.Errorf("command should see RG_TARGET/RG_SANDBOX, got %+v", res.outcome)
	}
}

// ---- unknown type -------------------------------------------------------

func TestRunCheckUnknownType(t *testing.T) {
	res := runCheck(contextspec.DrillCheck{Type: "bogus"}, fixedEnv("", "", time.Now()))
	if res.outcome.Pass {
		t.Error("an unknown check type must fail closed, never pass")
	}
}
