package drill

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// ---- floor() ---------------------------------------------------------------

// TestFloor covers the documented examples (2379 -> 2000, 1708 -> 1400,
// 65 -> 55, 46 -> 39) plus the edges: under 10 is always 1, and the
// otherwise-branch boundary at exactly 10.
func TestFloor(t *testing.T) {
	cases := []struct{ measured, want int }{
		{0, 1},
		{1, 1},
		{9, 1},
		{10, 8},
		{46, 39},
		{65, 55},
		{99, 84},
		{1708, 1400},
		{2379, 2000},
	}
	for _, c := range cases {
		if got := Floor(c.measured); got != c.want {
			t.Errorf("Floor(%d) = %d, want %d", c.measured, got, c.want)
		}
	}
}

// TestFloorNeverExceedsMeasured: a floor with more headroom than the
// measurement itself would be a false comfort, not a constraint.
func TestFloorNeverExceedsMeasured(t *testing.T) {
	for _, measured := range []int{10, 25, 100, 1000, 999999} {
		if got := Floor(measured); got >= measured {
			t.Errorf("Floor(%d) = %d, want strictly less than measured", measured, got)
		}
	}
}

// ---- round-trip helper ------------------------------------------------------

// assertProposeRoundTrips writes doc (Propose's output) as a v2 context file,
// parses it via contextspec, and asserts every declared drill lints clean of
// ERROR-level findings — the contract Propose's output must satisfy.
func assertProposeRoundTrips(t *testing.T, doc string) contextspec.Context {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proposed.yml")
	full := doc // Propose emits a complete context, version line included
	if err := os.WriteFile(path, []byte(full), 0o644); err != nil {
		t.Fatalf("write proposed context: %v", err)
	}
	ctx, err := contextspec.Load(path)
	if err != nil {
		t.Fatalf("proposed output does not parse as a v2 context: %v\n---\n%s", err, full)
	}
	if len(ctx.Drills) != 1 {
		t.Fatalf("expected exactly 1 drill, got %d", len(ctx.Drills))
	}
	for _, f := range Lint(ctx.Drills[0]) {
		if f.Severity == LintError {
			t.Errorf("proposed output has an ERROR-level lint finding: %s: %s\n---\n%s", f.Proof, f.Message, full)
		}
	}
	return ctx
}

// ---- DetectArtifactType -----------------------------------------------------

func TestDetectArtifactTypeMissingPath(t *testing.T) {
	if _, err := DetectArtifactType(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected an error for a nonexistent path")
	}
}

func TestDetectArtifactTypeSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	mustCreateSQLite(t, path, nil)
	if kind, err := DetectArtifactType(path); err != nil || kind != "sqlite" {
		t.Fatalf("DetectArtifactType(sqlite fixture) = %q, %v, want \"sqlite\"", kind, err)
	}
}

func TestDetectArtifactTypeByteIdentical(t *testing.T) {
	dir := t.TempDir()
	path := writeFileT(t, dir, "plain.bin", "not a database\n")
	if kind, err := DetectArtifactType(path); err != nil || kind != "byte_identical" {
		t.Fatalf("DetectArtifactType(plain file) = %q, %v, want \"byte_identical\"", kind, err)
	}
}

func TestDetectArtifactTypeGitWorktree(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	if kind, err := DetectArtifactType(dir); err != nil || kind != "git" {
		t.Fatalf("DetectArtifactType(git worktree) = %q, %v, want \"git\"", kind, err)
	}
}

func TestDetectArtifactTypeGitBare(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "--bare", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v: %s", err, out)
	}
	if kind, err := DetectArtifactType(dir); err != nil || kind != "git" {
		t.Fatalf("DetectArtifactType(bare git repo) = %q, %v, want \"git\"", kind, err)
	}
}

func TestDetectArtifactTypeKeysBySSHFile(t *testing.T) {
	dir := t.TempDir()
	genSSHKeypair(t, dir, "id_ed25519")
	if kind, err := DetectArtifactType(dir); err != nil || kind != "keys" {
		t.Fatalf("DetectArtifactType(dir with id_ed25519) = %q, %v, want \"keys\"", kind, err)
	}
}

func TestDetectArtifactTypeKeysByDirName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".ssh")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if kind, err := DetectArtifactType(dir); err != nil || kind != "keys" {
		t.Fatalf("DetectArtifactType(.ssh dir, empty) = %q, %v, want \"keys\"", kind, err)
	}
}

func TestDetectArtifactTypeFileTree(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, dir, "a.txt", "a")
	writeFileT(t, dir, "b.txt", "b")
	if kind, err := DetectArtifactType(dir); err != nil || kind != "file_tree" {
		t.Fatalf("DetectArtifactType(plain dir) = %q, %v, want \"file_tree\"", kind, err)
	}
}

// ---- Propose: one round-trip test per detected type -------------------------

func TestProposeSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	mustCreateSQLite(t, path, []sqliteFixtureTable{
		{name: "orders", rows: 500, freshnessCol: "created_at"},
		{name: "users", rows: 12},
	})
	doc, err := Propose(ProposeOptions{Artifact: path, Now: fixedNow(t)})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !strings.Contains(doc, "type: sqlite") || !strings.Contains(doc, "integrity: true") {
		t.Errorf("expected a sqlite check with integrity: true, got:\n%s", doc)
	}
	if !strings.Contains(doc, "orders:") || !strings.Contains(doc, "users:") {
		t.Errorf("expected both qualifying tables, got:\n%s", doc)
	}
	// Table floors default to a percentage of the live count, not an
	// absolute number — absolute floors rot the moment a legitimate
	// cleanup shrinks the table (this is what propose --lint would have
	// caught nothing wrong with, and what a hand-guessed absolute floor
	// would eventually go red on for no real reason).
	if !strings.Contains(doc, "orders: '>= 90%'") || !strings.Contains(doc, "users: '>= 90%'") {
		t.Errorf("expected both tables to default to a relative (>= 90%%) floor, got:\n%s", doc)
	}
	if !strings.Contains(doc, "relative to the live count at drill time") {
		t.Errorf("expected the one-line explainer for why floors default to relative, got:\n%s", doc)
	}
	if !strings.Contains(doc, "use an absolute floor like \">= 400\"") {
		t.Errorf("expected the explainer to name absolute floors as the alternative, got:\n%s", doc)
	}
	if !strings.Contains(doc, "measured 500 on") || !strings.Contains(doc, "measured 12 on") {
		t.Errorf("expected a 'measured N on <date>' comment per table, got:\n%s", doc)
	}
	if !strings.Contains(doc, "freshness:") || !strings.Contains(doc, "column: created_at") {
		t.Errorf("expected a freshness block on created_at, got:\n%s", doc)
	}
	if !strings.Contains(doc, "No budgets yet") {
		t.Errorf("expected the budgets-absent comment, got:\n%s", doc)
	}
	assertProposeRoundTrips(t, doc)
}

func TestProposeSQLiteNoFreshnessColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	mustCreateSQLite(t, path, []sqliteFixtureTable{{name: "widgets", rows: 20}})
	doc, err := Propose(ProposeOptions{Artifact: path, Now: fixedNow(t)})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if strings.Contains(doc, "freshness:") {
		t.Errorf("no freshness-capable column exists; must not emit freshness:, got:\n%s", doc)
	}
	if !strings.Contains(doc, "RPO cannot be measured") {
		t.Errorf("expected an RPO-not-measurable comment, got:\n%s", doc)
	}
	assertProposeRoundTrips(t, doc)
}

func TestProposeSQLiteCapsAtEightTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	var tables []sqliteFixtureTable
	for i := 0; i < 10; i++ {
		tables = append(tables, sqliteFixtureTable{name: sqlTableName(i), rows: 10 + i})
	}
	mustCreateSQLite(t, path, tables)
	doc, err := Propose(ProposeOptions{Artifact: path, Now: fixedNow(t)})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !strings.Contains(doc, "capped at the 8 largest tables (of 10 with rows)") {
		t.Errorf("expected a cap comment naming 8 of 10, got:\n%s", doc)
	}
	ctx := assertProposeRoundTrips(t, doc)
	if got := len(ctx.Drills[0].Validate[0].Tables); got != 8 {
		t.Errorf("expected exactly 8 emitted table constraints, got %d", got)
	}
}

func TestProposeGit(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	gitCommit(t, dir, "a.txt", "hello")
	doc, err := Propose(ProposeOptions{Artifact: dir, Now: fixedNow(t)})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !strings.Contains(doc, "type: git") || !strings.Contains(doc, "refs:") {
		t.Errorf("expected a git check with refs:, got:\n%s", doc)
	}
	assertProposeRoundTrips(t, doc)
}

func TestProposeKeys(t *testing.T) {
	dir := t.TempDir()
	genSSHKeypair(t, dir, "id_ed25519")
	doc, err := Propose(ProposeOptions{Artifact: dir, Now: fixedNow(t)})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !strings.Contains(doc, "type: key_fingerprint") || !strings.Contains(doc, "keys: ssh") {
		t.Errorf("expected a key_fingerprint/ssh check, got:\n%s", doc)
	}
	if !strings.Contains(doc, "expect_from: "+dir) {
		t.Errorf("expected expect_from pointing at the live dir, got:\n%s", doc)
	}
	assertProposeRoundTrips(t, doc)
}

func TestProposeFileTree(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, dir, "settings.yml", "a: 1\n")
	if err := os.Mkdir(filepath.Join(dir, "data"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeFileT(t, filepath.Join(dir, "data"), "current", "x")
	doc, err := Propose(ProposeOptions{Artifact: dir, Now: fixedNow(t)})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !strings.Contains(doc, "type: file_tree") || !strings.Contains(doc, "files:") {
		t.Errorf("expected a file_tree check with files:, got:\n%s", doc)
	}
	if !strings.Contains(doc, "must_exist:") {
		t.Errorf("expected a seeded must_exist:, got:\n%s", doc)
	}
	assertProposeRoundTrips(t, doc)
}

func TestProposeByteIdentical(t *testing.T) {
	dir := t.TempDir()
	path := writeFileT(t, dir, "plain.bin", "byte for byte\n")
	doc, err := Propose(ProposeOptions{Artifact: path, Now: fixedNow(t)})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !strings.Contains(doc, "type: byte_identical") {
		t.Errorf("expected a byte_identical check, got:\n%s", doc)
	}
	assertProposeRoundTrips(t, doc)
}

// ---- Propose: proof id / --source behavior ----------------------------------

func TestProposeDefaultProofIDSanitized(t *testing.T) {
	dir := t.TempDir()
	path := writeFileT(t, dir, "My App v2.0 (backup).bin", "x")
	doc, err := Propose(ProposeOptions{Artifact: path, Now: fixedNow(t)})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !strings.Contains(doc, "proof: my-app-v2-0-backup-bin-recovery") {
		t.Errorf("expected a sanitized default proof id, got:\n%s", doc)
	}
}

func TestProposeProofOverride(t *testing.T) {
	dir := t.TempDir()
	path := writeFileT(t, dir, "plain.bin", "x")
	doc, err := Propose(ProposeOptions{Artifact: path, Proof: "custom-id", Now: fixedNow(t)})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !strings.Contains(doc, "proof: custom-id") {
		t.Errorf("expected the overridden proof id, got:\n%s", doc)
	}
}

func TestProposeNoSourceEmitsPlaceholderAndNoPinCheck(t *testing.T) {
	dir := t.TempDir()
	path := writeFileT(t, dir, "plain.bin", "x")
	doc, err := Propose(ProposeOptions{Artifact: path, Now: fixedNow(t)})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if strings.Contains(doc, "pin_check:") {
		t.Errorf("no --source given; must not emit pin_check:, got:\n%s", doc)
	}
	if !strings.Contains(doc, "TODO: command that reconstructs this artifact") {
		t.Errorf("expected the placeholder recover:, got:\n%s", doc)
	}
	ctx := assertProposeRoundTrips(t, doc)
	// The one expected, correct WARN: a missing pin_check.
	findings := Lint(ctx.Drills[0])
	found := false
	for _, f := range findings {
		if f.Severity == LintWarn && strings.Contains(f.Message, "pin_check") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a WARN about the missing pin_check, got %+v", findings)
	}
}

func TestProposeWithSourceEmitsPinCheck(t *testing.T) {
	dir := t.TempDir()
	path := writeFileT(t, dir, "plain.bin", "x")
	source := t.TempDir() // classifies as "plain"
	doc, err := Propose(ProposeOptions{Artifact: path, Source: source, Now: fixedNow(t)})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !strings.Contains(doc, "pin_check:") {
		t.Errorf("--source given; expected a pin_check:, got:\n%s", doc)
	}
	if !strings.Contains(doc, "recovery_source: "+source) {
		t.Errorf("expected recovery_source: pointing at --source, got:\n%s", doc)
	}
	assertProposeRoundTrips(t, doc)
}

// ---- classifySource ---------------------------------------------------------

func TestClassifySourceRestic(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, dir, "config", "x")
	mustMkdir(t, dir, "data")
	mustMkdir(t, dir, "snapshots")
	assertSourceKind(t, dir, sourceRestic)
}

func TestClassifySourceBorg(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, dir, "config", "x")
	mustMkdir(t, dir, "data")
	writeFileT(t, dir, "README", "This is a Borg repository. See https://borgbackup.readthedocs.io\n")
	assertSourceKind(t, dir, sourceBorg)
}

func TestClassifySourceDatedSnapshot(t *testing.T) {
	dir := t.TempDir()
	mustMkdir(t, dir, "20260101")
	mustMkdir(t, dir, "20260102")
	mustMkdir(t, dir, "20260103")
	assertSourceKind(t, dir, sourceDatedSnapshot)
}

func TestClassifySourceDatedSnapshotISO(t *testing.T) {
	dir := t.TempDir()
	mustMkdir(t, dir, "2026-01-01")
	mustMkdir(t, dir, "2026-01-02")
	assertSourceKind(t, dir, sourceDatedSnapshot)
}

func TestClassifySourceArchive(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, dir, "backup-2026-01-01.tar.gz", "x")
	assertSourceKind(t, dir, sourceArchive)
}

func TestClassifySourcePlainDir(t *testing.T) {
	dir := t.TempDir()
	writeFileT(t, dir, "notes.txt", "x")
	mustMkdir(t, dir, "misc")
	assertSourceKind(t, dir, sourcePlain)
}

func TestClassifySourcePlainFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFileT(t, dir, "single-file-source", "x")
	assertSourceKind(t, path, sourcePlain)
}

func assertSourceKind(t *testing.T, path string, want sourceKind) {
	t.Helper()
	got, err := classifySource(path)
	if err != nil {
		t.Fatalf("classifySource: %v", err)
	}
	if got != want {
		t.Errorf("classifySource(%s) = %q, want %q", path, got, want)
	}
}

// ---- test fixtures ----------------------------------------------------------

func fixedNow(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
}

func writeFileT(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func mustMkdir(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", name, err)
	}
}

func gitCommit(t *testing.T, dir, name, content string) {
	t.Helper()
	writeFileT(t, dir, name, content)
	for _, args := range [][]string{
		{"-C", dir, "add", name},
		{"-C", dir, "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "-m", "fixture"},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
}

func sqlTableName(i int) string {
	return string(rune('a'+i)) + "_table"
}

type sqliteFixtureTable struct {
	name         string
	rows         int
	freshnessCol string // "" means no freshness column
}

// mustCreateSQLite creates a real sqlite database at path (via the same
// pure-Go driver the drill engine uses) with the given fixture tables, each
// populated with `rows` rows. A non-empty freshnessCol gets a TEXT column
// holding RFC3339 timestamps a few minutes apart, so MAX() is deterministic
// and parseable.
func mustCreateSQLite(t *testing.T, path string, tables []sqliteFixtureTable) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	// sql.Open is lazy and an empty sqlite file has no header until a real
	// write transaction commits a page — force one so DetectArtifactType
	// tests get a real, on-disk sqlite file even with zero fixture tables.
	if _, err := db.Exec("CREATE TABLE _propose_test_init (id INTEGER)"); err != nil {
		t.Fatalf("force sqlite file creation: %v", err)
	}

	for _, tbl := range tables {
		ddl := "CREATE TABLE " + tbl.name + " (id INTEGER PRIMARY KEY"
		if tbl.freshnessCol != "" {
			ddl += ", " + tbl.freshnessCol + " TEXT"
		}
		ddl += ")"
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("create table %s: %v", tbl.name, err)
		}
		for i := 0; i < tbl.rows; i++ {
			if tbl.freshnessCol != "" {
				ts := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
				if _, err := db.Exec("INSERT INTO "+tbl.name+" ("+tbl.freshnessCol+") VALUES (?)", ts); err != nil {
					t.Fatalf("insert into %s: %v", tbl.name, err)
				}
			} else if _, err := db.Exec("INSERT INTO " + tbl.name + " DEFAULT VALUES"); err != nil {
				t.Fatalf("insert into %s: %v", tbl.name, err)
			}
		}
	}
}

// TestProposeSQLiteNoFreshnessCommentNamesLargestTable pins the fix for a
// real dogfood bug: the "no freshness column on X (the largest table)"
// comment printed tables[0] of the alphabetically re-sorted list, so a small
// table that sorted first (e.g. "_sqlx_migrations", 2 rows) was reported as
// "the largest" while freshness detection had correctly inspected the real
// largest. The comment must name the table that was actually inspected.
func TestProposeSQLiteNoFreshnessCommentNamesLargestTable(t *testing.T) {
	db := filepath.Join(t.TempDir(), "app.db")
	mustCreateSQLite(t, db, []sqliteFixtureTable{
		{name: "_aaa_first", rows: 2},
		{name: "zz_big", rows: 50},
	})

	out, err := Propose(ProposeOptions{Artifact: db})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "no column on zz_big (the largest table)") {
		t.Errorf("comment does not name the actually-inspected largest table:\n%s", out)
	}
	if strings.Contains(out, "no column on _aaa_first") {
		t.Errorf("comment names the alphabetically-first table instead of the largest:\n%s", out)
	}
}
