// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// propose.go generates a draft drills: entry from a LIVE artifact instead of
// requiring one to be hand-authored. Type detection, invariants, and budgets
// are all derivable by measuring the artifact directly — only the recover
// command needs knowledge the tool cannot have (which backup tool, which
// paths), so it is always emitted as a marked stub the operator fills in or
// verifies. Portability is a hard requirement throughout: nothing here
// assumes a particular backup tool, path layout, or installed CLI beyond
// what the artifact/source classification itself requires (git, ssh-keygen,
// gpg — the same tools the drill engine already depends on).
package drill

import (
	"database/sql"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ProposeOptions configures Propose: which live artifact to measure, an
// optional recovery source to classify for a recover:/pin_check: stub, and
// an optional override for the generated proof id.
type ProposeOptions struct {
	Artifact string    // absolute path to the live artifact being measured (required)
	Source   string    // optional recovery source to classify and stub recover:/pin_check: for
	Proof    string    // optional override for the generated proof id (default: <basename>-recovery)
	Now      time.Time // measurement timestamp for "measured N on <date>" comments; zero means time.Now()
}

func (o ProposeOptions) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

// Propose measures a live artifact and renders a paste-ready drills: YAML
// fragment for it — the mechanical parts of authoring a drill (type,
// invariants) are derivable by measurement, so they are, rather than
// guessed. It never writes into an existing context file: a generator that
// edits declarations in place is a generator that eats hand-written intent.
// Budgets are deliberately omitted; see the comment Propose emits in their
// place and drill --calibrate, which derives them from real telemetry
// instead.
func Propose(opts ProposeOptions) (string, error) {
	kind, err := DetectArtifactType(opts.Artifact)
	if err != nil {
		return "", err
	}

	proof := opts.Proof
	if proof == "" {
		proof = defaultProofID(opts.Artifact)
	}

	var b strings.Builder
	// A complete, loadable context — `drill propose x > restoregap.local.yml`
	// then `restoregap drill` must just work for a first-time user (it did
	// not: without the version line the loader rejected the file). When
	// pasting into an existing context, drop the version line and merge the
	// drills: entry under the file's own drills: key.
	b.WriteString("version: 2\n")
	b.WriteString("drills:\n")
	fmt.Fprintf(&b, "  - proof: %s\n", yamlScalar(proof))
	fmt.Fprintf(&b, "    artifact: %s\n", yamlScalar(opts.Artifact))
	if opts.Source != "" {
		fmt.Fprintf(&b, "    recovery_source: %s\n", yamlScalar(opts.Source))
	}

	recoverSection, err := proposeRecoverSection(kind, opts.Artifact, opts.Source)
	if err != nil {
		return "", err
	}
	b.WriteString(recoverSection)
	b.WriteString(budgetsAbsentComment)

	validateBlock, err := proposeValidateBlock(kind, opts.Artifact, opts.now())
	if err != nil {
		return "", err
	}
	b.WriteString(validateBlock)

	// The proof is only half the point: a drill you can run is rung 2, a
	// change that is REFUSED until that drill has passed is rung 3. Declaring
	// the artifact as a lifeline guarded by its own proof is what connects
	// them — without it, `preflight` on this very file passes with "no
	// findings", which is the opposite of what someone who just wrote a
	// recovery drill for it expects. require_verified means an ingested
	// attestation is not enough; only a real drill run satisfies it.
	b.WriteString("guards:\n")
	fmt.Fprintf(&b, "  - id: %s\n", yamlScalar(proof+"-guard"))
	b.WriteString("    kind: lifeline\n")
	b.WriteString("    enforcement: block\n")
	b.WriteString("    match:\n")
	fmt.Fprintf(&b, "      paths: [%s]\n", yamlScalar(opts.Artifact))
	b.WriteString("    require_verified: true\n")
	fmt.Fprintf(&b, "    requires: {proofs: [%s]}\n", yamlScalar(proof))
	b.WriteString("    # Delete this guard if you only want the proof and not the gate.\n")

	return b.String(), nil
}

// DetectArtifactType classifies a live artifact for propose: sqlite (magic
// bytes, not extension), git (bare or worktree), keys (an ssh/gpg key
// directory), file_tree (any other directory), or byte_identical (any other
// regular file) — first match wins, in that order. A path that does not
// exist is reported as an error rather than guessed at: proposing against
// something unmeasurable would mean inventing the invariants, which is the
// failure mode this feature exists to end.
func DetectArtifactType(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		if isGitDir(path) {
			return "git", nil
		}
		if ssh, gpg, kerr := detectKeySchemes(path); kerr == nil && (ssh || gpg) {
			return "keys", nil
		}
		return "file_tree", nil
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("propose: %s is neither a regular file nor a directory", path)
	}
	isSQLite, err := hasSQLiteMagic(path)
	if err != nil {
		return "", err
	}
	if isSQLite {
		return "sqlite", nil
	}
	return "byte_identical", nil
}

const sqliteMagic = "SQLite format 3\x00"

// hasSQLiteMagic reports whether path's first 16 bytes are the sqlite file
// header — sqlite databases carry no reliable naming convention (.db,
// .sqlite, .sqlite3, or nothing at all), so detection reads the magic bytes
// instead of trusting the extension.
func hasSQLiteMagic(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, len(sqliteMagic))
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return false, err
	}
	return n == len(sqliteMagic) && string(buf) == sqliteMagic, nil
}

// isGitDir reports whether path is a git worktree (a .git/ subdirectory) or
// a bare repository (a HEAD file plus an objects/ directory at its root).
func isGitDir(path string) bool {
	if info, err := os.Stat(filepath.Join(path, ".git")); err == nil && info.IsDir() {
		return true
	}
	headInfo, headErr := os.Stat(filepath.Join(path, "HEAD"))
	objInfo, objErr := os.Stat(filepath.Join(path, "objects"))
	return headErr == nil && !headInfo.IsDir() && objErr == nil && objInfo.IsDir()
}

// detectKeySchemes reports which key fingerprinting schemes a directory
// looks like it holds: ssh (its name is .ssh, or it contains an id_*/*.pub
// file), gpg (its name is .gnupg, or it contains a *.asc file). Both may be
// true; propose then emits one key_fingerprint check per scheme found.
func detectKeySchemes(dir string) (ssh, gpg bool, err error) {
	switch filepath.Base(filepath.Clean(dir)) {
	case ".ssh":
		return true, false, nil
	case ".gnupg":
		return false, true, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, false, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if globMatch("id_*", name) || globMatch("*.pub", name) {
			ssh = true
		}
		if globMatch("*.asc", name) {
			gpg = true
		}
	}
	return ssh, gpg, nil
}

func globMatch(pattern, name string) bool {
	ok, err := filepath.Match(pattern, name)
	return err == nil && ok
}

// defaultProofID derives the proof id propose defaults to when --proof is
// not given: the artifact's basename, lowercased and sanitized to
// [a-z0-9-], with "-recovery" appended.
func defaultProofID(artifact string) string {
	base := strings.ToLower(filepath.Base(artifact))
	var b strings.Builder
	lastDash := false
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	id := strings.Trim(b.String(), "-")
	if id == "" {
		id = "artifact"
	}
	return id + "-recovery"
}

// yamlScalar renders s as a YAML scalar via the same encoder the rest of the
// document round-trips through, so quoting (or not) is exactly what a
// parser would require — never a hand-rolled guess at what needs escaping.
func yamlScalar(s string) string {
	b, err := yaml.Marshal(s)
	if err != nil {
		return s
	}
	return strings.TrimRight(string(b), "\n")
}

// ---- floor() -------------------------------------------------------------

// Floor computes the headroom-adjusted constraint propose emits for a
// measured count: values under 10 are too small for percentage headroom to
// mean anything, so the floor is simply 1 (any positive count). Otherwise
// the floor is 15% below the measured value, rounded DOWN to 2 significant
// figures — something a human would actually write, not a number that
// looks measured to the decimal. This is the one implementation of the
// rule, used by every check type and documented here, in --help, and in
// docs/drill-authoring.md so nobody mistakes it for magic: an experienced
// operator hand-authoring 13 drills came in 44x-8333x looser than the worst
// observed run, because eyeballing headroom is not a skill anyone reliably
// has.
func Floor(measured int) int {
	if measured < 10 {
		return 1
	}
	return roundDownSigFigs(float64(measured)*0.85, 2)
}

// roundDownSigFigs rounds v down to sigFigs significant figures — e.g.
// roundDownSigFigs(2022, 2) == 2000, roundDownSigFigs(39, 2) == 39 (a value
// with fewer digits than sigFigs is left as its own floor).
func roundDownSigFigs(v float64, sigFigs int) int {
	if v <= 0 {
		return 0
	}
	magnitude := math.Floor(math.Log10(v))
	scale := math.Pow(10, magnitude-float64(sigFigs-1))
	if scale < 1 {
		scale = 1
	}
	return int(math.Floor(v/scale) * scale)
}

// floorComment renders the standard "why this number" comment propose
// attaches to every measured constraint, so a reader never has to wonder
// where a floor value came from.
func floorComment(measured int, now time.Time) string {
	return fmt.Sprintf("  # measured %d on %s; floor gives headroom for normal growth/churn",
		measured, now.Format("2006-01-02"))
}

// measuredComment renders the lighter-weight "what this number was" comment
// propose attaches next to a percent-of-live tables: constraint — headroom
// is already expressed by the percentage itself, so there is nothing left
// to explain beyond what the live count was when it was measured.
func measuredComment(measured int, now time.Time) string {
	return fmt.Sprintf("  # measured %d on %s", measured, now.Format("2006-01-02"))
}

// defaultTableFloor is the constraint propose emits for every sqlite table
// row-count floor by default: 90% of the live count at drill time.
const defaultTableFloor = ">= 90%"

// relativeTableFloorComment is the one-line explainer propose emits once
// above every proposed tables: block: an absolute floor (">= 400") rots the
// moment a legitimate cleanup or retention job shrinks the table — the
// exact failure a real deployment hit (a floor tuned to a live count that
// later, correctly, dropped) and had to re-guess by hand. A percent-of-live
// floor tracks that change automatically; an absolute floor is still there
// for the rarer case where the requirement really is a hard minimum
// regardless of what live currently holds.
const relativeTableFloorComment = "          # relative to the live count at drill time, so a legitimate cleanup doesn't rot this into a false red — use an absolute floor like \">= 400\" instead if you need a hard minimum regardless of live count\n"

// ---- budgets: deliberately absent -----------------------------------------

const budgetsAbsentComment = `    # No budgets yet — on purpose. Run this drill a few times, then:
    #   restoregap drill --calibrate --context <this file> --ledger <ledger>
    # Budgets guessed by hand are decorative: measured on one real system, every
    # hand-written RTO budget was 44x-8333x looser than the worst real run.
`

// ---- validate: block, per detected type ------------------------------------

func proposeValidateBlock(kind, artifact string, now time.Time) (string, error) {
	switch kind {
	case "sqlite":
		return proposeSQLiteValidate(artifact, now)
	case "git":
		return proposeGitValidate(artifact, now)
	case "keys":
		return proposeKeysValidate(artifact)
	case "file_tree":
		return proposeFileTreeValidate(artifact, now)
	default: // byte_identical
		return "    validate:\n      - type: byte_identical\n", nil
	}
}

// sqliteTableMeasurement is one qualifying (non-sqlite_%, >0 rows) table and
// its live row count.
type sqliteTableMeasurement struct {
	name  string
	count int
}

// freshnessColumnCandidates is the priority order propose searches a
// sqlite table's columns for an RPO source — the first one present whose
// MAX() parses wins.
var freshnessColumnCandidates = []string{
	"created_at", "updated_at", "date", "timestamp", "ts", "time", "modified_at", "inserted_at",
}

func proposeSQLiteValidate(path string, now time.Time) (string, error) {
	prop, err := measureSQLiteForPropose(path)
	if err != nil {
		return "", fmt.Errorf("propose: measuring %s: %w", path, err)
	}

	var b strings.Builder
	b.WriteString("    validate:\n      - type: sqlite\n        integrity: true\n")

	if len(prop.tables) > 0 {
		b.WriteString("        tables:\n")
		b.WriteString(relativeTableFloorComment)
		for _, t := range prop.tables {
			fmt.Fprintf(&b, "          %s: %s%s\n",
				t.name, yamlScalar(defaultTableFloor), measuredComment(t.count, now))
		}
		if prop.qualifyingCount > len(prop.tables) {
			fmt.Fprintf(&b, "        # capped at the %d largest tables (of %d with rows) — add more by hand if needed\n",
				len(prop.tables), prop.qualifyingCount)
		}
	}

	if prop.hasFreshness {
		b.WriteString("        freshness:\n")
		fmt.Fprintf(&b, "          table: %s\n", yamlScalar(prop.freshnessTable))
		fmt.Fprintf(&b, "          column: %s\n", yamlScalar(prop.freshnessColumn))
	} else if prop.qualifyingCount > 0 {
		// prop.tables is re-sorted alphabetically for stable output, so
		// tables[0] is NOT the largest table — largestTable is the one
		// freshness detection actually inspected.
		fmt.Fprintf(&b, "        # RPO cannot be measured for this artifact: no column on %s (the largest table)\n", prop.largestTable)
		b.WriteString("        # named created_at/updated_at/date/timestamp/ts/time/modified_at/inserted_at\n")
		b.WriteString("        # (case-insensitive) parsed as a timestamp.\n")
	} else {
		b.WriteString("        # RPO cannot be measured for this artifact: no non-empty table to inspect for a freshness column.\n")
	}

	return b.String(), nil
}

// sqliteProposal is what propose measures from a live sqlite database.
type sqliteProposal struct {
	tables          []sqliteTableMeasurement // capped to the 8 largest, sorted by name
	qualifyingCount int                      // how many tables had >0 rows, before capping
	hasFreshness    bool
	largestTable    string // by row count — the table freshness detection inspected
	freshnessTable  string
	freshnessColumn string
}

// sqliteProposeCap is how many of the largest qualifying tables propose
// emits a constraint for — enough to be useful, few enough that the draft
// stays readable.
const sqliteProposeCap = 8

func measureSQLiteForPropose(path string) (sqliteProposal, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return sqliteProposal{}, fmt.Errorf("cannot open %s: %w", path, err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Ping(); err != nil {
		return sqliteProposal{}, fmt.Errorf("cannot open %s: %w", path, err)
	}

	names, err := sqliteUserTableNames(db)
	if err != nil {
		return sqliteProposal{}, err
	}

	var qualifying []sqliteTableMeasurement
	for _, name := range names {
		count, err := sqliteRowCount(db, name)
		if err != nil {
			return sqliteProposal{}, fmt.Errorf("counting %s: %w", name, err)
		}
		if count > 0 {
			qualifying = append(qualifying, sqliteTableMeasurement{name: name, count: count})
		}
	}
	if len(qualifying) == 0 {
		return sqliteProposal{}, nil
	}
	sort.Slice(qualifying, func(i, j int) bool {
		if qualifying[i].count != qualifying[j].count {
			return qualifying[i].count > qualifying[j].count
		}
		return qualifying[i].name < qualifying[j].name
	})

	prop := sqliteProposal{qualifyingCount: len(qualifying)}
	largest := qualifying[0]
	prop.largestTable = largest.name
	capped := qualifying
	if len(capped) > sqliteProposeCap {
		capped = capped[:sqliteProposeCap]
	}
	capped = append([]sqliteTableMeasurement{}, capped...)
	sort.Slice(capped, func(i, j int) bool { return capped[i].name < capped[j].name })
	prop.tables = capped

	col, ok, err := findFreshnessColumn(db, largest.name)
	if err != nil {
		return sqliteProposal{}, err
	}
	if ok {
		prop.hasFreshness = true
		prop.freshnessTable = largest.name
		prop.freshnessColumn = col
	}
	return prop, nil
}

func sqliteUserTableNames(db *sql.DB) ([]string, error) {
	// GLOB (not LIKE) so "_" is a literal character, not a single-char
	// wildcard — "sqlite_*" matches exactly the sqlite_% prefix the schema
	// declares reserved, without ESCAPE-clause ceremony.
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("listing tables: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("listing tables: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing tables: %w", err)
	}
	return names, nil
}

func sqliteRowCount(db *sql.DB, table string) (int, error) {
	var count int
	err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", quoteIdent(table))).Scan(&count)
	return count, err
}

// findFreshnessColumn looks for the first freshnessColumnCandidates entry
// present (case-insensitively) on table whose MAX() parses via the same
// timestamp parser the sqlite drill check itself uses.
func findFreshnessColumn(db *sql.DB, table string) (string, bool, error) {
	cols, err := sqliteTableColumns(db, table)
	if err != nil {
		return "", false, err
	}
	for _, cand := range freshnessColumnCandidates {
		for _, col := range cols {
			if !strings.EqualFold(col, cand) {
				continue
			}
			var raw sql.NullString
			q := fmt.Sprintf("SELECT MAX(%s) FROM %s", quoteIdent(col), quoteIdent(table))
			if err := db.QueryRow(q).Scan(&raw); err != nil || !raw.Valid {
				continue
			}
			if _, perr := parseFreshnessTimestamp(raw.String); perr == nil {
				return col, true, nil
			}
		}
	}
	return "", false, nil
}

func sqliteTableColumns(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", quoteIdent(table)))
	if err != nil {
		return nil, fmt.Errorf("table_info(%s): %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	var cols []string
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, fmt.Errorf("table_info(%s): %w", table, err)
		}
		cols = append(cols, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("table_info(%s): %w", table, err)
	}
	return cols, nil
}

func proposeGitValidate(path string, now time.Time) (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("propose: git not found on PATH, cannot measure %s", path)
	}
	out, err := exec.Command("git", "-C", path, "for-each-ref").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("propose: git for-each-ref on %s: %w — %s", path, err, firstLine(out))
	}
	count := countNonEmptyLines(out)
	var b strings.Builder
	b.WriteString("    validate:\n      - type: git\n")
	fmt.Fprintf(&b, "        refs: %s%s\n", yamlScalar(fmt.Sprintf(">= %d", Floor(count))), floorComment(count, now))
	return b.String(), nil
}

func proposeFileTreeValidate(path string, now time.Time) (string, error) {
	count, _, err := walkFileTree(path)
	if err != nil {
		return "", fmt.Errorf("propose: walking %s: %w", path, err)
	}
	entries, err := notableTopLevelEntries(path, 3)
	if err != nil {
		return "", fmt.Errorf("propose: reading %s: %w", path, err)
	}

	var b strings.Builder
	b.WriteString("    validate:\n      - type: file_tree\n")
	fmt.Fprintf(&b, "        files: %s%s\n", yamlScalar(fmt.Sprintf(">= %d", Floor(count))), floorComment(count, now))
	if len(entries) > 0 {
		b.WriteString("        must_exist:  # replace with the entries that actually matter\n")
		for _, e := range entries {
			fmt.Fprintf(&b, "          - %s\n", yamlScalar(e))
		}
	}
	return b.String(), nil
}

func proposeKeysValidate(path string) (string, error) {
	ssh, gpg, err := detectKeySchemes(path)
	if err != nil {
		return "", fmt.Errorf("propose: reading %s: %w", path, err)
	}
	if !ssh && !gpg {
		return "", fmt.Errorf("propose: %s looked like a keys directory but no ssh or gpg key files were found", path)
	}
	var b strings.Builder
	b.WriteString("    validate:\n")
	if ssh {
		b.WriteString("      - type: key_fingerprint\n        keys: ssh\n")
		fmt.Fprintf(&b, "        expect_from: %s\n", yamlScalar(path))
	}
	if gpg {
		b.WriteString("      - type: key_fingerprint\n        keys: gpg\n")
		fmt.Fprintf(&b, "        expect_from: %s\n", yamlScalar(path))
	}
	return b.String(), nil
}

// notableTopLevelEntries returns up to max top-level entries of dir, ranked
// by entryRank (visible+non-empty first) then name — a seed list for
// must_exist, never a claim that these are the entries that actually
// matter (the emitted comment says so).
func notableTopLevelEntries(dir string, max int) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		ri, rj := entryRank(dir, entries[i]), entryRank(dir, entries[j])
		if ri != rj {
			return ri < rj
		}
		return entries[i].Name() < entries[j].Name()
	})
	var picked []string
	for _, e := range entries {
		picked = append(picked, e.Name())
		if len(picked) == max {
			break
		}
	}
	return picked, nil
}

// entryRank scores one top-level entry for notableTopLevelEntries: visible
// and non-empty first, hidden and empty last. Nothing is ever excluded
// outright — a directory of only dotfiles still seeds something — this only
// orders the preference.
func entryRank(dir string, e os.DirEntry) int {
	hidden := strings.HasPrefix(e.Name(), ".")
	empty := isEmptyDirEntry(dir, e)
	switch {
	case !hidden && !empty:
		return 0
	case !hidden && empty:
		return 1
	case hidden && !empty:
		return 2
	default:
		return 3
	}
}

func isEmptyDirEntry(dir string, e os.DirEntry) bool {
	full := filepath.Join(dir, e.Name())
	if e.IsDir() {
		entries, err := os.ReadDir(full)
		return err != nil || len(entries) == 0
	}
	info, err := e.Info()
	return err != nil || info.Size() == 0
}

// ---- recovery-source classification + recover:/pin_check: stubs -----------

type sourceKind string

// The sourceKind values, checked by classifySource in this priority order
// (first match wins).
const (
	sourceRestic        sourceKind = "restic"
	sourceBorg          sourceKind = "borg"
	sourceDatedSnapshot sourceKind = "dated-snapshot"
	sourceArchive       sourceKind = "archive"
	sourcePlain         sourceKind = "plain"
)

var datedNamePattern = regexp.MustCompile(`^(\d{8}|\d{8}T\d{6}Z|\d{4}-\d{2}-\d{2})$`)

// classifySource identifies the shape of a --source path so propose can
// stub a matching recover:/pin_check:. It never scans the filesystem
// looking for backups beyond the one path it was given — guessing at
// someone's backup layout and being wrong is worse than asking.
func classifySource(path string) (sourceKind, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return sourcePlain, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return "", err
	}

	if isResticRepo(path, entries) {
		return sourceRestic, nil
	}
	if isBorgRepo(path, entries) {
		return sourceBorg, nil
	}
	if hasArchiveMember(entries) {
		return sourceArchive, nil
	}
	if looksDatedSnapshot(entries) {
		return sourceDatedSnapshot, nil
	}
	return sourcePlain, nil
}

// isResticRepo reports whether dir looks like a restic repository: config +
// data/ + snapshots/ at its root, restic's own on-disk layout.
func isResticRepo(dir string, entries []os.DirEntry) bool {
	names := entryNameSet(entries)
	return names["config"] && sourceSubdirExists(dir, "data") && sourceSubdirExists(dir, "snapshots")
}

// isBorgRepo reports whether dir looks like a borg repository: config +
// data/ + a README that actually mentions Borg (borg writes one into every
// repo it creates).
func isBorgRepo(dir string, entries []os.DirEntry) bool {
	names := entryNameSet(entries)
	if !names["config"] || !sourceSubdirExists(dir, "data") || !names["README"] {
		return false
	}
	content, err := os.ReadFile(filepath.Join(dir, "README"))
	return err == nil && strings.Contains(string(content), "Borg")
}

func entryNameSet(entries []os.DirEntry) map[string]bool {
	names := make(map[string]bool, len(entries))
	for _, e := range entries {
		names[e.Name()] = true
	}
	return names
}

func sourceSubdirExists(dir, name string) bool {
	info, err := os.Stat(filepath.Join(dir, name))
	return err == nil && info.IsDir()
}

// hasArchiveMember reports whether any regular file in entries looks like a
// backup archive.
func hasArchiveMember(entries []os.DirEntry) bool {
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".tar.gz") || strings.HasSuffix(n, ".tgz") || strings.HasSuffix(n, ".zip") {
			return true
		}
	}
	return false
}

// looksDatedSnapshot reports whether a majority of entries are named like a
// dated snapshot directory (YYYYMMDD, YYYYMMDDTHHMMSSZ, or YYYY-MM-DD).
func looksDatedSnapshot(entries []os.DirEntry) bool {
	if len(entries) == 0 {
		return false
	}
	dated := 0
	for _, e := range entries {
		if datedNamePattern.MatchString(e.Name()) {
			dated++
		}
	}
	return float64(dated)/float64(len(entries)) > 0.5
}

// artifactTargetIsDir reports whether RG_TARGET must be a directory for the
// given artifact kind (git/keys/file_tree) rather than a single file
// (sqlite/byte_identical) — the recover stub's placement step differs
// accordingly.
func artifactTargetIsDir(kind string) bool {
	switch kind {
	case "git", "keys", "file_tree":
		return true
	default:
		return false
	}
}

// proposeRecoverSection renders the recover:/pin_check: portion of the
// draft. With no --source, it emits an explicit placeholder and no
// pin_check — scanning the filesystem hunting for a backup would mean
// guessing at someone's layout. With --source, it classifies the path and
// emits a matching, clearly TODO-marked stub using only the declared env
// contract.
func proposeRecoverSection(artifactKind, artifact, source string) (string, error) {
	if source == "" {
		return renderNoSourceRecover(), nil
	}
	kind, err := classifySource(source)
	if err != nil {
		return "", fmt.Errorf("propose: classifying --source %s: %w", source, err)
	}
	isDir := artifactTargetIsDir(artifactKind)
	base := filepath.Base(artifact)
	switch kind {
	case sourceRestic:
		return resticStub(isDir, base), nil
	case sourceBorg:
		return borgStub(isDir, base), nil
	case sourceDatedSnapshot:
		return datedSnapshotStub(isDir, base), nil
	case sourceArchive:
		return archiveStub(isDir, base), nil
	default:
		return plainStub(), nil
	}
}

func renderNoSourceRecover() string {
	var b strings.Builder
	b.WriteString("    # No --source given, so this is a placeholder. A good recover command\n")
	b.WriteString("    # reconstructs the live artifact from wherever it actually gets restored\n")
	b.WriteString("    # from — a backup tool invocation, a replica promotion, a snapshot copy —\n")
	b.WriteString("    # using $RG_RECOVERY_SOURCE if you also pass --source next time. Replace\n")
	b.WriteString("    # this with the command you would actually run at 3am, then re-run:\n")
	b.WriteString("    #   restoregap drill --lint --context <this file>\n")
	fmt.Fprintf(&b, "    recover: %s\n", yamlScalar("# TODO: command that reconstructs this artifact into $RG_TARGET"))
	return b.String()
}

// renderRecoverSection renders a commented `recover: |` block scalar plus
// an optional pin_check: line, at the 4-space indent every other drill
// field uses.
func renderRecoverSection(comment, body []string, pinCheck string) string {
	var b strings.Builder
	for _, c := range comment {
		b.WriteString("    # " + c + "\n")
	}
	b.WriteString("    recover: |\n")
	for _, line := range body {
		if line == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString("      " + line + "\n")
	}
	if pinCheck != "" {
		b.WriteString("    pin_check: " + yamlScalar(pinCheck) + "\n")
	}
	return b.String()
}

func resticStub(isDir bool, base string) string {
	comment := []string{
		"TODO: verify this recovers the way YOUR backup actually restores. Supply",
		"credentials (RESTIC_PASSWORD / RESTIC_PASSWORD_FILE / RESTIC_PASSWORD_COMMAND)",
		"the way your setup already does — this stub does not hardcode any.",
	}
	body := []string{
		`STAGE="$RG_SANDBOX/stage"`,
		`mkdir -p "$STAGE"`,
		`restic -r "$RG_RECOVERY_SOURCE" restore latest --target "$STAGE"`,
	}
	body = append(body, placeFromStage(isDir, base)...)
	pin := `restic -r "$RG_RECOVERY_SOURCE" snapshots --latest 1 --json | grep -q '"short_id"'`
	return renderRecoverSection(comment, body, pin)
}

func borgStub(isDir bool, base string) string {
	comment := []string{
		"TODO: verify this recovers the way YOUR backup actually restores. Supply",
		"credentials (BORG_PASSPHRASE / BORG_PASSCOMMAND) the way your setup already",
		"does — this stub does not hardcode any.",
	}
	body := []string{
		`STAGE="$RG_SANDBOX/stage"`,
		`mkdir -p "$STAGE"`,
		`LATEST="$(borg list --short "$RG_RECOVERY_SOURCE" | tail -1)"`,
		`(cd "$STAGE" && borg extract "$RG_RECOVERY_SOURCE::$LATEST")`,
	}
	body = append(body, placeFromStage(isDir, base)...)
	pin := `test -n "$(borg list --short "$RG_RECOVERY_SOURCE" | tail -1)"`
	return renderRecoverSection(comment, body, pin)
}

func datedSnapshotStub(isDir bool, base string) string {
	comment := []string{"TODO: verify this recovers the way YOUR backup actually restores."}
	body := []string{`NEWEST="$(ls -1 "$RG_RECOVERY_SOURCE" | sort | tail -1)"`}
	if isDir {
		body = append(body,
			`mkdir -p "$RG_TARGET"`,
			`cp -a "$RG_RECOVERY_SOURCE/$NEWEST/." "$RG_TARGET/"`,
		)
	} else {
		body = append(body, fmt.Sprintf(`cp -a "$RG_RECOVERY_SOURCE/$NEWEST/%s" "$RG_TARGET"`, base))
	}
	pin := `test -n "$(ls -1 "$RG_RECOVERY_SOURCE" | sort | tail -1)"`
	return renderRecoverSection(comment, body, pin)
}

func archiveStub(isDir bool, base string) string {
	comment := []string{"TODO: verify this recovers the way YOUR backup actually restores."}
	body := []string{
		`LATEST="$(ls -1 "$RG_RECOVERY_SOURCE" | sort | tail -1)"`,
		`STAGE="$RG_SANDBOX/stage"`,
		`mkdir -p "$STAGE"`,
		`case "$LATEST" in`,
		`  *.tar.gz|*.tgz) tar -xzf "$RG_RECOVERY_SOURCE/$LATEST" -C "$STAGE" ;;`,
		`  *.zip) unzip -q "$RG_RECOVERY_SOURCE/$LATEST" -d "$STAGE" ;;`,
		`esac`,
	}
	body = append(body, placeFromStage(isDir, base)...)
	pin := `test -n "$(ls -1 "$RG_RECOVERY_SOURCE" | sort | tail -1)"`
	return renderRecoverSection(comment, body, pin)
}

func plainStub() string {
	comment := []string{
		"TODO: this is a plain path, not a recognized backup layout — replace with",
		"however you actually reconstruct this artifact from $RG_RECOVERY_SOURCE.",
	}
	body := []string{`cp -a "$RG_RECOVERY_SOURCE" "$RG_TARGET"`}
	pin := `test -e "$RG_RECOVERY_SOURCE"`
	return renderRecoverSection(comment, body, pin)
}

// placeFromStage renders the shared final step for stubs that first extract
// into a staging dir ($RG_SANDBOX/stage): locate the artifact by basename
// under the stage and copy it into place, as a file or a directory
// depending on what the declared checks expect RG_TARGET to be.
func placeFromStage(isDir bool, base string) []string {
	if isDir {
		return []string{
			fmt.Sprintf(`FOUND="$(find "$STAGE" -type d -name '%s' -print -quit)"`, base),
			`mkdir -p "$RG_TARGET"`,
			`cp -a "${FOUND:-$STAGE}/." "$RG_TARGET/"`,
		}
	}
	return []string{
		fmt.Sprintf(`cp -a "$(find "$STAGE" -type f -name '%s' -print -quit)" "$RG_TARGET"`, base),
	}
}
