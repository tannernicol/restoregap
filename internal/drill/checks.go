// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package drill

import (
	"database/sql"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver; pure Go, no cgo

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// freshnessRank orders competing RPO sources. Lower ranks are checked by the
// drill author on purpose (sqlite's freshness: block); higher ranks are
// inferred as a fallback and only used when nothing more specific exists.
const (
	freshnessRankSQLite = iota
	freshnessRankGit
	freshnessRankFileTree
)

// freshnessCandidate is one check's opinion of how stale the recovered
// artifact is, tagged with its rank so Run can apply RPO precedence across
// every declared check.
type freshnessCandidate struct {
	rank    int
	seconds float64
}

// checkEnv is the context every check implementation reads: where the
// recovery command wrote the recovered artifact, the declared recovery
// source, and the injectable clock RPO measurements read against.
type checkEnv struct {
	Target         string
	Sandbox        string
	RecoverySource string
	PreHash        string // set only when a byte_identical check is running
	Now            func() time.Time

	// Artifact is the live artifact's path (contextspec.Drill.Artifact),
	// used only by a sqlite check's percent-of-live tables: constraints
	// (see sqliteTableCount) to re-measure the live row count at drill
	// time. Empty when the caller has no live path to offer, in which case
	// a percent constraint fails closed rather than silently skipping.
	Artifact string
}

// checkResult is what running one DrillCheck produces.
type checkResult struct {
	outcome  contextspec.CheckOutcome
	rpo      *freshnessCandidate
	postHash string // byte_identical only
}

func failOutcome(checkType, detail string) checkResult {
	return checkResult{outcome: contextspec.CheckOutcome{Type: checkType, Pass: false, Detail: detail}}
}

// runCheck dispatches one declared check to its implementation. An unknown
// type cannot happen through contextspec.Load (which validates the closed
// set at parse time) but a Spec built directly in Go — as tests do — is not
// forced through that gate, so it fails closed here too.
func runCheck(c contextspec.DrillCheck, env checkEnv) checkResult {
	switch c.Type {
	case "byte_identical":
		return runByteIdentical(env)
	case "sqlite":
		return runSQLite(c, env)
	case "git":
		return runGit(c, env)
	case "file_tree":
		return runFileTree(c, env)
	case "command":
		return runCommand(c, env)
	case "serve":
		return runServe(c, env)
	case "key_fingerprint":
		return runKeyFingerprint(c, env)
	default:
		return failOutcome(c.Type, fmt.Sprintf("unknown check type %q", c.Type))
	}
}

// runByteIdentical is the original drill behavior: the recovered bytes must
// match the live artifact exactly.
func runByteIdentical(env checkEnv) checkResult {
	post, err := hashFile(env.Target)
	if err != nil {
		return failOutcome("byte_identical", fmt.Sprintf("cannot read the recovered artifact: %v", err))
	}
	if env.PreHash != post {
		return checkResult{
			postHash: post,
			outcome: contextspec.CheckOutcome{
				Type: "byte_identical", Pass: false,
				Detail: fmt.Sprintf("recovered bytes do NOT match the original (pre=%s… post=%s…)", truncate(env.PreHash), truncate(post)),
			},
		}
	}
	return checkResult{
		postHash: post,
		outcome:  contextspec.CheckOutcome{Type: "byte_identical", Pass: true, Detail: "recovered bytes match the original"},
	}
}

// runSQLite opens the recovered database read-only via the pure-Go sqlite
// driver and runs whichever of integrity/tables/freshness were declared, all
// folded into one CheckOutcome (one validate: entry, one recorded result).
func runSQLite(c contextspec.DrillCheck, env checkEnv) checkResult {
	db, err := sql.Open("sqlite", "file:"+env.Target+"?mode=ro")
	if err != nil {
		return failOutcome("sqlite", fmt.Sprintf("cannot open recovered database: %v", err))
	}
	defer func() { _ = db.Close() }()
	// mode=ro still allows a bad path to "open" successfully (sqlite opens
	// lazily); force a round trip now so a missing/corrupt file fails here
	// instead of surfacing as a confusing error from the first real query.
	if err := db.Ping(); err != nil {
		return failOutcome("sqlite", fmt.Sprintf("cannot open recovered database: %v", err))
	}

	// The live database is only opened when a percent-of-live tables:
	// constraint actually needs it (openLiveDB is lazy and memoized) — most
	// sqlite checks declare absolute floors and never pay for a second file
	// open.
	openLiveDB, closeLiveDB := lazyLiveDBOpener(env.Artifact)
	defer closeLiveDB()

	var parts []string
	pass := true

	if c.Integrity {
		ok, detail := sqliteIntegrityCheck(db)
		parts = append(parts, detail)
		pass = pass && ok
	}

	for _, table := range sortedKeys(c.Tables) {
		ok, detail := sqliteTableCount(db, openLiveDB, table, c.Tables[table])
		parts = append(parts, detail)
		pass = pass && ok
	}

	var rpo *freshnessCandidate
	if c.Freshness != nil {
		seconds, detail, ok := sqliteFreshness(db, *c.Freshness, env.Now())
		parts = append(parts, detail)
		if ok {
			rpo = &freshnessCandidate{rank: freshnessRankSQLite, seconds: seconds}
		} else {
			pass = false
		}
	}

	if len(parts) == 0 {
		parts = append(parts, "sqlite: no checks declared beyond opening the database")
	}

	return checkResult{rpo: rpo, outcome: contextspec.CheckOutcome{Type: "sqlite", Pass: pass, Detail: strings.Join(parts, "; ")}}
}

func sqliteIntegrityCheck(db *sql.DB) (bool, string) {
	var result string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return false, fmt.Sprintf("integrity check failed to run: %v", err)
	}
	if result != "ok" {
		return false, fmt.Sprintf("integrity FAILED: %s", result)
	}
	return true, "integrity ok"
}

// lazyLiveDBOpener returns a memoized opener for the live artifact's sqlite
// database at artifactPath, plus a closer the caller should defer
// regardless of whether the opener was ever actually called. The database
// is not opened until opener() is first invoked — most sqlite checks
// declare absolute tables: floors and never need the live artifact at all —
// and every call after the first returns the same *sql.DB (or the same
// error) rather than reopening it. artifactPath == "" is a valid input
// (no live artifact was given to this drill) and opener() reports that as
// its error rather than panicking or silently succeeding.
func lazyLiveDBOpener(artifactPath string) (opener func() (*sql.DB, error), closer func()) {
	var db *sql.DB
	var openErr error
	opener = func() (*sql.DB, error) {
		if db != nil || openErr != nil {
			return db, openErr
		}
		if artifactPath == "" {
			openErr = fmt.Errorf("no live artifact path was given to this drill")
			return nil, openErr
		}
		d, err := sql.Open("sqlite", "file:"+artifactPath+"?mode=ro")
		if err != nil {
			openErr = err
			return nil, err
		}
		if err := d.Ping(); err != nil {
			_ = d.Close()
			openErr = err
			return nil, err
		}
		db = d
		return db, nil
	}
	closer = func() {
		if db != nil {
			_ = db.Close()
		}
	}
	return opener, closer
}

// sqliteTableCount runs SELECT COUNT(*) against table in the recovered
// database and evaluates the result against constraint. table is quoted as
// a SQL identifier rather than bound as a parameter (COUNT(*) FROM ? is not
// legal SQL); it comes from the drill's own declared context document, not
// external input.
//
// constraint uses one of two grammars. Absolute (">= 400") is evaluated
// directly. Percent-of-live (">= 90%", parsePercentConstraint) is evaluated
// against openLiveDB()'s row count for the SAME table instead of a fixed
// number: threshold = ceil(fraction * live_count). This is what lets a
// floor track a legitimate cleanup that shrinks the live table — an
// absolute floor has no way to know the drop was intentional, so it rots
// into a false red the next time volume moves. A table missing from the
// live artifact, or no live artifact being available at all, fails this
// constraint closed rather than skipping it.
func sqliteTableCount(recoveredDB *sql.DB, openLiveDB func() (*sql.DB, error), table, constraint string) (bool, string) {
	q := fmt.Sprintf("SELECT COUNT(*) FROM %s", quoteIdent(table))
	var count int
	if err := recoveredDB.QueryRow(q).Scan(&count); err != nil {
		return false, fmt.Sprintf("%s: query failed: %v", table, err)
	}

	pc, isPercent, err := parsePercentConstraint(constraint)
	if err != nil {
		return false, fmt.Sprintf("%s: %v", table, err)
	}
	if !isPercent {
		ok, err := evalCountConstraint(constraint, count)
		if err != nil {
			return false, fmt.Sprintf("%s: %v", table, err)
		}
		return ok, fmt.Sprintf("%s=%d (%s)", table, count, constraint)
	}

	live, err := openLiveDB()
	if err != nil {
		return false, fmt.Sprintf("%s: constraint %q is relative to the live artifact, but it could not be opened: %v", table, constraint, err)
	}
	var liveCount int
	if err := live.QueryRow(q).Scan(&liveCount); err != nil {
		return false, fmt.Sprintf("%s: constraint %q is relative to the live artifact, but table %q could not be read from it: %v", table, constraint, table, err)
	}
	threshold := int(math.Ceil(pc.fraction * float64(liveCount)))
	ok := compareCount(pc.op, count, threshold)
	return ok, fmt.Sprintf("%s=%d (%s of live %d = %d)", table, count, constraint, liveCount, threshold)
}

// sqliteFreshness reads MAX(column) from table and reports how many seconds
// old it is as of now. An unparseable value fails loudly with that cell's own
// raw content — never anything else from the row — because the freshness
// column is a timestamp by definition, not a secret.
func sqliteFreshness(db *sql.DB, f contextspec.DrillFreshness, now time.Time) (seconds float64, detail string, ok bool) {
	q := fmt.Sprintf("SELECT MAX(%s) FROM %s", quoteIdent(f.Column), quoteIdent(f.Table))
	var raw sql.NullString
	if err := db.QueryRow(q).Scan(&raw); err != nil {
		return 0, fmt.Sprintf("freshness %s.%s: query failed: %v", f.Table, f.Column, err), false
	}
	if !raw.Valid {
		return 0, fmt.Sprintf("freshness %s.%s: table is empty, nothing to measure", f.Table, f.Column), false
	}
	ts, err := parseFreshnessTimestamp(raw.String)
	if err != nil {
		return 0, fmt.Sprintf("freshness %s.%s: %v", f.Table, f.Column, err), false
	}
	age := now.Sub(ts)
	return age.Seconds(), fmt.Sprintf("freshness %s.%s=%s (%s ago)", f.Table, f.Column, ts.Format(time.RFC3339), age.Round(time.Second)), true
}

// parseFreshnessTimestamp accepts the shapes a real schema uses for a "when
// was this row written" column: RFC3339, a plain SQL datetime, a bare date,
// or unix seconds.
func parseFreshnessTimestamp(raw string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, nil
		}
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("value %q is not RFC3339, \"YYYY-MM-DD HH:MM:SS\", \"YYYY-MM-DD\", or unix seconds", raw)
}

// quoteIdent renders a SQL identifier in double quotes, doubling any embedded
// quote — standard SQL identifier escaping, and what sqlite's own quoted-name
// syntax expects.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// runGit checks the recovered repository's integrity via `git fsck`, an
// optional ref-count constraint, and opportunistically reads the last commit
// time as an RPO candidate (used only if Run's precedence rules select it).
func runGit(c contextspec.DrillCheck, env checkEnv) checkResult {
	if _, err := exec.LookPath("git"); err != nil {
		// A git drill without git present cannot prove anything — skipping
		// would look like success, so this is a hard failure, not a skip.
		return failOutcome("git", "git not found on PATH")
	}
	if !isGitRepo(env.Target) {
		return failOutcome("git", fmt.Sprintf("%s is not a git repository (worktree or bare)", env.Target))
	}

	var parts []string
	pass := true

	if out, err := exec.Command("git", "-C", env.Target, "fsck", "--no-progress").CombinedOutput(); err != nil {
		pass = false
		parts = append(parts, fmt.Sprintf("fsck FAILED: %s", firstLine(out)))
	} else {
		parts = append(parts, "fsck ok")
	}

	if c.Refs != "" {
		ok, detail := gitRefCount(env.Target, c.Refs)
		parts = append(parts, detail)
		pass = pass && ok
	}

	var rpo *freshnessCandidate
	if seconds, ok := gitLastCommitAge(env.Target, env.Now()); ok {
		rpo = &freshnessCandidate{rank: freshnessRankGit, seconds: seconds}
	}

	return checkResult{rpo: rpo, outcome: contextspec.CheckOutcome{Type: "git", Pass: pass, Detail: strings.Join(parts, "; ")}}
}

// isGitRepo detects either a worktree or a bare repository, mirroring the
// spec's `rev-parse --is-inside-work-tree || --is-bare-repository` check.
func isGitRepo(target string) bool {
	if gitBoolCheck(target, "--is-inside-work-tree") {
		return true
	}
	return gitBoolCheck(target, "--is-bare-repository")
}

func gitBoolCheck(target, flag string) bool {
	out, err := exec.Command("git", "-C", target, "rev-parse", flag).CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

func gitRefCount(target, constraint string) (bool, string) {
	out, err := exec.Command("git", "-C", target, "for-each-ref").CombinedOutput()
	if err != nil {
		return false, fmt.Sprintf("refs: for-each-ref failed: %s", firstLine(out))
	}
	count := countNonEmptyLines(out)
	ok, evalErr := evalCountConstraint(constraint, count)
	if evalErr != nil {
		return false, fmt.Sprintf("refs: %v", evalErr)
	}
	return ok, fmt.Sprintf("refs=%d (%s)", count, constraint)
}

func countNonEmptyLines(b []byte) int {
	trimmed := strings.TrimRight(string(b), "\n")
	if trimmed == "" {
		return 0
	}
	return len(strings.Split(trimmed, "\n"))
}

func gitLastCommitAge(target string, now time.Time) (float64, bool) {
	out, err := exec.Command("git", "-C", target, "log", "-1", "--format=%ct").CombinedOutput()
	if err != nil {
		return 0, false
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, false
	}
	return now.Sub(time.Unix(ts, 0)).Seconds(), true
}

// runFileTree walks the recovered directory, checking a file-count
// constraint and MustExist paths, and opportunistically reads the newest
// file's mtime as an RPO candidate.
func runFileTree(c contextspec.DrillCheck, env checkEnv) checkResult {
	info, err := os.Stat(env.Target)
	if err != nil || !info.IsDir() {
		return failOutcome("file_tree", fmt.Sprintf("%s is not a directory", env.Target))
	}

	fileCount, newest, err := walkFileTree(env.Target)
	if err != nil {
		return failOutcome("file_tree", fmt.Sprintf("walk failed: %v", err))
	}

	var parts []string
	pass := true

	if c.Files != "" {
		ok, evalErr := evalCountConstraint(c.Files, fileCount)
		if evalErr != nil {
			pass = false
			parts = append(parts, fmt.Sprintf("files: %v", evalErr))
		} else {
			pass = pass && ok
			parts = append(parts, fmt.Sprintf("files=%d (%s)", fileCount, c.Files))
		}
	} else {
		parts = append(parts, fmt.Sprintf("files=%d", fileCount))
	}

	if len(c.MustExist) > 0 {
		missing := mustExistMissing(env.Target, c.MustExist)
		if len(missing) > 0 {
			pass = false
			parts = append(parts, fmt.Sprintf("must_exist FAILED: %s", strings.Join(missing, ", ")))
		} else {
			parts = append(parts, "must_exist ok")
		}
	}

	var rpo *freshnessCandidate
	if !newest.IsZero() {
		rpo = &freshnessCandidate{rank: freshnessRankFileTree, seconds: env.Now().Sub(newest).Seconds()}
	}

	return checkResult{rpo: rpo, outcome: contextspec.CheckOutcome{Type: "file_tree", Pass: pass, Detail: strings.Join(parts, "; ")}}
}

func walkFileTree(root string) (count int, newest time.Time, err error) {
	err = filepath.WalkDir(root, func(_ string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		count++
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	return count, newest, err
}

// mustExistMissing reports, for each declared path (relative to root), why it
// failed the "exists and is non-empty" requirement — a missing path, an empty
// file, or a directory with no entries.
func mustExistMissing(root string, paths []string) []string {
	var missing []string
	for _, rel := range paths {
		full := filepath.Join(root, rel)
		info, err := os.Stat(full)
		switch {
		case err != nil:
			missing = append(missing, rel+" (missing)")
		case info.IsDir():
			entries, rdErr := os.ReadDir(full)
			if rdErr != nil || len(entries) == 0 {
				missing = append(missing, rel+" (empty directory)")
			}
		case info.Size() == 0:
			missing = append(missing, rel+" (empty)")
		}
	}
	return missing
}

// runCommand runs an arbitrary invariant script against the recovered
// artifact. Exit 0 is pass; the first line of combined output (stdout and
// stderr) is kept as Detail either way, truncated by firstLine.
func runCommand(c contextspec.DrillCheck, env checkEnv) checkResult {
	cmd := exec.Command("sh", "-c", c.Run)
	cmd.Env = append(os.Environ(),
		"RG_TARGET="+env.Target,
		"RG_SANDBOX="+env.Sandbox,
		"RG_RECOVERY_SOURCE="+env.RecoverySource,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return failOutcome("command", fmt.Sprintf("command failed: %s", firstLine(out)))
	}
	return checkResult{outcome: contextspec.CheckOutcome{Type: "command", Pass: true, Detail: firstLine(out)}}
}
