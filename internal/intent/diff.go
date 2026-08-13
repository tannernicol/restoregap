package intent

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

// FileStatus classifies how a file changed in a diff.
type FileStatus string

// The FileStatus values.
const (
	FileAdded    FileStatus = "added"
	FileDeleted  FileStatus = "deleted"
	FileModified FileStatus = "modified"
	FileRenamed  FileStatus = "renamed"
)

// DiffLineKind classifies one line inside a hunk.
type DiffLineKind string

// The DiffLineKind values.
const (
	DiffLineContext DiffLineKind = "context"
	DiffLineAdded   DiffLineKind = "added"
	DiffLineRemoved DiffLineKind = "removed"
)

// DiffLine is one line inside a hunk, with its line number in the new (for
// added/context) or old (for removed) file.
type DiffLine struct {
	Kind   DiffLineKind
	Text   string
	LineNo int
}

// Hunk is one contiguous change region within a file diff.
type Hunk struct {
	OldStart, OldLines int
	NewStart, NewLines int
	Lines              []DiffLine
	Added, Removed     int
}

// FileDiff is one file's changes within a unified diff.
type FileDiff struct {
	OldPath string
	NewPath string
	Status  FileStatus
	Hunks   []Hunk
}

// Path is the file's effective path for guard matching: the new path unless
// the file was deleted, in which case it's the old path.
func (f FileDiff) Path() string {
	if f.Status == FileDeleted {
		return f.OldPath
	}
	return f.NewPath
}

const devNull = "/dev/null"

// ParseDiff hand-parses a unified diff (git or plain `diff -u` style) into
// per-file changes. It reads only what preflight needs: changed/deleted file
// paths and hunk line stats — not enough to reconstruct file contents.
// diffParser holds the state of a single ParseDiff scan: the completed files,
// the file and hunk currently being filled, and the running line counters that
// number added/removed/context lines.
type diffParser struct {
	files            []FileDiff
	cur              *FileDiff
	curHunk          *Hunk
	oldLine, newLine int
}

func (p *diffParser) flushHunk() {
	if p.cur != nil && p.curHunk != nil {
		p.cur.Hunks = append(p.cur.Hunks, *p.curHunk)
		p.curHunk = nil
	}
}

func (p *diffParser) flushFile() {
	p.flushHunk()
	if p.cur != nil {
		p.files = append(p.files, *p.cur)
		p.cur = nil
	}
}

// ensureFile covers diffs that omit the "diff --git" header (plain unified
// diffs), where the "---" line is the first thing identifying a file.
func (p *diffParser) ensureFile() {
	if p.cur == nil {
		p.cur = &FileDiff{Status: FileModified}
	}
}

func (p *diffParser) handleOldPath(line string) {
	path := stripDiffPrefix(strings.TrimSpace(strings.TrimPrefix(line, "--- ")))
	p.ensureFile()
	if path == devNull {
		p.cur.Status = FileAdded
	} else {
		p.cur.OldPath = path
	}
}

func (p *diffParser) handleNewPath(line string) {
	path := stripDiffPrefix(strings.TrimSpace(strings.TrimPrefix(line, "+++ ")))
	p.ensureFile()
	if path == devNull {
		p.cur.Status = FileDeleted
	} else {
		p.cur.NewPath = path
	}
	// Both sides named, different, and nothing stronger already decided: a
	// rename. Checked here because it needs both path lines to have landed.
	if p.cur.OldPath != "" && p.cur.NewPath != "" && p.cur.OldPath != p.cur.NewPath && p.cur.Status == FileModified {
		p.cur.Status = FileRenamed
	}
}

func (p *diffParser) handleHunkHeader(line string) error {
	p.flushHunk()
	h, err := parseHunkHeader(line)
	if err != nil {
		return err
	}
	if p.cur == nil {
		return fmt.Errorf("diff: hunk header %q outside any file", line)
	}
	p.curHunk = &h
	p.oldLine, p.newLine = h.OldStart, h.NewStart
	return nil
}

// handleBodyLine records one line inside a hunk. Added lines advance only the
// new-file counter, removed lines only the old-file counter, context both.
func (p *diffParser) handleBodyLine(line string) bool {
	if p.curHunk == nil {
		return false
	}
	switch {
	case len(line) > 0 && line[0] == '+':
		p.curHunk.Lines = append(p.curHunk.Lines, DiffLine{Kind: DiffLineAdded, Text: line[1:], LineNo: p.newLine})
		p.curHunk.Added++
		p.newLine++
	case len(line) > 0 && line[0] == '-':
		p.curHunk.Lines = append(p.curHunk.Lines, DiffLine{Kind: DiffLineRemoved, Text: line[1:], LineNo: p.oldLine})
		p.curHunk.Removed++
		p.oldLine++
	case len(line) == 0 || line[0] == ' ':
		text := line
		if len(text) > 0 {
			text = text[1:]
		}
		p.curHunk.Lines = append(p.curHunk.Lines, DiffLine{Kind: DiffLineContext, Text: text, LineNo: p.newLine})
		p.oldLine++
		p.newLine++
	default:
		return false
	}
	return true
}

// ParseDiff parses a unified diff into per-file hunks.
func ParseDiff(r io.Reader) ([]FileDiff, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	p := &diffParser{}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "diff --git "):
			p.flushFile()
			a, b := parseGitDiffHeader(line)
			p.cur = &FileDiff{OldPath: a, NewPath: b, Status: FileModified}
		case strings.HasPrefix(line, "--- "):
			p.handleOldPath(line)
		case strings.HasPrefix(line, "+++ "):
			p.handleNewPath(line)
		case strings.HasPrefix(line, "@@ "):
			if err := p.handleHunkHeader(line); err != nil {
				return nil, err
			}
		default:
			p.handleBodyLine(line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("diff: %w", err)
	}
	p.flushFile()
	return p.files, nil
}

// stripDiffPrefix removes the conventional "a/" / "b/" prefix git adds to
// diff paths, if present.
func stripDiffPrefix(path string) string {
	if strings.HasPrefix(path, "a/") || strings.HasPrefix(path, "b/") {
		return path[2:]
	}
	return path
}

func parseGitDiffHeader(line string) (oldPath, newPath string) {
	// "diff --git a/<old> b/<new>"
	rest := strings.TrimPrefix(line, "diff --git ")
	idx := strings.Index(rest, " b/")
	if idx == -1 {
		return "", ""
	}
	oldPath = strings.TrimPrefix(rest[:idx], "a/")
	newPath = rest[idx+len(" b/"):]
	return oldPath, newPath
}

// parseHunkHeader parses "@@ -l,s +l,s @@ optional context".
func parseHunkHeader(line string) (Hunk, error) {
	body := strings.TrimPrefix(line, "@@ ")
	end := strings.Index(body, " @@")
	if end == -1 {
		return Hunk{}, fmt.Errorf("diff: malformed hunk header %q", line)
	}
	ranges := strings.Fields(body[:end])
	if len(ranges) != 2 {
		return Hunk{}, fmt.Errorf("diff: malformed hunk header %q", line)
	}
	oldStart, oldLines, err := parseRange(ranges[0], '-')
	if err != nil {
		return Hunk{}, fmt.Errorf("diff: %w", err)
	}
	newStart, newLines, err := parseRange(ranges[1], '+')
	if err != nil {
		return Hunk{}, fmt.Errorf("diff: %w", err)
	}
	return Hunk{OldStart: oldStart, OldLines: oldLines, NewStart: newStart, NewLines: newLines}, nil
}

func parseRange(field string, want byte) (start, count int, err error) {
	if len(field) == 0 || field[0] != want {
		return 0, 0, fmt.Errorf("malformed range %q", field)
	}
	field = field[1:]
	parts := strings.SplitN(field, ",", 2)
	start, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("malformed range %q: %w", field, err)
	}
	count = 1
	if len(parts) == 2 {
		count, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("malformed range %q: %w", field, err)
		}
	}
	return start, count, nil
}

// Rebase resolves repo-relative diff paths against root, so that paths parsed
// out of `git diff` ("bin/ctx") can match guards declared absolutely
// ("/home/user/bin/ctx"). An empty root, or a path that is already absolute,
// is left untouched — callers that hand-build absolute diffs keep working.
func Rebase(files []FileDiff, root string) []FileDiff {
	if root == "" {
		return files
	}
	rebase := func(p string) string {
		if p == "" || strings.HasPrefix(p, "/") {
			return p
		}
		return filepath.Join(root, p)
	}
	out := make([]FileDiff, len(files))
	for i, f := range files {
		f.OldPath = rebase(f.OldPath)
		f.NewPath = rebase(f.NewPath)
		out[i] = f
	}
	return out
}

// ToChangeIntents normalizes parsed file diffs into one ChangeIntent per
// file: deletions map to delete_file, renames to move_file, everything else
// (added/modified) to modify_file.
func ToChangeIntents(files []FileDiff) []ChangeIntent {
	intents := make([]ChangeIntent, 0, len(files))
	for _, f := range files {
		switch f.Status {
		case FileDeleted:
			intents = append(intents, ChangeIntent{Action: ActionDeleteFile, Paths: []string{f.Path()}, Source: "diff"})
		case FileRenamed:
			intents = append(intents, ChangeIntent{Action: ActionMoveFile, Paths: []string{f.OldPath}, TargetPaths: []string{f.NewPath}, Source: "diff"})
		default:
			intents = append(intents, ChangeIntent{Action: ActionModifyFile, Paths: []string{f.Path()}, Source: "diff"})
		}
	}
	return intents
}
