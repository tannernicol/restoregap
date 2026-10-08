// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package shellintent turns a shell command line into the recovery-relevant
// operations it would run, so the agent hook can evaluate each one against the
// declared guards. The old hook read the first word of the first line, which
// let "echo ok && rm -rf ~/Backups/x" and "ssh nas docker rm vol" through
// unexamined. This package is pure: it never expands, executes or touches the
// filesystem, so it can only be wrong by missing something, never by doing it.
//
// It is a classifier, not a shell. What it does not see (interpreter code,
// scripts run by path, aliases, functions, heredocs, `cd` changing what a
// relative path means) is listed in docs/agent-gate.md.
package shellintent

import (
	"path"
	"strings"
)

const (
	maxInput = 64 << 10
	// maxDepth bounds recursion into $(...), backticks, `bash -c STRING` and
	// ssh command strings so a hostile line cannot make the parser quadratic.
	maxDepth = 4
)

// Operation is one simple command after transparent prefixes were unwrapped.
type Operation struct {
	// Action is delete_file, move_file, modify_file, run_command, or "" when the
	// command is not one this package recognizes as recovery-relevant.
	Action string
	// Paths are the local path operands (delete/modify/move source). They are
	// empty for any remote- or container-wrapped operation: a path inside
	// another host must never be matched against local path guards.
	Paths []string
	// Targets is the move_file destination.
	Targets []string
	// Command is the normalized command for guard `commands` globs: words
	// joined by single spaces, with a wrapper restored as a prefix ("ssh HOST
	// ..." or "docker exec CONTAINER ..."). Unwrapped sudo, env, nice, nohup,
	// time, timeout and bash -c are dropped.
	Command string
	// Remote is the ssh host or container/pod/service name when wrapped. For
	// nested wrappers it is the outermost; Command carries all of them.
	Remote string
	// Words is the unwrapped simple command, for diagnostics.
	Words []string
	// Dir is the working directory the command runs in after `cd`/`pushd` earlier
	// in the same command line, or "" for the hook's own directory. Relative Paths
	// and Targets are relative to it. It may itself be relative to the hook's
	// directory, or start with "~/". Always "" for wrapped operations.
	Dir string
	// Benign marks an unrecognized (Action "") command that is a shell builtin or
	// a read-only tool. It is not recovery-relevant and a strict-mode caller
	// need not refuse a compound command for containing it.
	Benign bool
	// RepoScoped marks run_command shapes whose effect is anchored to the working
	// directory's repository (git, terraform, tofu, pulumi, dropdb). Pure code
	// cannot ask git for the root, so the caller supplies the path.
	RepoScoped bool
}

// Result is the parse of one command line.
type Result struct {
	// Ops has one entry per simple command in order, including Action == ""
	// ones so a caller can count the pieces it does not recognize. It is nil
	// when Unparseable: a failed parse never yields a partial guess.
	Ops         []Operation
	Unparseable bool
	// Reason says why: unbalanced quotes, heredoc, process substitution, input
	// over 64 KiB, or nesting deeper than 4.
	Reason string
}

// Parse splits a shell command line into the simple commands it would run,
// after unwrapping transparent prefixes, and classifies each into a
// recovery-relevant operation. It never expands or executes anything.
func Parse(command string) Result {
	if len(command) > maxInput {
		return Result{Unparseable: true, Reason: "command longer than 64 KiB"}
	}
	p := &parser{}
	p.parseString(command, wrapper{}, 0, "")
	if p.fail != "" {
		return Result{Unparseable: true, Reason: p.fail}
	}
	return Result{Ops: p.ops}
}

// wrapper is the remote context a command string runs in: the host or
// container, plus the words that restore it as a Command prefix.
type wrapper struct {
	remote string
	prefix []string
}

func (w wrapper) with(remote string, prefix ...string) wrapper {
	if w.remote != "" {
		remote = w.remote
	}
	return wrapper{remote: remote, prefix: append(append([]string(nil), w.prefix...), prefix...)}
}

type parser struct {
	ops  []Operation
	fail string
}

type redirect struct {
	op, fd, target string
}

// parseString parses one command string. dir is the working directory it
// starts in; a `cd` carries through `&&`, `||`, `;` and newlines, but not
// through a pipe, a background `&`, a subshell, or a substitution.
func (p *parser) parseString(s string, w wrapper, depth int, dir string) {
	if p.fail != "" {
		return
	}
	if depth > maxDepth {
		p.fail = "nesting deeper than 4 levels"
		return
	}
	toks, fail := tokenize(s)
	if fail != "" {
		p.fail = fail
		return
	}
	var (
		words   []string
		redirs  []redirect
		pending *redirect
		cwd     = dir
		saved   []string
		prevSep string
	)
	end := func(sep string) {
		next, changed := p.command(words, redirs, w, depth, cwd)
		// A cd on either side of a pipe, or before `&`, runs in a subshell.
		if changed && prevSep != "|" && sep != "|" && sep != "&" {
			cwd = next
		}
		words, redirs, pending, prevSep = nil, nil, nil, sep
		switch sep {
		case "(":
			saved = append(saved, cwd)
		case ")":
			if n := len(saved); n > 0 {
				cwd, saved = saved[n-1], saved[:n-1]
			}
		}
	}
	for _, t := range toks {
		if p.fail != "" {
			return
		}
		switch t.kind {
		case tSep:
			end(t.text)
		case tSub:
			// Substitutions run before the command that contains them, in the
			// directory the line has reached so far.
			p.parseString(t.text, w, depth+1, cwd)
		case tRedir:
			redirs = append(redirs, redirect{op: t.text, fd: t.fd})
			pending = &redirs[len(redirs)-1]
		case tWord:
			switch {
			case pending != nil:
				pending.target = t.text
				pending = nil
			case !t.quoted && (t.text == "{" || t.text == "}"):
			default:
				words = append(words, t.text)
			}
		}
	}
	end("")
}

// reserved are shell keywords that can precede a command; "then rm x" runs rm.
var reserved = map[string]bool{"if": true, "then": true, "else": true, "elif": true, "do": true, "while": true, "until": true, "!": true, "fi": true, "done": true, "esac": true}

func isAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := w[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

func stripLeading(words []string) []string {
	for len(words) > 0 && (isAssignment(words[0]) || reserved[words[0]]) {
		words = words[1:]
	}
	return words
}

// command records the operations of one simple command run in cwd. It reports
// the directory a `cd`-like command moves to, and whether this was one.
func (p *parser) command(words []string, redirs []redirect, w wrapper, depth int, cwd string) (string, bool) {
	words = stripLeading(words)
	// ": > file" is the truncate idiom; the colon itself is not a command.
	if len(words) == 1 && words[0] == ":" {
		words = nil
	}
	before := len(p.ops)
	if len(words) > 0 {
		p.simple(words, w, depth, cwd)
	}
	for _, r := range redirs {
		if !writesFile(r) {
			continue
		}
		p.redirectOp(words, r, w, before, cwd)
	}
	if len(words) > 0 && w.remote == "" {
		return changeDir(words, cwd)
	}
	return cwd, false
}

// changeDir applies cd, pushd and popd to cwd. Anything it cannot know
// statically (a variable, a glob, `cd -`, popd) falls back to "", the hook's own
// directory, rather than guessing a path.
func changeDir(words []string, cwd string) (string, bool) {
	switch words[0] {
	case "popd":
		return "", true
	case "cd", "pushd":
	default:
		return cwd, false
	}
	var target string
	if ops := positionals(words[1:], nil); len(ops) > 0 {
		target = ops[0]
	}
	switch {
	case target == "" || target == "~" || target == "-" || strings.ContainsAny(target, "$`*?[") || strings.HasPrefix(target, "+"):
		return "", true
	case strings.HasPrefix(target, "/") || strings.HasPrefix(target, "~/"):
		return path.Clean(target), true
	case cwd == "":
		return path.Clean(target), true
	}
	return path.Join(cwd, target), true
}

// writesFile reports whether a redirection can create or overwrite a regular
// file on stdout. 2> and the like are ignored on purpose: they are diagnostics.
func writesFile(r redirect) bool {
	switch r.op {
	case ">", ">>", ">|", "&>", "&>>":
	case ">&":
		if r.target == "" || r.target == "-" || isDigits(r.target) {
			return false
		}
	default:
		return false
	}
	if r.fd != "" && r.fd != "1" {
		return false
	}
	if r.target == "" || r.target == "/dev/null" || r.target == "/dev/stdout" || r.target == "/dev/stderr" || r.target == "/dev/tty" || strings.HasPrefix(r.target, "/dev/fd/") {
		return false
	}
	return true
}

func (p *parser) redirectOp(words []string, r redirect, w wrapper, before int, cwd string) {
	text := r.op + " " + r.target
	if w.remote != "" {
		// A redirect inside a remote string writes on the remote host, so it is
		// part of that command's text rather than a local file operation.
		if len(p.ops) > before {
			last := &p.ops[len(p.ops)-1]
			last.Command += " " + text
			return
		}
		p.ops = append(p.ops, Operation{Action: "run_command", Command: join(append(append([]string(nil), w.prefix...), text)), Remote: w.remote, Words: words})
		return
	}
	cmd := text
	if len(words) > 0 {
		cmd = join(words) + " " + text
	}
	p.ops = append(p.ops, Operation{Action: "modify_file", Paths: []string{r.target}, Command: cmd, Words: words, Dir: cwd})
}

func join(words []string) string { return strings.Join(words, " ") }

// simple unwraps transparent prefixes and wrappers until stable, then records
// the resulting operation(s).
func (p *parser) simple(words []string, w wrapper, depth int, dir string) {
	for guard := 0; guard < 32 && len(words) > 0 && p.fail == ""; guard++ {
		if rest, ok := unwrapPrefix(words); ok {
			words = rest
			continue
		}
		name := base(words[0])
		switch {
		case name == "ssh":
			if host, inner, ok := parseSSH(words); ok {
				nw := w.with(host, "ssh", host)
				if plain(inner) {
					p.simple(inner, nw, depth, "")
				} else {
					p.parseString(join(inner), nw, depth+1, "")
				}
				return
			}
		case isShell(name):
			if script, ok := shellDashC(words); ok {
				p.parseString(script, w, depth+1, dir)
				return
			}
		case name == "docker" || name == "podman" || name == "docker-compose" || name == "kubectl":
			if target, prefix, inner, ok := parseExec(words); ok {
				p.simple(inner, w.with(target, prefix...), depth, "")
				return
			}
		}
		break
	}
	if len(words) == 0 {
		return
	}
	if w.remote != "" {
		p.ops = append(p.ops, Operation{Action: "run_command", Command: join(append(append([]string(nil), w.prefix...), words...)), Remote: w.remote, Words: words})
		return
	}
	op := classify(words)
	op.Dir = dir
	p.ops = append(p.ops, op)
}

// plain reports whether re-lexing the words would change nothing, so a wrapped
// command can be classified directly without spending a nesting level.
func plain(words []string) bool {
	for _, w := range words {
		if strings.ContainsAny(w, " \t\n\r;&|()<>$`'\"\\#") {
			return false
		}
	}
	return true
}

func base(word string) string {
	if i := strings.LastIndexByte(word, '/'); i >= 0 {
		return word[i+1:]
	}
	return word
}
