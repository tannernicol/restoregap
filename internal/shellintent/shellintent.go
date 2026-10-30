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
	// time, timeout and bash -c are dropped. An ssh host typed in a form ssh
	// would resolve differently (NAS, 192.0.521, [fe80::1%en0]) yields the
	// operation once as typed and once per canonical spelling.
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
	// over 64 KiB, nesting deeper than 4, too many spellings of nested ssh
	// hosts, or an scp or sftp command whose hosts cannot be read.
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
	// alts are the same prefix with its ssh hosts in their other spellings
	// (see hostSpellings), each with its own outermost remote.
	alts []spelling
}

type spelling struct {
	remote string
	prefix []string
}

func (w wrapper) with(remote string, prefix ...string) wrapper {
	if w.remote != "" {
		remote = w.remote
	}
	nw := wrapper{remote: remote, prefix: append(append([]string(nil), w.prefix...), prefix...)}
	for _, a := range w.alts {
		nw.alts = append(nw.alts, spelling{remote: a.remote, prefix: append(append([]string(nil), a.prefix...), prefix...)})
	}
	return nw
}

// withSSH is with for an ssh host. Each other spelling of the host (and of
// also, the host inside an ssh:// destination, when there is one), combined
// with each spelling the wrapper already has, becomes an alternative prefix,
// so a glob written for any of them matches. It reports false past
// maxSpellings.
func (w wrapper) withSSH(host, also string) (wrapper, bool) {
	nw := w.with(host, "ssh", host)
	bases := append([]spelling{{remote: w.remote, prefix: w.prefix}}, w.alts...)
	nw.alts = nil
	seen := map[string]bool{join(nw.prefix): true}
	hosts := hostSpellings(host)
	if also != "" {
		hosts = append(hosts, hostSpellings(also)...)
	}
	for _, b := range bases {
		for _, h := range hosts {
			remote := b.remote
			if remote == "" {
				remote = h
			}
			prefix := append(append([]string(nil), b.prefix...), "ssh", h)
			if key := join(prefix); !seen[key] {
				seen[key] = true
				nw.alts = append(nw.alts, spelling{remote: remote, prefix: prefix})
			}
		}
	}
	return nw, len(nw.alts) <= maxSpellings
}

// remoteOp records a run_command inside w, the prefix followed by tail, once
// for the prefix as typed and once for each of its other spellings.
func (p *parser) remoteOp(w wrapper, words []string, tail ...string) {
	for _, s := range append([]spelling{{remote: w.remote, prefix: w.prefix}}, w.alts...) {
		command := join(append(append([]string(nil), s.prefix...), tail...))
		p.ops = append(p.ops, Operation{Action: "run_command", Command: command, Remote: s.remote, Words: words})
	}
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
	if len(words) > 0 {
		p.simple(words, w, depth, cwd)
	}
	for _, r := range redirs {
		if !writesFile(r) {
			continue
		}
		p.redirectOp(words, r, w, cwd)
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
// file on any output descriptor. Diagnostics redirected to a file are still
// writes and must be evaluated; descriptor duplication is not a file write.
func writesFile(r redirect) bool {
	switch r.op {
	case ">", ">>", ">|", "&>", "&>>", "<>":
	case ">&":
		if r.target == "" || r.target == "-" || isDigits(r.target) {
			return false
		}
	default:
		return false
	}
	if r.target == "" || r.target == "/dev/null" || r.target == "/dev/stdout" || r.target == "/dev/stderr" || r.target == "/dev/tty" || strings.HasPrefix(r.target, "/dev/fd/") {
		return false
	}
	return true
}

func (p *parser) redirectOp(words []string, r redirect, w wrapper, cwd string) {
	text := r.fd + r.op + " " + r.target
	if w.remote != "" {
		// Keep a remote write separate from the command whose output it
		// redirects. Otherwise a broad read-only command guard (for example,
		// `ssh nas cat *`) can accidentally cover the write as part of its glob.
		// Remote paths stay out of local Paths and require their own command
		// coverage.
		p.remoteOp(w, words, text)
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
			if host, uriHost, inner, ok := parseSSH(words); ok {
				nw, ok := w.withSSH(host, uriHost)
				if !ok {
					p.fail = "too many spellings of nested ssh hosts"
					return
				}
				if sshHasUnsupportedOptions(words) {
					p.remoteOp(nw, nil, "[unsupported-options]")
				}
				if len(inner) == 0 {
					p.remoteOp(nw, nil)
					return
				}
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
		p.remoteOp(w, words, words...)
		return
	}
	if name := base(words[0]); name == "scp" || name == "sftp" || name == "rsync" {
		p.transfer(name, words, dir)
		return
	}
	op := classify(words)
	op.Dir = dir
	p.ops = append(p.ops, op)
}

// transfer records an scp, sftp or rsync command run here. The command
// itself is classified like cp (see copyShape), so globs on its text apply.
// Each operand on another host is also an ssh session to that host, recorded
// as the equivalent ssh command (scp -t PATH for the destination it writes,
// scp -f PATH for a source it reads, sftp for a session, rsync --server for
// rsync, an rsync daemon included), so host coverage and `ssh HOST ...` guards
// apply as they would to ssh itself; options ssh would not drop add an
// `ssh HOST [unsupported-options]` operation. A host typed in another spelling
// repeats both in its canonical forms. A command whose hosts, or whose rsync
// remote shell, cannot be read fails the parse: it must not pass as a local
// copy.
func (p *parser) transfer(name string, words []string, dir string) {
	ends, ok := transferEnds(name, words[1:])
	if !ok {
		p.fail = name + " destination could not be determined"
		return
	}
	if name == "rsync" && len(ends) > 0 {
		if shell, given := rsyncShell(words[1:]); given {
			if _, ok := rsyncSSH(shell); !ok {
				p.fail = "rsync remote shell is not ssh"
				return
			}
		}
	}
	classified := map[string]bool{}
	for _, respelled := range respellTransfer(words, ends) {
		if key := join(respelled); !classified[key] {
			classified[key] = true
			op := classify(respelled)
			op.Dir = dir
			p.ops = append(p.ops, op)
		}
	}
	unsupported := transferHasUnsupportedOptions(name, words[1:])
	flagged := map[string]bool{}
	for _, e := range ends {
		nw, _ := wrapper{}.withSSH(e.host, "")
		if unsupported && !flagged[e.host] {
			flagged[e.host] = true
			p.remoteOp(nw, nil, "[unsupported-options]")
		}
		p.remoteOp(nw, words, e.verb...)
	}
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
