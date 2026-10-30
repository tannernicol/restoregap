// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package shellintent

import (
	"regexp"
	"strings"
)

// classify names the recovery-relevant operation an unwrapped local command
// performs. Anything it does not recognize keeps Action "".
func classify(words []string) Operation {
	op := Operation{Words: words, Command: join(words)}
	name, args := base(words[0]), words[1:]
	if action, paths, targets := fileShape(name, args); action != "" {
		op.Action, op.Paths, op.Targets = action, paths, targets
		return op
	}
	if runShape(name, args) {
		op.Action = "run_command"
		switch name {
		case "git", "terraform", "tofu", "pulumi", "dropdb":
			op.RepoScoped = true
		}
		return op
	}
	op.Benign = benign(name, args)
	return op
}

// builtins are shell builtins and keywords that change no recoverable state of
// their own (a redirect on them is caught separately, as modify_file).
var builtins = set("cd", "pushd", "popd", "echo", "printf", "true", "false", "test", "[", "[[", "export", "unset", "set",
	"read", "type", "which", "pwd", "exit", "return", "source", ".")

// readOnly are tools that only read. tee, cp, mv and friends are absent on
// purpose; sed, find, env and git are judged by their arguments.
var readOnly = set("ls", "cat", "head", "tail", "less", "more", "wc", "sort", "uniq", "cut", "tr", "grep", "egrep", "fgrep",
	"rg", "awk", "diff", "stat", "file", "du", "df", "date", "uname", "hostname", "whoami", "id", "sleep")

// benign reports whether an unrecognized command is a no-op or read-only, so a
// strict-mode caller can tell "cd /tmp && rm x" from "mystery-tool && rm x".
func benign(name string, args []string) bool {
	switch {
	case builtins[name] || readOnly[name]:
		return true
	case name == "command":
		return len(args) > 0 && (args[0] == "-v" || args[0] == "-V")
	case name == "env":
		return len(skipOptions(args, set("-u", "-C", "--unset", "--chdir"))) == 0
	case name == "sed":
		return !hasAny(args, "--in-place") && !hasPrefixAny(args, "--in-place=") && !hasShortFlag(args, "i")
	case name == "find":
		return !hasAny(args, "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls")
	case name == "git":
		return gitReadOnly(args)
	}
	return false
}

func gitReadOnly(args []string) bool {
	sub, rest := gitSubcommand(args)
	switch sub {
	case "status", "log", "diff", "show", "rev-parse", "fetch", "ls-files", "grep", "blame", "describe":
		return true
	case "branch":
		return !hasShortFlag(rest, "dD") && !hasAny(rest, "--delete")
	case "tag":
		return !hasShortFlag(rest, "d") && !hasAny(rest, "--delete")
	case "remote":
		for _, a := range rest {
			if a != "-v" && a != "--verbose" {
				return false
			}
		}
		return true
	case "stash":
		return firstIs(positionals(rest, nil), 0, "list")
	}
	return false
}

// gitSubcommand returns the git subcommand and its arguments, skipping git's
// own global options.
func gitSubcommand(args []string) (sub string, rest []string) {
	valued := set("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix", "--config-env")
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "-") {
			return args[i], args[i+1:]
		}
		if valued[args[i]] {
			i++
		}
	}
	return "", nil
}

// fileShape handles commands whose operands are local paths. A shape with no
// usable operand returns "" rather than an empty path list.
func fileShape(name string, args []string) (action string, paths, targets []string) {
	switch name {
	case "rm", "unlink", "rmdir":
		return pathsOp("delete_file", positionals(args, nil))
	case "shred":
		return pathsOp("delete_file", positionals(args, set("-n", "-s", "--iterations", "--size", "--random-source")))
	case "find":
		return findShape(args)
	case "mv":
		return moveShape(args)
	case "truncate":
		return pathsOp("modify_file", positionals(args, set("-s", "-r", "--size", "--reference")))
	case "dd":
		for _, a := range args {
			if v, ok := strings.CutPrefix(a, "of="); ok && v != "" && !devSink(v) {
				paths = []string{v}
			}
		}
		return pathsOp("modify_file", paths)
	case "tee":
		return pathsOp("modify_file", filterSinks(positionals(args, nil)))
	case "cp", "install", "rsync", "scp", "sftp":
		return copyShape(name, args)
	case "chmod", "chown", "chgrp":
		return ownershipShape(name, args)
	}
	return "", nil, nil
}

var chmodMode = regexp.MustCompile(`^[-+][rwxXstugo]+$`)

// ownershipShape drops the mode or owner operand and keeps the files. chmod's
// "-x" is a mode, not a flag, so it is peeled off before flags are skipped.
func ownershipShape(name string, args []string) (string, []string, []string) {
	haveSpec := hasPrefixAny(args, "--reference")
	var rest []string
	for _, a := range args {
		if name == "chmod" && !haveSpec && chmodMode.MatchString(a) {
			haveSpec = true
			continue
		}
		rest = append(rest, a)
	}
	pos := positionals(rest, set("--reference"))
	if !haveSpec && len(pos) > 0 {
		pos = pos[1:]
	}
	return pathsOp("modify_file", pos)
}

func pathsOp(action string, paths []string) (string, []string, []string) {
	if len(paths) == 0 {
		return "", nil, nil
	}
	return action, paths, nil
}

func hasPrefixAny(args []string, prefixes ...string) bool {
	for _, a := range args {
		for _, p := range prefixes {
			if strings.HasPrefix(a, p) {
				return true
			}
		}
	}
	return false
}

func devSink(p string) bool {
	return p == "/dev/null" || p == "/dev/stdout" || p == "/dev/stderr" || p == "/dev/tty"
}

func filterSinks(paths []string) []string {
	var out []string
	for _, p := range paths {
		if !devSink(p) {
			out = append(out, p)
		}
	}
	return out
}

// targetDir pulls a -t DIR / --target-directory DIR option out of args.
func targetDir(args []string) (dir string, rest []string, ok bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return dir, append(rest, args[i:]...), ok
		case (a == "-t" || a == "--target-directory") && i+1 < len(args):
			dir, ok = args[i+1], true
			i++
		case strings.HasPrefix(a, "--target-directory="):
			dir, ok = strings.TrimPrefix(a, "--target-directory="), true
		default:
			rest = append(rest, a)
		}
	}
	return dir, rest, ok
}

func moveShape(args []string) (string, []string, []string) {
	dir, rest, hasDir := targetDir(args)
	pos := positionals(rest, set("-S", "--suffix"))
	if hasDir {
		if len(pos) == 0 {
			return "", nil, nil
		}
		return "move_file", pos, []string{dir}
	}
	if len(pos) < 2 {
		return "", nil, nil
	}
	return "move_file", pos[:len(pos)-1], pos[len(pos)-1:]
}

// rsyncValued are the rsync and openrsync options that take a value. rsync
// accepts options after its operands, so a missing entry would let a trailing
// "--opt value" pass for the destination.
var rsyncValued = set("-e", "--rsh", "--exclude", "--include", "--exclude-from", "--include-from", "--filter", "-f", "--files-from",
	"--backup-dir", "--link-dest", "--compare-dest", "--copy-dest", "--port", "--bwlimit", "--log-file", "--chmod", "--chown",
	"--max-size", "--min-size", "--rsync-path", "--temp-dir", "-T", "--timeout", "--suffix",
	"-B", "--block-size", "-M", "--remote-option", "-@", "--modify-window", "--info", "--debug", "--stderr", "--max-delete",
	"--max-alloc", "--partial-dir", "--usermap", "--groupmap", "--contimeout", "--compress-choice", "--zc", "--compress-level",
	"--zl", "--skip-compress", "--address", "--sockopts", "--out-format", "--log-file-format", "--password-file", "--early-input",
	"--stop-after", "--stop-at", "--write-batch", "--only-write-batch", "--read-batch", "--protocol", "--iconv",
	"--checksum-choice", "--cc", "--checksum-seed", "--outbuf", "--copy-as", "--config", "--dparam")

// copyShape treats cp, install and rsync as a write to the destination only.
// A destination with a colon is another host, which is no local path. scp and
// sftp follow their own rule for that (see transferShape). rsync's -t is
// --times, not a target directory, and a lone remote rsync operand lists that
// host.
func copyShape(name string, args []string) (string, []string, []string) {
	if name == "scp" || name == "sftp" {
		return transferShape(name, args)
	}
	valued := set("-S", "--suffix", "-m", "--mode", "-o", "--owner", "-g", "--group")
	dir, rest, hasDir := targetDir(args)
	if name == "rsync" {
		valued = rsyncValued
		dir, rest, hasDir = "", args, false
	}
	if name == "install" && hasShortFlag(args, "d") {
		return "", nil, nil
	}
	pos := positionals(rest, valued)
	var dst string
	switch {
	case hasDir:
		dst = dir
	case len(pos) >= 2:
		dst = pos[len(pos)-1]
	case name == "rsync" && len(pos) == 1:
		if _, _, _, remote, _ := rsyncOperand(pos[0]); remote {
			return "run_command", nil, nil
		}
		return "", nil, nil
	default:
		return "", nil, nil
	}
	if strings.Contains(dst, ":") {
		return "run_command", nil, nil
	}
	return "modify_file", []string{dst}, nil
}

var (
	transferValued = map[string]map[string]bool{
		"scp":  set("-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-S", "-X"),
		"sftp": set("-B", "-b", "-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-R", "-S", "-s", "-X"),
	}
	// transferSafe are the scp and sftp options that only tune the copy or
	// the connection. -o is vetted per option, as for ssh; anything else (an
	// ssh config, jump host, program to run instead of ssh, batch file or
	// agent forwarding) needs coverage of its own.
	transferSafe = map[string]map[string]bool{
		"scp":  set("-3", "-4", "-6", "-B", "-C", "-O", "-p", "-q", "-R", "-r", "-s", "-T", "-v", "-c", "-i", "-l", "-P"),
		"sftp": set("-4", "-6", "-a", "-C", "-f", "-N", "-p", "-q", "-r", "-v", "-B", "-c", "-i", "-l", "-P", "-R"),
	}
)

// transferShape is copyShape for scp and sftp. A local scp destination is a
// write to that path, as with cp, and a remote one is a run_command. sftp's
// operand is always a host, so it is a run_command, and its optional second
// operand is the local file a download writes. What either reaches on the
// other host is recorded by parser.transfer.
func transferShape(name string, args []string) (string, []string, []string) {
	pos := positionals(args, transferValued[name])
	if name == "sftp" {
		switch len(pos) {
		case 1:
			return "run_command", nil, nil
		case 2:
			return "modify_file", pos[1:], nil
		}
		return "", nil, nil
	}
	if len(pos) < 2 {
		return "", nil, nil
	}
	dst := pos[len(pos)-1]
	if _, _, remote, _ := scpOperand(dst); remote {
		return "run_command", nil, nil
	}
	return "modify_file", []string{dst}, nil
}

// remoteEnd is one scp or sftp operand on another host.
type remoteEnd struct {
	operand string
	// host is what ssh is given: no user@, no IPv6 brackets.
	host string
	// before and after are the operand's text around the host as typed, so
	// the operand can be respelled with the host in another form.
	before, after string
	// verb is the equivalent remote command: scp -t PATH, scp -f PATH, sftp.
	verb []string
}

// transferEnds returns the operands of an scp, sftp or rsync command that
// name another host. It reports false when it cannot tell which hosts the
// command reaches: the wrong number of operands, a host written with shell
// syntax this package does not expand ($H, a glob, a brace list), or a mode
// with no ssh destination (-D talks to a local sftp server; -t and -f are
// scp's own remote end).
func transferEnds(name string, args []string) ([]remoteEnd, bool) {
	if name == "rsync" {
		return rsyncEnds(args)
	}
	direct := false
	transferOptions(name, args, func(flag, _ string) {
		direct = direct || flag == "-D" || (name == "scp" && (flag == "-t" || flag == "-f"))
	})
	if direct {
		return nil, false
	}
	pos := positionals(args, transferValued[name])
	if name == "sftp" {
		return sftpEnds(pos)
	}
	return scpEnds(pos)
}

// sftpEnds reads sftp's operands: one destination, then an optional local file.
func sftpEnds(pos []string) ([]remoteEnd, bool) {
	if len(pos) == 0 || len(pos) > 2 {
		return nil, false
	}
	e, path, ok := sftpDestination(pos[0])
	if !ok {
		return nil, false
	}
	e.verb = []string{"sftp"}
	if path != "" {
		e.verb = append(e.verb, path)
	}
	return []remoteEnd{e}, true
}

// scpEnds reads scp's operands: sources, then the destination last.
func scpEnds(pos []string) ([]remoteEnd, bool) {
	if len(pos) < 2 {
		return nil, false
	}
	var ends []remoteEnd
	for i, a := range pos {
		e, path, remote, ok := scpOperand(a)
		if !ok {
			return nil, false
		}
		if !remote {
			continue
		}
		mode := "-f"
		if i == len(pos)-1 {
			mode = "-t"
		}
		if path == "" {
			path = "."
		}
		e.verb = []string{"scp", mode, path}
		ends = append(ends, e)
	}
	return ends, true
}

// scpOperand applies scp's rule for an operand naming another host: an
// scp:// URI, or [user@]host:path with the colon before any slash and an IPv6
// host in brackets. A leading colon, or a slash first, makes a local path.
// ok is false for a remote operand whose host cannot be read.
func scpOperand(a string) (e remoteEnd, path string, remote, ok bool) {
	if rest, isURI := cutURI(a, "scp"); isURI {
		e, path, ok = uriEnd(a, rest)
		return e, path, true, ok
	}
	colon := scpColon(a)
	if colon < 0 {
		return remoteEnd{}, "", false, true
	}
	at := strings.LastIndexByte(a[:colon], '@') + 1
	e, ok = newEnd(a, at, colon)
	return e, a[colon+1:], true, ok
}

// sftpDestination reads sftp's one host operand: an sftp:// URI, or
// [user@]host with an optional :path, an IPv6 host in brackets. It returns the
// path too, when there is one.
func sftpDestination(a string) (remoteEnd, string, bool) {
	if rest, isURI := cutURI(a, "sftp"); isURI {
		return uriEnd(a, rest)
	}
	colon, path := scpColon(a), ""
	if colon < 0 {
		colon = len(a)
	} else {
		path = a[colon+1:]
	}
	at := strings.LastIndexByte(a[:colon], '@') + 1
	e, ok := newEnd(a, at, colon)
	return e, path, ok
}

// scpColon is OpenSSH's colon(): the index of the colon that ends the host
// part of an operand, or -1 when the operand is a local path.
func scpColon(a string) int {
	if a == "" || a[0] == ':' {
		return -1
	}
	bracket := a[0] == '['
	for i := 0; i < len(a); i++ {
		switch {
		case a[i] == '@' && i+1 < len(a) && a[i+1] == '[':
			bracket = true
		case a[i] == ']' && i+1 < len(a) && a[i+1] == ':' && bracket:
			return i + 1
		case a[i] == ':' && !bracket:
			return i
		case a[i] == '/':
			return -1
		}
	}
	return -1
}

// cutURI returns what follows "scheme://", matching the scheme without regard
// to case as OpenSSH does.
func cutURI(a, scheme string) (string, bool) {
	n := len(scheme) + len("://")
	if len(a) < n || !strings.EqualFold(a[:len(scheme)], scheme) || a[len(scheme):n] != "://" {
		return "", false
	}
	return a[n:], true
}

// uriEnd reads scheme://[user@]host[:port][/path] given what follows "://".
func uriEnd(a, rest string) (remoteEnd, string, bool) {
	authority, path, _ := strings.Cut(rest, "/")
	at := strings.LastIndexByte(authority, '@') + 1
	hostport := authority[at:]
	end := strings.IndexByte(hostport, ':')
	if strings.HasPrefix(hostport, "[") {
		if end = strings.IndexByte(hostport, ']') + 1; end == 0 {
			return remoteEnd{}, "", false
		}
	}
	if end < 0 {
		end = len(hostport)
	}
	start := len(a) - len(rest) + at
	e, ok := newEnd(a, start, start+end)
	return e, path, ok
}

// newEnd makes a remoteEnd whose host is operand[start:end]. ok is false for
// an empty host or one using shell syntax the parser leaves unexpanded.
func newEnd(operand string, start, end int) (remoteEnd, bool) {
	host := operand[start:end]
	if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if host == "" || strings.ContainsAny(host, "$`*?[]{}~ \t\n") {
		return remoteEnd{}, false
	}
	return remoteEnd{operand: operand, host: host, before: operand[:start], after: operand[end:]}, true
}

// transferOptions visits each scp or sftp option letter with its value, up to
// "--". Operands are skipped rather than ending the options. It reports false
// for a form neither tool has: a long option, or a value missing at the end.
func transferOptions(name string, args []string, visit func(flag, value string)) bool {
	valued := transferValued[name]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return true
		}
		if len(a) < 2 || a[0] != '-' {
			continue
		}
		if a[1] == '-' {
			return false
		}
		for j := 1; j < len(a); j++ {
			flag := "-" + string(a[j])
			if !valued[flag] {
				visit(flag, "")
				continue
			}
			value := a[j+1:]
			if value == "" {
				if i+1 >= len(args) {
					return false
				}
				i++
				value = args[i]
			}
			visit(flag, value)
			break
		}
	}
	return true
}

// transferHasUnsupportedOptions is sshHasUnsupportedOptions for scp, sftp and
// rsync.
func transferHasUnsupportedOptions(name string, args []string) bool {
	if name == "rsync" {
		return rsyncHasUnsupportedOptions(args)
	}
	unsupported := false
	ok := transferOptions(name, args, func(flag, value string) {
		if flag == "-o" {
			option, _, found := strings.Cut(value, "=")
			unsupported = unsupported || !found || !sshSafeOptions[strings.ToLower(option)]
			return
		}
		unsupported = unsupported || !transferSafe[name][flag]
	})
	return unsupported || !ok
}

// respellTransfer returns words as typed, then a copy for each further host
// spelling index with every remote operand's host in that spelling (or its
// last one), so each spelling of each host appears in some copy.
func respellTransfer(words []string, ends []remoteEnd) [][]string {
	out := [][]string{words}
	spellings := make([][]string, len(ends))
	most := 0
	for i, e := range ends {
		spellings[i] = hostSpellings(e.host)
		most = max(most, len(spellings[i]))
	}
	for k := 1; k < most; k++ {
		swap := map[string]string{}
		for i, e := range ends {
			h := spellings[i][min(k, len(spellings[i])-1)]
			if strings.Contains(h, ":") {
				h = "[" + h + "]"
			}
			swap[e.operand] = e.before + h + e.after
		}
		respelled := append([]string(nil), words...)
		for j := 1; j < len(respelled); j++ {
			if r, ok := swap[respelled[j]]; ok {
				respelled[j] = r
			}
		}
		out = append(out, respelled)
	}
	return out
}

// hasShortFlag reports whether any short-flag cluster in args contains letter.
func hasShortFlag(args []string, letters string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsAny(a[1:], letters) {
			return true
		}
	}
	return false
}

func findShape(args []string) (string, []string, []string) {
	i := 0
	for i < len(args) && isFindGlobalOption(args[i]) {
		if args[i] == "-D" {
			i++
		}
		i++
	}
	var roots []string
	for i < len(args) && !strings.HasPrefix(args[i], "-") && args[i] != "(" && args[i] != "!" {
		roots = append(roots, args[i])
		i++
	}
	expr := args[min(i, len(args)):]
	destructive := false
	for j, a := range expr {
		if a == "-delete" {
			destructive = true
		}
		if (a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir") && j+1 < len(expr) {
			switch base(expr[j+1]) {
			case "rm", "shred", "unlink", "rmdir":
				destructive = true
			}
		}
	}
	if !destructive {
		return "", nil, nil
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	return "delete_file", roots, nil
}

// isFindGlobalOption tells find's -H/-L/-P/-D/-O options, which precede the
// root list, from the start of its expression, which ends it.
func isFindGlobalOption(a string) bool {
	switch a {
	case "-H", "-L", "-P", "-D":
		return true
	}
	return len(a) == 3 && a[:2] == "-O"
}

var sqlDestructive = regexp.MustCompile(`(?i)\b(drop|truncate)\b|\bdelete\s+from\b`)

// runShape reports whether an unwrapped command is a destructive operation with
// no file operand to guard, so only a `commands` glob can express it.
func runShape(name string, args []string) bool {
	switch name {
	case "git":
		return gitDestructive(args)
	case "terraform", "tofu":
		pos := positionals(args, nil)
		return len(pos) > 0 && (pos[0] == "destroy" || (pos[0] == "apply" && hasAny(args, "-destroy", "--destroy")))
	case "pulumi":
		return firstIs(positionals(args, set("-C", "--cwd", "-s", "--stack")), 0, "destroy")
	case "dropdb":
		return true
	case "psql", "mysql", "mariadb", "sqlite3":
		return sqlHasDestructive(name, args)
	case "redis-cli":
		for _, a := range args {
			if l := strings.ToLower(a); l == "flushall" || l == "flushdb" {
				return true
			}
		}
		return false
	case "docker", "podman", "docker-compose":
		return containerDestructive(name, args)
	case "kubectl":
		return firstIs(positionals(args, kubeValued), 0, "delete")
	case "helm":
		return firstIs(positionals(args, set("-n", "--namespace", "--kube-context", "--kubeconfig")), 0, "uninstall", "delete", "un")
	case "systemctl":
		return firstIs(positionals(args, set("-H", "--host", "-M", "--machine", "-t", "--type", "-p", "--property", "-s", "--signal", "-n", "--lines", "-o", "--output", "--root")), 0, "disable", "mask")
	case "zfs", "zpool":
		return firstIs(positionals(args, nil), 0, "destroy")
	case "btrfs":
		pos := positionals(args, nil)
		return firstIs(pos, 0, "subvolume") && firstIs(pos, 1, "delete", "del")
	case "lvremove", "vgremove", "wipefs":
		return true
	case "sgdisk":
		return hasPrefixAny(args, "--zap") || hasShortFlag(args, "zZ")
	case "parted":
		return hasAny(args, "rm", "mklabel", "mktable")
	case "restic":
		return anyOfFirst(positionals(args, set("-r", "--repo", "--password-file", "-p", "-o", "--option", "--cache-dir", "--cacert", "--key-hint", "--limit-download", "--limit-upload", "--repository-file")), 2, "forget", "prune")
	case "borg":
		return anyOfFirst(positionals(args, set("--repo", "-r", "--remote-path", "--lock-wait", "--umask")), 2, "prune", "delete", "compact")
	case "rclone":
		return anyOfFirst(positionals(args, set("--config", "--transfers", "--checkers", "--bwlimit", "--filter", "--include", "--exclude", "--log-file", "--log-level", "--max-age", "--min-age", "--retries", "--timeout", "--contimeout", "--backup-dir", "--suffix")), 2, "delete", "purge", "sync", "move")
	case "aws":
		pos := positionals(args, set("--profile", "--region", "--endpoint-url", "--output", "--query", "--cli-read-timeout", "--cli-connect-timeout", "--ca-bundle"))
		if !firstIs(pos, 0, "s3") {
			return false
		}
		return firstIs(pos, 1, "rm", "rb") || (firstIs(pos, 1, "sync") && hasAny(args, "--delete"))
	case "gsutil":
		return firstIs(positionals(args, set("-o", "-h", "-u")), 0, "rm", "rb")
	case "crontab":
		return hasShortFlag(args, "r")
	case "launchctl":
		return firstIs(positionals(args, nil), 0, "bootout", "remove")
	case "gh":
		pos := positionals(args, set("-R", "--repo", "--hostname"))
		return (firstIs(pos, 0, "repo") || firstIs(pos, 0, "release")) && firstIs(pos, 1, "delete")
	case "xargs":
		return xargsRemoves(args)
	}
	if strings.HasPrefix(name, "mkfs") {
		return true
	}
	return false
}

func firstIs(pos []string, i int, want ...string) bool {
	if i >= len(pos) {
		return false
	}
	for _, w := range want {
		if pos[i] == w {
			return true
		}
	}
	return false
}

// anyOfFirst checks the first n positionals, because a tool's own value-taking
// flags can push the verb back one slot when this package does not know them.
func anyOfFirst(pos []string, n int, want ...string) bool {
	for i := 0; i < n; i++ {
		if firstIs(pos, i, want...) {
			return true
		}
	}
	return false
}

func hasAny(args []string, want ...string) bool {
	for _, a := range args {
		for _, w := range want {
			if a == w {
				return true
			}
		}
	}
	return false
}

func gitDestructive(args []string) bool {
	sub, rest := gitSubcommand(args)
	switch sub {
	case "push":
		for _, a := range rest {
			if a == "--force" || strings.HasPrefix(a, "--force-with-lease") || a == "--force-if-includes" {
				return true
			}
			// "git push origin +main" force-updates that ref.
			if len(a) > 1 && a[0] == '+' {
				return true
			}
		}
		return hasShortFlag(rest, "f")
	case "branch":
		deleting := hasAny(rest, "--delete") || hasShortFlag(rest, "d")
		forced := hasAny(rest, "--force") || hasShortFlag(rest, "f")
		return hasShortFlag(rest, "D") || (deleting && forced)
	case "reset":
		return hasAny(rest, "--hard")
	case "clean":
		if hasAny(rest, "--dry-run") || hasShortFlag(rest, "n") {
			return false
		}
		return hasAny(rest, "--force") || hasShortFlag(rest, "fxdX")
	case "stash":
		return firstIs(positionals(rest, nil), 0, "drop", "clear")
	case "checkout", "restore":
		return hasAny(rest, ".")
	}
	return false
}

func sqlHasDestructive(name string, args []string) bool {
	var sql []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c" || a == "-e" || a == "--command" || a == "--execute" || a == "-cmd":
			if i+1 < len(args) {
				sql = append(sql, args[i+1])
				i++
			}
		case strings.HasPrefix(a, "--command="):
			sql = append(sql, strings.TrimPrefix(a, "--command="))
		case strings.HasPrefix(a, "--execute="):
			sql = append(sql, strings.TrimPrefix(a, "--execute="))
		case len(a) > 2 && a[0] == '-' && (a[1] == 'c' || a[1] == 'e') && a != "-cmd":
			sql = append(sql, a[2:])
		}
	}
	if name == "sqlite3" {
		if pos := positionals(args, nil); len(pos) > 1 {
			sql = append(sql, pos[1:]...)
		}
	}
	for _, s := range sql {
		if sqlDestructive.MatchString(s) {
			return true
		}
	}
	return false
}

// containerDestructive covers docker, podman and docker-compose verbs that
// remove containers, volumes, stacks or everything unused.
func containerDestructive(name string, args []string) bool {
	pos := positionals(args, dockerGlobal)
	if name == "docker-compose" {
		return firstIs(pos, 0, "down")
	}
	switch {
	case firstIs(pos, 0, "rm"):
		return true
	case firstIs(pos, 0, "container"):
		return firstIs(pos, 1, "rm", "remove", "prune")
	case firstIs(pos, 0, "volume"):
		return firstIs(pos, 1, "rm", "remove", "prune")
	case firstIs(pos, 0, "system"):
		return firstIs(pos, 1, "prune")
	case firstIs(pos, 0, "compose"):
		return firstIs(pos, 1, "down")
	case firstIs(pos, 0, "stack"):
		return firstIs(pos, 1, "rm", "remove", "down")
	}
	return false
}

// xargsRemoves recognizes "xargs [options] rm ...": the paths come from stdin,
// so nothing can be named, but the command is still a delete.
func xargsRemoves(args []string) bool {
	rest := skipOptions(args, set("-I", "-n", "-P", "-L", "-E", "-d", "-s", "-a", "--arg-file", "--max-args", "--max-procs", "--max-lines", "--delimiter", "--max-chars", "--replace"))
	for len(rest) > 0 {
		next, ok := unwrapPrefix(rest)
		if !ok {
			break
		}
		rest = next
	}
	if len(rest) == 0 {
		return false
	}
	switch base(rest[0]) {
	case "rm", "shred", "unlink", "rmdir":
		return true
	}
	return false
}

// rsyncEnds reads rsync's operands: sources, then the destination last; a lone
// operand is a listing, so a read. Each remote one is recorded as the server
// rsync runs there, with --sender when it reads and --daemon for a module.
func rsyncEnds(args []string) ([]remoteEnd, bool) {
	pos := positionals(args, rsyncValued)
	var ends []remoteEnd
	for i, a := range pos {
		e, path, daemon, remote, ok := rsyncOperand(a)
		if !ok {
			return nil, false
		}
		if !remote {
			continue
		}
		verb := []string{"rsync", "--server"}
		if i < len(pos)-1 || len(pos) == 1 {
			verb = append(verb, "--sender")
		}
		if daemon {
			verb = append(verb, "--daemon")
		}
		if path == "" {
			path = "."
		}
		e.verb = append(verb, ".", path)
		ends = append(ends, e)
	}
	return ends, true
}

// rsyncOperand applies rsync's rule for an operand naming another host: an
// rsync:// URL or host::module (both a daemon), or [user@]host:path with the
// colon before any slash and an IPv6 host in brackets. ok is false for a remote
// operand whose host cannot be read.
func rsyncOperand(a string) (e remoteEnd, path string, daemon, remote, ok bool) {
	if rest, isURI := cutURI(a, "rsync"); isURI {
		e, path, ok = uriEnd(a, rest)
		return e, path, true, true, ok
	}
	colon := rsyncColon(a)
	if colon < 0 {
		return remoteEnd{}, "", false, false, true
	}
	at := strings.LastIndexByte(a[:colon], '@') + 1
	e, ok = newEnd(a, at, colon)
	path, daemon = strings.CutPrefix(a[colon+1:], ":")
	return e, path, daemon, true, ok
}

// rsyncColon is rsync's check_for_hostspec without a URL: the index of the
// colon that ends the host part, or -1 for a local path (no colon, or a slash
// first). A bracketed IPv6 host must start the host part.
func rsyncColon(a string) int {
	hostStart := 0
	for i := 0; i < len(a); i++ {
		switch a[i] {
		case ':':
			return i
		case '/':
			return -1
		case '@':
			hostStart = i + 1
		case '[':
			end := strings.IndexAny(a[i:], "]/")
			if i != hostStart || end < 0 || a[i+end] != ']' {
				return -1
			}
			i += end
		}
	}
	return -1
}

// rsyncOptions visits each rsync option with its value, up to "--". A long
// option is --name or --name=value; short ones may be clustered.
func rsyncOptions(args []string, visit func(flag, value string)) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return
		}
		if len(a) < 2 || a[0] != '-' {
			continue
		}
		if strings.HasPrefix(a, "--") {
			name, value, inline := strings.Cut(a, "=")
			if !inline && rsyncValued[name] && i+1 < len(args) {
				i++
				value = args[i]
			}
			visit(name, value)
			continue
		}
		for j := 1; j < len(a); j++ {
			flag := "-" + string(a[j])
			if !rsyncValued[flag] {
				visit(flag, "")
				continue
			}
			value := a[j+1:]
			if value == "" && i+1 < len(args) {
				i++
				value = args[i]
			}
			visit(flag, value)
			break
		}
	}
}

// rsyncShell returns the remote shell -e or --rsh names, if one is given.
func rsyncShell(args []string) (shell string, given bool) {
	rsyncOptions(args, func(flag, value string) {
		if flag == "-e" || flag == "--rsh" {
			shell, given = value, true
		}
	})
	return shell, given
}

// rsyncSSH splits a remote shell the way rsync does and reports whether it is
// ssh with nothing but its own options, so that the host rsync appends is the
// one ssh connects to. "ssh nas" would connect to nas whatever the operand
// says; anything other than ssh is not modeled at all.
func rsyncSSH(shell string) ([]string, bool) {
	toks, fail := tokenize(shell)
	if fail != "" {
		return nil, false
	}
	var words []string
	for _, t := range toks {
		if t.kind != tWord {
			return nil, false
		}
		words = append(words, t.text)
	}
	if len(words) == 0 || base(words[0]) != "ssh" {
		return nil, false
	}
	for i := 1; i < len(words); i++ {
		a := words[i]
		if len(a) < 2 || a[0] != '-' || a == "--" {
			return nil, false
		}
		if takesNext(a, sshValued) {
			if i++; i >= len(words) {
				return nil, false
			}
		}
	}
	return words, true
}

// rsyncHasUnsupportedOptions reports options that change what rsync runs on
// the other host (--rsync-path, -M/--remote-option) or ssh options that ssh
// itself would not drop.
func rsyncHasUnsupportedOptions(args []string) bool {
	unsupported := false
	rsyncOptions(args, func(flag, _ string) {
		unsupported = unsupported || flag == "--rsync-path" || flag == "-M" || flag == "--remote-option"
	})
	if shell, given := rsyncShell(args); given {
		words, ok := rsyncSSH(shell)
		unsupported = unsupported || !ok || sshHasUnsupportedOptions(words)
	}
	return unsupported
}
