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
	case "cp", "install", "rsync":
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

var rsyncValued = set("-e", "--rsh", "--exclude", "--include", "--exclude-from", "--include-from", "--filter", "-f", "--files-from",
	"--backup-dir", "--link-dest", "--compare-dest", "--copy-dest", "--port", "--bwlimit", "--log-file", "--chmod", "--chown",
	"--max-size", "--min-size", "--rsync-path", "--temp-dir", "-T", "--timeout", "--suffix")

// copyShape treats cp, install and rsync as a write to the destination only.
// A destination with a colon is another host, which is no local path.
func copyShape(name string, args []string) (string, []string, []string) {
	valued := set("-S", "--suffix", "-m", "--mode", "-o", "--owner", "-g", "--group")
	if name == "rsync" {
		valued = rsyncValued
	}
	if name == "install" && hasShortFlag(args, "d") {
		return "", nil, nil
	}
	dir, rest, hasDir := targetDir(args)
	pos := positionals(rest, valued)
	var dst string
	switch {
	case hasDir:
		dst = dir
	case len(pos) >= 2:
		dst = pos[len(pos)-1]
	default:
		return "", nil, nil
	}
	if strings.Contains(dst, ":") {
		return "run_command", nil, nil
	}
	return "modify_file", []string{dst}, nil
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
