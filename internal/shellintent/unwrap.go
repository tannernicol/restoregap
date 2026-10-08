// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package shellintent

import "strings"

// positionals returns the non-flag words of args. valued lists flags (as
// "-x" or "--long") whose value is the following word; a short flag inside a
// cluster ("-it", "-p2222") is honored too. "--" ends flag parsing.
func positionals(args []string, valued map[string]bool) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return append(out, args[i+1:]...)
		}
		if len(a) < 2 || a[0] != '-' {
			out = append(out, a)
			continue
		}
		if takesNext(a, valued) {
			i++
		}
	}
	return out
}

// takesNext reports whether flag word a consumes the next word as its value.
func takesNext(a string, valued map[string]bool) bool {
	if strings.HasPrefix(a, "--") {
		return valued[a] && !strings.Contains(a, "=")
	}
	for j := 1; j < len(a); j++ {
		if valued["-"+string(a[j])] {
			return j == len(a)-1
		}
	}
	return false
}

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

// unwrapPrefix removes one transparent prefix (sudo, env, nice, ...) and any
// assignments that follow it. It reports false when the first word is not a
// prefix or nothing would remain, so a bare "sudo" stays a command of its own.
func unwrapPrefix(words []string) ([]string, bool) {
	name := base(words[0])
	args := words[1:]
	var rest []string
	switch name {
	case "sudo", "doas":
		rest = skipOptions(args, set("-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-r", "-t", "-U", "--user", "--group", "--host", "--prompt", "--chdir", "--role", "--type"))
	case "env":
		rest = skipOptions(args, set("-u", "-C", "--unset", "--chdir"))
	case "nice":
		rest = skipOptions(args, set("-n", "--adjustment"))
	case "nohup", "time", "builtin":
		rest = skipOptions(args, nil)
	case "command":
		// "command -v x" only looks a name up; it runs nothing.
		if len(args) > 0 && (args[0] == "-v" || args[0] == "-V") {
			return nil, false
		}
		rest = skipOptions(args, nil)
	case "exec":
		rest = skipOptions(args, set("-a"))
	case "stdbuf":
		rest = skipOptions(args, set("-i", "-o", "-e", "--input", "--output", "--error"))
	case "timeout":
		rest = skipOptions(args, set("-s", "-k", "--signal", "--kill-after"))
		// The duration is the first operand.
		if len(rest) > 0 {
			rest = rest[1:]
		}
	default:
		return nil, false
	}
	for len(rest) > 0 && isAssignment(rest[0]) {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return nil, false
	}
	return rest, true
}

// skipOptions drops leading flags (and the values of valued ones) and, for
// env-style wrappers, VAR=value assignments, stopping at the first operand.
func skipOptions(args []string, valued map[string]bool) []string {
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--":
			return args[i+1:]
		case isAssignment(a):
			i++
		case len(a) >= 2 && a[0] == '-':
			if takesNext(a, valued) {
				i++
			}
			i++
		default:
			return args[i:]
		}
	}
	return nil
}

var sshValued = set("-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w")

// parseSSH splits "ssh [options] [user@]host cmd..." into the host and the
// remote command words. It reports false for an interactive session.
func parseSSH(words []string) (host string, inner []string, ok bool) {
	args := words[1:]
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if len(a) < 2 || a[0] != '-' {
			break
		}
		if takesNext(a, sshValued) {
			i++
		}
		i++
	}
	if i >= len(args) {
		return "", nil, false
	}
	host = args[i]
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}
	inner = args[i+1:]
	if host == "" || len(inner) == 0 {
		return "", nil, false
	}
	return host, inner, true
}

func isShell(name string) bool {
	switch name {
	case "bash", "sh", "zsh", "dash", "ksh":
		return true
	}
	return false
}

// shellDashC returns STRING from "bash [-l -e -x ...] -c STRING", including the
// combined forms -lc, -ec and -xc. Running a script by path is not unwrapped.
func shellDashC(words []string) (string, bool) {
	args := words[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return "", false
		case a == "-o" || a == "+o" || a == "-O" || a == "+O":
			i++
		case len(a) >= 2 && (a[0] == '-' || a[0] == '+') && a[1] != '-' && isLetters(a[1:]):
			if a[0] == '-' && strings.Contains(a, "c") {
				if i+1 < len(args) {
					return args[i+1], true
				}
				return "", false
			}
		case strings.HasPrefix(a, "--"):
		default:
			return "", false
		}
	}
	return "", false
}

func isLetters(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

var (
	dockerGlobal = set("-H", "--host", "--context", "-c", "-l", "--log-level", "--config", "--tlscacert", "--tlscert", "--tlskey",
		"-f", "--file", "-p", "--project-name", "--profile", "--env-file", "--project-directory", "--parallel", "--ansi")
	dockerExecValued = set("-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file", "--detach-keys", "--index")
	kubeValued       = set("-n", "--namespace", "--context", "--kubeconfig", "-s", "--server", "--cluster", "--user", "--token", "--as", "--request-timeout", "-c", "--container", "-f", "--filename", "-v")
)

// parseExec recognizes "docker exec", "docker container exec", "podman exec",
// "docker compose exec", "docker-compose exec" and "kubectl exec". It returns
// the container/service/pod, the Command prefix that restores the wrapper, and
// the words executed inside it.
func parseExec(words []string) (target string, prefix, inner []string, ok bool) {
	name := base(words[0])
	args := words[1:]
	if name == "kubectl" {
		return parseKubectlExec(args)
	}
	// Locate the verb, skipping client-level flags such as -H or --context.
	i := 0
	nextWord := func() (string, bool) {
		for i < len(args) {
			a := args[i]
			if a == "--" {
				return "", false
			}
			if len(a) < 2 || a[0] != '-' {
				i++
				return a, true
			}
			if takesNext(a, dockerGlobal) {
				i++
			}
			i++
		}
		return "", false
	}
	verb, found := nextWord()
	if !found {
		return "", nil, nil, false
	}
	compose := name == "docker-compose"
	if verb == "container" || verb == "compose" {
		compose = compose || verb == "compose"
		if verb, found = nextWord(); !found {
			return "", nil, nil, false
		}
	}
	if verb != "exec" {
		return "", nil, nil, false
	}
	rest := args[i:]
	pos := 0
	for pos < len(rest) {
		a := rest[pos]
		if a == "--" {
			pos++
			break
		}
		if len(a) < 2 || a[0] != '-' {
			break
		}
		if takesNext(a, dockerExecValued) {
			pos++
		}
		pos++
	}
	if pos >= len(rest) {
		return "", nil, nil, false
	}
	target = rest[pos]
	inner = rest[pos+1:]
	if len(inner) == 0 {
		return "", nil, nil, false
	}
	switch {
	case name == "docker-compose":
		prefix = []string{"docker-compose", "exec", target}
	case compose:
		prefix = []string{name, "compose", "exec", target}
	default:
		prefix = []string{name, "exec", target}
	}
	return target, prefix, inner, true
}

func parseKubectlExec(args []string) (string, []string, []string, bool) {
	pos := positionals(args, kubeValued)
	if len(pos) < 2 || pos[0] != "exec" {
		return "", nil, nil, false
	}
	pod := pos[1]
	// Everything after "--" is the command; without it (older syntax) it is what
	// follows the pod name.
	var inner []string
	for i, a := range args {
		if a == "--" {
			inner = args[i+1:]
			break
		}
	}
	if inner == nil {
		seen := false
		for i, a := range args {
			if a == pod {
				seen = true
				inner = args[i+1:]
				break
			}
		}
		if !seen {
			return "", nil, nil, false
		}
		inner = dropFlagsWithValues(inner, kubeValued)
	}
	if len(inner) == 0 {
		return "", nil, nil, false
	}
	return pod, []string{"kubectl", "exec", pod}, inner, true
}

// dropFlagsWithValues removes the leading kubectl flags that follow a pod name
// when no "--" separator was given.
func dropFlagsWithValues(args []string, valued map[string]bool) []string {
	i := 0
	for i < len(args) {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			break
		}
		if takesNext(a, valued) {
			i++
		}
		i++
	}
	if i > len(args) {
		return nil
	}
	return args[i:]
}
