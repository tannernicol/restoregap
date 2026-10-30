// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package preflight

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// ResolveLocalPath resolves aliases for a local hook path, including existing
// parents of a file that has not been created yet. Relative paths use hook cwd.
func ResolveLocalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return abs, nil
	}
	resolved, err = ResolveLocalPath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(abs)), nil
}

// localPathAliases resolves only the literal prefix of each policy pattern.
// Wildcards retain their meaning; declarations and signed proofs stay intact.
func localPathAliases(ctx contextspec.Context) (map[string]string, error) {
	aliases := map[string]string{}
	add := func(raw string) error {
		if _, ok := aliases[raw]; ok || raw == "" {
			return nil
		}
		resolved, err := resolveLocalPattern(raw)
		if err != nil {
			// Policy declarations are already valid lexical matchers. Alias
			// resolution is only an additional way to match a local hook path,
			// so an inaccessible policy directory must not make the entire gate
			// unavailable. Keep the declaration's lexical form and continue.
			slog.Debug("restoregap: cannot canonicalize policy path; retaining lexical path", "path", raw, "error", err)
			aliases[raw] = raw
			return nil
		}
		aliases[raw] = resolved
		return nil
	}
	for _, guard := range ctx.Guards {
		for _, path := range guard.Match.Paths {
			if err := add(path); err != nil {
				return nil, err
			}
		}
	}
	for _, proof := range ctx.Proofs {
		if proof.Dependencies != nil {
			for _, path := range proof.Dependencies.Paths {
				if err := add(path); err != nil {
					return nil, err
				}
			}
		}
	}
	return aliases, nil
}

func resolveLocalPattern(raw string) (string, error) {
	path := raw
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = home + path[1:]
	}
	prefix, suffix := path, ""
	if i := strings.IndexAny(path, "*?["); i >= 0 {
		slash := strings.LastIndex(path[:i], "/")
		prefix, suffix = ".", path
		if slash >= 0 {
			prefix, suffix = path[:slash+1], path[slash+1:]
		}
	}
	resolved, err := ResolveLocalPath(prefix)
	if err != nil {
		return "", fmt.Errorf("resolve policy path %q: %w", raw, err)
	}
	if suffix != "" {
		resolved = strings.TrimSuffix(resolved, string(filepath.Separator)) + string(filepath.Separator) + suffix
	}
	return resolved, nil
}
