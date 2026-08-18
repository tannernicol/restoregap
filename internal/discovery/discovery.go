// Package discovery implements the shared $RESTOREGAP_CONTEXT /
// restoregap.local.yml / restoregap.yml lookup order used by every entry
// point that wants a zero-config context fallback: the CLI (internal/cli)
// and the MCP server (internal/mcpserver). It is a plain, cobra-free
// package on purpose — internal/cli already imports internal/mcpserver (to
// wire `restoregap mcp serve`), so mcpserver cannot import internal/cli
// without a cycle; both instead import this one.
package discovery

import (
	"os"
	"strings"
)

// ContextPaths returns the discovered context file path(s), or nil when
// nothing is discoverable. $RESTOREGAP_CONTEXT may hold a colon-separated
// list of paths — every one of them is returned, in declared order, so a
// caller that aggregates multiple contexts (status, preflight) sees the
// whole list. A caller that wants exactly one path uses ContextPaths()[0].
//
// When the env var is unset, at most one path is ever returned:
// ./restoregap.local.yml if present, else ./restoregap.yml, else nil —
// callers that fall further back to a built-in default policy treat a nil
// result as "nothing discoverable".
func ContextPaths() []string {
	if v := os.Getenv("RESTOREGAP_CONTEXT"); v != "" {
		var out []string
		for _, p := range strings.Split(v, ":") {
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	for _, candidate := range []string{"restoregap.local.yml", "restoregap.yml"} {
		if isRegularFile(candidate) {
			return []string{candidate}
		}
	}
	return nil
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
