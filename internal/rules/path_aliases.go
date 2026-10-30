// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package rules

import "github.com/tannernicol/restoregap/internal/contextspec"

// matchingContext adds caller-resolved local path aliases to a private matching
// view. It must never be used for proof verification or recipe binding: those
// checks require the original declarations, including signed dependencies.
func matchingContext(ctx contextspec.Context, aliases map[string]string) contextspec.Context {
	if len(aliases) == 0 {
		return ctx
	}
	paths := func(original []string) []string {
		out := append([]string(nil), original...)
		for _, path := range original {
			if alias := aliases[path]; alias != "" && alias != path && !containsString(out, alias) {
				out = append(out, alias)
			}
		}
		return out
	}
	ctx.Guards = append([]contextspec.Guard(nil), ctx.Guards...)
	for i := range ctx.Guards {
		ctx.Guards[i].Match.Paths = paths(ctx.Guards[i].Match.Paths)
	}
	ctx.Proofs = append([]contextspec.Proof(nil), ctx.Proofs...)
	for i := range ctx.Proofs {
		if original := ctx.Proofs[i].Dependencies; original != nil {
			deps := *original
			deps.Paths = paths(original.Paths)
			ctx.Proofs[i].Dependencies = &deps
		}
	}
	return ctx
}
