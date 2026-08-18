// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package drill

import (
	"fmt"
	"strconv"
	"strings"
)

// countOps are the operators the shared count-check grammar accepts, in
// match order — longer operators before their single-character prefixes
// (">=" before ">") so ">= 5" is never misread as "> = 5".
var countOps = []string{">=", "<=", "==", ">", "<"}

// compareCount applies one already-parsed operator to (got, n). It is the
// one implementation of "N of things, bounded" the engine has; both the
// absolute grammar (evalCountConstraint) and the sqlite-only
// percent-of-live grammar (parsePercentConstraint) route their comparison
// through it so the two grammars can never quietly disagree about what
// ">=" means.
func compareCount(op string, got, n int) bool {
	switch op {
	case ">=":
		return got >= n
	case "<=":
		return got <= n
	case "==":
		return got == n
	case ">":
		return got > n
	default: // "<"
		return got < n
	}
}

// evalCountConstraint parses one constraint of the shared count-check
// grammar (">= N", "> N", "== N", "<= N", "< N") and reports whether got
// satisfies it. Shared by sqlite table counts, git ref counts, and
// file_tree file counts so there is exactly one implementation of "N of
// things, bounded" in the engine.
func evalCountConstraint(constraint string, got int) (bool, error) {
	c := strings.TrimSpace(constraint)
	for _, op := range countOps {
		if !strings.HasPrefix(c, op) {
			continue
		}
		rest := strings.TrimSpace(c[len(op):])
		n, err := strconv.Atoi(rest)
		if err != nil {
			return false, fmt.Errorf("constraint %q: %q is not an integer", constraint, rest)
		}
		return compareCount(op, got, n), nil
	}
	return false, fmt.Errorf("constraint %q: must start with >=, <=, ==, >, or <", constraint)
}

// percentConstraint is one parsed "op N% [live]" sqlite tables: floor — a
// row-count bound expressed as a fraction of the same table's row count in
// the LIVE artifact at drill time, rather than a number fixed at authoring
// time.
type percentConstraint struct {
	op       string
	fraction float64 // e.g. 0.90 for "90%"
}

// parsePercentConstraint reports whether constraint uses the sqlite-only
// percent-of-live grammar: an operator, optional whitespace, a number, a
// literal "%", and either nothing or the explicit " live" spelling (">=
// 90%" and ">= 90% live" are equivalent — the trailing word exists only for
// readers who want the relative-ness spelled out).
//
// A constraint containing no "%" is not this grammar at all: isPercent is
// false and err is nil, so the caller falls back to evalCountConstraint's
// absolute grammar without treating "no percent sign" as a syntax error.
func parsePercentConstraint(constraint string) (percentConstraint, bool, error) {
	c := strings.TrimSpace(constraint)
	if !strings.Contains(c, "%") {
		return percentConstraint{}, false, nil
	}
	for _, op := range countOps {
		if !strings.HasPrefix(c, op) {
			continue
		}
		rest := strings.TrimSpace(c[len(op):])
		idx := strings.Index(rest, "%")
		if idx < 0 {
			break // has "%" somewhere, but not after a recognized operator
		}
		numPart := strings.TrimSpace(rest[:idx])
		suffix := strings.TrimSpace(rest[idx+1:])
		if suffix != "" && suffix != "live" {
			return percentConstraint{}, false, fmt.Errorf(
				"constraint %q: unexpected %q after the percentage (use \"N%%\" or \"N%% live\")", constraint, suffix)
		}
		pct, err := strconv.ParseFloat(numPart, 64)
		if err != nil {
			return percentConstraint{}, false, fmt.Errorf("constraint %q: %q is not a valid percentage", constraint, numPart)
		}
		if pct < 0 {
			return percentConstraint{}, false, fmt.Errorf("constraint %q: percentage must not be negative", constraint)
		}
		return percentConstraint{op: op, fraction: pct / 100}, true, nil
	}
	return percentConstraint{}, false, fmt.Errorf("constraint %q: must start with >=, <=, ==, >, or <", constraint)
}

// validateTableConstraintSyntax reports whether constraint parses under
// either grammar a sqlite tables: entry accepts — absolute
// (evalCountConstraint) or percent-of-live (parsePercentConstraint) —
// without evaluating it against any real count. drill --lint uses this to
// catch a malformed tables: entry before a drill ever runs, rather than
// mid-run as a confusing per-table failure.
func validateTableConstraintSyntax(constraint string) error {
	_, isPercent, err := parsePercentConstraint(constraint)
	if err != nil {
		return err
	}
	if isPercent {
		return nil
	}
	_, err = evalCountConstraint(constraint, 0)
	return err
}
