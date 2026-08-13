package drill

import (
	"fmt"
	"strconv"
	"strings"
)

// evalCountConstraint parses one constraint of the shared count-check
// grammar (">= N", "> N", "== N", "<= N", "< N") and reports whether got
// satisfies it. Shared by sqlite table counts, git ref counts, and
// file_tree file counts so there is exactly one implementation of "N of
// things, bounded" in the engine.
//
// Longer operators are matched before their single-character prefixes
// (">=" before ">") so ">= 5" is never misread as "> = 5".
func evalCountConstraint(constraint string, got int) (bool, error) {
	c := strings.TrimSpace(constraint)
	for _, op := range []string{">=", "<=", "==", ">", "<"} {
		if !strings.HasPrefix(c, op) {
			continue
		}
		rest := strings.TrimSpace(c[len(op):])
		n, err := strconv.Atoi(rest)
		if err != nil {
			return false, fmt.Errorf("constraint %q: %q is not an integer", constraint, rest)
		}
		switch op {
		case ">=":
			return got >= n, nil
		case "<=":
			return got <= n, nil
		case "==":
			return got == n, nil
		case ">":
			return got > n, nil
		default: // "<"
			return got < n, nil
		}
	}
	return false, fmt.Errorf("constraint %q: must start with >=, <=, ==, >, or <", constraint)
}
