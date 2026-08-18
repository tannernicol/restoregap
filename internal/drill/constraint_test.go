// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package drill

import "testing"

func TestEvalCountConstraint(t *testing.T) {
	cases := []struct {
		constraint string
		got        int
		want       bool
	}{
		{">= 5", 5, true},
		{">= 5", 4, false},
		{">=5", 5, true}, // no space is legal
		{"<= 5", 5, true},
		{"<= 5", 6, false},
		{"== 5", 5, true},
		{"== 5", 4, false},
		{"> 5", 6, true},
		{"> 5", 5, false},
		{"< 5", 4, true},
		{"< 5", 5, false},
		{"  >= 5  ", 5, true}, // surrounding whitespace tolerated
	}
	for _, c := range cases {
		got, err := evalCountConstraint(c.constraint, c.got)
		if err != nil {
			t.Errorf("evalCountConstraint(%q, %d): unexpected error: %v", c.constraint, c.got, err)
			continue
		}
		if got != c.want {
			t.Errorf("evalCountConstraint(%q, %d) = %v, want %v", c.constraint, c.got, got, c.want)
		}
	}
}

func TestEvalCountConstraintMalformed(t *testing.T) {
	cases := []string{
		"",
		"5",       // no operator
		">= five", // not an integer
		"=> 5",    // wrong order
		"~= 5",    // unknown operator
		">=",      // operator with nothing after it
		"between 1 and 5",
	}
	for _, c := range cases {
		if _, err := evalCountConstraint(c, 0); err == nil {
			t.Errorf("evalCountConstraint(%q, 0): expected error, got none", c)
		}
	}
}

func TestParsePercentConstraint(t *testing.T) {
	cases := []struct {
		constraint   string
		wantOp       string
		wantFraction float64
	}{
		{">= 90%", ">=", 0.90},
		{">=90%", ">=", 0.90},       // no space is legal
		{">= 90% live", ">=", 0.90}, // explicit spelling
		{">=90%live", ">=", 0.90},   // explicit spelling, no spaces at all
		{"  >= 90%  ", ">=", 0.90},  // surrounding whitespace tolerated
		{"< 50%", "<", 0.50},
		{"== 100%", "==", 1.0},
		{"> 0%", ">", 0.0},
	}
	for _, c := range cases {
		pc, isPercent, err := parsePercentConstraint(c.constraint)
		if err != nil {
			t.Errorf("parsePercentConstraint(%q): unexpected error: %v", c.constraint, err)
			continue
		}
		if !isPercent {
			t.Errorf("parsePercentConstraint(%q): isPercent = false, want true", c.constraint)
			continue
		}
		if pc.op != c.wantOp || pc.fraction != c.wantFraction {
			t.Errorf("parsePercentConstraint(%q) = {%q, %v}, want {%q, %v}",
				c.constraint, pc.op, pc.fraction, c.wantOp, c.wantFraction)
		}
	}
}

func TestParsePercentConstraintNotPercent(t *testing.T) {
	// No "%" at all: not this grammar, no error — the caller falls back to
	// evalCountConstraint.
	for _, c := range []string{">= 400", "", "5", "between 1 and 5"} {
		_, isPercent, err := parsePercentConstraint(c)
		if err != nil {
			t.Errorf("parsePercentConstraint(%q): unexpected error: %v", c, err)
		}
		if isPercent {
			t.Errorf("parsePercentConstraint(%q): isPercent = true, want false", c)
		}
	}
}

func TestParsePercentConstraintMalformed(t *testing.T) {
	cases := []string{
		"90%",           // no operator
		">= five%",      // not a number
		">= 90% future", // unexpected trailing word
		">= -5%",        // negative percentage
		"~= 90%",        // unknown operator
	}
	for _, c := range cases {
		if _, isPercent, err := parsePercentConstraint(c); err == nil {
			t.Errorf("parsePercentConstraint(%q): expected error, got none (isPercent=%v)", c, isPercent)
		}
	}
}

func TestValidateTableConstraintSyntax(t *testing.T) {
	valid := []string{">= 400", ">= 90%", ">= 90% live", "== 0", "< 5"}
	for _, c := range valid {
		if err := validateTableConstraintSyntax(c); err != nil {
			t.Errorf("validateTableConstraintSyntax(%q): unexpected error: %v", c, err)
		}
	}

	invalid := []string{"", "not a constraint", ">= five", ">= 90% future", ">= -5%"}
	for _, c := range invalid {
		if err := validateTableConstraintSyntax(c); err == nil {
			t.Errorf("validateTableConstraintSyntax(%q): expected error, got none", c)
		}
	}
}
