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
