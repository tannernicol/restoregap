package engine

// Overall reduces a finding set to a single top-level verdict: any block
// wins, else any warn, else pass. Mirrors the Python local-mode reduction
// (docs/ARCHITECTURE.md, testdata/golden/NOTES.md).
func Overall(findings []Finding) Verdict {
	sawWarn := false
	for _, f := range findings {
		switch f.Verdict {
		case VerdictBlock:
			return VerdictBlock
		case VerdictWarn:
			sawWarn = true
		}
	}
	if sawWarn {
		return VerdictWarn
	}
	return VerdictPass
}

// ExitCode maps a verdict to the frozen process exit-code contract: 0 pass,
// 1 block (or warn with failOnWarn), 2 is reserved for usage/internal errors
// and is never returned here.
func ExitCode(v Verdict, failOnWarn bool) int {
	switch v {
	case VerdictBlock:
		return 1
	case VerdictWarn:
		if failOnWarn {
			return 1
		}
		return 0
	default:
		return 0
	}
}
