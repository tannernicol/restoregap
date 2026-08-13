package contextspec

import "time"

// FormatRTO renders an RTO measurement (seconds) as a human duration,
// rounded to 100ms — most drills finish in single-digit seconds, where
// sub-second precision is real information, not noise.
func FormatRTO(seconds float64) string {
	return time.Duration(seconds * float64(time.Second)).Round(100 * time.Millisecond).String()
}

// FormatRPO renders an RPO measurement (seconds) as a human duration,
// rounded to the whole second — RPO is measured in hours in practice, so
// finer precision would be noise. Shared by drill CLI output and the status
// recovery inventory so "how stale" is spelled the same way everywhere.
func FormatRPO(seconds float64) string {
	return time.Duration(seconds * float64(time.Second)).Round(time.Second).String()
}
