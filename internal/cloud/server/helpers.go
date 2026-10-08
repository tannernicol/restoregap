// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package server

import (
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"time"
)

// funcMap is the small set of formatting helpers the templates share. Times
// are rendered on the server ("3h ago") so the pages need no script and show
// the same thing in every browser; the absolute time rides along in a title.
func (s *Server) funcMap() template.FuncMap {
	return template.FuncMap{
		"rel":  func(t time.Time) string { return relTime(t, s.now()) },
		"relp": func(t *time.Time) string { return relTimePtr(t, s.now()) },
		"abs":  absTime,
		"absp": func(t *time.Time) string {
			if t == nil {
				return ""
			}
			return absTime(*t)
		},
		"short":    shortHex,
		"bytes":    humanBytes,
		"cadence":  cadenceLabel,
		"cadences": func() []cadenceOption { return cadenceOptions },
		"proofHref": func(links map[string]string, source, proof string) string {
			id, ok := links[source]
			if !ok {
				return ""
			}
			return "/app/hosts/" + url.PathEscape(id) + "/proofs/" + url.PathEscape(proof)
		},
		"pathEscape": url.PathEscape,
		"upper":      strings.ToUpper,
		"money":      func(n int) string { return fmt.Sprintf("$%d", n) },
		"limit": func(n int) string {
			if n == 0 {
				return "unlimited"
			}
			return fmt.Sprint(n)
		},
		"retention": func(days int) string {
			switch {
			case days == 0:
				return "unlimited"
			case days%365 == 0:
				if days == 365 {
					return "1 year"
				}
				return fmt.Sprintf("%d years", days/365)
			default:
				return fmt.Sprintf("%d days", days)
			}
		},
	}
}

func absTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }

func relTimePtr(t *time.Time, now time.Time) string {
	if t == nil {
		return "never"
	}
	return relTime(*t, now)
}

// relTime renders the gap between t and now as a single coarse unit. Beyond
// 60 days a date reads better than "73d ago".
func relTime(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	suffix := " ago"
	if d < 0 {
		d, suffix = -d, ""
		if d < time.Minute {
			return "just now"
		}
		return "in " + coarse(d)
	}
	if d < time.Minute {
		return "just now"
	}
	if d > 60*24*time.Hour {
		return t.UTC().Format("2006-01-02")
	}
	return coarse(d) + suffix
}

func coarse(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	default:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
}

// shortHex truncates an identifier for a table cell.
func shortHex(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func humanBytes(n int64) string {
	switch {
	case n < 1<<10:
		return fmt.Sprintf("%d B", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
}

// cadenceOption is one choice of the "expected cadence" dropdown. Value is
// the form value; D is the duration it stands for (0 is "none").
type cadenceOption struct {
	Value, Label string
	D            time.Duration
}

// cadenceOptions is the fixed menu docs/CLOUD.md's monitoring section implies:
// a host's expected interval is a choice, not free text, so a typo cannot
// produce a cadence that lapses every minute.
var cadenceOptions = []cadenceOption{
	{"none", "none (never lapses)", 0},
	{"1h", "every hour", time.Hour},
	{"6h", "every 6 hours", 6 * time.Hour},
	{"24h", "every day", 24 * time.Hour},
	{"7d", "every week", 7 * 24 * time.Hour},
	{"30d", "every 30 days", 30 * 24 * time.Hour},
}

func cadenceByValue(v string) (cadenceOption, bool) {
	for _, c := range cadenceOptions {
		if c.Value == v {
			return c, true
		}
	}
	return cadenceOption{}, false
}

// cadenceValue is the dropdown value for a stored duration, "" when the stored
// value is not one of the menu entries (set through the store directly).
func cadenceValue(d time.Duration) string {
	for _, c := range cadenceOptions {
		if c.D == d {
			return c.Value
		}
	}
	return ""
}

func cadenceLabel(d time.Duration) string {
	if d == 0 {
		return "none"
	}
	for _, c := range cadenceOptions {
		if c.D == d {
			return c.Label
		}
	}
	return d.String()
}
