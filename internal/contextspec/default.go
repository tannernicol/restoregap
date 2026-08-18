// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package contextspec

// DefaultOrigin labels findings produced under the zero-config path.
const DefaultOrigin = "built-in default local lifeline policy"

// Default returns the built-in zero-config lifeline policy: what preflight
// evaluates against when the caller supplies NO --context. This is a real,
// separate policy — not "no policy" — mirroring the Python implementation's
// adapters/local/default_policy.py (docs/ARCHITECTURE.md §Compatibility
// stance, point 2: "Zero-config safety"). Every guard here is a lifeline
// guard with no declared requirements, which CheckProof/CheckFact treat as
// permanently unproven (see internal/rules): zero-config can name what must
// stay recoverable, but it has no proof vocabulary of its own, so a match
// always blocks until the caller declares a real context.
//
// An explicitly supplied context file — even an otherwise-empty `version: 2`
// document — REPLACES this default; it is never merged with it.
func Default() Context {
	lifeline := func(id string, paths []string) Guard {
		return Guard{
			ID:           id,
			Kind:         GuardKindLifeline,
			Match:        Matcher{Paths: paths},
			Enforcement:  EnforcementBlock,
			RecoveryCopy: "customer-owned password manager, encrypted recovery bundle, or break-glass account",
		}
	}
	return Context{
		Version: 2,
		Origin:  DefaultOrigin,
		Guards: []Guard{
			lifeline("default-ssh-private-keys", []string{
				"**/.ssh/id_*",
				"**/.ssh/*_ed25519",
				"**/.ssh/*_rsa",
				"**/.ssh/*_ecdsa",
				"**/authorized_keys",
				"**/.gnupg/**",
				"**/.password-store/**",
				"**/.config/age/**",
				"**/.config/sops/**",
			}),
			lifeline("default-recovery-bootstrap", []string{
				"RECOVERY.md",
				"RUNBOOK.md",
				"BOOTSTRAP.md",
				"bootstrap.sh",
				"restore.sh",
				"recovery-kit/**",
				"runbooks/**",
				"recovery/**",
				"disaster-recovery/**",
				"recovery-usb/**",
				"**/recovery-usb/**",
				"media/recovery-usb/**",
				"**/media/recovery-usb/**",
			}),
			lifeline("default-backup-manifest", []string{
				"**/Backups/**",
				"**/backup/**",
				"**/backups/**",
				"*backup-manifest*",
				"*.manifest",
			}),
		},
	}
}
