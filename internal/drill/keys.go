package drill

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// walkCandidateFiles returns every regular file under path — path itself if
// it's a file, or every regular file found by a recursive walk if it's a
// directory. Non-key files are expected here (a recovery kit legitimately
// holds config, README, known_hosts.old alongside real keys) and are
// filtered out later by asking the fingerprinting tool itself whether a
// file is a key, never by name or extension guessing.
func walkCandidateFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	var files []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		files = append(files, p)
		return nil
	})
	return files, err
}

// collectSSHFingerprints returns the set of SHA256 fingerprints for every
// recognizable ssh key file under path (a single file, or a directory
// walked recursively). ssh-keygen accepts public keys, private keys, and
// authorized_keys/known_hosts lines; a file it rejects is simply not a key
// and is skipped silently — that is not a failure. A private key and its
// public counterpart fingerprint identically, so collecting into a set is
// the entire dedup mechanism: no separate bookkeeping is needed to avoid
// counting an id_ed25519/id_ed25519.pub pair as two keys.
//
// WALL-1 (non-negotiable, settled product decision): this reads key files
// ONLY to ask ssh-keygen for a fingerprint. It never inspects, logs,
// stores, or returns key content, comments, or anything beyond the
// SHA256:... string ssh-keygen itself prints as its second output field.
func collectSSHFingerprints(path string) (map[string]bool, error) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		// A key check that silently passed because the tool is absent would
		// be exactly the false comfort this product exists to kill (same
		// precedent as the git check's missing-binary handling).
		return nil, fmt.Errorf("ssh-keygen not found on PATH")
	}
	files, err := walkCandidateFiles(path)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, f := range files {
		out, err := exec.Command("ssh-keygen", "-lf", f).CombinedOutput()
		if err != nil {
			continue // not a key file (or unreadable) — not a failure, just not a key
		}
		fields := strings.Fields(string(out))
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "SHA256:") {
			continue
		}
		set[fields[1]] = true
	}
	return set, nil
}

// collectGPGFingerprints returns the set of fingerprints for every
// recognizable OpenPGP key file under path (a single file, or a directory
// walked recursively), via `gpg --show-keys --with-colons`. Each call gets
// its own throwaway --homedir, created here and removed before this
// function returns, so the check CANNOT touch the operator's real keyring
// or trustdb — not "probably doesn't", but structurally cannot, even on a
// machine where gpg has never been run before (an empty default ~/.gnupg
// would otherwise get its keybox/trustdb scaffolding created as a side
// effect of the very first `gpg --show-keys` call). A secret-key export
// yields the primary fingerprint plus any subkeys; those are distinct keys
// and all are kept, but the same fingerprint seen twice (e.g. via both a
// public and a secret export of the same key) is one.
//
// WALL-1 (non-negotiable, settled product decision): this reads key files
// ONLY to ask gpg for their fingerprints. It never imports anything into a
// keyring, never decrypts, and never inspects, logs, stores, or returns key
// content — only the fpr: field gpg's own colon-output already prints.
func collectGPGFingerprints(path string) (map[string]bool, error) {
	if _, err := exec.LookPath("gpg"); err != nil {
		return nil, fmt.Errorf("gpg not found on PATH")
	}
	files, err := walkCandidateFiles(path)
	if err != nil {
		return nil, err
	}

	homedir, err := os.MkdirTemp("", "restoregap-gpg-homedir-")
	if err != nil {
		return nil, fmt.Errorf("cannot create an isolated gpg homedir: %w", err)
	}
	defer func() { _ = os.RemoveAll(homedir) }()
	if err := os.Chmod(homedir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot secure the isolated gpg homedir: %w", err)
	}

	set := map[string]bool{}
	for _, f := range files {
		out, err := exec.Command("gpg", "--homedir", homedir, "--show-keys", "--with-colons", f).CombinedOutput()
		if err != nil {
			continue // not a key file — not a failure
		}
		for _, line := range strings.Split(string(out), "\n") {
			// fpr:::::::::<FINGERPRINT>: — field 10 (1-indexed), i.e.
			// fields[9] after splitting on ":".
			fields := strings.Split(line, ":")
			if len(fields) < 10 || fields[0] != "fpr" {
				continue
			}
			fp := strings.ToUpper(strings.TrimSpace(fields[9]))
			if fp != "" {
				set[fp] = true
			}
		}
	}
	return set, nil
}

// fingerprintCollector resolves the collector for a keys scheme. The
// default case cannot be reached through contextspec.Load (which validates
// keys at parse time) but a DrillCheck built directly in Go — as tests do —
// is not forced through that gate, so it fails closed here too.
func fingerprintCollector(keys string) (func(string) (map[string]bool, error), error) {
	switch keys {
	case "ssh":
		return collectSSHFingerprints, nil
	case "gpg":
		return collectGPGFingerprints, nil
	default:
		return nil, fmt.Errorf("unknown keys scheme %q (must be ssh or gpg)", keys)
	}
}

// runKeyFingerprint proves the recovered key material is the RIGHT key
// material, by fingerprint: collect the recovered set from RG_TARGET,
// require every ExpectFrom (live) fingerprint and every explicit Expect
// fingerprint to be present, and require at least MinKeys keys total.
// MinKeys is used exactly as declared — 0 legitimately means "no minimum,
// rely on ExpectFrom/Expect instead" and is never re-defaulted here (see
// contextspec.DrillCheck.MinKeys).
func runKeyFingerprint(c contextspec.DrillCheck, env checkEnv) checkResult {
	collect, err := fingerprintCollector(c.Keys)
	if err != nil {
		return failOutcome("key_fingerprint", err.Error())
	}

	recovered, err := collect(env.Target)
	if err != nil {
		return failOutcome("key_fingerprint", fmt.Sprintf("%s: %v", c.Keys, err))
	}

	pass := true
	parts := []string{fmt.Sprintf("%s: %d keys recovered", c.Keys, len(recovered))}

	if c.ExpectFrom != "" {
		live, err := collect(c.ExpectFrom)
		if err != nil {
			return failOutcome("key_fingerprint", fmt.Sprintf("%s: expect_from: %v", c.Keys, err))
		}
		if missing := missingFingerprints(live, recovered); len(missing) > 0 {
			pass = false
			parts = append(parts, fmt.Sprintf("%d live fingerprint%s NOT in the recovery copy: %s",
				len(missing), plural(len(missing)), truncateFingerprints(missing)))
		} else {
			parts = append(parts, fmt.Sprintf("all %d live fingerprints covered", len(live)))
		}
	}

	if len(c.Expect) > 0 {
		want := map[string]bool{}
		for _, e := range c.Expect {
			want[normalizeFingerprint(c.Keys, e)] = true
		}
		if missing := missingFingerprints(want, recovered); len(missing) > 0 {
			pass = false
			parts = append(parts, fmt.Sprintf("%d expected fingerprint%s missing: %s",
				len(missing), plural(len(missing)), truncateFingerprints(missing)))
		} else {
			parts = append(parts, fmt.Sprintf("all %d expected fingerprints present", len(c.Expect)))
		}
	}

	if len(recovered) < c.MinKeys {
		pass = false
		parts = append(parts, fmt.Sprintf("min_keys not met: found %d, need >= %d", len(recovered), c.MinKeys))
	}

	return checkResult{outcome: contextspec.CheckOutcome{Type: "key_fingerprint", Pass: pass, Detail: strings.Join(parts, "; ")}}
}

// normalizeFingerprint puts an explicitly-declared expect: entry into the
// same form its collector would produce, so comparison against the
// recovered set is exact. GPG fingerprints are hex and case-insensitive —
// collectGPGFingerprints uppercase-normalizes them, so an expect: entry
// must be too. SSH fingerprints are "SHA256:<base64>": base64 IS
// case-sensitive (upper- and lower-case letters are different symbols), so
// an ssh fingerprint must be left exactly as declared — uppercasing it
// would corrupt the comparison, not normalize it.
func normalizeFingerprint(keys, fp string) string {
	if keys == "gpg" {
		return strings.ToUpper(strings.TrimSpace(fp))
	}
	return strings.TrimSpace(fp)
}

// missingFingerprints returns, sorted for a deterministic detail string,
// every fingerprint in want that is not in have.
func missingFingerprints(want, have map[string]bool) []string {
	var missing []string
	for fp := range want {
		if !have[fp] {
			missing = append(missing, fp)
		}
	}
	sort.Strings(missing)
	return missing
}

// truncateFingerprints renders at most the first 5 fingerprints plus a
// count of the rest — a detail naming every fingerprint in a large,
// thoroughly-broken recovery kit would be unreadable, not more informative.
func truncateFingerprints(fps []string) string {
	if len(fps) <= 5 {
		return strings.Join(fps, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(fps[:5], ", "), len(fps)-5)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
