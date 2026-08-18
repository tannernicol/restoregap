package copycheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func store(t *testing.T, entries ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, e := range entries {
		p := filepath.Join(dir, e)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte("ciphertext"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return dir
}

func markSecretStore(t *testing.T, dir string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".gpg-id"), []byte("tanner@local\n"), 0o644); err != nil {
		t.Fatalf("write .gpg-id: %v", err)
	}
	return dir
}

// TestDetectSecretStore: a pass-style store announces itself with .gpg-id, and
// must be recognised so the report names what it compared.
func TestDetectSecretStore(t *testing.T) {
	s := markSecretStore(t, store(t, "a.gpg"))
	if got := Detect(s); got != KindSecretStore {
		t.Errorf("want secret-store, got %s", got)
	}
	if got := Detect(store(t, "notes.txt")); got != KindTree {
		t.Errorf("want tree, got %s", got)
	}
}

// TestFaithfulCopy: identical entry sets report faithful and list nothing.
func TestFaithfulCopy(t *testing.T) {
	live := markSecretStore(t, store(t, "a.gpg", "sub/b.gpg"))
	rec := markSecretStore(t, store(t, "a.gpg", "sub/b.gpg"))

	res, err := Compare(live, rec, KindSecretStore, nil)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if !res.Faithful() {
		t.Errorf("identical stores must be faithful, got %+v", res)
	}
	if !strings.Contains(res.Text(), "faithful") {
		t.Errorf("text should say faithful, got %q", res.Text())
	}
}

// TestMissingFromRecovery is the case that matters: an entry that exists only
// live is one you would lose. It must be named, not just counted — knowing the
// count is off does not tell you which secret is gone.
func TestMissingFromRecovery(t *testing.T) {
	live := markSecretStore(t, store(t, "a.gpg", "homelab/restic-password.gpg"))
	rec := markSecretStore(t, store(t, "a.gpg"))

	res, err := Compare(live, rec, KindSecretStore, nil)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if res.Faithful() {
		t.Fatal("a missing entry must not report faithful")
	}
	if len(res.OnlyLive) != 1 || res.OnlyLive[0] != filepath.Join("homelab", "restic-password.gpg") {
		t.Errorf("want the missing entry named, got %v", res.OnlyLive)
	}
	text := res.Text()
	if !strings.Contains(text, "MISSING FROM RECOVERY") || !strings.Contains(text, "restic-password.gpg") {
		t.Errorf("text must name the missing entry, got %q", text)
	}
}

// TestExtraInRecovery: a stale entry the live store no longer has is reported
// too, separately — it means the copy is out of date in the other direction.
func TestExtraInRecovery(t *testing.T) {
	live := markSecretStore(t, store(t, "a.gpg"))
	rec := markSecretStore(t, store(t, "a.gpg", "deleted.gpg"))

	res, err := Compare(live, rec, KindSecretStore, nil)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if res.Faithful() || len(res.OnlyRecovery) != 1 {
		t.Errorf("want one recovery-only entry, got %+v", res)
	}
	if !strings.Contains(res.Text(), "recovery only") {
		t.Errorf("text should mark it recovery-only, got %q", res.Text())
	}
}

// TestSecretStoreIgnoresNonEntries: a secret store comparison counts .gpg
// entries only, so a stray README or .gpg-id does not read as drift.
func TestSecretStoreIgnoresNonEntries(t *testing.T) {
	live := markSecretStore(t, store(t, "a.gpg", "README.md"))
	rec := markSecretStore(t, store(t, "a.gpg"))

	res, err := Compare(live, rec, KindSecretStore, nil)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if !res.Faithful() {
		t.Errorf("non-.gpg files must not count as drift, got %+v", res)
	}
}

// TestMissingDirectoryIsAnError: an unreadable recovery copy is itself a
// recovery gap, and must not be mistaken for "nothing to report".
func TestMissingDirectoryIsAnError(t *testing.T) {
	live := markSecretStore(t, store(t, "a.gpg"))
	if _, err := Compare(live, filepath.Join(t.TempDir(), "nope"), KindSecretStore, nil); err == nil {
		t.Error("a missing recovery directory must error, not report faithful")
	}
}

// TestStaleContentIsNotFaithful is the bug this package shipped with. Comparing
// names alone reported "faithful" for a copy holding every entry under the right
// name while two were weeks-stale API tokens — the exact drift that survived
// undetected in production until a drill compared content. Present-but-stale is
// not faithful: an entry you cannot use is no better than one you do not have.
func TestStaleContentIsNotFaithful(t *testing.T) {
	live := markSecretStore(t, store(t, "gitea/api-token.gpg", "a.gpg"))
	rec := markSecretStore(t, store(t, "gitea/api-token.gpg", "a.gpg"))
	// Same name, different bytes — a rotated secret the copy never received.
	if err := os.WriteFile(filepath.Join(rec, "gitea", "api-token.gpg"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Compare(live, rec, KindSecretStore, nil)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if res.Faithful() {
		t.Fatal("a stale entry must not report faithful")
	}
	if len(res.Differing) != 1 || res.Differing[0] != filepath.Join("gitea", "api-token.gpg") {
		t.Errorf("want the stale entry named, got %v", res.Differing)
	}
	if len(res.OnlyLive) != 0 || len(res.OnlyRecovery) != 0 {
		t.Errorf("a stale entry is not missing; it should only be reported as stale, got %+v", res)
	}
	text := res.Text()
	if !strings.Contains(text, "STALE IN RECOVERY") || !strings.Contains(text, "out of date") {
		t.Errorf("text must distinguish stale from missing, got %q", text)
	}
}

// TestIdenticalContentIsFaithful: matching bytes must not be reported as drift,
// or every run would cry wolf.
func TestIdenticalContentIsFaithful(t *testing.T) {
	live := markSecretStore(t, store(t, "a.gpg", "sub/b.gpg"))
	rec := markSecretStore(t, store(t, "a.gpg", "sub/b.gpg"))
	res, err := Compare(live, rec, KindSecretStore, nil)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if !res.Faithful() || len(res.Differing) != 0 {
		t.Errorf("identical content must be faithful, got %+v", res)
	}
}

// TestLiveOlderIsNotReportedAsStaleRecovery guards the 2026-08-12 regression.
//
// Every content difference used to be reported as "the recovery copy is out of
// date", which the fingerprint comparison gives no evidence for. The obvious
// remedy for that sentence is to refresh the backup — so when the LIVE tree is
// the one that got reverted, following the tool's own advice overwrites the
// last good copy with stale data. A recovery tool must never emit guidance
// whose natural next step is data loss.
//
// Scenario is the real one: a sync job rewrote the live tree from a months-old
// source, preserving the old mtime, while the recovery copy stayed correct.
func TestLiveOlderIsNotReportedAsStaleRecovery(t *testing.T) {
	live, rec := t.TempDir(), t.TempDir()
	const name = "voice-captures.md"

	if err := os.WriteFile(filepath.Join(rec, name), []byte("a\nb\nc\nd\ne\n"), 0o644); err != nil {
		t.Fatalf("write recovery: %v", err)
	}
	// The reverted live copy: shorter, and older, exactly as rsync -a leaves it.
	if err := os.WriteFile(filepath.Join(live, name), []byte("a\nb\n"), 0o644); err != nil {
		t.Fatalf("write live: %v", err)
	}
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(filepath.Join(live, name), old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	res, err := Compare(live, rec, KindTree, nil)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if res.Faithful() {
		t.Fatal("differing content must not report faithful")
	}
	if len(res.LiveOlder) != 1 || res.LiveOlder[0] != name {
		t.Fatalf("want the live-older entry named, got %v", res.LiveOlder)
	}

	text := res.Text()
	if strings.Contains(text, "STALE IN RECOVERY") {
		t.Errorf("must not blame the recovery copy when live is older, got %q", text)
	}
	if strings.Contains(text, "the recovery copy is out of date") {
		t.Errorf("must not assert the recovery copy is out of date, got %q", text)
	}
	if !strings.Contains(text, "LIVE IS OLDER") {
		t.Errorf("must name which side is older, got %q", text)
	}
	if !strings.Contains(text, "Do NOT refresh the recovery copy") {
		t.Errorf("must warn against the destructive remedy, got %q", text)
	}
}

// TestRecoveryOlderStillBlamesRecovery: the fix must not mute the ordinary case
// the tool exists for — a backup that genuinely fell behind.
func TestRecoveryOlderStillBlamesRecovery(t *testing.T) {
	live, rec := t.TempDir(), t.TempDir()
	const name = "notes.md"

	if err := os.WriteFile(filepath.Join(rec, name), []byte("old\n"), 0o644); err != nil {
		t.Fatalf("write recovery: %v", err)
	}
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(filepath.Join(rec, name), old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(live, name), []byte("new content\n"), 0o644); err != nil {
		t.Fatalf("write live: %v", err)
	}

	res, err := Compare(live, rec, KindTree, nil)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if len(res.LiveOlder) != 0 {
		t.Fatalf("live is newer here; want no live-older entries, got %v", res.LiveOlder)
	}
	text := res.Text()
	if !strings.Contains(text, "STALE IN RECOVERY") || !strings.Contains(text, "out of date") {
		t.Errorf("a genuinely behind backup must still be named as such, got %q", text)
	}
}

// TestCompareExcludesDropEntriesFromBothSidesBeforeComparison: an excluded
// entry must never surface as missing, stale, or only-in-recovery, and must
// not be counted toward LiveCount/RecoveryCount — the whole point is that a
// large, expected class of noise (e.g. local config backup snapshots) never
// reaches the report at all.
func TestCompareExcludesDropEntriesFromBothSidesBeforeComparison(t *testing.T) {
	live := store(t, "a.txt", "restoregap.local.yml.bak.1", "restoregap.local.yml.bak.2")
	rec := store(t, "a.txt")

	res, err := Compare(live, rec, KindTree, []string{"restoregap.local.yml.bak.*"})
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if !res.Faithful() {
		t.Errorf("excluded-only drift must report faithful, got %+v", res)
	}
	if res.LiveCount != 1 || res.RecoveryCount != 1 {
		t.Errorf("excluded entries must not count toward LiveCount/RecoveryCount, got live=%d recovery=%d", res.LiveCount, res.RecoveryCount)
	}
	if res.ExcludedCount != 2 {
		t.Errorf("ExcludedCount = %d, want 2", res.ExcludedCount)
	}
}

// TestEntriesSkipsRestoregapIgnoreFile: .restoregapignore is check's own
// configuration, not recoverable content — it must never itself show up as
// an entry (which would otherwise report as permanently missing from every
// recovery copy that correctly doesn't carry one).
func TestEntriesSkipsRestoregapIgnoreFile(t *testing.T) {
	live := store(t, "a.txt", ".restoregapignore")
	rec := store(t, "a.txt")

	res, err := Compare(live, rec, KindTree, nil)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if !res.Faithful() {
		t.Errorf(".restoregapignore must not be compared as content, got %+v", res)
	}
}

// TestCompareNoExcludesUnchanged: a nil exclude list must behave exactly as
// before the feature existed (globmatch.MatchPathAny(nil, ...) is false).
func TestCompareNoExcludesUnchanged(t *testing.T) {
	live := store(t, "a.txt", "b.txt")
	rec := store(t, "a.txt")

	res, err := Compare(live, rec, KindTree, nil)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if res.Faithful() || len(res.OnlyLive) != 1 || res.ExcludedCount != 0 {
		t.Errorf("unexcluded run must behave as before, got %+v", res)
	}
}
