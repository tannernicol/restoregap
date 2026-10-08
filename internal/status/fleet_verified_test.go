// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/bundle"
)

func loadVerifiedItem(t *testing.T, path string) VerifiedBundle {
	t.Helper()
	// Go through the bytes entry point so the service path is what is tested.
	archive, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := bundle.LoadVerifiedBytes(archive)
	if err != nil {
		t.Fatalf("LoadVerifiedBytes(%s): %v", path, err)
	}
	return VerifiedBundle{Label: path, Manifest: loaded.Manifest, Context: loaded.Context}
}

func TestMergeVerifiedEqualsMergeBundles(t *testing.T) {
	dir := t.TempDir()
	// Same proof id on two hosts and a host-only proof, so the comparison
	// covers more than a trivial single-row merge.
	b1 := exportSyntheticBundle(t, dir, "host-a", "aaaaaaaaaaaaaaaa", "epocha00000", "prod", "web", "shared-proof")
	b2 := exportSyntheticBundle(t, dir, "host-b", "bbbbbbbbbbbbbbbb", "epochb00000", "prod", "db", "host-b-only")

	want, err := MergeBundles([]string{b1, b2})
	if err != nil {
		t.Fatalf("MergeBundles: %v", err)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	got, err := MergeVerified([]VerifiedBundle{loadVerifiedItem(t, b1), loadVerifiedItem(t, b2)}, now)
	if err != nil {
		t.Fatalf("MergeVerified: %v", err)
	}
	if !got.GeneratedAt.Equal(now) {
		t.Errorf("Fleet.GeneratedAt = %v, want the supplied now %v", got.GeneratedAt, now)
	}
	if len(got.Proofs) != 2 {
		t.Fatalf("expected 2 proofs, got %+v", got.Proofs)
	}
	if !reflect.DeepEqual(got.Proofs, want.Proofs) {
		t.Errorf("Proofs differ:\nverified: %+v\nbundles:  %+v", got.Proofs, want.Proofs)
	}
	if !reflect.DeepEqual(got.Conflicts, want.Conflicts) {
		t.Errorf("Conflicts differ:\nverified: %+v\nbundles:  %+v", got.Conflicts, want.Conflicts)
	}
	if !reflect.DeepEqual(got.Bundles, want.Bundles) {
		t.Errorf("Bundles differ:\nverified: %+v\nbundles:  %+v", got.Bundles, want.Bundles)
	}
}

func TestMergeVerifiedReportsCollisionLikeMergeBundles(t *testing.T) {
	dir := t.TempDir()
	// Identical identity and scope in both bundles forces a merge-key
	// collision, which both entry points must resolve identically.
	b1 := exportSyntheticBundle(t, dir, "host-a", "aaaaaaaaaaaaaaaa", "epocha00000", "prod", "web", "p1")
	older := loadVerifiedItem(t, b1)
	newer := older
	newer.Label = "newer"
	newer.Manifest.GeneratedAt = older.Manifest.GeneratedAt.Add(time.Hour)

	fleet, err := MergeVerified([]VerifiedBundle{older, newer}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(fleet.Proofs) != 1 || fleet.Proofs[0].SourceBundle != "newer" {
		t.Fatalf("later generated_at must win, got %+v", fleet.Proofs)
	}
	if len(fleet.Conflicts) != 1 || fleet.Conflicts[0].KeptBundle != "newer" || fleet.Conflicts[0].DroppedBundle != b1 {
		t.Fatalf("expected one conflict keeping the newer bundle, got %+v", fleet.Conflicts)
	}
}

func TestMergeVerifiedRequiresAtLeastOneBundle(t *testing.T) {
	if _, err := MergeVerified(nil, time.Now()); err == nil {
		t.Fatal("expected an error for zero verified bundles")
	}
}

func TestFleetRowsEqualsSingleBundleMergeVerified(t *testing.T) {
	dir := t.TempDir()
	b1 := exportSyntheticBundle(t, dir, "host-a", "aaaaaaaaaaaaaaaa", "epocha00000", "prod", "web", "p-a")
	item := loadVerifiedItem(t, b1)

	rows := FleetRows(item)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %+v", rows)
	}
	if rows[0].SourceBundle != b1 {
		t.Errorf("SourceBundle = %q, want the item's label %q", rows[0].SourceBundle, b1)
	}
	fleet, err := MergeVerified([]VerifiedBundle{item}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rows, fleet.Proofs) {
		t.Errorf("FleetRows differ from MergeVerified's rows:\nrows:  %+v\nfleet: %+v", rows, fleet.Proofs)
	}
}
