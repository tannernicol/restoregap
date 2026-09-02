// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ---- databases ----

func TestCollectDatabasesFindsLargeMatchingFiles(t *testing.T) {
	home := t.TempDir()
	big := make([]byte, databaseMinSize+1)
	if err := os.WriteFile(filepath.Join(home, "money.sqlite3"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	small := make([]byte, 10)
	if err := os.WriteFile(filepath.Join(home, "tiny.db"), small, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "notes.txt"), big, 0o644); err != nil {
		t.Fatal(err)
	}

	got := collectDatabases(home)
	if len(got) != 1 || got[0].Name != "money.sqlite3" {
		t.Fatalf("collectDatabases = %+v; want exactly one candidate, money.sqlite3", got)
	}
	if got[0].Kind != KindDatabase || got[0].Weight != weightFor(KindDatabase) {
		t.Errorf("unexpected kind/weight: %+v", got[0])
	}
}

func TestCollectDatabasesSkipsExcludedDirs(t *testing.T) {
	home := t.TempDir()
	big := make([]byte, databaseMinSize+1)
	for _, dir := range []string{"node_modules", ".git", ".cache", ".venv"} {
		full := filepath.Join(home, dir)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(full, "x.db"), big, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := collectDatabases(home); len(got) != 0 {
		t.Fatalf("collectDatabases = %+v; want none (all under excluded dirs)", got)
	}
}

func TestCollectDatabasesRespectsMaxDepth(t *testing.T) {
	home := t.TempDir()
	deep := home
	for i := 0; i < databaseMaxDepth+3; i++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, databaseMinSize+1)
	if err := os.WriteFile(filepath.Join(deep, "buried.db"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := collectDatabases(home); len(got) != 0 {
		t.Fatalf("collectDatabases = %+v; want none (beyond maxDepth)", got)
	}
}

// ---- containers ----

func TestCollectContainersDegradesToEmptyWhenDockerAbsent(t *testing.T) {
	orig := runDockerPS
	defer func() { runDockerPS = orig }()
	runDockerPS = func() ([]byte, error) { return nil, errors.New("exec: \"docker\": executable file not found in $PATH") }

	if got := collectContainers(); got != nil {
		t.Fatalf("collectContainers() = %+v; want nil when docker is absent", got)
	}
}

func TestCollectContainersFiltersMounts(t *testing.T) {
	origPS, origInspect := runDockerPS, runDockerInspect
	defer func() { runDockerPS, runDockerInspect = origPS, origInspect }()

	runDockerPS = func() ([]byte, error) { return []byte("jellyfin\n"), nil }
	runDockerInspect = func(name string) ([]byte, error) {
		return []byte(`[{"Mounts":[
			{"Type":"bind","Source":"/mnt/backup/media","Destination":"/media","RW":true},
			{"Type":"bind","Source":"/tmp/scratch","Destination":"/scratch","RW":true},
			{"Type":"bind","Source":"/mnt/backup/ro","Destination":"/ro","RW":false},
			{"Type":"volume","Source":"","Destination":"/named","RW":true},
			{"Type":"bind","Source":"/run/docker.sock","Destination":"/var/run/docker.sock","RW":true}
		]}]`), nil
	}

	got := collectContainers()
	if len(got) != 1 || got[0].Path != "/mnt/backup/media" {
		t.Fatalf("collectContainers = %+v; want exactly one candidate at /mnt/backup/media", got)
	}
	if got[0].Kind != KindContainerVolume || got[0].Name != "jellyfin" {
		t.Errorf("unexpected candidate shape: %+v", got[0])
	}
}

// ---- services ----

func TestCollectServicesDegradesToEmptyWhenSystemctlAbsent(t *testing.T) {
	origUnits, origFiles := runSystemctlListUnits, runSystemctlListUnitFiles
	defer func() { runSystemctlListUnits, runSystemctlListUnitFiles = origUnits, origFiles }()
	runSystemctlListUnits = func() ([]byte, error) { return nil, errors.New("systemctl not found") }

	if got := collectServices(t.TempDir()); got != nil {
		t.Fatalf("collectServices() = %+v; want nil when systemctl is absent", got)
	}
}

func TestCollectServicesFindsStatePath(t *testing.T) {
	home := t.TempDir()
	origUnits, origFiles, origCat := runSystemctlListUnits, runSystemctlListUnitFiles, runSystemctlCat
	defer func() {
		runSystemctlListUnits, runSystemctlListUnitFiles, runSystemctlCat = origUnits, origFiles, origCat
	}()

	runSystemctlListUnits = func() ([]byte, error) {
		return []byte("myapp.service loaded active running My App\nother.service loaded inactive dead Other\n"), nil
	}
	runSystemctlListUnitFiles = func() ([]byte, error) {
		return []byte("myapp.service enabled\nother.service disabled\n"), nil
	}
	runSystemctlCat = func(unit string) ([]byte, error) {
		if unit == "myapp.service" {
			return []byte("[Service]\nExecStart=/usr/bin/myapp --data=" + home + "/myapp/state.db\n"), nil
		}
		return []byte("[Service]\nExecStart=/usr/bin/other\n"), nil
	}

	got := collectServices(home)
	if len(got) != 1 || got[0].Name != "myapp.service" {
		t.Fatalf("collectServices = %+v; want exactly one candidate for myapp.service", got)
	}
	if got[0].Path != home+"/myapp/state.db" {
		t.Errorf("Path = %q, want %s/myapp/state.db", got[0].Path, home)
	}
}

// ---- system ----

func TestCollectSystemAlwaysEmitsThreeFixedCandidates(t *testing.T) {
	dir := t.TempDir()
	machineID := filepath.Join(dir, "machine-id")
	if err := os.WriteFile(machineID, []byte("abc123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sp := SystemPaths{MachineID: machineID, PackageManifests: []string{filepath.Join(dir, "nonexistent")}, Etc: dir}

	got := collectSystem(sp)
	if len(got) != 3 {
		t.Fatalf("collectSystem = %+v; want exactly 3 fixed candidates", got)
	}
	kinds := map[Kind]bool{}
	for _, c := range got {
		kinds[c.Kind] = true
	}
	for _, want := range []Kind{KindMachineID, KindPackageManifest, KindEtcConfig} {
		if !kinds[want] {
			t.Errorf("missing fixed candidate kind %q", want)
		}
	}
}
