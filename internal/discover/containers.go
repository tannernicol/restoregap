// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
)

// containerSkipPrefixes are host paths a container bind-mount source is
// never counted as a recovery candidate under: ephemeral, virtual, or
// process-scoped filesystems that never survive a reboot regardless of
// what a container has bind-mounted from them.
var containerSkipPrefixes = []string{"/tmp", "/proc", "/sys", "/dev", "/var/run"}

// runDockerPS and runDockerInspect are function variables so tests can
// inject fixed output or simulate docker being absent; production shells
// out to the real docker CLI.
var runDockerPS = func() ([]byte, error) {
	return exec.Command("docker", "ps", "--format", "{{.Names}}").Output() //nolint:gosec // fixed invocation, no arguments
}

var runDockerInspect = func(name string) ([]byte, error) {
	return exec.Command("docker", "inspect", name).Output() //nolint:gosec // name comes from our own `docker ps` call
}

// dockerMount is the subset of `docker inspect`'s Mounts entries this
// collector needs.
type dockerMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

type dockerInspectEntry struct {
	Mounts []dockerMount `json:"Mounts"`
}

// collectContainers lists running containers and their writable bind
// mounts. It degrades to an empty result — never an error — whenever
// docker is not installed or not running: the command that runs it must
// never fail just because this host has no docker.
func collectContainers() []Candidate {
	names, err := containerNames()
	if err != nil {
		return nil
	}
	var out []Candidate
	for _, name := range names {
		out = append(out, containerVolumeCandidates(name)...)
	}
	return out
}

// containerNames returns the running container names from `docker ps`.
func containerNames() ([]string, error) {
	out, err := runDockerPS()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			names = append(names, line)
		}
	}
	return names, nil
}

// containerVolumeCandidates returns one candidate per writable bind mount
// on the named container that is not under containerSkipPrefixes and does
// not point at a socket.
func containerVolumeCandidates(name string) []Candidate {
	out, err := runDockerInspect(name)
	if err != nil {
		return nil
	}
	var entries []dockerInspectEntry
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil
	}
	var candidates []Candidate
	for _, entry := range entries {
		for _, m := range entry.Mounts {
			if !isCandidateBindMount(m) {
				continue
			}
			candidates = append(candidates, Candidate{
				Kind: KindContainerVolume, Name: name, Path: m.Source,
				SizeBytes: dirEntrySize(m.Source), Weight: weightFor(KindContainerVolume),
			})
		}
	}
	return candidates
}

// isCandidateBindMount reports whether m is a writable bind mount worth
// reporting: type "bind", RW true, source not under a skip prefix, and not
// a socket.
func isCandidateBindMount(m dockerMount) bool {
	if m.Type != "bind" || !m.RW || m.Source == "" {
		return false
	}
	if underAny(m.Source, containerSkipPrefixes) {
		return false
	}
	return !isSocket(m.Source)
}

// underAny reports whether path equals or is nested under any of prefixes.
func underAny(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// isSocket reports whether path is a unix socket. When the path cannot be
// stat'd (e.g. it lives inside the container's mount namespace, not this
// host's), it falls back to a name heuristic rather than guessing wrong in
// either direction silently.
func isSocket(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return strings.HasSuffix(path, ".sock")
	}
	return info.Mode()&os.ModeSocket != 0
}
