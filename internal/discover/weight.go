// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package discover

// weightByKind is the blast-radius hint table, derived from Kind ALONE —
// never from a candidate's size, name, or path. No scoring cleverness lives
// here; the agent reading the report does the judging.
//
//	4  machine-id, package-manifest, etc-config  — the machine floor: a
//	   rebuild cannot even boot into a shell that matches this host
//	   without these, and losing /etc's hand edits or the package
//	   manifest is close in spirit to losing identity/secrets material.
//	3  database                                  — a running service's
//	   own data; loss is a real incident but the service itself is
//	   reinstallable.
//	2  container-volume, service-state           — state a running
//	   service keeps on the host outside its own image/package; usually
//	   overlaps with a database candidate but not always (config dirs,
//	   media libraries).
//	1  repo                                      — local, unpushed work;
//	   real to lose, but scoped to whatever was written since the last
//	   push, never the whole estate.
var weightByKind = map[Kind]int{
	KindMachineID:       4,
	KindAgent:           4,
	KindPackageManifest: 4,
	KindEtcConfig:       4,
	KindDatabase:        3,
	KindContainerVolume: 2,
	KindServiceState:    2,
	KindRepo:            1,
}

// weightFor returns kind's blast-radius weight, 0 for an unknown kind
// (never expected outside a test building a Candidate by hand).
func weightFor(kind Kind) int {
	return weightByKind[kind]
}
