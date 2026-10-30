// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package hostid computes this machine's durable identity: a host id derived
// from /etc/machine-id (fallback: hostname + first MAC) and an epoch id
// derived from the machine id plus the root filesystem UUID. Together they
// answer "was this proof drilled on THIS machine, and on THIS install of it"
// — a proof imported from another host, or recorded before a reinstall, is
// evidence about a different world and must be re-drilled.
package hostid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Identity is one machine's host/epoch stamp, carried by proofs and ledger
// entries (docs/SCHEMA.md §Identity & epoch). HostID is 16 hex chars, Epoch
// 12; both are truncated sha256 digests, not secrets — they exist to be
// compared, printed, and shipped inside bundles.
type Identity struct {
	HostName string `json:"name"`
	HostID   string `json:"id"`
	Epoch    string `json:"epoch"`
}

// Override is returned by Current instead of resolving the machine, when
// non-nil — the seam tests use to pin identity without touching /etc or the
// filesystem UUID. Production code never sets it.
var Override *Identity

// Current resolves this machine's identity. It never fails hard: a machine
// whose id sources are all unreadable gets an id derived from whatever WAS
// readable (hostname at minimum), because "unknown identity" must not make
// every command unusable — it makes the stamp weak, not absent.
func Current() Identity {
	if Override != nil {
		return *Override
	}
	name, _ := os.Hostname()
	if name == "" {
		name = "unknown"
	}
	mid := machineID()
	root := rootUUID()
	return Identity{
		HostName: name,
		HostID:   hostID(mid, name),
		Epoch:    epochID(mid, root),
	}
}

// hostID = sha256(machine-id)[:16 hex]; fallback input is hostname+first MAC
// when no machine-id exists (e.g. some containers).
func hostID(machineID, hostname string) string {
	src := machineID
	if src == "" {
		src = hostname + firstMAC()
	}
	return truncateHex(src, 16)
}

// epochID = sha256(machine-id + root-fs-uuid)[:12 hex]. A reinstall (new
// filesystem UUID) or a machine-id reset starts a new epoch: proofs stamped
// with the old epoch are from a previous world.
func epochID(machineID, rootUUID string) string {
	return truncateHex(machineID+"|"+rootUUID, 12)
}

func truncateHex(input string, n int) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])[:n]
}

// machineID reads the lowercase machine-id from either standard location.
// systemd's "uninitialized" placeholder (a cloned image that has not yet
// generated its own id) is treated as absent — it identifies the clone
// lineage, not this machine, so the hostname+MAC fallback gives a better
// answer than trusting it.
func machineID() string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		id := strings.TrimSpace(strings.ToLower(string(raw)))
		if id == "" || strings.HasSuffix(id, "uninitialized") {
			continue
		}
		return id
	}
	return ""
}

// rootUUID resolves the root filesystem's UUID, via findmnt when available
// and /proc/mounts otherwise. Empty when neither source yields one — the
// epoch then varies only by machine-id, which is still a usable identity.
func rootUUID() string {
	if out, err := exec.Command("findmnt", "-no", "UUID", "/").Output(); err == nil {
		if id := strings.TrimSpace(string(out)); id != "" {
			return id
		}
	}
	raw, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "/" {
			continue
		}
		for _, opt := range strings.Split(fields[2], ",") {
			if value, ok := strings.CutPrefix(opt, "UUID="); ok {
				return value
			}
		}
	}
	return ""
}

// firstMAC returns the first non-loopback hardware MAC, colon-free, as part
// of the machine-id fallback. Empty when no interface reports one.
func firstMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		return iface.HardwareAddr.String()
	}
	return ""
}

// String renders the one-line form commands print: "host <name> (<id>) ·
// epoch <epoch>". Stable on purpose — it appears in command output tests.
func (i Identity) String() string {
	return fmt.Sprintf("host %s (%s) · epoch %s", i.HostName, i.HostID, i.Epoch)
}
