// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/tannernicol/restoregap/internal/ledger"
)

// VerifyResult is `bundle verify`'s outcome: whether the bundle's signature,
// content digests, and embedded ledger slice all check out, and — when they
// do — the identity it vouches for.
type VerifyResult struct {
	OK       bool
	Manifest Manifest
	// Reason explains a false OK: which check failed and on what.
	Reason string
}

// Verify opens path, checks the detached Ed25519 signature over
// manifest.json, recomputes and compares every content digest the manifest
// claims, and re-verifies the embedded ledger slice's own internal hash
// chain (see verifySliceChain). It stops at the first failure — a bundle
// that fails one check is not "mostly trustworthy".
func Verify(path string) (VerifyResult, error) {
	return VerifyWithExpectedKey(path, "")
}

// VerifyWithExpectedKey verifies a full tar.gz bundle and, when expectedKey
// is supplied, requires the detached signer to match that independently
// trusted Ed25519 public key. An empty expectedKey preserves the historical
// integrity-only API for full bundles.
func VerifyWithExpectedKey(path, expectedKey string) (VerifyResult, error) {
	archive, err := os.ReadFile(path) //nolint:gosec // caller-provided bundle path, same trust level as any other CLI arg
	if err != nil {
		return VerifyResult{}, fmt.Errorf("bundle verify: %s: %w", path, err)
	}
	_, result, err := verifyArchive(archive, expectedKey, path)
	return result, err
}

// VerifyBytes is Verify over an in-memory archive — what a service holding a
// request body needs, without a temp file per request. It runs the exact
// same checks as Verify (one implementation, see verifyArchive).
func VerifyBytes(archive []byte) (VerifyResult, error) {
	return VerifyBytesWithExpectedKey(archive, "")
}

// VerifyBytesWithExpectedKey is VerifyWithExpectedKey over an in-memory
// archive: with a non-empty expectedKey the detached signer must match it.
func VerifyBytesWithExpectedKey(archive []byte, expectedKey string) (VerifyResult, error) {
	_, result, err := verifyArchive(archive, expectedKey, "")
	return result, err
}

// scoped renders the "<prefix>: <label>: " error lead-in the path-based
// functions have always produced, or "<prefix>: " when there is no path to
// name (the in-memory entry points).
func scoped(prefix, label string) string {
	if label == "" {
		return prefix + ": "
	}
	return prefix + ": " + label + ": "
}

// verifyArchive is the single verification implementation behind Verify,
// VerifyBytes and the Load* functions. label is the path to name in error
// text ("" for in-memory callers). It also returns the decoded tar members
// so LoadVerified* can reuse them instead of decompressing twice.
func verifyArchive(archive []byte, expectedKey, label string) (map[string][]byte, VerifyResult, error) {
	members, err := readTarGzBytes(archive)
	if err != nil {
		return nil, VerifyResult{}, fmt.Errorf("%s%w", scoped("bundle verify", label), err)
	}

	manifestBytes, ok := members[manifestName]
	if !ok {
		return members, VerifyResult{OK: false, Reason: "missing " + manifestName}, nil
	}
	sigBytes, ok := members[signatureName]
	if !ok {
		return members, VerifyResult{OK: false, Reason: "missing " + signatureName}, nil
	}

	signatureOK, reason, err := verifyFullBundleSignature(manifestBytes, sigBytes, expectedKey)
	if err != nil {
		return nil, VerifyResult{}, err
	}
	if !signatureOK {
		return members, VerifyResult{OK: false, Reason: reason}, nil
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return members, VerifyResult{OK: false, Reason: fmt.Sprintf("unreadable %s: %v", manifestName, err)}, nil
	}

	if reason, ok := verifyContentDigests(manifest, members); !ok {
		return members, VerifyResult{OK: false, Manifest: manifest, Reason: reason}, nil
	}

	entries, reason, ok := decodeAndVerifyLedgerSlice(manifest, members)
	if !ok {
		return members, VerifyResult{OK: false, Manifest: manifest, Reason: reason}, nil
	}
	if len(entries) != manifest.LedgerSlice.EntryCount {
		return members, VerifyResult{OK: false, Manifest: manifest, Reason: fmt.Sprintf(
			"ledger slice entry count mismatch: manifest claims %d, slice has %d", manifest.LedgerSlice.EntryCount, len(entries))}, nil
	}

	return members, VerifyResult{OK: true, Manifest: manifest}, nil
}

func verifyFullBundleSignature(manifestBytes, sigBytes []byte, expectedKey string) (bool, string, error) {
	var sig Signature
	if err := json.Unmarshal(sigBytes, &sig); err != nil {
		return false, fmt.Sprintf("unreadable %s: %v", signatureName, err), nil
	}
	pub, err := hex.DecodeString(sig.PublicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false, "signature public key is not a valid Ed25519 key", nil
	}
	if expectedKey != "" {
		expected, err := parseExpectedPublicKey(expectedKey)
		if err != nil {
			return false, "", err
		}
		if !bytes.Equal(pub, expected) {
			return false, "bundle signer does not match the expected public key", nil
		}
	}
	sigRaw, err := hex.DecodeString(sig.SignatureHex)
	if err != nil || len(sigRaw) != ed25519.SignatureSize {
		return false, "signature is not a valid Ed25519 signature", nil
	}
	if !ed25519.Verify(pub, manifestBytes, sigRaw) {
		return false, "signature does not verify against manifest.json — tampered or wrong key", nil
	}
	return true, "", nil
}

// verifyContentDigests recomputes every context file's sha256 and the
// ledger slice's sha256 straight from the tar members and compares them
// against what manifest.json claims — the "manifest <-> contents digests"
// half of the contract, independent of the ledger slice's own internal
// chain (checked separately by decodeAndVerifyLedgerSlice).
func verifyContentDigests(manifest Manifest, members map[string][]byte) (reason string, ok bool) {
	for _, ref := range manifest.ContextFiles {
		data, present := members[ref.Name]
		if !present {
			return fmt.Sprintf("manifest names context file %q, not present in the bundle", ref.Name), false
		}
		if got := sha256Hex(data); got != ref.SHA256 {
			return fmt.Sprintf("context file %q digest mismatch: manifest says %s, bundle has %s", ref.Name, ref.SHA256, got), false
		}
	}
	sliceData := members[manifest.LedgerSlice.Name]
	if got := sha256Hex(sliceData); got != manifest.LedgerSlice.SHA256 {
		return fmt.Sprintf("ledger slice digest mismatch: manifest says %s, bundle has %s", manifest.LedgerSlice.SHA256, got), false
	}
	return "", true
}

// decodeAndVerifyLedgerSlice parses the embedded ledger/slice.jsonl member
// and checks its own internal hash chain via ledger.VerifyEntriesFrom,
// seeded with the slice's own first entry's Prev rather than
// ledger.GenesisHash — a --since truncated slice is not, in general, the
// whole ledger, so it trusts the boundary it was cut at (recorded in
// manifest.LedgerSlice.FirstPrev, matching entries[0].Prev) and otherwise
// applies the exact same per-entry hash/chain-anchor checks a full-ledger
// Verify does.
func decodeAndVerifyLedgerSlice(manifest Manifest, members map[string][]byte) ([]ledger.Entry, string, bool) {
	entries, err := parseLedgerJSONL(members[manifest.LedgerSlice.Name])
	if err != nil {
		return nil, fmt.Sprintf("unreadable ledger slice: %v", err), false
	}
	if len(entries) == 0 {
		return entries, "", true
	}
	result := ledger.VerifyEntriesFrom(entries, entries[0].Prev)
	if !result.OK {
		return nil, fmt.Sprintf("ledger slice: %s", result.Reason), false
	}
	return entries, "", true
}

func parseLedgerJSONL(data []byte) ([]ledger.Entry, error) {
	var entries []ledger.Entry
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var e ledger.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// readTarGz reads path and delegates to readTarGzBytes.
func readTarGz(path string) (map[string][]byte, error) {
	archive, err := os.ReadFile(path) //nolint:gosec // caller-provided bundle path, same trust level as any other CLI arg
	if err != nil {
		return nil, err
	}
	return readTarGzBytes(archive)
}

// readTarGzBytes decompresses and untars an in-memory archive, returning
// every member's content keyed by name — bundles are small (policy text, a
// bounded ledger slice, evidence metadata), so reading them fully into
// memory is the simple choice, not a streaming concern.
// MaxDecompressedBytes bounds the total decompressed size readTarGzBytes
// will hold in memory. A bundle is a few context files plus a ledger slice;
// real ones are kilobytes to low megabytes. The cap exists because a hosted
// endpoint receives archives from token holders, and a small gzip bomb must
// fail with an error rather than exhaust the process. Path-based callers
// inherit it too: an archive this large is not a bundle anyone made.
const MaxDecompressedBytes = 256 << 20

func readTarGzBytes(archive []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("not a gzip file: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	members := map[string][]byte{}
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// LimitReader +1 so an over-limit member is detected rather than
		// silently truncated into a digest mismatch with a confusing reason.
		data, err := io.ReadAll(io.LimitReader(tr, MaxDecompressedBytes-total+1))
		if err != nil {
			return nil, fmt.Errorf("reading tar member %s: %w", hdr.Name, err)
		}
		total += int64(len(data))
		if total > MaxDecompressedBytes {
			return nil, fmt.Errorf("archive expands past %d bytes; refusing to read it", MaxDecompressedBytes)
		}
		members[hdr.Name] = data
	}
	return members, nil
}
