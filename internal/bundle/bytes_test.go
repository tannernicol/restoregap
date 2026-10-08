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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// exportForBytes exports a one-context signed bundle and returns its path and
// the signing seed, so byte-level tests share the path-based fixtures.
func exportForBytes(t *testing.T) (path, seed string) {
	t.Helper()
	setTestHost(t)
	dir := t.TempDir()
	ctxPath := writeCtx(t, dir, "restoregap.yml", sprintfFixture(writeCtx(t, dir, "evidence.txt", "evidence bytes")))
	path = filepath.Join(dir, "out.tgz")
	seed = testSigningKey(t)
	if _, err := Export(ExportRequest{ContextPaths: []string{ctxPath}, SigningKey: seed, Out: path}); err != nil {
		t.Fatal(err)
	}
	return path, seed
}

func readArchive(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// requireSameVerify asserts the path-based and bytes-based entry points agree
// on one archive: same OK/Reason/Manifest and same error-or-not.
func requireSameVerify(t *testing.T, path, expectedKey string) VerifyResult {
	t.Helper()
	want, wantErr := VerifyWithExpectedKey(path, expectedKey)
	got, gotErr := VerifyBytesWithExpectedKey(readArchive(t, path), expectedKey)
	if (wantErr == nil) != (gotErr == nil) {
		t.Fatalf("error disagreement: path=%v bytes=%v", wantErr, gotErr)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("VerifyBytes disagrees with Verify:\npath:  %+v\nbytes: %+v", want, got)
	}
	return got
}

func TestVerifyBytesAgreesWithVerifyValid(t *testing.T) {
	path, _ := exportForBytes(t)
	if res := requireSameVerify(t, path, ""); !res.OK {
		t.Fatalf("expected valid bundle to verify, got %+v", res)
	}
	// The no-key convenience wrapper must agree too.
	a, err := VerifyBytes(readArchive(t, path))
	if err != nil || !a.OK {
		t.Fatalf("VerifyBytes: %+v %v", a, err)
	}
}

func TestVerifyBytesAgreesWithVerifyTamperedManifest(t *testing.T) {
	path, _ := exportForBytes(t)
	members, err := readTarGz(path)
	if err != nil {
		t.Fatal(err)
	}
	tamperTarGzMember(t, path, manifestName, append(append([]byte(nil), members[manifestName]...), ' '))
	if res := requireSameVerify(t, path, ""); res.OK {
		t.Fatal("tampered manifest must not verify")
	}
}

func TestVerifyBytesAgreesWithVerifyBadSignature(t *testing.T) {
	path, _ := exportForBytes(t)
	members, err := readTarGz(path)
	if err != nil {
		t.Fatal(err)
	}
	var sig Signature
	if err := json.Unmarshal(members[signatureName], &sig); err != nil {
		t.Fatal(err)
	}
	// Flip the first signature nibble: still well-formed hex, no longer valid.
	flipped := []byte(sig.SignatureHex)
	if flipped[0] == '0' {
		flipped[0] = '1'
	} else {
		flipped[0] = '0'
	}
	sig.SignatureHex = string(flipped)
	raw, err := json.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	tamperTarGzMember(t, path, signatureName, raw)
	if res := requireSameVerify(t, path, ""); res.OK {
		t.Fatal("bad signature must not verify")
	}
}

func TestVerifyBytesAgreesWithVerifyExpectedKey(t *testing.T) {
	path, _ := exportForBytes(t)
	members, err := readTarGz(path)
	if err != nil {
		t.Fatal(err)
	}
	var sig Signature
	if err := json.Unmarshal(members[signatureName], &sig); err != nil {
		t.Fatal(err)
	}

	if res := requireSameVerify(t, path, sig.PublicKeyHex); !res.OK {
		t.Fatalf("matching expected key must verify, got %+v", res)
	}
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if res := requireSameVerify(t, path, hex.EncodeToString(other)); res.OK {
		t.Fatal("wrong expected key must not verify")
	}
	// A malformed expected key is an error on both paths, not a Reason.
	if _, err := VerifyBytesWithExpectedKey(readArchive(t, path), "not-hex"); err == nil {
		t.Fatal("malformed expected key must error")
	}
}

func TestVerifyBytesRejectsNonArchive(t *testing.T) {
	if _, err := VerifyBytes([]byte("not a tar.gz")); err == nil {
		t.Fatal("expected an error for a non-gzip body")
	}
	if _, err := LoadVerifiedBytes([]byte("not a tar.gz")); err == nil {
		t.Fatal("expected LoadVerifiedBytes to error for a non-gzip body")
	}
}

func TestLoadVerifiedBytesMatchesLoadVerifiedAndCarriesSignature(t *testing.T) {
	path, _ := exportForBytes(t)
	archive := readArchive(t, path)

	loaded, err := LoadVerifiedBytes(archive)
	if err != nil {
		t.Fatalf("LoadVerifiedBytes: %v", err)
	}
	manifest, ctx, err := LoadVerified(path)
	if err != nil {
		t.Fatalf("LoadVerified: %v", err)
	}
	if !reflect.DeepEqual(loaded.Manifest, manifest) {
		t.Errorf("manifest differs:\nbytes: %+v\npath:  %+v", loaded.Manifest, manifest)
	}
	if len(loaded.Context.Proofs) != 1 || len(ctx.Proofs) != 1 || loaded.Context.Proofs[0].ID != ctx.Proofs[0].ID {
		t.Errorf("context differs: bytes=%+v path=%+v", loaded.Context.Proofs, ctx.Proofs)
	}

	members, err := readTarGz(path)
	if err != nil {
		t.Fatal(err)
	}
	var want Signature
	if err := json.Unmarshal(members[signatureName], &want); err != nil {
		t.Fatal(err)
	}
	if want.PublicKeyHex == "" || want.SignatureHex == "" {
		t.Fatalf("fixture signature is empty: %+v", want)
	}
	if loaded.Signature != want {
		t.Errorf("signature = %+v, want manifest.sig's %+v", loaded.Signature, want)
	}
}

func TestLoadVerifiedBytesRefusesTampered(t *testing.T) {
	path, _ := exportForBytes(t)
	members, err := readTarGz(path)
	if err != nil {
		t.Fatal(err)
	}
	tamperTarGzMember(t, path, manifestName, append(append([]byte(nil), members[manifestName]...), ' '))
	if _, err := LoadVerifiedBytes(readArchive(t, path)); err == nil {
		t.Fatal("LoadVerifiedBytes must refuse a tampered bundle")
	}
}

// TestReadTarGzBytesRefusesOversizedArchive pins the decompression cap: a
// tar.gz whose members expand past MaxDecompressedBytes is refused with an
// error instead of being read into memory.
func TestReadTarGzBytesRefusesOversizedArchive(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	size := int64(MaxDecompressedBytes) + 1
	if err := tw.WriteHeader(&tar.Header{Name: "bomb", Mode: 0o600, Size: size, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	zeros := make([]byte, 1<<20)
	for written := int64(0); written < size; {
		n := int64(len(zeros))
		if size-written < n {
			n = size - written
		}
		if _, err := tw.Write(zeros[:n]); err != nil {
			t.Fatal(err)
		}
		written += n
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readTarGzBytes(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "expands past") {
		t.Fatalf("readTarGzBytes on a %d-byte-expanding archive: err = %v; want the cap error", size, err)
	}
}
