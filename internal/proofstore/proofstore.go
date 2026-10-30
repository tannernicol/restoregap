// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// Package proofstore owns persistence of generated proof records in a v2
// context file. A producer supplies the complete replacement fields for one or
// more proof IDs; proofstore serializes the read/modify/validate/write
// transaction and keeps the file replacement atomic.
package proofstore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

var (
	// These seams are deliberately package-private. They make pre-rename
	// failures deterministic in this package's tests without weakening the
	// production transaction or exposing a second persistence API.
	writeTemp = func(file *os.File, data []byte) error {
		n, err := file.Write(data)
		if err == nil && n != len(data) {
			return io.ErrShortWrite
		}
		return err
	}
	syncTemp      = func(file *os.File) error { return file.Sync() }
	closeTemp     = func(file *os.File) error { return file.Close() }
	renameTemp    = os.Rename
	syncDirectory = func(dir string) error {
		file, err := os.Open(dir)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
		return file.Sync()
	}
)

// Upsert validates and atomically merges generated proof records into path.
// Each entry must contain a non-empty string id. An existing proof with that
// id is updated field by field, preserving fields the entry does not own;
// otherwise the entry is appended. The input slice must not contain duplicate
// IDs. The destination must already exist as a regular, non-symlink file.
func Upsert(path string, entries []map[string]any) error {
	if path == "" {
		return errors.New("proofstore: context path is empty")
	}
	if err := validateEntries(entries); err != nil {
		return err
	}

	// Validate before opening the lock as well as after it. The second check is
	// the security boundary that protects against a destination being replaced
	// while this process waited for another writer.
	if _, err := regularDestination(path); err != nil {
		return err
	}

	lock, err := openLock(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = unlock(lock)
		_ = lock.Close()
	}()

	info, raw, err := readDestination(path)
	if err != nil {
		return fmt.Errorf("proofstore: read %s: %w", path, err)
	}

	doc, err := parseDocument(raw)
	if err != nil {
		return fmt.Errorf("proofstore: parse %s: %w", path, err)
	}
	if err := mergeProofs(doc, entries); err != nil {
		return fmt.Errorf("proofstore: update %s: %w", path, err)
	}
	encoded, err := encodeDocument(doc)
	if err != nil {
		return fmt.Errorf("proofstore: encode %s: %w", path, err)
	}
	if _, err := contextspec.Parse(strings.NewReader(string(encoded))); err != nil {
		return fmt.Errorf("proofstore: updated context failed validation, not written: %w", err)
	}
	if err := replace(path, info.Mode().Perm(), encoded); err != nil {
		return fmt.Errorf("proofstore: replace %s: %w", path, err)
	}
	return nil
}

func validateEntries(entries []map[string]any) error {
	seen := make(map[string]struct{}, len(entries))
	for i, entry := range entries {
		if entry == nil {
			return fmt.Errorf("proofstore: entry %d is nil", i)
		}
		id, ok := entry["id"].(string)
		if !ok || strings.TrimSpace(id) == "" {
			return fmt.Errorf("proofstore: entry %d requires a non-empty string id", i)
		}
		if _, ok := seen[id]; ok {
			return fmt.Errorf("proofstore: duplicate proof id %q", id)
		}
		seen[id] = struct{}{}
		if _, err := entryNode(entry); err != nil {
			return fmt.Errorf("proofstore: entry %d (%s): %w", i, id, err)
		}
	}
	return nil
}

func regularDestination(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("proofstore: destination %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("proofstore: destination %s is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("proofstore: destination %s is not a regular file", path)
	}
	return info, nil
}

func openLock(path string) (*os.File, error) {
	lockPath := path + ".lock"
	if info, err := os.Lstat(lockPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("proofstore: lock %s is a symlink", lockPath)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("proofstore: lock %s is not a regular file", lockPath)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("proofstore: inspect lock %s: %w", lockPath, err)
	}
	lock, err := openLockFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("proofstore: open lock %s without following symlinks: %w", lockPath, err)
	}
	if err := lockExclusive(lock); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("proofstore: lock %s: %w", lockPath, err)
	}
	return lock, nil
}

func parseDocument(raw []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("context document must be a YAML mapping")
	}
	return &doc, nil
}

func encodeDocument(doc *yaml.Node) ([]byte, error) {
	var out strings.Builder
	enc := yaml.NewEncoder(&out)
	if err := enc.Encode(doc); err != nil {
		_ = enc.Close()
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(out.String()), nil
}

func mergeProofs(doc *yaml.Node, entries []map[string]any) error {
	root := doc.Content[0]
	proofs := mappingValue(root, "proofs")
	if proofs == nil {
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "proofs"}
		proofs = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		root.Content = append(root.Content, key, proofs)
	}
	if proofs.Kind != yaml.SequenceNode {
		return errors.New("proofs must be a sequence")
	}

	for _, entry := range entries {
		incoming, err := entryNode(entry)
		if err != nil {
			return err
		}
		id := mappingScalar(incoming, "id")
		for _, existing := range proofs.Content {
			if existing.Kind == yaml.MappingNode && mappingScalar(existing, "id") == id {
				mergeMapping(existing, incoming)
				incoming = nil
				break
			}
		}
		if incoming != nil {
			proofs.Content = append(proofs.Content, incoming)
		}
	}
	return nil
}

func entryNode(entry map[string]any) (*yaml.Node, error) {
	raw, err := yaml.Marshal(entry)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("entry must encode as a YAML mapping")
	}
	return doc.Content[0], nil
}

func mappingValue(mapping *yaml.Node, name string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == name {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func mappingScalar(mapping *yaml.Node, name string) string {
	node := mappingValue(mapping, name)
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func mergeMapping(existing, incoming *yaml.Node) {
	for i := 0; i+1 < len(incoming.Content); i += 2 {
		key, value := incoming.Content[i], incoming.Content[i+1]
		for j := 0; j+1 < len(existing.Content); j += 2 {
			if existing.Content[j].Value == key.Value {
				if isNull(value) {
					// A producer uses nil to explicitly clear a field it
					// owns. This keeps declarative metadata intact while
					// preventing stale generated authority from surviving
					// a replacement.
					existing.Content = append(existing.Content[:j], existing.Content[j+2:]...)
					value = nil
					break
				}
				if key.Value == "scope" && existing.Content[j+1].Kind == yaml.MappingNode && value.Kind == yaml.MappingNode {
					mergeScope(existing.Content[j+1], value)
				} else {
					// Generated nested records such as measurements and
					// signatures are replacement units. Retaining omitted
					// children would carry stale authority forward.
					existing.Content[j+1] = value
				}
				value = nil
				break
			}
		}
		if value != nil && !isNull(value) {
			existing.Content = append(existing.Content, key, value)
		}
	}
}

func mergeScope(existing, incoming *yaml.Node) {
	for i := 0; i+1 < len(incoming.Content); i += 2 {
		key, value := incoming.Content[i], incoming.Content[i+1]
		for j := 0; j+1 < len(existing.Content); j += 2 {
			if existing.Content[j].Value != key.Value {
				continue
			}
			if key.Value == "host" && !isNull(value) && existing.Content[j+1].Kind == yaml.ScalarNode && existing.Content[j+1].Value != "" {
				// scope.host is declarative taxonomy metadata. A default
				// stamp fills it only when absent and never overrides an
				// explicit host on a re-drill.
				value = nil
				break
			}
			if isNull(value) {
				existing.Content = append(existing.Content[:j], existing.Content[j+2:]...)
			} else {
				existing.Content[j+1] = value
			}
			value = nil
			break
		}
		if value != nil && !isNull(value) {
			existing.Content = append(existing.Content, key, value)
		}
	}
}

func isNull(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.Tag == "!!null"
}

func replace(path string, mode os.FileMode, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if err := writeTemp(temp, data); err != nil {
		_ = closeTemp(temp)
		return fmt.Errorf("write temporary file: %w", err)
	}
	// Apply the destination mode after writing so a read-only source (for
	// example 0400) can still be replaced by its owner through the temporary
	// file, while the final inode retains the original permissions.
	if err := temp.Chmod(mode); err != nil {
		_ = closeTemp(temp)
		return fmt.Errorf("set temporary mode: %w", err)
	}
	if err := syncTemp(temp); err != nil {
		_ = closeTemp(temp)
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := closeTemp(temp); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := renameTemp(tempPath, path); err != nil {
		return fmt.Errorf("rename temporary file: %w", err)
	}
	removeTemp = false
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync containing directory: %w", err)
	}
	return nil
}
