package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// canonicalize renders e (with Hash always cleared) as a JCS-compatible
// canonical JSON encoding: object keys sorted at every level and compact
// separators, matching RFC 8785's structural requirements. It does not
// implement RFC 8785's exact number-formatting rules (ECMAScript
// Number-to-String) since ledger entries never contain floats — see
// ValidateNoFloats, which enforces that invariant on anything read back off
// disk. Documented in docs/ARCHITECTURE.md §5 as a "JCS-compatible subset".
func canonicalize(e Entry) ([]byte, error) {
	e.Hash = ""
	structBytes, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("ledger: cannot marshal entry: %w", err)
	}

	// Round-trip through map[string]any: encoding/json sorts map keys at
	// every nesting level, which is what makes the second Marshal below
	// canonical. UseNumber preserves integers exactly instead of widening
	// them through float64.
	var generic map[string]any
	dec := json.NewDecoder(bytes.NewReader(structBytes))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("ledger: cannot canonicalize entry: %w", err)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil {
		return nil, fmt.Errorf("ledger: cannot encode canonical entry: %w", err)
	}
	// Encoder.Encode appends a trailing newline; canonical form has none.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// hashEntry computes the entry hash: sha256 over the canonical JSON of e
// with its hash field omitted, hex-encoded with a "sha256:" prefix (the
// same convention testdata/golden uses for evidence hashes).
func hashEntry(e Entry) (string, error) {
	canonical, err := canonicalize(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ValidateNoFloats walks arbitrary decoded JSON (as produced by a
// json.Decoder with UseNumber) and rejects any number that isn't a plain
// integer literal. Ledger entries we write are float-free by construction
// (every numeric Go field is an int); this guards entries read back off
// disk against hand-edited or corrupted non-integer numbers.
func ValidateNoFloats(v any) error {
	switch t := v.(type) {
	case json.Number:
		s := t.String()
		for _, c := range s {
			if c == '.' || c == 'e' || c == 'E' {
				return fmt.Errorf("ledger: number %q is not an integer", s)
			}
		}
		return nil
	case map[string]any:
		for k, child := range t {
			if err := ValidateNoFloats(child); err != nil {
				return fmt.Errorf("%s.%w", k, err)
			}
		}
		return nil
	case []any:
		for i, child := range t {
			if err := ValidateNoFloats(child); err != nil {
				return fmt.Errorf("[%d]%w", i, err)
			}
		}
		return nil
	default:
		return nil
	}
}
