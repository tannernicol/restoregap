package ledger

import "testing"

// TestEntryValidate exercises the exactly-one-payload rule the Payload
// union's doc comment promises: exactly one field set, and it must match
// EntryType. Chain anchors extend the same closed union as every other
// entry type, so they're checked alongside the rest here rather than in a
// separate test.
func TestEntryValidate(t *testing.T) {
	tests := []struct {
		name    string
		entry   Entry
		wantErr bool
	}{
		{
			name: "decision payload matching decision type",
			entry: Entry{ID: "e1", EntryType: EntryDecision, Payload: Payload{
				Decision: &DecisionPayload{Verdict: "block"},
			}},
			wantErr: false,
		},
		{
			name: "chain_anchor payload matching chain_anchor type",
			entry: Entry{ID: "e1", EntryType: EntryChainAnchor, Payload: Payload{
				ChainAnchor: &ChainAnchorPayload{EntryID: "e0", StoredHash: "sha256:a", RecomputedHash: "sha256:b", Reason: "r", ApprovedBy: "tanner"},
			}},
			wantErr: false,
		},
		{
			name:    "no payload set",
			entry:   Entry{ID: "e1", EntryType: EntryDecision, Payload: Payload{}},
			wantErr: true,
		},
		{
			name: "two payload fields set",
			entry: Entry{ID: "e1", EntryType: EntryDecision, Payload: Payload{
				Decision: &DecisionPayload{Verdict: "block"},
				Override: &OverridePayload{FindingID: "f1", ApprovedBy: "tanner", Reason: "r"},
			}},
			wantErr: true,
		},
		{
			name: "payload set but entry_type does not match it",
			entry: Entry{ID: "e1", EntryType: EntryOverride, Payload: Payload{
				Decision: &DecisionPayload{Verdict: "block"},
			}},
			wantErr: true,
		},
		{
			name: "chain_anchor payload but entry_type says decision",
			entry: Entry{ID: "e1", EntryType: EntryDecision, Payload: Payload{
				ChainAnchor: &ChainAnchorPayload{EntryID: "e0", StoredHash: "sha256:a", RecomputedHash: "sha256:b", Reason: "r", ApprovedBy: "tanner"},
			}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entry.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
