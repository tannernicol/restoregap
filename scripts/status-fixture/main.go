// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

// status-fixture renders synthetic browser test data without consulting the host.
package main

import (
	"os"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
	"github.com/tannernicol/restoregap/internal/status"
)

func main() {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	s := status.Summary{
		Verdict: "warn", Origin: "Synthetic release fixture", GeneratedAt: now,
		InventorySummary: "1 of 2 provably restorable", LedgerOK: true,
		Context: contextspec.Context{Guards: []contextspec.Guard{
			{ID: "app", Requires: contextspec.Requirement{Proofs: []string{"app-db"}}, Scope: contextspec.Scope{System: "demo-app"}},
			{ID: "files", Requires: contextspec.Requirement{Proofs: []string{"files"}}, Scope: contextspec.Scope{System: "demo-files"}},
		}},
		Inventory: []status.InventoryRow{
			{Level: "declared", Proof: "app-db", IsDrilled: true, SourceFile: "demo.yml", RPO: "—", RTO: "—", ProofAge: "no drill"},
			{Level: "restores", LevelRank: contextspec.LevelRestores.Rung(), Proof: "files", IsDrilled: true, RPO: "1h", RTO: "1s", ProofAge: "1h"},
		},
	}
	if len(os.Args) > 1 && os.Args[1] == "empty" {
		s = status.Summary{Verdict: "warn", Origin: "Empty release fixture", GeneratedAt: now}
	}
	out, err := s.RenderHTML()
	if err != nil {
		panic(err)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		panic(err)
	}
}
