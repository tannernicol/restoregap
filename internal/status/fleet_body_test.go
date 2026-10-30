// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

import (
	"strings"
	"testing"
	"time"

	"github.com/tannernicol/restoregap/internal/contextspec"
)

// TestFleetPageDataMatchesRenderHTML pins the accessor to the page it was
// extracted from: every row RenderHTML shows is in PageData, carrying the
// label its bundle was merged under so a service can link rows back to hosts.
func TestFleetPageDataMatchesRenderHTML(t *testing.T) {
	fleet := Fleet{
		GeneratedAt: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC),
		Bundles:     []FleetBundleInfo{{Path: "web-1", Host: "web-1", HostID: "h1"}},
		Proofs: []FleetProof{{
			Proof: "pg-restore", Layer: contextspec.LayerDataApps, Category: "databases", State: StateRestored, Level: "restores",
			Why: "fresh", Host: "web-1", SourceBundle: "web-1",
		}},
	}
	data := fleet.PageData()
	if !data.HasAny || len(data.Layers) != 1 {
		t.Fatalf("PageData = %+v", data)
	}
	row := data.Layers[0].Categories[0].Rows[0]
	if row.Proof != "pg-restore" || row.Source != "web-1" || row.Host != "web-1" {
		t.Fatalf("row = %+v", row)
	}
	page, err := fleet.RenderHTML()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), "pg-restore") {
		t.Fatal("RenderHTML does not show the row PageData has")
	}
	if !strings.Contains(StyleSheet(), ".rgs-taxrow") {
		t.Fatal("StyleSheet lacks the fleet tree's own rules")
	}
	if (Fleet{}).PageData().HasAny {
		t.Fatal("empty fleet must report HasAny=false")
	}
}
