// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

package status

// PageData is the fleet tree fleet.html renders — layer → category → proof
// rows, filter chips, the environment × system roll-up and merge conflicts —
// as data instead of a standalone page. A service (Restore Gap Cloud) that
// wraps the tree in its own page shell and links each row elsewhere needs the
// pieces, not RenderHTML's whole document; exporting the builder RenderHTML
// and RenderText already share keeps the three from ever computing the tree
// differently.
func (f Fleet) PageData() FleetPageData { return buildFleetPageData(f) }

// StyleSheet is the stylesheet the fleet tree's class names (rgs-*) are
// defined in: the design-system CSS plus the status page's own rules. It is
// the same text fleet.html inlines, so a page that embeds PageData's tree
// looks identical to the standalone page.
func StyleSheet() string { return statusCSS }
