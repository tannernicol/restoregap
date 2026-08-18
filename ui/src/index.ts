// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Tanner Nicol

import "./tokens.css";
import "./components.css";
// Recovery-graph styles ride in the shared stylesheet (a few KB); the graph
// RENDERER stays a separate dist entry so only graph-bearing pages pay for it.
import "./components/graph.css";

// restoregap page behaviors: theme persistence, table sort/filter, copy
// buttons. Everything is progressive enhancement over static HTML — evidence
// artifacts must remain fully readable with JS disabled or stripped.

const THEME_KEY = "rg-theme";

/** Apply the persisted theme. Inlined FIRST in <head> by the Go renderer
 * (before CSS) so pages never flash the wrong theme. Kept tiny on purpose. */
export const THEME_BOOT_SNIPPET =
  `(function(){try{var t=localStorage.getItem("${THEME_KEY}");` +
  `if(t)document.documentElement.setAttribute("data-theme",t)}catch(e){}})()`;

function initTheme(): void {
  document.querySelectorAll<HTMLElement>("[data-rg-theme-toggle]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const root = document.documentElement;
      // Dark is the unconditional default; only an explicit "light" isn't dark.
      const next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      root.setAttribute("data-theme", next);
      try {
        localStorage.setItem(THEME_KEY, next);
      } catch {
        /* private mode: theme just won't persist */
      }
    });
  });
}

function cellText(row: HTMLTableRowElement, idx: number): string {
  return row.cells[idx]?.textContent?.trim() ?? "";
}

function initTables(): void {
  document.querySelectorAll<HTMLTableElement>("table.rg-table").forEach((table) => {
    const body = table.tBodies[0];
    if (!body) return;

    table.querySelectorAll<HTMLTableCellElement>("thead th[data-sortable]").forEach((th) => {
      th.addEventListener("click", () => {
        const idx = th.cellIndex;
        const asc = th.getAttribute("aria-sort") !== "ascending";
        table
          .querySelectorAll("thead th")
          .forEach((o) => o.removeAttribute("aria-sort"));
        th.setAttribute("aria-sort", asc ? "ascending" : "descending");
        const rows = Array.from(body.rows);
        rows.sort((a, b) => {
          const av = cellText(a, idx);
          const bv = cellText(b, idx);
          const an = Number(av);
          const bn = Number(bv);
          const cmp =
            !Number.isNaN(an) && !Number.isNaN(bn) && av !== "" && bv !== ""
              ? an - bn
              : av.localeCompare(bv);
          return asc ? cmp : -cmp;
        });
        rows.forEach((r) => body.appendChild(r));
      });
    });

    const filterFor = table.closest("[data-rg-tableset]")?.querySelector<HTMLInputElement>("input.rg-filter");
    filterFor?.addEventListener("input", () => {
      const q = filterFor.value.toLowerCase();
      Array.from(body.rows).forEach((row) => {
        row.hidden = q !== "" && !row.textContent!.toLowerCase().includes(q);
      });
    });
  });
}

function initCopy(): void {
  document.querySelectorAll<HTMLElement>(".rg-code").forEach((block) => {
    if (block.querySelector(".rg-copy")) return;
    const btn = document.createElement("button");
    btn.className = "rg-copy";
    btn.type = "button";
    btn.textContent = "copy";
    btn.addEventListener("click", () => {
      const text = block.textContent?.replace(/copy$|copied$/, "").trimEnd() ?? "";
      void navigator.clipboard.writeText(text).then(() => {
        btn.textContent = "copied";
        setTimeout(() => (btn.textContent = "copy"), 1200);
      });
    });
    block.appendChild(btn);
  });
}

export function init(): void {
  initTheme();
  initTables();
  initCopy();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
