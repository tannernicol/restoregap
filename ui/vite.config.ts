import { defineConfig } from "vite";

// Builds exactly the artifacts internal/report inlines into self-contained
// HTML evidence pages (docs/ARCHITECTURE.md §UI):
//   dist/restoregap.css       — the whole design system
//   dist/restoregap.js        — theme boot, table sort/filter, copy buttons
//   dist/restoregap-graph.js  — interactive recovery graph (separate: only
//                               graph-bearing pages pay for it)
export default defineConfig({
  build: {
    outDir: "dist",
    emptyOutDir: true,
    cssCodeSplit: false,
    minify: true,
    rollupOptions: {
      input: {
        restoregap: "src/index.ts",
        "restoregap-graph": "src/components/graph.js",
      },
      output: {
        entryFileNames: "[name].js",
        assetFileNames: "restoregap.[ext]",
      },
    },
  },
});
