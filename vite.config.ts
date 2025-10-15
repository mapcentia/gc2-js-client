import { defineConfig } from "vite";
import path from "node:path";

// Vite lib-mode config to mirror previous Webpack dev build
// Emits ./build/gc2-js-client.js exposing global `gc2`
export default defineConfig(({ mode }) => ({
  build: {
    outDir: "build",
    emptyOutDir: false,
    sourcemap: mode === "development" ? "inline" : false,
    lib: {
      entry: path.resolve(__dirname, "src/index.ts"),
      name: "gc2",
      formats: ["umd"],
      fileName: () => "gc2-js-client.js",
    },
    rollupOptions: {
      // No externals since previous Webpack build bundled everything for examples
      output: {
        globals: {
          // add externals here if needed later
        },
      },
    },
  },
}));
