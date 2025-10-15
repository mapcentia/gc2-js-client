// tsdown.config.ts

import { defineConfig } from "tsdown";

export default defineConfig((options) => ({
    entry: [
        "src/index.ts",
    ],
    dts: true,
    outDir: "dist",
    format: ["esm", "cjs"],
    name: "@mapcentia/gc2-js-client",
    splitting: true,
    sourcemap: true,
    clean: true,
    minify: false,
    // minify: !options.watch == Conditional config ==
}));
