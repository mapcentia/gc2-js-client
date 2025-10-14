// tsup.config.ts

import { defineConfig } from "tsup";

export default defineConfig((options) => ({
    entry: [
        "src",
    ],
    dts: true,
    outDir: "dist",
    format: ["esm", "cjs"],
    name: "@mapcentia/gc2-js-client",
    splitting: false,
    sourcemap: true,
    clean: true,
    minify: false,
    // minify: !options.watch == Conditional config ==
}));
