import { defineConfig } from 'tsdown'

export default defineConfig({
    entry: {
        'centia-io-sdk': './src/index.ts'
    },
    dts: {
        sourcemap: true,
    },
    target: "es2017",
    platform: "browser",
    external: ['configstore', 'proper-lockfile', 'node:fs', 'node:os', 'node:path'],
    exports: {
        devExports: false,
    },
    format: ["esm", "cjs", "umd"],
    globalName: "CentiaSDK"
})
