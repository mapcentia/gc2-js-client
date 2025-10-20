import { defineConfig } from 'tsdown'

export default defineConfig({
    entry: {
        'centia-io-sdk': './src/index.ts'
    },
    dts: {
        sourcemap: true,
    },
    platform: "browser",
    exports: {
        devExports: true,
    },
    format: ["esm", "cjs", "umd"],
    globalName: "CentiaSDK"
})
