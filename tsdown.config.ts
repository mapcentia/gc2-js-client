import { defineConfig } from 'tsdown'

export default defineConfig([
    {
        entry: {
            'centia-io-sdk': './src/index.ts'
        },
        dts: {
            sourcemap: true,
        },
        target: "es2017",
        platform: "browser",
        external: ['configstore', 'proper-lockfile', 'node:fs', 'node:os', 'node:path'],
        exports: false,
        format: ["esm", "cjs", "umd"],
        globalName: "CentiaSDK"
    },
    {
        entry: {
            'centia-io-sdk-node': './src/node.ts'
        },
        dts: {
            sourcemap: true,
        },
        target: "es2017",
        platform: "browser",
        external: ['configstore', 'proper-lockfile', 'node:fs', 'node:os', 'node:path'],
        exports: false,
        format: ["esm", "cjs"],
    }
])
