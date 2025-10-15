import { defineConfig } from 'tsdown'

export default defineConfig({
    dts: {
        sourcemap: true,
    },
    platform: "browser",
    exports: {
        devExports: true,
    },
})
