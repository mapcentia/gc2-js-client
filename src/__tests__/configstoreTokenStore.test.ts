import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createConfigstoreTokenStore } from '../auth/configstoreTokenStore'

let xdgDir: string
let originalXdg: string | undefined

beforeEach(() => {
    xdgDir = mkdtempSync(join(tmpdir(), 'gc2-cs-'))
    originalXdg = process.env.XDG_CONFIG_HOME
    process.env.XDG_CONFIG_HOME = xdgDir
})

afterEach(() => {
    if (originalXdg === undefined) delete process.env.XDG_CONFIG_HOME
    else process.env.XDG_CONFIG_HOME = originalXdg
    rmSync(xdgDir, { recursive: true, force: true })
})

function configstorePath(name: string): string {
    return join(xdgDir, 'configstore', `${name}.json`)
}

describe('createConfigstoreTokenStore', () => {
    it('returns empty credentials when no file exists', async () => {
        const store = createConfigstoreTokenStore('gc2-test-1')
        await expect(store.get()).resolves.toEqual({})
    })

    it('reads existing credentials from the configstore file', async () => {
        mkdirSync(join(xdgDir, 'configstore'), { recursive: true })
        writeFileSync(
            configstorePath('gc2-test-2'),
            JSON.stringify({ token: 't', refresh_token: 'r', host: 'https://h.example' }),
        )

        const store = createConfigstoreTokenStore('gc2-test-2')
        await expect(store.get()).resolves.toEqual({
            token: 't',
            refresh_token: 'r',
            host: 'https://h.example',
        })
    })
})
