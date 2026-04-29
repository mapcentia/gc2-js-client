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

    it('persists a patch and merges with existing data', async () => {
        const store = createConfigstoreTokenStore('gc2-test-3')
        await store.set({ token: 'a', refresh_token: 'b' })
        await store.set({ token: 'c', host: 'h' })

        await expect(store.get()).resolves.toEqual({
            token: 'c',
            refresh_token: 'b',
            host: 'h',
        })
    })

    it('writes valid JSON to the configstore file', async () => {
        const store = createConfigstoreTokenStore('gc2-test-4')
        await store.set({ token: 'tok', refresh_token: 'ref' })

        const { readFileSync } = await import('node:fs')
        const raw = readFileSync(configstorePath('gc2-test-4'), 'utf8')
        const parsed = JSON.parse(raw)
        expect(parsed.token).toBe('tok')
        expect(parsed.refresh_token).toBe('ref')
    })

    it('serializes concurrent in-process set() calls', async () => {
        const store = createConfigstoreTokenStore('gc2-test-5')
        await Promise.all([
            store.set({ token: 'one' }),
            store.set({ refresh_token: 'two' }),
            store.set({ host: 'three' }),
        ])

        await expect(store.get()).resolves.toEqual({
            token: 'one',
            refresh_token: 'two',
            host: 'three',
        })
    })
})
