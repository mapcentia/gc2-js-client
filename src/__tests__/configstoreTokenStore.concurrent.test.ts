import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const FIXTURE = resolve(fileURLToPath(import.meta.url), '..', 'fixtures', 'concurrentSetWriter.ts')

let xdgDir: string

beforeEach(() => {
    xdgDir = mkdtempSync(join(tmpdir(), 'gc2-cs-conc-'))
})

afterEach(() => {
    rmSync(xdgDir, { recursive: true, force: true })
})

function runWriter(name: string, token: string): Promise<number> {
    return new Promise((resolvePromise, rejectPromise) => {
        const child = spawn('pnpm', ['exec', 'tsx', FIXTURE, name, token], {
            env: { ...process.env, XDG_CONFIG_HOME: xdgDir },
            stdio: ['ignore', 'inherit', 'inherit'],
        })
        child.on('error', rejectPromise)
        child.on('exit', (code) => resolvePromise(code ?? 0))
    })
}

describe('createConfigstoreTokenStore (cross-process)', () => {
    it('keeps the file valid JSON under simultaneous writes from two processes', async () => {
        const name = 'gc2-conc-1'
        const [code1, code2] = await Promise.all([
            runWriter(name, 'A'),
            runWriter(name, 'B'),
        ])
        expect(code1).toBe(0)
        expect(code2).toBe(0)

        const filePath = join(xdgDir, 'configstore', `${name}.json`)
        const raw = readFileSync(filePath, 'utf8')

        // Must parse — i.e. no half-written / corrupt content.
        const parsed = JSON.parse(raw)
        expect(typeof parsed).toBe('object')
        expect(parsed).not.toBeNull()

        // Whichever process won, the file holds a coherent pair.
        expect(['A', 'B']).toContain(parsed.token)
        expect(parsed.refresh_token).toBe(`refresh-for-${parsed.token}`)
    }, 20_000)
})
