/**
 * Child-process helper for the concurrent lock test.
 *
 * Usage:
 *   tsx concurrentSetWriter.ts <storeName> <tokenValue>
 *
 * Reads XDG_CONFIG_HOME from the env (set by the test) and writes a single
 * patch via createConfigstoreTokenStore.
 */
import { createConfigstoreTokenStore } from '../../auth/configstoreTokenStore'

async function main(): Promise<void> {
    const [, , name, token] = process.argv
    if (!name || !token) {
        console.error('usage: concurrentSetWriter.ts <name> <token>')
        process.exit(2)
    }
    const store = createConfigstoreTokenStore(name)
    await store.set({ token, refresh_token: `refresh-for-${token}` })
}

main().catch((err) => {
    console.error(err)
    process.exit(1)
})
