export interface StorageLike {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

class MemoryStorage implements StorageLike {
  private store = new Map<string, string>()

  getItem(key: string): string | null {
    return this.store.has(key) ? this.store.get(key)! : null
  }

  setItem(key: string, value: string): void {
    this.store.set(key, String(value))
  }

  removeItem(key: string): void {
    this.store.delete(key)
  }
}

let cached: StorageLike | null = null

export function getStorage(): StorageLike {
  if (cached) return cached
  try {
    const g: any = typeof globalThis !== 'undefined' ? (globalThis as any) : (window as any)
    if (g && g.localStorage && typeof g.localStorage.getItem === 'function') {
      cached = g.localStorage as StorageLike
      return cached
    }
  } catch (e) {
    // ignore and fall back to memory storage
  }
  const g: any = typeof globalThis !== 'undefined' ? (globalThis as any) : {}
  if (!g.__gc2_memory_storage) {
    g.__gc2_memory_storage = new MemoryStorage()
  }
  cached = g.__gc2_memory_storage as StorageLike
  return cached
}
