/**
 * In-Memory Storage Implementation
 * @module storage/memory
 */

import type { IStorage } from './interface.js';

/**
 * In-memory storage (default, non-persistent)
 */
export class MemoryStorage implements IStorage {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }

  keys(): string[] {
    return Array.from(this.store.keys());
  }
}
