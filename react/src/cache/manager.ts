/**
 * Request Cache Manager
 * @module cache/manager
 *
 * Handles request deduplication and caching for React hooks.
 */

interface CacheEntry<T> {
  promise: Promise<T>;
  timestamp: number;
  data?: T;
  error?: Error;
}

/**
 * Request cache for deduplicating concurrent requests
 */
export class RequestCache {
  private cache: Map<string, CacheEntry<unknown>> = new Map();
  private readonly defaultTtl: number;

  /**
   * Create a new request cache
   *
   * @param ttl - Default TTL in milliseconds (default: 5000)
   */
  constructor(ttl: number = 5000) {
    this.defaultTtl = ttl;
  }

  /**
   * Fetch with deduplication
   *
   * If a request with the same key is already in flight, returns the
   * existing promise instead of making a new request.
   *
   * @param key - Cache key
   * @param fetcher - Function to fetch data
   * @param ttl - Optional TTL override
   * @returns Fetched data
   */
  async fetch<T>(
    key: string,
    fetcher: () => Promise<T>,
    ttl?: number
  ): Promise<T> {
    const now = Date.now();
    const cacheTtl = ttl ?? this.defaultTtl;

    // Check for valid cached entry
    const existing = this.cache.get(key) as CacheEntry<T> | undefined;
    if (existing) {
      // If we have cached data and it's still fresh, return it
      if (existing.data !== undefined && now - existing.timestamp < cacheTtl) {
        return existing.data;
      }

      // If request is in flight, return the existing promise
      if (existing.promise && !existing.data && !existing.error) {
        return existing.promise;
      }
    }

    // Create new request
    const promise = fetcher();
    const entry: CacheEntry<T> = {
      promise,
      timestamp: now,
    };

    this.cache.set(key, entry as CacheEntry<unknown>);

    try {
      const data = await promise;
      entry.data = data;
      entry.timestamp = Date.now();
      return data;
    } catch (error) {
      entry.error = error instanceof Error ? error : new Error(String(error));
      // Remove failed entries after a short delay
      setTimeout(() => {
        const current = this.cache.get(key);
        if (current === entry) {
          this.cache.delete(key);
        }
      }, 1000);
      throw error;
    }
  }

  /**
   * Get cached data without fetching
   *
   * @param key - Cache key
   * @returns Cached data or undefined
   */
  get<T>(key: string): T | undefined {
    const entry = this.cache.get(key) as CacheEntry<T> | undefined;
    return entry?.data;
  }

  /**
   * Check if a key is being fetched
   *
   * @param key - Cache key
   * @returns Whether the key is being fetched
   */
  isFetching(key: string): boolean {
    const entry = this.cache.get(key);
    return entry !== undefined && entry.data === undefined && entry.error === undefined;
  }

  /**
   * Invalidate a cache entry
   *
   * @param key - Cache key
   */
  invalidate(key: string): void {
    this.cache.delete(key);
  }

  /**
   * Invalidate entries matching a pattern
   *
   * @param pattern - RegExp pattern to match keys
   */
  invalidatePattern(pattern: RegExp): void {
    for (const key of this.cache.keys()) {
      if (pattern.test(key)) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Invalidate entries with a prefix
   *
   * @param prefix - Key prefix
   */
  invalidatePrefix(prefix: string): void {
    for (const key of this.cache.keys()) {
      if (key.startsWith(prefix)) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Clear all cache entries
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache size
   */
  get size(): number {
    return this.cache.size;
  }
}

/**
 * Global request cache instance
 */
export const requestCache = new RequestCache();
