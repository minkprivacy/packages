/**
 * Storage Interface
 * @module storage/interface
 */

/**
 * Storage adapter interface
 */
export interface IStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}
