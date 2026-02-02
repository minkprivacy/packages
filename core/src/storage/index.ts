/**
 * Mink SDK Storage
 * @module storage
 */

export type { IStorage } from './interface.js';
export { MemoryStorage } from './memory.js';
export { BrowserStorage, SessionStorage } from './browser.js';
