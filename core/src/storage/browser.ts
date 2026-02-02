/**
 * Browser Storage Implementations
 * @module storage/browser
 */

import type { IStorage } from './interface.js';

/**
 * localStorage-based storage with prefix
 */
export class BrowserStorage implements IStorage {
  private prefix: string;

  constructor(prefix: string = 'mink_') {
    this.prefix = prefix;
  }

  private getFullKey(key: string): string {
    return this.prefix + key;
  }

  private isAvailable(): boolean {
    try {
      const test = '__storage_test__';
      localStorage.setItem(test, test);
      localStorage.removeItem(test);
      return true;
    } catch {
      return false;
    }
  }

  getItem(key: string): string | null {
    if (!this.isAvailable()) return null;
    return localStorage.getItem(this.getFullKey(key));
  }

  setItem(key: string, value: string): void {
    if (!this.isAvailable()) return;
    localStorage.setItem(this.getFullKey(key), value);
  }

  removeItem(key: string): void {
    if (!this.isAvailable()) return;
    localStorage.removeItem(this.getFullKey(key));
  }

  clear(): void {
    if (!this.isAvailable()) return;
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(this.prefix)) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach((key) => localStorage.removeItem(key));
  }

  keys(): string[] {
    if (!this.isAvailable()) return [];
    const result: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(this.prefix)) {
        result.push(key.slice(this.prefix.length));
      }
    }
    return result;
  }
}

/**
 * sessionStorage-based storage with prefix
 */
export class SessionStorage implements IStorage {
  private prefix: string;

  constructor(prefix: string = 'mink_') {
    this.prefix = prefix;
  }

  private getFullKey(key: string): string {
    return this.prefix + key;
  }

  private isAvailable(): boolean {
    try {
      const test = '__storage_test__';
      sessionStorage.setItem(test, test);
      sessionStorage.removeItem(test);
      return true;
    } catch {
      return false;
    }
  }

  getItem(key: string): string | null {
    if (!this.isAvailable()) return null;
    return sessionStorage.getItem(this.getFullKey(key));
  }

  setItem(key: string, value: string): void {
    if (!this.isAvailable()) return;
    sessionStorage.setItem(this.getFullKey(key), value);
  }

  removeItem(key: string): void {
    if (!this.isAvailable()) return;
    sessionStorage.removeItem(this.getFullKey(key));
  }

  clear(): void {
    if (!this.isAvailable()) return;
    const keysToRemove: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith(this.prefix)) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach((key) => sessionStorage.removeItem(key));
  }

  keys(): string[] {
    if (!this.isAvailable()) return [];
    const result: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith(this.prefix)) {
        result.push(key.slice(this.prefix.length));
      }
    }
    return result;
  }
}
