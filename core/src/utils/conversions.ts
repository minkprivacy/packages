/**
 * Type Conversions and Utilities
 * @module utils/conversions
 */

import BN from 'bn.js';
import type { NumericInput } from '../types/operations.js';

/**
 * Convert various numeric types to BN
 */
export function toBN(value: NumericInput): BN {
  if (typeof value === 'bigint') {
    return new BN(value.toString());
  }
  if (typeof value === 'string') {
    return new BN(value);
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new Error(`Cannot convert non-integer number to BN: ${value}`);
    }
    return new BN(value);
  }
  throw new Error(`Cannot convert ${typeof value} to BN`);
}

/**
 * Convert various numeric types to bigint
 */
export function toBigInt(value: NumericInput): bigint {
  if (typeof value === 'bigint') {
    return value;
  }
  if (typeof value === 'string') {
    return BigInt(value);
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new Error(`Cannot convert non-integer number to bigint: ${value}`);
    }
    return BigInt(value);
  }
  throw new Error(`Cannot convert ${typeof value} to bigint`);
}

/**
 * Convert BN to bigint
 */
export function bnToBigInt(bn: BN): bigint {
  return BigInt(bn.toString());
}

/**
 * Convert bigint to BN
 */
export function bigIntToBN(value: bigint): BN {
  return new BN(value.toString());
}

/**
 * Convert Uint8Array to hex string
 */
export function toHex(buffer: Uint8Array): string {
  return Array.from(buffer)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to Uint8Array
 */
export function fromHex(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes to hex string (alias for toHex)
 */
export const bytesToHex = toHex;

/**
 * Convert hex to bytes (alias for fromHex)
 */
export const hexToBytes = fromHex;

/**
 * Convert lamports to SOL
 */
export function lamportsToSol(lamports: bigint | number): number {
  const value = typeof lamports === 'bigint' ? lamports : BigInt(lamports);
  return Number(value) / 1_000_000_000;
}

/**
 * Convert SOL to lamports
 */
export function solToLamports(sol: number): bigint {
  return BigInt(Math.floor(sol * 1_000_000_000));
}

/**
 * Format token amount with decimals
 */
export function formatTokenAmount(
  amount: bigint | number,
  decimals: number
): number {
  const value = typeof amount === 'bigint' ? amount : BigInt(amount);
  return Number(value) / Math.pow(10, decimals);
}

/**
 * Parse token amount to base units
 */
export function parseTokenAmount(
  amount: number,
  decimals: number
): bigint {
  return BigInt(Math.floor(amount * Math.pow(10, decimals)));
}

/**
 * Timing-safe comparison of two Uint8Arrays
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Check if two Uint8Arrays are equal
 */
export function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
