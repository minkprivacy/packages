/**
 * Cache Key Generation
 * @module cache/keys
 */

import type { TokenName } from '@minkprivacy/core';

/**
 * Cache key prefixes
 */
export const CACHE_PREFIXES = {
  BALANCE: 'balance',
  TOKEN_BALANCE: 'tokenBalance',
  INBOX: 'inbox',
  UTXOS: 'utxos',
} as const;

/**
 * Generate balance cache key
 *
 * @param walletAddress - Wallet address
 * @returns Cache key
 */
export function balanceKey(walletAddress: string): string {
  return `${CACHE_PREFIXES.BALANCE}:${walletAddress}`;
}

/**
 * Generate token balance cache key
 *
 * @param walletAddress - Wallet address
 * @param token - Token name
 * @returns Cache key
 */
export function tokenBalanceKey(walletAddress: string, token: TokenName): string {
  return `${CACHE_PREFIXES.TOKEN_BALANCE}:${walletAddress}:${token}`;
}

/**
 * Generate inbox cache key
 *
 * @param walletAddress - Wallet address
 * @returns Cache key
 */
export function inboxKey(walletAddress: string): string {
  return `${CACHE_PREFIXES.INBOX}:${walletAddress}`;
}

/**
 * Generate UTXOs cache key
 *
 * @param walletAddress - Wallet address
 * @param token - Token name
 * @returns Cache key
 */
export function utxosKey(walletAddress: string, token: TokenName): string {
  return `${CACHE_PREFIXES.UTXOS}:${walletAddress}:${token}`;
}
