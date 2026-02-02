/**
 * Wallet Adapter Types
 * @module types/wallet
 */

import type { PublicKey, VersionedTransaction } from '@solana/web3.js';

/**
 * Transaction signer function type
 */
export type TransactionSigner = <T extends VersionedTransaction>(
  transaction: T
) => Promise<T>;

/**
 * Message signer function type
 */
export type MessageSigner = (message: Uint8Array) => Promise<Uint8Array>;

/**
 * Auth token getter function type
 */
export type AuthTokenGetter = () => Promise<string | null>;

/**
 * Minimal wallet adapter interface
 */
export interface WalletAdapter {
  /** Connected wallet public key */
  publicKey: PublicKey | null;
  /** Sign a message */
  signMessage?: MessageSigner;
  /** Sign a transaction */
  signTransaction?: TransactionSigner;
  /** Whether wallet is connected */
  connected: boolean;
}

/**
 * Token name type
 */
export type TokenName = 'SOL' | 'USDC' | 'USDT';

/**
 * Token information
 */
export interface TokenInfo {
  /** Token name */
  name: TokenName;
  /** Token mint address (mainnet) */
  mint: PublicKey;
  /** Token mint address (devnet) */
  mintDevnet?: PublicKey;
  /** Storage prefix for this token */
  prefix: string;
  /** Token decimals */
  decimals: number;
  /** Units per whole token */
  unitsPerToken: number;
}

/**
 * Encryption key with IV
 */
export interface EncryptionKey {
  /** AES encryption key */
  key: Uint8Array;
  /** Initialization vector (generated per encryption) */
  iv: Uint8Array;
}
