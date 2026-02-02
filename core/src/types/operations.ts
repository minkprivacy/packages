/**
 * Operation Types
 * @module types/operations
 */

import type { PublicKey } from '@solana/web3.js';
import type { TokenName } from './wallet.js';

/**
 * Numeric input type - accepts bigint, string, or number
 */
export type NumericInput = bigint | string | number;

/**
 * Deposit parameters
 */
export interface DepositParams {
  /** Amount in lamports */
  amount: NumericInput;
  /** Optional referrer address */
  referrer?: string;
}

/**
 * Deposit token parameters
 */
export interface DepositTokenParams {
  /** Token name: 'USDC' or 'USDT' */
  token: TokenName;
  /** Amount in base units (e.g., 1 USDC = 1_000_000) */
  amount: NumericInput;
  /** Optional referrer address */
  referrer?: string;
}

/**
 * Deposit result
 */
export interface DepositResult {
  /** Transaction signature */
  signature: string;
  /** Amount deposited in base units */
  amount: bigint;
  /** Commitment hash */
  commitment: string;
}

/**
 * Withdraw parameters
 */
export interface WithdrawParams {
  /** Amount in lamports */
  amount: NumericInput;
  /** Recipient address (defaults to connected wallet) */
  recipientAddress?: string;
  /** Optional referrer address */
  referrer?: string;
}

/**
 * Withdraw result
 */
export interface WithdrawResult {
  /** Transaction signature */
  signature: string;
  /** Amount withdrawn in base units */
  amount: bigint;
  /** Fee paid to relayer */
  fee: bigint;
  /** Recipient address */
  recipient: string;
  /** Whether withdrawal was partial (insufficient balance) */
  isPartial: boolean;
}

/**
 * Balance result for SOL
 */
export interface BalanceResult {
  /** Balance in lamports */
  lamports: bigint;
  /** Balance in SOL */
  sol: number;
}

/**
 * Token balance result
 */
export interface TokenBalanceResult {
  /** Balance in base units */
  amount: bigint;
  /** Balance formatted (divided by decimals) */
  formatted: number;
  /** Token name */
  token: TokenName;
}

/**
 * All balances result
 */
export interface AllBalancesResult {
  SOL: BalanceResult;
  USDC: TokenBalanceResult;
  USDT: TokenBalanceResult;
}

/**
 * Fee estimate
 */
export interface FeeEstimate {
  /** Fee in lamports */
  feeLamports: bigint;
  /** Fee in SOL */
  feeSol: number;
  /** Net amount after fee in lamports */
  netAmountLamports: bigint;
  /** Net amount after fee in SOL */
  netAmountSol: number;
}

/**
 * UTXO data from decryption
 */
export interface UTXOData {
  /** Amount in base units */
  amount: bigint;
  /** Blinding factor */
  blinding: bigint;
  /** Tree index */
  index: number;
  /** Token mint address */
  mintAddress: string;
  /** Encryption version */
  version: 'v1' | 'v2' | 'v3';
}

/**
 * Inbox status
 */
export enum InboxStatus {
  Active = 0,
  Paused = 1,
}

/**
 * Private Inbox
 */
export interface PrivateInbox {
  /** PDA address of the inbox */
  address: PublicKey;
  /** Owner's ZK public key */
  zkPubkey: bigint;
  /** Owner's X25519 encryption public key */
  encPubkey?: Uint8Array;
  /** Token mint */
  mint: PublicKey;
  /** Inbox nonce */
  nonce: number;
  /** Whether auto-forward is enabled */
  autoForward: boolean;
  /** Forward fee in basis points */
  forwardFeeBps: number;
  /** Pending balance */
  pendingBalance: bigint;
  /** Total amount forwarded */
  totalForwarded: bigint;
  /** Status */
  status: InboxStatus;
}

/**
 * Create inbox parameters
 */
export interface CreateInboxParams {
  /** Token mint (defaults to SOL) */
  mint?: PublicKey;
  /** Enable auto-forward (defaults to true) */
  autoForward?: boolean;
  /** Forward fee in basis points */
  forwardFeeBps?: number;
}

/**
 * Create inbox result
 */
export interface CreateInboxResult {
  /** Created inbox */
  inbox: PrivateInbox;
  /** Transaction signature */
  signature: string;
}

/**
 * Viewing key scope
 */
export enum ViewingScope {
  /** Private Inbox only */
  Proxy = 0,
  /** Privacy Pool only */
  Pool = 1,
  /** Full access */
  Full = 2,
}

/**
 * Serialized viewing key for sharing
 */
export interface SerializedViewingKey {
  /** Base58-encoded viewing key */
  base58: string;
  /** URL format for sharing */
  url: string;
  /** QR code data */
  qr: string;
  /** Scope of access */
  scope: ViewingScope;
}

/**
 * ZK Proof result
 */
export interface ProofResult {
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    protocol: string;
    curve: string;
  };
  publicSignals: string[];
}
