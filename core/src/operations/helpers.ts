/**
 * Helper utilities for Privacy SDK (Browser)
 *
 * Common utility functions for ZK proofs and Solana interactions.
 */

import BN from 'bn.js';
import * as borsh from 'borsh';
import { sha256 } from 'ethers';
import { PublicKey } from '@solana/web3.js';
import { DEFAULT_PROGRAM_ID, RELAYER_API_URL } from '../crypto/constants.js';
import { ConsoleLogger } from '../logger/console.js';

const logger = new ConsoleLogger({ prefix: '[Mink]', minLevel: 'info' });

/**
 * Convert a mint address to a field element for ZK circuits
 *
 * Uses first 31 bytes of the mint address as a big-endian number.
 * This provides good collision resistance while fitting in the BN254 field.
 *
 * NOTE: We use the same logic for ALL mints (including SOL) to maintain
 * consistency with existing deposits. Changing this would break nullifier
 * computation for already-deposited UTXOs.
 */
export function getMintAddressField(mint: PublicKey): string {
  // For all mints (including SOL): use first 31 bytes (248 bits)
  // This ensures consistency with existing deposits
  const mintBytes = mint.toBytes();
  return new BN(mintBytes.slice(0, 31), 'be').toString();
}

/**
 * External data hash calculation using Borsh serialization
 *
 * Used for ZK proof verification - the hash of all external (non-private) data
 */
export function getExtDataHash(extData: {
  recipient: string | PublicKey;
  extAmount: string | number | BN;
  encryptedOutput1?: string | Uint8Array;
  encryptedOutput2?: string | Uint8Array;
  fee: string | number | BN;
  feeRecipient: string | PublicKey;
  mintAddress: string | PublicKey;
}): Uint8Array {
  // Convert all inputs to their appropriate types
  const recipient =
    extData.recipient instanceof PublicKey
      ? extData.recipient
      : new PublicKey(extData.recipient);

  const feeRecipient =
    extData.feeRecipient instanceof PublicKey
      ? extData.feeRecipient
      : new PublicKey(extData.feeRecipient);

  const mintAddress =
    extData.mintAddress instanceof PublicKey
      ? extData.mintAddress
      : new PublicKey(extData.mintAddress);

  // Convert to BN for proper i64/u64 handling
  const extAmount = new BN(extData.extAmount.toString());
  const fee = new BN(extData.fee.toString());

  // Handle encrypted outputs
  const encryptedOutput1 = extData.encryptedOutput1
    ? new Uint8Array(extData.encryptedOutput1 as ArrayLike<number>)
    : new Uint8Array(0);
  const encryptedOutput2 = extData.encryptedOutput2
    ? new Uint8Array(extData.encryptedOutput2 as ArrayLike<number>)
    : new Uint8Array(0);

  // Define the borsh schema matching the Rust struct
  const schema = {
    struct: {
      recipient: { array: { type: 'u8', len: 32 } },
      extAmount: 'i64',
      encryptedOutput1: { array: { type: 'u8' } },
      encryptedOutput2: { array: { type: 'u8' } },
      fee: 'u64',
      feeRecipient: { array: { type: 'u8', len: 32 } },
      mintAddress: { array: { type: 'u8', len: 32 } },
    },
  };

  const value = {
    recipient: recipient.toBytes(),
    extAmount: extAmount,
    encryptedOutput1: encryptedOutput1,
    encryptedOutput2: encryptedOutput2,
    fee: fee,
    feeRecipient: feeRecipient.toBytes(),
    mintAddress: mintAddress.toBytes(),
  };

  // Serialize with Borsh
  const serializedData = borsh.serialize(schema, value);

  // Calculate SHA-256 hash
  const hashHex = sha256(serializedData);
  // Convert from hex string to Uint8Array
  return hexToBytes(hashHex.slice(2));
}

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Fetch Merkle proof from relayer API
 * Returns pathElements, pathIndices (bits), leafIndex (number), and the root that matches this proof
 *
 * @param commitment The commitment (hex-encoded) to get proof for
 * @param mint Optional token mint address (defaults to SOL mint)
 * @param relayerUrl Relayer API URL
 */
export async function fetchMerkleProof(
  commitment: string,
  mint?: string,
  relayerUrl: string = RELAYER_API_URL
): Promise<{ pathElements: string[]; pathIndices: number[]; leafIndex: number; root: string }> {
  let url = `${relayerUrl}/merkle/proof/${commitment}`;
  if (mint) {
    url += '?mint=' + encodeURIComponent(mint);
  }

  logger.debug(`Fetching Merkle proof from: ${url}`);

  const response = await fetch(url, {
    method: 'GET',
    cache: 'no-store',
    headers: {
      'Cache-Control': 'no-cache',
      'Pragma': 'no-cache',
    },
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch Merkle proof: ${response.status} ${response.statusText}`);
  }

  const rawData = await response.json();

  // Handle wrapped response format { success, data: { ... } }
  let pathElements: string[];
  let pathIndices: number[];
  let leafIndex: number;
  let root: string;

  if (typeof rawData === 'object' && 'success' in rawData && 'data' in rawData) {
    pathElements = rawData.data.pathElements;
    pathIndices = rawData.data.pathIndices;
    leafIndex = rawData.data.leafIndex;
    root = rawData.data.root;
  } else {
    pathElements = rawData.pathElements;
    pathIndices = rawData.pathIndices;
    leafIndex = rawData.leafIndex;
    root = rawData.root;
  }

  logger.debug(`Fetched Merkle proof with ${pathElements.length} elements, leafIndex=${leafIndex}, root=${root.slice(0, 20)}...`);
  return { pathElements, pathIndices, leafIndex, root };
}

/**
 * Query remote tree state from relayer API
 *
 * @param mint Optional token mint address (defaults to SOL mint)
 * @param relayerUrl Relayer API URL
 */
export async function queryRemoteTreeState(
  mint?: string,
  relayerUrl: string = RELAYER_API_URL
): Promise<{ root: string; nextIndex: number }> {
  let url = `${relayerUrl}/merkle/root`;
  if (mint) {
    url += '?mint=' + encodeURIComponent(mint);
  }

  logger.debug(`Fetching tree state from: ${url}`);

  const response = await fetch(url, {
    method: 'GET',
    cache: 'no-store',
    headers: {
      'Cache-Control': 'no-cache',
      'Pragma': 'no-cache',
    },
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch Merkle state: ${response.status} ${response.statusText}`);
  }

  const rawData = await response.json();

  // Handle wrapped response format { success, data: { root, nextIndex } }
  let root: string;
  let nextIndex: number;

  if (typeof rawData === 'object' && 'success' in rawData && 'data' in rawData) {
    root = rawData.data.root;
    nextIndex = rawData.data.nextIndex;
  } else {
    root = rawData.root;
    nextIndex = rawData.nextIndex;
  }

  logger.debug(`Fetched root: ${root}, nextIndex: ${nextIndex}`);
  return { root, nextIndex };
}

/**
 * Find nullifier PDAs for a proof
 */
export function findNullifierPDAs(
  inputNullifiers: Uint8Array[],
  programId: PublicKey = DEFAULT_PROGRAM_ID
): { nullifier0PDA: PublicKey; nullifier1PDA: PublicKey } {
  const [nullifier0PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from('nullifier0'), Buffer.from(inputNullifiers[0])],
    programId
  );

  const [nullifier1PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from('nullifier1'), Buffer.from(inputNullifiers[1])],
    programId
  );

  return { nullifier0PDA, nullifier1PDA };
}

/**
 * Find cross-check nullifier PDAs (for additional validation)
 */
export function findCrossCheckNullifierPDAs(
  inputNullifiers: Uint8Array[],
  programId: PublicKey = DEFAULT_PROGRAM_ID
): { nullifier2PDA: PublicKey; nullifier3PDA: PublicKey } {
  const [nullifier2PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from('nullifier0'), Buffer.from(inputNullifiers[1])],
    programId
  );

  const [nullifier3PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from('nullifier1'), Buffer.from(inputNullifiers[0])],
    programId
  );

  return { nullifier2PDA, nullifier3PDA };
}

/**
 * Get program PDAs for SOL vault (tree, token, config accounts)
 */
export function getProgramAccounts(programId: PublicKey = DEFAULT_PROGRAM_ID): {
  treeAccount: PublicKey;
  treeTokenAccount: PublicKey;
  globalConfigAccount: PublicKey;
} {
  const [treeAccount] = PublicKey.findProgramAddressSync(
    [Buffer.from('merkle_tree')],
    programId
  );

  const [treeTokenAccount] = PublicKey.findProgramAddressSync(
    [Buffer.from('tree_token')],
    programId
  );

  const [globalConfigAccount] = PublicKey.findProgramAddressSync(
    [Buffer.from('global_config')],
    programId
  );

  return { treeAccount, treeTokenAccount, globalConfigAccount };
}

/**
 * Get program PDAs for SPL token vault
 */
export function getTokenVaultAccounts(
  mint: PublicKey,
  programId: PublicKey = DEFAULT_PROGRAM_ID
): {
  stealthVault: PublicKey;
  globalConfigAccount: PublicKey;
} {
  // SPL token vault: seeds = [b"merkle_tree", mint.key()]
  const [stealthVault] = PublicKey.findProgramAddressSync(
    [Buffer.from('merkle_tree'), mint.toBytes()],
    programId
  );

  const [globalConfigAccount] = PublicKey.findProgramAddressSync(
    [Buffer.from('global_config')],
    programId
  );

  return { stealthVault, globalConfigAccount };
}

/**
 * Get Associated Token Address (ATA)
 */
export function getAssociatedTokenAddress(
  mint: PublicKey,
  owner: PublicKey
): PublicKey {
  const TOKEN_PROGRAM_ID = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
  const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');

  const [ata] = PublicKey.findProgramAddressSync(
    [owner.toBytes(), TOKEN_PROGRAM_ID.toBytes(), mint.toBytes()],
    ASSOCIATED_TOKEN_PROGRAM_ID
  );

  return ata;
}

/**
 * Calculate deposit fee
 */
export function calculateDepositFee(amount: number, feeRate: number): number {
  return Math.floor((amount * feeRate) / 10000);
}

/**
 * Calculate withdrawal fee
 */
export function calculateWithdrawalFee(amount: number, feeRate: number): number {
  return Math.floor((amount * feeRate) / 10000);
}

/**
 * Sleep for a specified duration
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Validate if a Merkle root exists in on-chain history
 *
 * CRITICAL: This should be called before generating ZK proofs to ensure
 * the root will be accepted by the on-chain program. Prevents UnknownRoot errors.
 *
 * @param root The Merkle root (decimal string) to validate
 * @param mint Optional token mint address (defaults to SOL mint)
 * @param relayerUrl Optional relayer URL
 * @returns Object with validation result and optional error message
 */
export async function validateMerkleRoot(
  root: string,
  mint?: string,
  relayerUrl: string = RELAYER_API_URL
): Promise<{ valid: boolean; message?: string }> {
  let url = `${relayerUrl}/merkle/validate-root/${encodeURIComponent(root)}`;
  if (mint) {
    url += '?mint=' + encodeURIComponent(mint);
  }

  logger.debug(`Validating Merkle root from: ${url}`);

  try {
    const response = await fetch(url, {
      method: 'GET',
      cache: 'no-store',
      headers: {
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
      },
    });
    if (!response.ok) {
      logger.warn(`Root validation request failed: ${response.status}`);
      return { valid: false, message: `Validation request failed: ${response.status}` };
    }

    const rawData = await response.json();

    // Handle wrapped response format { success, data: { valid, message } }
    if (typeof rawData === 'object' && 'success' in rawData && 'data' in rawData) {
      return rawData.data as { valid: boolean; message?: string };
    }

    return rawData as { valid: boolean; message?: string };
  } catch (err) {
    logger.warn(`Root validation error: ${err}`);
    return { valid: false, message: `Validation error: ${err}` };
  }
}
