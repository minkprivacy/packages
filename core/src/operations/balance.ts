/**
 * UTXO Fetching for Privacy SDK (Browser)
 *
 * Fetches and decrypts UTXOs from the relayer API.
 */

import { Connection, PublicKey } from '@solana/web3.js';
import BN from 'bn.js';
import type { LightWasm } from '@lightprotocol/hasher.rs';
// @ts-ignore - ffjavascript doesn't have proper types
import { utils as ffUtils } from 'ffjavascript';
import { Keypair } from '../crypto/keypair.js';
import { Utxo } from '../models/utxo.js';
import { EncryptionService } from '../crypto/encryption.js';
import type { IStorage } from '../storage/interface.js';
import {
  DEFAULT_PROGRAM_ID,
  FETCH_UTXOS_GROUP_SIZE,
  RELAYER_API_URL,
  LSK_ENCRYPTED_OUTPUTS,
  LSK_FETCH_OFFSET,
  SOL_MINT_ADDRESS,
} from '../crypto/constants.js';
import { ConsoleLogger } from '../logger/console.js';
import { sleep } from './helpers.js';

const { unstringifyBigInts, leInt2Buff } = ffUtils;

// Create a local logger instance
const logger = new ConsoleLogger({ prefix: '[Mink]', minLevel: 'info' });

/**
 * API response format (legacy direct format)
 */
interface ApiResponse {
  count: number;
  encrypted_outputs: string[];
  hasMore: boolean;
  total: number;
}

/**
 * Wrapped API response format (new relayer format)
 */
interface WrappedApiResponse {
  success: boolean;
  data: {
    encryptedOutputs: string[];
    hasMore: boolean;
    total: number;
  };
}

/**
 * Decryption result type
 */
type DecryptResult = {
  status: 'decrypted' | 'skipped' | 'unDecrypted';
  utxo?: Utxo;
  encryptedOutput?: string;
};

/**
 * Check if encrypted output is V3 format (ECDH-based)
 */
function isV3EncryptedOutput(hex: string): boolean {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  return cleanHex.length >= 2 && cleanHex.substring(0, 2) === '03';
}

/**
 * Generate localStorage key for a wallet
 */
export function localStorageKey(publicKey: PublicKey, programId: PublicKey = DEFAULT_PROGRAM_ID): string {
  return programId.toString().substring(0, 6) + publicKey.toString();
}

/**
 * Parameters for getUtxos
 */
export interface GetUtxosParams {
  publicKey: PublicKey;
  connection: Connection;
  encryptionService: EncryptionService;
  storage: IStorage;
  lightWasm: LightWasm;
  programId?: PublicKey;
  relayerUrl?: string;
  abortSignal?: AbortSignal;
  offset?: number;
  onProgress?: (current: number, total: number) => void;
  /** Token mint address for filtering UTXOs (defaults to SOL mint) */
  mint?: string;
  /** Filter UTXOs created after this Unix timestamp (seconds) */
  fromTimestamp?: number;
}

/**
 * Fetch and decrypt all UTXOs for a user
 */
export async function getUtxos({
  publicKey,
  connection,
  encryptionService,
  storage,
  lightWasm,
  programId = DEFAULT_PROGRAM_ID,
  relayerUrl = RELAYER_API_URL,
  abortSignal,
  offset = 0,
  onProgress,
  mint = SOL_MINT_ADDRESS,
  fromTimestamp,
}: GetUtxosParams): Promise<Utxo[]> {
  const validUtxos: Utxo[] = [];
  const validStrings: string[] = [];
  const historyIndexes: number[] = [];

  // Include mint in storage key to separate cache per token
  const storageKeyPrefix = localStorageKey(publicKey, programId) + '_' + mint;

  // Get stored offset (or force reset to 0 for fresh fetch)
  const storedOffsetStr = storage.getItem(LSK_FETCH_OFFSET + storageKeyPrefix);
  let roundStartIndex = storedOffsetStr ? Number(storedOffsetStr) : 0;

  roundStartIndex = Math.max(offset, roundStartIndex);

  // Derive UTXO keypairs for both versions
  const utxoPrivateKeyV1 = encryptionService.getUtxoPrivateKey('v1');
  const utxoKeypairV1 = new Keypair(utxoPrivateKeyV1, lightWasm);
  const utxoPrivateKeyV2 = encryptionService.getUtxoPrivateKey('v2');
  const utxoKeypairV2 = new Keypair(utxoPrivateKeyV2, lightWasm);

  while (true) {
    if (abortSignal?.aborted) {
      throw new Error('Fetch UTXOs aborted');
    }

    let fetchOffset = storage.getItem(LSK_FETCH_OFFSET + storageKeyPrefix);
    let fetchUtxoOffset = fetchOffset ? Number(fetchOffset) : 0;

    fetchUtxoOffset = Math.max(offset, fetchUtxoOffset);

    const fetchUtxoEnd = fetchUtxoOffset + FETCH_UTXOS_GROUP_SIZE;
    // Build URL with optional from_timestamp parameter for backend filtering
    // Subtract 30 minutes (1800 seconds) as safety margin to ensure UTXOs aren't missed
    // due to timing issues when timestamp was recorded after the transaction
    let fetchUrl = `${relayerUrl}/utxos/range?start=${fetchUtxoOffset}&end=${fetchUtxoEnd}&mint=${encodeURIComponent(mint)}`;
    if (fromTimestamp !== undefined) {
      const safeTimestamp = Math.max(0, fromTimestamp - 1800); // 30 min safety margin
      fetchUrl += `&from_timestamp=${safeTimestamp}`;
    }

    const fetched = await fetchUserUtxos({
      url: fetchUrl,
      encryptionService,
      storage,
      lightWasm,
      utxoKeypairV1,
      utxoKeypairV2,
      relayerUrl,
      storageKeyPrefix,
      roundStartIndex,
      onProgress,
      mint,
    });

    // Collect non-zero UTXOs
    const nonZeroUtxos: Utxo[] = [];
    const nonZeroEncrypted: string[] = [];

    for (let k = 0; k < fetched.utxos.length; k++) {
      const utxo = fetched.utxos[k];
      historyIndexes.push(utxo.index);
      if (utxo.amount.toNumber() > 0) {
        nonZeroUtxos.push(utxo);
        nonZeroEncrypted.push(fetched.encryptedOutputs[k]);
      }
    }

    // Check which UTXOs are spent
    if (nonZeroUtxos.length > 0) {
      const spentFlags = await areUtxosSpent(connection, nonZeroUtxos, programId);
      for (let i = 0; i < nonZeroUtxos.length; i++) {
        if (!spentFlags[i]) {
          // Deduplicate by checking if already in validStrings
          if (!validStrings.includes(nonZeroEncrypted[i])) {
            logger.debug(`Found unspent encrypted_output ${nonZeroEncrypted[i]}`);
            validUtxos.push(nonZeroUtxos[i]);
            validStrings.push(nonZeroEncrypted[i]);
          }
        }
      }
    }

    storage.setItem(
      LSK_FETCH_OFFSET + storageKeyPrefix,
      (fetchUtxoOffset + fetched.len).toString()
    );

    if (!fetched.hasMore) {
      break;
    }

    await sleep(20);
  }

  // Store trade history (last 20 unique indexes)
  const historyKey = 'tradeHistory' + storageKeyPrefix;
  const existingHistory = storage.getItem(historyKey);
  let allIndexes = [...historyIndexes];
  if (existingHistory?.length) {
    allIndexes = [...allIndexes, ...existingHistory.split(',').map((n) => Number(n))];
  }
  const uniqueIndexes = Array.from(new Set(allIndexes));
  const top20 = uniqueIndexes.sort((a, b) => b - a).slice(0, 20);
  if (top20.length) {
    storage.setItem(historyKey, top20.join(','));
  }

  // Store valid encrypted outputs
  const uniqueValidStrings = [...new Set(validStrings)];
  logger.debug(`Storing ${uniqueValidStrings.length} valid encrypted outputs`);
  storage.setItem(LSK_ENCRYPTED_OUTPUTS + storageKeyPrefix, JSON.stringify(uniqueValidStrings));

  // Filter UTXOs by mint address
  const filteredUtxos = validUtxos.filter(utxo => {
    const utxoMint = utxo.mintAddress === 'native' ? SOL_MINT_ADDRESS : utxo.mintAddress;
    const requestedMint = mint === 'native' ? SOL_MINT_ADDRESS : mint;
    return utxoMint === requestedMint;
  });

  logger.info(`[UTXOS] Found ${filteredUtxos.length} UTXOs for mint ${mint.slice(0, 8)}...`);

  return filteredUtxos;
}

/**
 * Fetch UTXOs from a specific URL range
 */
async function fetchUserUtxos({
  url,
  encryptionService,
  storage,
  lightWasm,
  utxoKeypairV1,
  utxoKeypairV2,
  relayerUrl,
  storageKeyPrefix,
  roundStartIndex,
  onProgress,
  mint,
}: {
  url: string;
  encryptionService: EncryptionService;
  storage: IStorage;
  lightWasm: LightWasm;
  utxoKeypairV1: Keypair;
  utxoKeypairV2: Keypair;
  relayerUrl: string;
  storageKeyPrefix: string;
  roundStartIndex: number;
  onProgress?: (current: number, total: number) => void;
  mint: string;
}): Promise<{
  encryptedOutputs: string[];
  utxos: Utxo[];
  hasMore: boolean;
  len: number;
}> {
  logger.debug('Fetching UTXO data from', url);

  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`HTTP error! status: ${res.status}`);
  }

  const rawData = await res.json();
  logger.debug('Got UTXO data:', JSON.stringify(rawData).slice(0, 200));

  let encryptedOutputs: string[] = [];
  let apiHasMore: boolean = false;
  let apiTotal: number = 0;

  // Handle wrapped API response format: { success, data: { encryptedOutputs, hasMore, total } }
  if (typeof rawData === 'object' && 'success' in rawData && 'data' in rawData) {
    const wrapped = rawData as WrappedApiResponse;
    if (!wrapped.success) {
      throw new Error('API returned error response');
    }
    encryptedOutputs = wrapped.data.encryptedOutputs || [];
    apiHasMore = wrapped.data.hasMore ?? false;
    apiTotal = wrapped.data.total ?? encryptedOutputs.length;
  } else if (Array.isArray(rawData)) {
    // Handle array of UTXOs with encrypted_output field
    encryptedOutputs = (rawData as Array<{ encrypted_output?: string }>)
      .filter((utxo) => utxo.encrypted_output)
      .map((utxo) => utxo.encrypted_output!);
    apiHasMore = false;
    apiTotal = encryptedOutputs.length;
  } else if (typeof rawData === 'object' && 'encrypted_outputs' in rawData) {
    const data = rawData as ApiResponse;
    encryptedOutputs = data.encrypted_outputs;
    apiHasMore = data.hasMore ?? false;
    apiTotal = data.total ?? encryptedOutputs.length;
  } else {
    throw new Error('API returned unexpected data format');
  }

  // Decrypt outputs
  const myUtxos: Utxo[] = [];
  const myEncryptedOutputs: string[] = [];

  // Get cached outputs
  const cachedString = storage.getItem(LSK_ENCRYPTED_OUTPUTS + storageKeyPrefix);
  const cachedStringNum = cachedString ? JSON.parse(cachedString).length : 0;
  const totalToDecrypt = apiTotal + cachedStringNum - roundStartIndex;

  // Decrypt batch
  let decryptedCount = 0;
  const batchRes = await decryptOutputs(
    encryptedOutputs,
    encryptionService,
    utxoKeypairV1,
    utxoKeypairV2,
    lightWasm,
    mint
  );
  decryptedCount += encryptedOutputs.length;

  for (const dres of batchRes) {
    if (dres.status === 'decrypted' && dres.utxo) {
      myUtxos.push(dres.utxo);
      myEncryptedOutputs.push(dres.encryptedOutput!);
    }
  }

  if (onProgress) {
    onProgress(decryptedCount, totalToDecrypt);
  }

  // Process cached outputs when no more to fetch
  if (!apiHasMore && cachedString) {
    const cachedEncryptedOutputs = JSON.parse(cachedString) as string[];

    // Filter out cached outputs that we already have from the API
    const newCachedOutputs = cachedEncryptedOutputs.filter(
      (cached) => !myEncryptedOutputs.includes(cached)
    );

    if (newCachedOutputs.length > 0) {
      logger.debug(`Processing ${newCachedOutputs.length} new cached outputs (${cachedEncryptedOutputs.length - newCachedOutputs.length} already fetched from API)`);

      const cachedBatchRes = await decryptOutputs(
        newCachedOutputs,
        encryptionService,
        utxoKeypairV1,
        utxoKeypairV2,
        lightWasm,
        mint
      );
      decryptedCount += newCachedOutputs.length;

      for (const dres of cachedBatchRes) {
        if (dres.status === 'decrypted' && dres.utxo) {
          // Double-check deduplication before adding
          if (!myEncryptedOutputs.includes(dres.encryptedOutput!)) {
            myUtxos.push(dres.utxo);
            myEncryptedOutputs.push(dres.encryptedOutput!);
          }
        }
      }
    } else {
      logger.debug('All cached outputs already fetched from API, skipping');
    }

    if (onProgress) {
      onProgress(decryptedCount, totalToDecrypt);
    }
  }

  // Update UTXO indices from API
  if (myEncryptedOutputs.length > 0) {
    const indicesUrl = relayerUrl + '/utxos/indices';
    const indicesRes = await fetch(indicesUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ encryptedOutputs: myEncryptedOutputs }),
    });
    const rawIndicesData = await indicesRes.json();

    // Handle wrapped response format
    let indices: number[] | Record<string, number>;
    if (typeof rawIndicesData === 'object' && 'success' in rawIndicesData && 'data' in rawIndicesData) {
      indices = rawIndicesData.data.indices;
    } else {
      indices = rawIndicesData.indices;
    }

    // Handle both array and Record<string, number> format for indices
    const indicesArray: number[] = Array.isArray(indices)
      ? indices
      : myEncryptedOutputs.map((eo) => (indices as Record<string, number>)[eo] ?? -1);

    if (!indicesArray || indicesArray.length !== myEncryptedOutputs.length) {
      throw new Error('Failed fetching /utxos/indices');
    }

    for (let i = 0; i < myUtxos.length; i++) {
      const newIndex = indicesArray[i];
      if (myUtxos[i].index !== newIndex && typeof newIndex === 'number' && newIndex >= 0) {
        logger.debug(`Updated UTXO index from ${myUtxos[i].index} to ${newIndex}`);
        myUtxos[i].index = newIndex;
      }
    }
  }

  return {
    encryptedOutputs: myEncryptedOutputs,
    utxos: myUtxos,
    hasMore: apiHasMore,
    len: encryptedOutputs.length,
  };
}

/**
 * Decrypt encrypted outputs to UTXOs
 *
 * Supports V1, V2, and V3 (ECDH) encrypted outputs.
 * V3 outputs require encryptionService.hasEncPrivKey() to be true.
 */
async function decryptOutputs(
  encryptedOutputs: string[],
  encryptionService: EncryptionService,
  utxoKeypairV1: Keypair,
  utxoKeypairV2: Keypair,
  lightWasm: LightWasm,
  mint: string
): Promise<DecryptResult[]> {
  const results: DecryptResult[] = [];

  for (const encryptedOutput of encryptedOutputs) {
    if (!encryptedOutput) {
      results.push({ status: 'skipped' });
      continue;
    }

    try {
      // Check if V3 format and skip if we don't have enc private key
      if (isV3EncryptedOutput(encryptedOutput) && !encryptionService.hasEncPrivKey()) {
        logger.debug('Skipping V3 output - enc private key not set');
        results.push({ status: 'unDecrypted' });
        continue;
      }

      // Convert hex string to Uint8Array
      const encryptedBuffer = hexToBytes(encryptedOutput);
      const utxoData = await encryptionService.decryptUtxoData(encryptedBuffer, mint);

      // Use the correct keypair based on UTXO version
      // V3 uses the same keypair as V2 (derived from spending key)
      const utxoKeypair = utxoData.version === 'v1' ? utxoKeypairV1 : utxoKeypairV2;

      // Reconstruct UTXO
      const utxo = new Utxo({
        lightWasm,
        amount: utxoData.amount,
        blinding: utxoData.blinding,
        index: utxoData.index,
        mintAddress: utxoData.mintAddress,
        keypair: utxoKeypair,
        version: utxoData.version || 'v2',
      });

      logger.debug(`Decrypted ${utxoData.version} UTXO: index=${utxoData.index}, amount=${utxoData.amount}, mint=${utxoData.mintAddress?.slice(0, 8)}...`);

      results.push({ status: 'decrypted', utxo, encryptedOutput });
    } catch (err) {
      logger.debug(`Failed to decrypt output: ${err instanceof Error ? err.message : String(err)}`);
      results.push({ status: 'unDecrypted' });
    }
  }

  return results.filter((r) => r.status === 'decrypted');
}

/**
 * Check if a single UTXO is spent
 */
export async function isUtxoSpent(
  connection: Connection,
  utxo: Utxo,
  programId: PublicKey = DEFAULT_PROGRAM_ID
): Promise<boolean> {
  try {
    const nullifier = await utxo.getNullifier();
    logger.debug(`Checking if UTXO with nullifier ${nullifier} is spent`);

    // Convert nullifier to bytes
    const nullifierBytes = Array.from(
      leInt2Buff(unstringifyBigInts(nullifier), 32)
    ).reverse() as number[];

    // Check nullifier0 PDA
    const [nullifier0PDA] = PublicKey.findProgramAddressSync(
      [Buffer.from('nullifier0'), Buffer.from(nullifierBytes)],
      programId
    );

    const nullifier0Account = await connection.getAccountInfo(nullifier0PDA);
    if (nullifier0Account !== null) {
      logger.debug('UTXO is spent (nullifier0 account exists)');
      return true;
    }

    // Check nullifier1 PDA
    const [nullifier1PDA] = PublicKey.findProgramAddressSync(
      [Buffer.from('nullifier1'), Buffer.from(nullifierBytes)],
      programId
    );

    const nullifier1Account = await connection.getAccountInfo(nullifier1PDA);
    if (nullifier1Account !== null) {
      logger.debug('UTXO is spent (nullifier1 account exists)');
      return true;
    }

    return false;
  } catch (error) {
    logger.error('Error checking if UTXO is spent:', error);
    await sleep(3000);
    return isUtxoSpent(connection, utxo, programId);
  }
}

/**
 * Check if multiple UTXOs are spent (batched)
 */
async function areUtxosSpent(
  connection: Connection,
  utxos: Utxo[],
  programId: PublicKey = DEFAULT_PROGRAM_ID
): Promise<boolean[]> {
  try {
    const allPDAs: { utxoIndex: number; pda: PublicKey }[] = [];

    for (let i = 0; i < utxos.length; i++) {
      const utxo = utxos[i];
      const nullifier = await utxo.getNullifier();

      const nullifierBytes = Array.from(
        leInt2Buff(unstringifyBigInts(nullifier), 32)
      ).reverse() as number[];

      const [nullifier0PDA] = PublicKey.findProgramAddressSync(
        [Buffer.from('nullifier0'), Buffer.from(nullifierBytes)],
        programId
      );
      const [nullifier1PDA] = PublicKey.findProgramAddressSync(
        [Buffer.from('nullifier1'), Buffer.from(nullifierBytes)],
        programId
      );

      allPDAs.push({ utxoIndex: i, pda: nullifier0PDA });
      allPDAs.push({ utxoIndex: i, pda: nullifier1PDA });
    }

    const results = await connection.getMultipleAccountsInfo(allPDAs.map((x) => x.pda));

    const spentFlags = new Array(utxos.length).fill(false);
    for (let i = 0; i < allPDAs.length; i++) {
      if (results[i] !== null) {
        spentFlags[allPDAs[i].utxoIndex] = true;
      }
    }

    const spentCount = spentFlags.filter(Boolean).length;
    if (spentCount > 0) {
      logger.debug(`[SPENT-CHECK] ${spentCount}/${utxos.length} UTXOs are spent`);
    }

    return spentFlags;
  } catch (error) {
    logger.error('Error checking if UTXOs are spent:', error);
    await sleep(3000);
    return areUtxosSpent(connection, utxos, programId);
  }
}

/**
 * Calculate total balance from UTXOs
 */
export function getBalanceFromUtxos(utxos: Utxo[]): { lamports: number } {
  const totalBalance = utxos.reduce((sum, utxo) => sum.add(utxo.amount), new BN(0));
  return { lamports: totalBalance.toNumber() };
}

/**
 * Convert hex string to bytes
 */
function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
