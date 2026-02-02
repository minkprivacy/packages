/**
 * Withdraw functionality for Privacy SDK (Browser)
 *
 * Handles SOL withdrawals from the privacy pool.
 */

import { Connection, PublicKey, LAMPORTS_PER_SOL } from '@solana/web3.js';
import BN from 'bn.js';
import type { LightWasm } from '@lightprotocol/hasher.rs';
import { Keypair } from '../crypto/keypair.js';
import { Utxo } from '../models/utxo.js';
import { getUtxos } from './balance.js';
import { EncryptionService, serializeProofAndExtData } from '../crypto/encryption.js';
import { prove, parseProofToBytesArray, parseToBytesArray } from '../proofs/prover.js';
import type { IStorage } from '../storage/interface.js';
import {
  DEFAULT_PROGRAM_ID,
  DEFAULT_ALT_ADDRESS,
  FIELD_SIZE,
  MERKLE_TREE_DEPTH,
  RELAYER_API_URL,
} from '../crypto/constants.js';
import {
  getExtDataHash,
  fetchMerkleProof,
  findNullifierPDAs,
  findCrossCheckNullifierPDAs,
  getProgramAccounts,
  getTokenVaultAccounts,
  getAssociatedTokenAddress,
  queryRemoteTreeState,
  validateMerkleRoot,
  getMintAddressField,
} from './helpers.js';
import { ConsoleLogger } from '../logger/console.js';
import type { WithdrawResult, AuthTokenGetter } from '../types/index.js';

const logger = new ConsoleLogger({ prefix: '[Mink]', minLevel: 'info' });

/**
 * Default fee configuration (fallback if relayer config unavailable)
 * Fee rate is in basis points (50 = 0.5%)
 * Rent fee is in lamports - covers relayer operational costs:
 *   - 2 nullifier PDAs x ~953,520 = ~1,907,040 lamports
 *   - Transaction fee: ~25,000 lamports
 *   - Buffer: ~67,960 lamports
 *   - Total: 2,000,000 lamports (0.002 SOL)
 */
const DEFAULT_WITHDRAW_FEE_RATE_BPS = 50; // 0.5% in basis points
const DEFAULT_WITHDRAW_RENT_FEE = 2_000_000; // 0.002 SOL in lamports (covers nullifier rents + tx fee)

/**
 * Relayer config cache
 */
let cachedConfig: { withdraw_fee_rate_bps: number; withdraw_rent_fee: number; fee_recipient: string } | null = null;

/**
 * Clear the relayer config cache
 * Call this if you need to refresh config from the relayer
 */
export function clearRelayerConfigCache(): void {
  cachedConfig = null;
  logger.debug('Relayer config cache cleared');
}

/**
 * Withdraw parameters
 */
export interface WithdrawParams {
  publicKey: PublicKey;
  connection: Connection;
  amountLamports: number;
  recipient: PublicKey;
  storage: IStorage;
  encryptionService: EncryptionService;
  zkAssetsPath: string;
  lightWasm: LightWasm;
  programId?: PublicKey;
  altAddress?: PublicKey;
  relayerUrl?: string;
  feeLamports?: number;
  onStatusChange?: (status: string) => void;
  getAuthToken?: AuthTokenGetter;
}

/**
 * Fetch relayer config
 * Fee rate is returned in basis points to match on-chain calculation
 * Rent fee is returned in lamports
 */
async function getRelayerConfig(relayerUrl: string): Promise<{ withdraw_fee_rate_bps: number; withdraw_rent_fee: number; fee_recipient: string }> {
  if (cachedConfig) {
    return cachedConfig;
  }

  try {
    const response = await fetch(`${relayerUrl}/config`);
    if (response.ok) {
      const responseJson = await response.json() as { success?: boolean; data?: Record<string, unknown> } & Record<string, unknown>;

      // Handle both envelope format {success, data} and direct format
      const config = responseJson.data ?? responseJson;

      const feeRecipient = typeof config.fee_recipient === 'string' ? config.fee_recipient : '';
      if (!feeRecipient) {
        throw new Error('fee_recipient not configured in relayer');
      }

      // Relayer returns fee rate - convert to basis points if needed
      // If relayer returns decimal (e.g., 0.005 for 0.5%), convert to bps (50)
      // If relayer returns bps directly (e.g., 50), use as-is
      let feeRateBps: number;
      const rawRate = typeof config.withdraw_fee_rate === 'number' ? config.withdraw_fee_rate : DEFAULT_WITHDRAW_FEE_RATE_BPS;

      if (rawRate < 1) {
        // Decimal format (e.g., 0.005 = 0.5%) - convert to basis points
        feeRateBps = Math.round(rawRate * 10000);
      } else {
        // Already in basis points
        feeRateBps = rawRate;
      }

      // Rent fee in lamports (default to 1M lamports = 0.001 SOL)
      const rentFee = typeof config.withdraw_rent_fee === 'number' ? config.withdraw_rent_fee : DEFAULT_WITHDRAW_RENT_FEE;

      cachedConfig = {
        withdraw_fee_rate_bps: feeRateBps,
        withdraw_rent_fee: rentFee,
        fee_recipient: feeRecipient,
      };
      logger.debug(`Relayer config: fee_rate=${cachedConfig.withdraw_fee_rate_bps} bps, rent_fee=${cachedConfig.withdraw_rent_fee} lamports, fee_recipient=${cachedConfig.fee_recipient}`);
      return cachedConfig;
    }
  } catch (err) {
    logger.debug(`Failed to fetch relayer config: ${err}`);
    throw new Error(`Failed to fetch relayer config: ${err}`);
  }

  throw new Error('Failed to fetch relayer config');
}

/**
 * Calculate fee based on relayer config
 * fee = (amount * withdraw_fee_rate_bps / 10000) + withdraw_rent_fee
 * This matches the on-chain calculation in SkitConfig::calculate_withdrawal_fee
 */
async function calculateFee(amountLamports: number, relayerUrl: string): Promise<number> {
  const config = await getRelayerConfig(relayerUrl);
  // Match on-chain: fee = (amount * rate / 10000) + rent_fee
  const percentageFee = Math.floor(amountLamports * config.withdraw_fee_rate_bps / 10000);
  const fee = percentageFee + config.withdraw_rent_fee;
  logger.debug(`Calculated fee: ${fee} lamports (${fee / LAMPORTS_PER_SOL} SOL) = ${percentageFee} (${config.withdraw_fee_rate_bps} bps) + ${config.withdraw_rent_fee} rent`);
  return fee;
}

/**
 * Submit withdraw request to indexer backend
 */
async function submitWithdrawToIndexer(
  params: Record<string, unknown>,
  relayerUrl: string,
  getAuthToken?: AuthTokenGetter
): Promise<{ jobId: string; status: string }> {
  // Build headers with optional auth
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (getAuthToken) {
    const token = await getAuthToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
  }

  const response = await fetch(`${relayerUrl}/withdraw`, {
    method: 'POST',
    headers,
    body: JSON.stringify(params),
  });

  if (!response.ok) {
    const errorData = (await response.json()) as { error?: { message?: string }; message?: string };
    throw new Error(errorData.error?.message || errorData.message || `Withdraw failed: ${response.status}`);
  }

  const result = (await response.json()) as {
    success: boolean;
    data: { jobId: string; status: string };
  };

  if (!result.success || !result.data) {
    throw new Error('Invalid response from relayer');
  }

  logger.debug(`Withdraw request submitted: jobId=${result.data.jobId}`);
  return result.data;
}

/**
 * Withdraw SOL from the privacy pool
 */
export async function withdraw({
  publicKey,
  connection,
  amountLamports,
  recipient,
  storage,
  encryptionService,
  zkAssetsPath,
  lightWasm,
  programId = DEFAULT_PROGRAM_ID,
  altAddress = DEFAULT_ALT_ADDRESS,
  relayerUrl = RELAYER_API_URL,
  feeLamports: providedFee,
  onStatusChange,
  getAuthToken,
}: WithdrawParams): Promise<WithdrawResult> {
  const updateStatus = (status: string) => {
    logger.info(status);
    onStatusChange?.(status);
  };

  // Fetch relayer config (includes fee_recipient)
  updateStatus('Fetching relayer config...');
  const relayerConfig = await getRelayerConfig(relayerUrl);
  const feeRecipient = new PublicKey(relayerConfig.fee_recipient);

  // Calculate fee from relayer config or use provided
  let feeLamports = providedFee ?? await calculateFee(amountLamports, relayerUrl);
  let withdrawAmountLamports = amountLamports - feeLamports;
  let isPartial = false;

  logger.debug(`Recipient: ${recipient.toString()}`);
  logger.debug(`Requested amount: ${amountLamports} lamports`);
  logger.debug(`Fee: ${feeLamports} lamports`);
  logger.debug(`Fee recipient: ${feeRecipient.toString()}`);

  const { treeAccount, treeTokenAccount, globalConfigAccount } = getProgramAccounts(programId);

  // Get current tree state
  updateStatus('Fetching tree state...');
  const { root, nextIndex: currentNextIndex } = await queryRemoteTreeState(undefined, relayerUrl);

  logger.debug(`Using tree root: ${root}`);

  // Get UTXO keypairs (V1 for reading old UTXOs, V2 for creating new ones)
  const utxoPrivateKeyV1 = encryptionService.getUtxoPrivateKey('v1');
  const utxoKeypairV1 = new Keypair(utxoPrivateKeyV1, lightWasm);

  const utxoPrivateKeyV2 = encryptionService.getUtxoPrivateKey('v2');
  const utxoKeypairV2 = new Keypair(utxoPrivateKeyV2, lightWasm);

  // Fetch existing UTXOs
  updateStatus('Fetching existing UTXOs...');
  const unspentUtxos = await getUtxos({
    connection,
    publicKey,
    encryptionService,
    storage,
    lightWasm,
    programId,
    relayerUrl,
  });

  logger.debug(`Found ${unspentUtxos.length} total UTXOs`);

  // Calculate total balance
  const totalUnspentBalance = unspentUtxos.reduce((sum, utxo) => sum.add(utxo.amount), new BN(0));
  logger.debug(`Total unspent balance: ${totalUnspentBalance.toString()} lamports`);

  if (unspentUtxos.length < 1) {
    throw new Error('Need at least 1 unspent UTXO to perform a withdrawal');
  }

  // Sort by amount descending to use largest UTXOs first
  unspentUtxos.sort((a, b) => b.amount.cmp(a.amount));

  // Use largest UTXOs as inputs
  const firstInput = unspentUtxos[0];
  const secondInput =
    unspentUtxos.length > 1
      ? unspentUtxos[1]
      : new Utxo({ lightWasm, keypair: utxoKeypairV1, amount: '0' });

  const inputs = [firstInput, secondInput];
  const totalInputAmount = firstInput.amount.add(secondInput.amount);

  logger.debug(`First input amount: ${firstInput.amount.toString()}`);
  logger.debug(`Second input amount: ${secondInput.amount.toString()}`);

  if (totalInputAmount.toNumber() === 0) {
    throw new Error('No balance available for withdrawal');
  }

  // Reject if requested amount exceeds available balance
  if (totalInputAmount.lt(new BN(amountLamports))) {
    throw new Error(
      `Insufficient balance: requested ${amountLamports / LAMPORTS_PER_SOL} SOL but only ${totalInputAmount.toNumber() / LAMPORTS_PER_SOL} SOL available in UTXOs`
    );
  }

  // Calculate change amount
  const changeAmount = totalInputAmount.sub(new BN(withdrawAmountLamports)).sub(new BN(feeLamports));

  if (changeAmount.lt(new BN(0))) {
    throw new Error(
      `Insufficient balance after fee: need ${(withdrawAmountLamports + feeLamports) / LAMPORTS_PER_SOL} SOL (amount + fee) but only ${totalInputAmount.toNumber() / LAMPORTS_PER_SOL} SOL available`
    );
  }

  logger.debug(`Withdrawing ${withdrawAmountLamports} lamports, fee ${feeLamports}, change ${changeAmount.toString()}`);

  // Get Merkle proofs for inputs
  updateStatus('Fetching Merkle proofs...');
  const inputMerkleProofs = await Promise.all(
    inputs.map(async (utxo) => {
      if (utxo.amount.eq(new BN(0))) {
        return {
          pathElements: [...new Array(MERKLE_TREE_DEPTH).fill('0')],
          pathIndices: Array(MERKLE_TREE_DEPTH).fill(0),
          leafIndex: 0,
          root: root, // Use the fetched root for dummy inputs
        };
      }
      const commitment = await utxo.getCommitment();
      return fetchMerkleProof(commitment, undefined, relayerUrl);
    })
  );

  // Use the root from the first non-zero input's proof
  // This ensures the root matches the pathElements
  const proofRoot = inputMerkleProofs.find(p => p.root !== root)?.root || root;

  logger.debug(`Tree state root: ${root}`);
  logger.debug(`Proof computed root: ${proofRoot}`);

  // If roots differ, use the proof root (it matches the pathElements)
  const circuitRoot = proofRoot;

  if (proofRoot !== root) {
    logger.warn(`Root mismatch! Using proof root for circuit. Tree state: ${root}, Proof: ${proofRoot}`);
  }

  // CRITICAL: Validate the circuit root exists in on-chain root history
  // This prevents UnknownRoot errors when DB state is out of sync with on-chain
  updateStatus('Validating Merkle root...');
  const rootValidation = await validateMerkleRoot(circuitRoot, undefined, relayerUrl);

  if (!rootValidation.valid) {
    logger.error(`Root validation failed: ${rootValidation.message}`);
    throw new Error(
      `UnknownRoot: The Merkle root ${circuitRoot.slice(0, 20)}... is not found in on-chain history. ` +
      `This usually means the relayer database is out of sync. Please try again in a few moments. ` +
      `(${rootValidation.message})`
    );
  }

  logger.debug(`Circuit root validated against on-chain history`);

  const inputMerklePathElements = inputMerkleProofs.map((proof) => proof.pathElements);
  // Use the leaf index from the proof response if available, otherwise use UTXO index
  const inputMerklePathIndices = inputMerkleProofs.map((proof, i) =>
    proof.leafIndex !== undefined ? proof.leafIndex : (inputs[i].index || 0)
  );

  // Create outputs (change and empty)
  const outputs = [
    new Utxo({
      lightWasm,
      amount: changeAmount.toString(),
      keypair: utxoKeypairV2,
      index: currentNextIndex,
    }),
    new Utxo({
      lightWasm,
      amount: '0',
      keypair: utxoKeypairV2,
      index: currentNextIndex + 1,
    }),
  ];

  // For withdrawals, extAmount is negative
  const extAmount = -withdrawAmountLamports;
  const publicAmountForCircuit = new BN(extAmount)
    .sub(new BN(feeLamports))
    .add(FIELD_SIZE)
    .mod(FIELD_SIZE);

  // Generate nullifiers and commitments
  const inputNullifiers = await Promise.all(inputs.map((x) => x.getNullifier()));
  const inputCommitments = await Promise.all(inputs.map((x) => x.getCommitment()));
  const outputCommitments = await Promise.all(outputs.map((x) => x.getCommitment()));

  // Encrypt UTXOs
  updateStatus('Encrypting UTXOs...');
  const encryptedOutput1 = await encryptionService.encryptUtxo({
    amount: outputs[0].amount.toString(),
    blinding: outputs[0].blinding.toString(),
    index: outputs[0].index,
  });
  const encryptedOutput2 = await encryptionService.encryptUtxo({
    amount: outputs[1].amount.toString(),
    blinding: outputs[1].blinding.toString(),
    index: outputs[1].index,
  });

  // Create extData
  const extData = {
    recipient,
    extAmount: new BN(extAmount),
    encryptedOutput1,
    encryptedOutput2,
    fee: new BN(feeLamports),
    feeRecipient: feeRecipient,
    mintAddress: inputs[0].mintAddress,
  };

  const calculatedExtDataHash = getExtDataHash(extData);

  // Log commitment details for debugging
  for (let i = 0; i < inputs.length; i++) {
    const commitment = await inputs[i].getCommitment();
    logger.debug(`Input[${i}] commitment: ${commitment}`);
    logger.debug(`Input[${i}] amount: ${inputs[i].amount.toString()}`);
    logger.debug(`Input[${i}] pubkey: ${inputs[i].keypair.pubkey}`);
    logger.debug(`Input[${i}] blinding: ${inputs[i].blinding.toString()}`);
    logger.debug(`Input[${i}] mintAddress: ${inputs[i].mintAddress}`);
    logger.debug(`Input[${i}] index: ${inputs[i].index}`);
    logger.debug(`Input[${i}] pathIndices: ${inputMerklePathIndices[i]}`);
    logger.debug(`Input[${i}] pathElements[0]: ${inputMerklePathElements[i][0]}`);
  }

  // Create circuit input
  // Use circuitRoot (from proof) to ensure it matches the pathElements
  const input = {
    root: circuitRoot,
    inputNullifier: inputNullifiers,
    outputCommitment: outputCommitments,
    publicAmount: publicAmountForCircuit.toString(),
    extDataHash: calculatedExtDataHash,
    inAmount: inputs.map((x) => x.amount.toString(10)),
    inPrivateKey: inputs.map((x) => x.keypair.privkey),
    inBlinding: inputs.map((x) => x.blinding.toString(10)),
    inPathIndices: inputMerklePathIndices,
    inPathElements: inputMerklePathElements,
    outAmount: outputs.map((x) => x.amount.toString(10)),
    outBlinding: outputs.map((x) => x.blinding.toString(10)),
    outPubkey: outputs.map((x) => x.keypair.pubkey),
    mintAddress: getMintAddressField(new PublicKey(inputs[0].mintAddress)),
  };

  logger.debug(`Circuit root: ${circuitRoot}`);
  logger.debug(`Circuit inPathIndices: ${JSON.stringify(inputMerklePathIndices)}`);

  // Generate ZK proof
  updateStatus('Generating ZK proof...');
  const wasmUrl = `${zkAssetsPath}/stealth.wasm`;
  const zkeyUrl = `${zkAssetsPath}/stealth.zkey`;
  const { proof, publicSignals } = await prove(input, wasmUrl, zkeyUrl);

  // Parse proof
  const proofInBytes = parseProofToBytesArray(proof);
  const inputsInBytes = parseToBytesArray(publicSignals);

  const proofToSubmit = {
    proofA: new Uint8Array(proofInBytes.proofA),
    proofB: new Uint8Array(proofInBytes.proofB.flat()),
    proofC: new Uint8Array(proofInBytes.proofC),
    root: new Uint8Array(inputsInBytes[0]),
    publicAmount: new Uint8Array(inputsInBytes[1]),
    extDataHash: new Uint8Array(inputsInBytes[2]),
    inputNullifiers: [new Uint8Array(inputsInBytes[3]), new Uint8Array(inputsInBytes[4])],
    outputCommitments: [new Uint8Array(inputsInBytes[5]), new Uint8Array(inputsInBytes[6])],
  };

  // Find PDAs
  const { nullifier0PDA, nullifier1PDA } = findNullifierPDAs(
    proofToSubmit.inputNullifiers,
    programId
  );
  const { nullifier2PDA, nullifier3PDA } = findCrossCheckNullifierPDAs(
    proofToSubmit.inputNullifiers,
    programId
  );

  // Serialize proof with 'withdraw' type to use REVEAL discriminator
  // mint must match what was used in getExtDataHash (inputs[0].mintAddress)
  const serializedProof = serializeProofAndExtData(proofToSubmit, {
    extAmount: extAmount,
    fee: feeLamports,
    encryptedOutput1,
    encryptedOutput2,
    recipient: recipient.toBytes(),
    relayer: feeRecipient.toBytes(),
    mint: new PublicKey(inputs[0].mintAddress).toBytes(),
  }, false, 'withdraw');

  // Prepare withdraw params for relayer
  const withdrawParams = {
    serializedProof: Buffer.from(serializedProof).toString('base64'),
    treeAccount: treeAccount.toString(),
    nullifier0PDA: nullifier0PDA.toString(),
    nullifier1PDA: nullifier1PDA.toString(),
    nullifier2PDA: nullifier2PDA.toString(),
    nullifier3PDA: nullifier3PDA.toString(),
    treeTokenAccount: treeTokenAccount.toString(),
    globalConfigAccount: globalConfigAccount.toString(),
    recipient: recipient.toString(),
    feeRecipientAccount: feeRecipient.toString(),
    extAmount: extAmount,
    encryptedOutput1: Buffer.from(encryptedOutput1).toString('base64'),
    encryptedOutput2: Buffer.from(encryptedOutput2).toString('base64'),
    fee: feeLamports,
    lookupTableAddress: altAddress.toString(),
    // PRIVACY: senderAddress removed - identity should not be tracked
    // Input commitments for linking nullifiers to UTXOs in relayer DB
    inputCommitments: inputCommitments.filter(c => c !== '0'), // Filter out zero-value dummy UTXOs
  };

  // Submit to relayer
  updateStatus('Submitting transaction to relayer...');
  const { jobId } = await submitWithdrawToIndexer(withdrawParams, relayerUrl, getAuthToken);

  // Poll for job completion
  updateStatus('Waiting for transaction...');
  let retryTimes = 0;
  const start = Date.now();
  let signature = '';

  while (true) {
    await new Promise((resolve) => setTimeout(resolve, 2000));

    // Check job status
    const statusRes = await fetch(`${relayerUrl}/transactions/${jobId}/status`);
    const statusJson = (await statusRes.json()) as {
      success: boolean;
      data: {
        jobId: string;
        status: 'queued' | 'processing' | 'completed' | 'failed';
        signature?: string;
        error?: { code: string; message: string };
      };
    };

    if (statusJson.success && statusJson.data) {
      const { status, signature: txSig, error } = statusJson.data;

      if (status === 'completed' && txSig) {
        signature = txSig;
        break;
      }

      if (status === 'failed') {
        throw new Error(error?.message || 'Transaction failed');
      }

      updateStatus(`Transaction ${status}...`);
    }

    if (retryTimes >= 30) {
      throw new Error('Transaction confirmation timeout. Check transaction status later.');
    }
    retryTimes++;
  }

  // Wait for UTXO to be indexed
  updateStatus('Waiting for confirmation...');
  const encryptedOutputStr = Buffer.from(encryptedOutput1).toString('hex');
  let utxoRetries = 0;

  while (utxoRetries < 10) {
    await new Promise((resolve) => setTimeout(resolve, 2000));

    const res = await fetch(`${relayerUrl}/utxos/check?hex=${encryptedOutputStr}`);
    const resJson = (await res.json()) as { success: boolean; data: { exists: boolean; treeIndex?: number } };

    if (resJson.success && resJson.data?.exists) {
      break;
    }
    utxoRetries++;
  }

  const duration = ((Date.now() - start) / 1000).toFixed(2);
  logger.debug(`Withdraw confirmed in ${duration} seconds`);
  updateStatus('Withdrawal confirmed!');

  return {
    signature,
    amount: BigInt(withdrawAmountLamports),
    fee: BigInt(feeLamports),
    recipient: recipient.toString(),
    isPartial,
  };
}

/**
 * Withdraw token parameters
 */
export interface WithdrawTokenParams extends WithdrawParams {
  /** SPL token mint address */
  mint: PublicKey;
}

/**
 * Calculate token fee (percentage only, no rent fee for tokens)
 */
async function calculateTokenFee(amountBaseUnits: number, relayerUrl: string): Promise<number> {
  const config = await getRelayerConfig(relayerUrl);
  const percentageFee = Math.floor(amountBaseUnits * config.withdraw_fee_rate_bps / 10000);
  logger.debug(`Calculated token fee: ${percentageFee} base units (${config.withdraw_fee_rate_bps} bps, no rent)`);
  return percentageFee;
}

/**
 * Withdraw SPL tokens from the privacy pool
 */
export async function withdrawToken({
  publicKey,
  connection,
  amountLamports,
  recipient,
  mint,
  storage,
  encryptionService,
  zkAssetsPath,
  lightWasm,
  programId = DEFAULT_PROGRAM_ID,
  altAddress = DEFAULT_ALT_ADDRESS,
  relayerUrl = RELAYER_API_URL,
  feeLamports: providedFee,
  onStatusChange,
  getAuthToken,
}: WithdrawTokenParams): Promise<WithdrawResult> {
  const updateStatus = (status: string) => {
    logger.info(status);
    onStatusChange?.(status);
  };

  // Fetch relayer config (includes fee_recipient)
  updateStatus('Fetching relayer config...');
  const relayerConfig = await getRelayerConfig(relayerUrl);
  const feeRecipient = new PublicKey(relayerConfig.fee_recipient);

  // Token fees: percentage only, no rent_fee
  let feeLamports = providedFee ?? await calculateTokenFee(amountLamports, relayerUrl);
  let withdrawAmount = amountLamports - feeLamports;
  let isPartial = false;

  logger.debug(`Recipient: ${recipient.toString()}`);
  logger.debug(`Mint: ${mint.toString()}`);
  logger.debug(`Requested amount: ${amountLamports} base units`);
  logger.debug(`Fee: ${feeLamports} base units`);
  logger.debug(`Fee recipient: ${feeRecipient.toString()}`);

  const { stealthVault, globalConfigAccount } = getTokenVaultAccounts(mint, programId);

  // Get current tree state for this token's tree
  const mintBase58 = mint.toBase58();
  updateStatus('Fetching tree state...');
  const { root, nextIndex: currentNextIndex } = await queryRemoteTreeState(mintBase58, relayerUrl);

  logger.debug(`Using tree root: ${root}`);

  // Get UTXO keypairs (V1 for reading old UTXOs, V2 for creating new ones)
  const utxoPrivateKeyV1 = encryptionService.getUtxoPrivateKey('v1');
  const utxoKeypairV1 = new Keypair(utxoPrivateKeyV1, lightWasm);

  const utxoPrivateKeyV2 = encryptionService.getUtxoPrivateKey('v2');
  const utxoKeypairV2 = new Keypair(utxoPrivateKeyV2, lightWasm);

  // Fetch existing UTXOs filtered by mint
  updateStatus('Fetching existing UTXOs...');
  const unspentUtxos = await getUtxos({
    connection,
    publicKey,
    encryptionService,
    storage,
    lightWasm,
    programId,
    relayerUrl,
    mint: mintBase58,
  });

  logger.debug(`Found ${unspentUtxos.length} total UTXOs for mint ${mint.toString()}`);

  // Calculate total balance
  const totalUnspentBalance = unspentUtxos.reduce((sum, utxo) => sum.add(utxo.amount), new BN(0));
  logger.debug(`Total unspent balance: ${totalUnspentBalance.toString()} base units`);

  if (unspentUtxos.length < 1) {
    throw new Error('Need at least 1 unspent UTXO to perform a token withdrawal');
  }

  // Sort by amount descending to use largest UTXOs first
  unspentUtxos.sort((a, b) => b.amount.cmp(a.amount));

  // Use largest UTXOs as inputs
  const firstInput = unspentUtxos[0];
  const secondInput =
    unspentUtxos.length > 1
      ? unspentUtxos[1]
      : new Utxo({ lightWasm, keypair: utxoKeypairV1, amount: '0', mintAddress: mintBase58 });

  const inputs = [firstInput, secondInput];
  const totalInputAmount = firstInput.amount.add(secondInput.amount);

  logger.debug(`First input amount: ${firstInput.amount.toString()}`);
  logger.debug(`Second input amount: ${secondInput.amount.toString()}`);

  if (totalInputAmount.toNumber() === 0) {
    throw new Error('No token balance available for withdrawal');
  }

  // Reject if requested amount exceeds available balance
  if (totalInputAmount.lt(new BN(amountLamports))) {
    throw new Error(
      `Insufficient token balance: requested ${amountLamports} but only ${totalInputAmount.toNumber()} available in UTXOs`
    );
  }

  // Calculate change amount
  const changeAmount = totalInputAmount.sub(new BN(withdrawAmount)).sub(new BN(feeLamports));

  if (changeAmount.lt(new BN(0))) {
    throw new Error(
      `Insufficient token balance after fee: need ${withdrawAmount + feeLamports} (amount + fee) but only ${totalInputAmount.toNumber()} available`
    );
  }

  logger.debug(`Withdrawing ${withdrawAmount} base units, fee ${feeLamports}, change ${changeAmount.toString()}`);

  // Get Merkle proofs for inputs
  updateStatus('Fetching Merkle proofs...');
  const inputMerkleProofs = await Promise.all(
    inputs.map(async (utxo) => {
      if (utxo.amount.eq(new BN(0))) {
        return {
          pathElements: [...new Array(MERKLE_TREE_DEPTH).fill('0')],
          pathIndices: Array(MERKLE_TREE_DEPTH).fill(0),
          leafIndex: 0,
          root: root,
        };
      }
      const commitment = await utxo.getCommitment();
      return fetchMerkleProof(commitment, mintBase58, relayerUrl);
    })
  );

  const proofRoot = inputMerkleProofs.find(p => p.root !== root)?.root || root;

  logger.debug(`Tree state root: ${root}`);
  logger.debug(`Proof computed root: ${proofRoot}`);

  const circuitRoot = proofRoot;

  if (proofRoot !== root) {
    logger.warn(`Root mismatch! Using proof root for circuit. Tree state: ${root}, Proof: ${proofRoot}`);
  }

  // Validate the circuit root exists in on-chain root history
  updateStatus('Validating Merkle root...');
  const rootValidation = await validateMerkleRoot(circuitRoot, mintBase58, relayerUrl);

  if (!rootValidation.valid) {
    logger.error(`Root validation failed: ${rootValidation.message}`);
    throw new Error(
      `UnknownRoot: The Merkle root ${circuitRoot.slice(0, 20)}... is not found in on-chain history. ` +
      `This usually means the relayer database is out of sync. Please try again in a few moments. ` +
      `(${rootValidation.message})`
    );
  }

  logger.debug(`Circuit root validated against on-chain history`);

  const inputMerklePathElements = inputMerkleProofs.map((proof) => proof.pathElements);
  const inputMerklePathIndices = inputMerkleProofs.map((proof, i) =>
    proof.leafIndex !== undefined ? proof.leafIndex : (inputs[i].index || 0)
  );

  // Create outputs (change and empty) with mintAddress
  const outputs = [
    new Utxo({
      lightWasm,
      amount: changeAmount.toString(),
      keypair: utxoKeypairV2,
      index: currentNextIndex,
      mintAddress: mint.toBase58(),
    }),
    new Utxo({
      lightWasm,
      amount: '0',
      keypair: utxoKeypairV2,
      index: currentNextIndex + 1,
      mintAddress: mint.toBase58(),
    }),
  ];

  // For withdrawals, extAmount is negative
  const extAmount = -withdrawAmount;
  const publicAmountForCircuit = new BN(extAmount)
    .sub(new BN(feeLamports))
    .add(FIELD_SIZE)
    .mod(FIELD_SIZE);

  // Generate nullifiers and commitments
  const inputNullifiers = await Promise.all(inputs.map((x) => x.getNullifier()));
  const inputCommitments = await Promise.all(inputs.map((x) => x.getCommitment()));
  const outputCommitments = await Promise.all(outputs.map((x) => x.getCommitment()));

  // Encrypt UTXOs
  updateStatus('Encrypting UTXOs...');
  const encryptedOutput1 = await encryptionService.encryptUtxo({
    amount: outputs[0].amount.toString(),
    blinding: outputs[0].blinding.toString(),
    index: outputs[0].index,
  });
  const encryptedOutput2 = await encryptionService.encryptUtxo({
    amount: outputs[1].amount.toString(),
    blinding: outputs[1].blinding.toString(),
    index: outputs[1].index,
  });

  // Create extData
  const extData = {
    recipient,
    extAmount: new BN(extAmount),
    encryptedOutput1,
    encryptedOutput2,
    fee: new BN(feeLamports),
    feeRecipient: feeRecipient,
    mintAddress: mint.toBase58(),
  };

  const calculatedExtDataHash = getExtDataHash(extData);

  // Log commitment details for debugging
  for (let i = 0; i < inputs.length; i++) {
    const commitment = await inputs[i].getCommitment();
    logger.debug(`Input[${i}] commitment: ${commitment}`);
    logger.debug(`Input[${i}] amount: ${inputs[i].amount.toString()}`);
    logger.debug(`Input[${i}] pubkey: ${inputs[i].keypair.pubkey}`);
    logger.debug(`Input[${i}] blinding: ${inputs[i].blinding.toString()}`);
    logger.debug(`Input[${i}] mintAddress: ${inputs[i].mintAddress}`);
    logger.debug(`Input[${i}] index: ${inputs[i].index}`);
    logger.debug(`Input[${i}] pathIndices: ${inputMerklePathIndices[i]}`);
    logger.debug(`Input[${i}] pathElements[0]: ${inputMerklePathElements[i][0]}`);
  }

  // Create circuit input
  const input = {
    root: circuitRoot,
    inputNullifier: inputNullifiers,
    outputCommitment: outputCommitments,
    publicAmount: publicAmountForCircuit.toString(),
    extDataHash: calculatedExtDataHash,
    inAmount: inputs.map((x) => x.amount.toString(10)),
    inPrivateKey: inputs.map((x) => x.keypair.privkey),
    inBlinding: inputs.map((x) => x.blinding.toString(10)),
    inPathIndices: inputMerklePathIndices,
    inPathElements: inputMerklePathElements,
    outAmount: outputs.map((x) => x.amount.toString(10)),
    outBlinding: outputs.map((x) => x.blinding.toString(10)),
    outPubkey: outputs.map((x) => x.keypair.pubkey),
    mintAddress: getMintAddressField(mint),
  };

  logger.debug(`Circuit root: ${circuitRoot}`);
  logger.debug(`Circuit inPathIndices: ${JSON.stringify(inputMerklePathIndices)}`);

  // Generate ZK proof
  updateStatus('Generating ZK proof...');
  const wasmUrl = `${zkAssetsPath}/stealth.wasm`;
  const zkeyUrl = `${zkAssetsPath}/stealth.zkey`;
  const { proof, publicSignals } = await prove(input, wasmUrl, zkeyUrl);

  // Parse proof
  const proofInBytes = parseProofToBytesArray(proof);
  const inputsInBytes = parseToBytesArray(publicSignals);

  const proofToSubmit = {
    proofA: new Uint8Array(proofInBytes.proofA),
    proofB: new Uint8Array(proofInBytes.proofB.flat()),
    proofC: new Uint8Array(proofInBytes.proofC),
    root: new Uint8Array(inputsInBytes[0]),
    publicAmount: new Uint8Array(inputsInBytes[1]),
    extDataHash: new Uint8Array(inputsInBytes[2]),
    inputNullifiers: [new Uint8Array(inputsInBytes[3]), new Uint8Array(inputsInBytes[4])],
    outputCommitments: [new Uint8Array(inputsInBytes[5]), new Uint8Array(inputsInBytes[6])],
  };

  // Find PDAs
  const { nullifier0PDA, nullifier1PDA } = findNullifierPDAs(
    proofToSubmit.inputNullifiers,
    programId
  );
  const { nullifier2PDA, nullifier3PDA } = findCrossCheckNullifierPDAs(
    proofToSubmit.inputNullifiers,
    programId
  );

  // Serialize proof with 'withdraw' type and isSpl=true to use REVEAL_TOKEN discriminator
  const serializedProof = serializeProofAndExtData(proofToSubmit, {
    extAmount: extAmount,
    fee: feeLamports,
    encryptedOutput1,
    encryptedOutput2,
    recipient: recipient.toBytes(),
    relayer: feeRecipient.toBytes(),
    mint: mint.toBytes(),
  }, true, 'withdraw');

  // Derive token account addresses for the relayer
  const recipientTokenAccount = getAssociatedTokenAddress(mint, recipient);
  const poolTokenAccount = getAssociatedTokenAddress(mint, stealthVault);
  const feeRecipientTokenAccount = getAssociatedTokenAddress(mint, feeRecipient);

  // Prepare withdraw params for relayer
  const withdrawParams = {
    serializedProof: Buffer.from(serializedProof).toString('base64'),
    treeAccount: stealthVault.toString(),
    nullifier0PDA: nullifier0PDA.toString(),
    nullifier1PDA: nullifier1PDA.toString(),
    nullifier2PDA: nullifier2PDA.toString(),
    nullifier3PDA: nullifier3PDA.toString(),
    treeTokenAccount: stealthVault.toString(), // For tokens, vault is the tree
    globalConfigAccount: globalConfigAccount.toString(),
    recipient: recipient.toString(),
    feeRecipientAccount: feeRecipient.toString(),
    extAmount: extAmount,
    encryptedOutput1: Buffer.from(encryptedOutput1).toString('base64'),
    encryptedOutput2: Buffer.from(encryptedOutput2).toString('base64'),
    fee: feeLamports,
    lookupTableAddress: altAddress.toString(),
    inputCommitments: inputCommitments.filter(c => c !== '0'),
    // Token-specific fields
    isToken: true,
    mint: mint.toString(),
    recipientTokenAccount: recipientTokenAccount.toString(),
    poolTokenAccount: poolTokenAccount.toString(),
    feeRecipientTokenAccount: feeRecipientTokenAccount.toString(),
  };

  // Submit to relayer
  updateStatus('Submitting transaction to relayer...');
  const { jobId } = await submitWithdrawToIndexer(withdrawParams, relayerUrl, getAuthToken);

  // Poll for job completion
  updateStatus('Waiting for transaction...');
  let retryTimes = 0;
  const start = Date.now();
  let signature = '';

  while (true) {
    await new Promise((resolve) => setTimeout(resolve, 2000));

    const statusRes = await fetch(`${relayerUrl}/transactions/${jobId}/status`);
    const statusJson = (await statusRes.json()) as {
      success: boolean;
      data: {
        jobId: string;
        status: 'queued' | 'processing' | 'completed' | 'failed';
        signature?: string;
        error?: { code: string; message: string };
      };
    };

    if (statusJson.success && statusJson.data) {
      const { status, signature: txSig, error } = statusJson.data;

      if (status === 'completed' && txSig) {
        signature = txSig;
        break;
      }

      if (status === 'failed') {
        throw new Error(error?.message || 'Transaction failed');
      }

      updateStatus(`Transaction ${status}...`);
    }

    if (retryTimes >= 30) {
      throw new Error('Transaction confirmation timeout. Check transaction status later.');
    }
    retryTimes++;
  }

  // Wait for UTXO to be indexed
  updateStatus('Waiting for confirmation...');
  const encryptedOutputStr = Buffer.from(encryptedOutput1).toString('hex');
  let utxoRetries = 0;

  while (utxoRetries < 10) {
    await new Promise((resolve) => setTimeout(resolve, 2000));

    const res = await fetch(`${relayerUrl}/utxos/check?hex=${encryptedOutputStr}&mint=${mint.toBase58()}`);
    const resJson = (await res.json()) as { success: boolean; data: { exists: boolean; treeIndex?: number } };

    if (resJson.success && resJson.data?.exists) {
      break;
    }
    utxoRetries++;
  }

  const duration = ((Date.now() - start) / 1000).toFixed(2);
  logger.debug(`Token withdraw confirmed in ${duration} seconds`);
  updateStatus('Token withdrawal confirmed!');

  return {
    signature,
    amount: BigInt(withdrawAmount),
    fee: BigInt(feeLamports),
    recipient: recipient.toString(),
    isPartial,
  };
}
