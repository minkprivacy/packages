/**
 * Deposit functionality for Privacy SDK (Browser)
 *
 * Handles SOL and SPL token deposits into the privacy pool.
 */

import type { LightWasm } from "@lightprotocol/hasher.rs";
import {
  AddressLookupTableAccount,
  ComputeBudgetProgram,
  Connection,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import BN from "bn.js";
import {
  CLOAK_IX_DISCRIMINATOR,
  CLOAK_TOKEN_IX_DISCRIMINATOR,
  DEFAULT_ALT_ADDRESS,
  DEFAULT_PROGRAM_ID,
  FIELD_SIZE,
  MERKLE_TREE_DEPTH,
  RELAYER_API_URL,
  type TokenName,
} from "../crypto/constants.js";
import { EncryptionService } from "../crypto/encryption.js";
import { Keypair } from "../crypto/keypair.js";
import { ConsoleLogger } from "../logger/console.js";
import { MerkleTree } from "../merkle/tree.js";
import { Utxo } from "../models/utxo.js";
import {
  parseProofToBytesArray,
  parseToBytesArray,
  prove,
} from "../proofs/prover.js";
import type { IStorage } from "../storage/interface.js";
import type {
  AuthTokenGetter,
  DepositResult,
  TransactionSigner,
} from "../types/index.js";
import { getUtxos } from "./balance.js";
import {
  fetchMerkleProof,
  getAssociatedTokenAddress,
  getExtDataHash,
  getMintAddressField,
  getProgramAccounts,
  getTokenVaultAccounts,
  queryRemoteTreeState,
} from "./helpers.js";

const logger = new ConsoleLogger({ prefix: "[Mink]", minLevel: "info" });

// SPL Token Program IDs
const TOKEN_PROGRAM_ID = new PublicKey(
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
);
const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey(
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
);

/**
 * Relayer config cache
 */
let cachedConfig: { fee_recipient: string } | null = null;

/**
 * Fetch relayer config (fee_recipient)
 */
async function getRelayerConfig(
  relayerUrl: string,
): Promise<{ fee_recipient: string }> {
  if (cachedConfig) {
    return cachedConfig;
  }

  try {
    const response = await fetch(`${relayerUrl}/config`);
    if (response.ok) {
      const responseJson = (await response.json()) as {
        success?: boolean;
        data?: Record<string, unknown>;
      } & Record<string, unknown>;

      // Handle both envelope format {success, data} and direct format
      const config = responseJson.data ?? responseJson;

      const feeRecipient =
        typeof config.fee_recipient === "string" ? config.fee_recipient : "";
      if (!feeRecipient) {
        throw new Error("fee_recipient not configured in relayer");
      }
      cachedConfig = {
        fee_recipient: feeRecipient,
      };
      logger.debug(
        `Relayer config: fee_recipient=${cachedConfig.fee_recipient}`,
      );
      return cachedConfig;
    }
  } catch (err) {
    logger.debug(`Failed to fetch relayer config: ${err}`);
    throw new Error(`Failed to fetch relayer config: ${err}`);
  }

  throw new Error("Failed to fetch relayer config");
}

/**
 * Pad or truncate a Uint8Array to a fixed length
 */
function padToFixedLength(data: Uint8Array, length: number): Uint8Array {
  if (data.length === length) {
    return data;
  }
  const result = new Uint8Array(length);
  if (data.length > length) {
    // Truncate
    result.set(data.slice(0, length));
  } else {
    // Pad with zeros
    result.set(data);
  }
  return result;
}

/**
 * Serialize the cloak instruction data for Anchor
 * Format: discriminator (8) + NullifierInputs + ZkProof + ExtData
 * Note: output_commitments removed from ExtData (using proof.output_commitments instead)
 */
function serializeCloakInstruction(params: {
  nullifiers: {
    nullifier0: Uint8Array;
    nullifier1: Uint8Array;
  };
  proof: {
    proofA: Uint8Array;
    proofB: Uint8Array;
    proofC: Uint8Array;
    root: Uint8Array;
    inputNullifiers: Uint8Array[];
    outputCommitments: Uint8Array[];
    publicAmount: Uint8Array;
    extDataHash: Uint8Array;
  };
  extData: {
    recipient: PublicKey;
    extAmount: bigint;
    relayer: PublicKey;
    fee: bigint;
    encryptedOutput1: Uint8Array;
    encryptedOutput2: Uint8Array;
    mint: PublicKey;
  };
}): Buffer {
  const { nullifiers, proof, extData } = params;

  // Calculate total size:
  // discriminator: 8
  // NullifierInputs: 32 + 32 = 64
  // ZkProof: 64 + 128 + 64 + 32 + 64 + 64 + 32 + 32 = 480
  // ExtData: 32 + 16 + 32 + 8 + 86 + 86 + 32 = 292 (removed output_commitments: 64)
  // Total: 8 + 64 + 480 + 292 = 844
  const totalSize = 8 + 64 + 480 + 292;
  const buffer = Buffer.alloc(totalSize);
  let offset = 0;

  // 1. Discriminator (8 bytes) - sha256("global:cloak")[0..8]
  buffer.set(CLOAK_IX_DISCRIMINATOR, offset);
  offset += 8;

  // 2. NullifierInputs
  buffer.set(nullifiers.nullifier0, offset);
  offset += 32;
  buffer.set(nullifiers.nullifier1, offset);
  offset += 32;

  // 3. ZkProof
  // proof_a: [u8; 64]
  buffer.set(proof.proofA, offset);
  offset += 64;
  // proof_b: [u8; 128]
  buffer.set(proof.proofB, offset);
  offset += 128;
  // proof_c: [u8; 64]
  buffer.set(proof.proofC, offset);
  offset += 64;
  // root: [u8; 32]
  buffer.set(proof.root, offset);
  offset += 32;
  // input_nullifiers: [[u8; 32]; 2]
  buffer.set(proof.inputNullifiers[0], offset);
  offset += 32;
  buffer.set(proof.inputNullifiers[1], offset);
  offset += 32;
  // output_commitments: [[u8; 32]; 2]
  buffer.set(proof.outputCommitments[0], offset);
  offset += 32;
  buffer.set(proof.outputCommitments[1], offset);
  offset += 32;
  // public_amount: [u8; 32]
  buffer.set(proof.publicAmount, offset);
  offset += 32;
  // ext_data_hash: [u8; 32]
  buffer.set(proof.extDataHash, offset);
  offset += 32;

  // 4. ExtData (output_commitments removed - using proof.output_commitments on-chain)
  // recipient: Pubkey (32)
  buffer.set(extData.recipient.toBytes(), offset);
  offset += 32;
  // ext_amount: i128 (16 bytes, little-endian)
  const extAmountBN = new BN(extData.extAmount.toString());
  const extAmountBytes = extAmountBN.toTwos(128).toArray("le", 16);
  buffer.set(extAmountBytes, offset);
  offset += 16;
  // relayer: Pubkey (32)
  buffer.set(extData.relayer.toBytes(), offset);
  offset += 32;
  // fee: u64 (8 bytes, little-endian)
  const feeBN = new BN(extData.fee.toString());
  const feeBytes = feeBN.toArray("le", 8);
  buffer.set(feeBytes, offset);
  offset += 8;
  // encrypted_output1: [u8; 86] - full AES-256-GCM format
  buffer.set(extData.encryptedOutput1, offset);
  offset += 86;
  // encrypted_output2: [u8; 86] - full AES-256-GCM format
  buffer.set(extData.encryptedOutput2, offset);
  offset += 86;
  // mint: Pubkey (32)
  buffer.set(extData.mint.toBytes(), offset);
  offset += 32;

  return buffer;
}

/**
 * Deposit parameters
 */
export interface DepositParams {
  publicKey: PublicKey;
  connection: Connection;
  amountLamports: number;
  storage: IStorage;
  encryptionService: EncryptionService;
  zkAssetsPath: string;
  lightWasm: LightWasm;
  transactionSigner: TransactionSigner;
  programId?: PublicKey;
  altAddress?: PublicKey;
  relayerUrl?: string;
  onStatusChange?: (status: string) => void;
  getAuthToken?: AuthTokenGetter;
}

/**
 * Relay deposit transaction to indexer backend
 * PRIVACY: publicKey parameter removed - identity should not be tracked
 */
async function relayDepositToIndexer(
  signedTransaction: string,
  relayerUrl: string,
  getAuthToken?: AuthTokenGetter,
): Promise<string> {
  logger.debug("Relaying pre-signed deposit transaction to indexer backend...");

  // PRIVACY: senderAddress removed - identity should not be tracked
  const params: Record<string, string> = {
    signedTransaction,
  };

  // Build headers with auth token if available
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (getAuthToken) {
    try {
      const token = await getAuthToken();
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }
    } catch (err) {
      logger.warn("Failed to get auth token for deposit:", err);
    }
  }

  const response = await fetch(`${relayerUrl}/deposit`, {
    method: "POST",
    headers,
    body: JSON.stringify(params),
  });

  if (!response.ok) {
    const errorText = await response.text();
    logger.error("Deposit relay error:", errorText);
    throw new Error(`Deposit relay failed: ${response.status}`);
  }

  // Handle wrapped response format
  const rawResult = await response.json();
  let signature: string;

  if (
    typeof rawResult === "object" &&
    "success" in rawResult &&
    "data" in rawResult
  ) {
    signature = rawResult.data.signature;
  } else {
    signature = rawResult.signature;
  }

  logger.debug("Deposit transaction relayed successfully");
  return signature;
}

/**
 * Check deposit limit from on-chain config
 */
async function checkDepositLimit(
  connection: Connection,
  programId: PublicKey,
): Promise<number | undefined> {
  try {
    const [treeAccount] = PublicKey.findProgramAddressSync(
      [Buffer.from("merkle_tree")],
      programId,
    );

    const accountInfo = await connection.getAccountInfo(treeAccount);
    if (!accountInfo) {
      logger.error("Tree account not found");
      return undefined;
    }

    const maxDepositAmount = new BN(accountInfo.data.slice(4120, 4128), "le");
    const lamportsPerSol = new BN(LAMPORTS_PER_SOL);
    const maxDepositSol = maxDepositAmount.div(lamportsPerSol);

    return maxDepositSol.toNumber();
  } catch (error) {
    logger.error("Error reading deposit limit:", error);
    return undefined;
  }
}

/**
 * Fetch Address Lookup Table
 */
async function fetchALT(
  connection: Connection,
  altAddress: PublicKey,
): Promise<AddressLookupTableAccount> {
  const lookupTableAccount = await connection.getAddressLookupTable(altAddress);
  if (!lookupTableAccount.value) {
    throw new Error(`ALT not found at address ${altAddress.toString()}`);
  }
  return lookupTableAccount.value;
}

/**
 * Deposit SOL into the privacy pool
 */
export async function deposit({
  publicKey,
  connection,
  amountLamports,
  storage,
  encryptionService,
  zkAssetsPath,
  lightWasm,
  transactionSigner,
  programId = DEFAULT_PROGRAM_ID,
  altAddress = DEFAULT_ALT_ADDRESS,
  relayerUrl = RELAYER_API_URL,
  onStatusChange,
  getAuthToken,
}: DepositParams): Promise<DepositResult> {
  const updateStatus = (status: string) => {
    logger.info(status);
    onStatusChange?.(status);
  };

  // Check deposit limit
  const limitAmount = await checkDepositLimit(connection, programId);
  if (limitAmount && amountLamports > limitAmount * LAMPORTS_PER_SOL) {
    throw new Error(`Deposit amount exceeds limit of ${limitAmount} SOL`);
  }

  // Fetch relayer config (includes fee_recipient)
  updateStatus("Fetching relayer config...");
  const relayerConfig = await getRelayerConfig(relayerUrl);
  const feeRecipient = new PublicKey(relayerConfig.fee_recipient);

  const feeAmountLamports = 0; // Deposits are free

  logger.debug(`User wallet: ${publicKey.toString()}`);
  logger.debug(`Fee recipient: ${feeRecipient.toString()}`);
  logger.debug(
    `Deposit amount: ${amountLamports} lamports (${amountLamports / LAMPORTS_PER_SOL} SOL)`,
  );

  // Check wallet balance
  const balance = await connection.getBalance(publicKey);
  logger.debug(`Wallet balance: ${balance / LAMPORTS_PER_SOL} SOL`);

  if (balance < amountLamports + feeAmountLamports) {
    throw new Error(
      `Insufficient balance: ${balance / LAMPORTS_PER_SOL} SOL. Need at least ${(amountLamports + feeAmountLamports) / LAMPORTS_PER_SOL} SOL.`,
    );
  }

  const { treeAccount, treeTokenAccount } = getProgramAccounts(programId);

  // Create merkle tree (used to compute empty root and path elements)
  const tree = new MerkleTree(MERKLE_TREE_DEPTH, lightWasm);

  // Get current tree state from relayer
  updateStatus("Fetching tree state...");
  const { root: apiRoot, nextIndex: currentNextIndex } =
    await queryRemoteTreeState(undefined, relayerUrl);

  logger.debug(`API root: ${apiRoot}`);
  logger.debug(
    `New UTXOs will be inserted at indices: ${currentNextIndex} and ${currentNextIndex + 1}`,
  );

  // Get UTXO keypair
  const utxoPrivateKey = encryptionService.getUtxoPrivateKey("v2");
  const utxoKeypair = new Keypair(utxoPrivateKey, lightWasm);

  // Fetch existing UTXOs
  updateStatus("Fetching existing UTXOs...");
  const existingUnspentUtxos = await getUtxos({
    connection,
    publicKey,
    encryptionService,
    storage,
    lightWasm,
    programId,
    relayerUrl,
  });

  // Filter out invalid UTXOs (no amount or index out of bounds)
  const validUtxos = existingUnspentUtxos.filter((utxo) => {
    if (!utxo || !utxo.amount) {
      logger.warn("[DEPOSIT] Found invalid UTXO without amount, skipping");
      return false;
    }
    // Validate index is within tree bounds (index must be < nextIndex)
    if (utxo.index !== undefined && utxo.index >= currentNextIndex) {
      logger.warn(
        `[DEPOSIT] Discarding invalid UTXO: index=${utxo.index} >= nextIndex=${currentNextIndex} (corrupted cache)`,
      );
      return false;
    }
    return true;
  });

  // Calculate amounts and create inputs/outputs
  let extAmount: number;
  let outputAmount: string;
  let inputs: Utxo[];
  let inputMerklePathIndices: number[];
  let inputMerklePathElements: string[][];
  let root: string; // The merkle root to use in the proof

  if (validUtxos.length === 0) {
    // Fresh deposit - no existing UTXOs
    // IMPORTANT: Always use the on-chain root because the program validates
    // that proof.root is in its root history. The ZK circuit skips root
    // verification for zero-amount inputs, but the program always checks.
    extAmount = amountLamports;
    outputAmount = new BN(amountLamports)
      .sub(new BN(feeAmountLamports))
      .toString();

    logger.debug("Fresh deposit scenario (no existing UTXOs)");

    // Use the on-chain root (NOT the computed empty root)
    root = apiRoot;
    logger.debug(`Using ON-CHAIN root for fresh deposit: ${root}`);

    // Use dummy UTXOs as inputs (zero amounts)
    inputs = [
      new Utxo({ lightWasm, keypair: utxoKeypair }),
      new Utxo({ lightWasm, keypair: utxoKeypair }),
    ];

    inputMerklePathIndices = inputs.map((input) => input.index || 0);
    inputMerklePathElements = inputs.map(() => [
      ...new Array(tree.levels).fill("0"),
    ]);
  } else {
    // Deposit with consolidation of existing UTXOs
    // Use the API root since we have existing UTXOs to prove against
    root = apiRoot;
    logger.debug(`Using API root for consolidation deposit: ${root}`);

    const firstUtxo = validUtxos[0];
    const firstUtxoAmount = firstUtxo.amount;
    const secondUtxoAmount =
      validUtxos.length > 1 ? validUtxos[1].amount : new BN(0);

    extAmount = amountLamports;
    outputAmount = firstUtxoAmount
      .add(secondUtxoAmount)
      .add(new BN(amountLamports))
      .sub(new BN(feeAmountLamports))
      .toString();

    logger.debug("Deposit with consolidation scenario");
    logger.debug(`First UTXO amount: ${firstUtxoAmount.toString()}`);

    const secondUtxo =
      validUtxos.length > 1
        ? validUtxos[1]
        : new Utxo({ lightWasm, keypair: utxoKeypair, amount: "0" });

    inputs = [firstUtxo, secondUtxo];

    // Fetch Merkle proofs
    const firstUtxoCommitment = await firstUtxo.getCommitment();
    const firstUtxoMerkleProof = await fetchMerkleProof(
      firstUtxoCommitment,
      undefined,
      relayerUrl,
    );

    let secondUtxoMerkleProof;
    if (secondUtxo.amount.gt(new BN(0))) {
      const secondUtxoCommitment = await secondUtxo.getCommitment();
      secondUtxoMerkleProof = await fetchMerkleProof(
        secondUtxoCommitment,
        undefined,
        relayerUrl,
      );
    }

    inputMerklePathIndices = [
      firstUtxo.index || 0,
      secondUtxo.amount.gt(new BN(0)) ? secondUtxo.index || 0 : 0,
    ];

    inputMerklePathElements = [
      firstUtxoMerkleProof.pathElements,
      secondUtxo.amount.gt(new BN(0))
        ? secondUtxoMerkleProof!.pathElements
        : [...new Array(tree.levels).fill("0")],
    ];
  }

  // Calculate public amount for circuit
  const publicAmountForCircuit = new BN(extAmount)
    .sub(new BN(feeAmountLamports))
    .add(FIELD_SIZE)
    .mod(FIELD_SIZE);

  // Create outputs
  const outputs = [
    new Utxo({
      lightWasm,
      amount: outputAmount,
      keypair: utxoKeypair,
      index: currentNextIndex,
    }),
    new Utxo({
      lightWasm,
      amount: "0",
      keypair: utxoKeypair,
      index: currentNextIndex + 1,
    }),
  ];

  // Generate nullifiers and commitments
  const inputNullifiers = await Promise.all(
    inputs.map((x) => x.getNullifier()),
  );
  const outputCommitments = await Promise.all(
    outputs.map((x) => x.getCommitment()),
  );

  // Encrypt UTXOs
  updateStatus("Encrypting UTXOs...");
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
    recipient: new PublicKey("TmYrwibiy2seJZnsi9cGvioixVsh21Q2XmVrVXy9eDH"),
    extAmount: new BN(extAmount),
    encryptedOutput1,
    encryptedOutput2,
    fee: new BN(feeAmountLamports),
    feeRecipient: feeRecipient,
    mintAddress: inputs[0].mintAddress,
  };

  const calculatedExtDataHash = getExtDataHash(extData);

  // Create circuit input
  const input = {
    root,
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

  // Generate ZK proof
  updateStatus("Generating ZK proof...");
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
    inputNullifiers: [
      new Uint8Array(inputsInBytes[3]),
      new Uint8Array(inputsInBytes[4]),
    ],
    outputCommitments: [
      new Uint8Array(inputsInBytes[5]),
      new Uint8Array(inputsInBytes[6]),
    ],
  };

  // Find nullifier PDAs - seeds are [b"nullifier0", nullifier_bytes] and [b"nullifier1", nullifier_bytes]
  const [nullifier0PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier0"), Buffer.from(proofToSubmit.inputNullifiers[0])],
    programId,
  );
  const [nullifier1PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier1"), Buffer.from(proofToSubmit.inputNullifiers[1])],
    programId,
  );

  // Recipient must match what was used in getExtDataHash for ext_data_hash verification
  const recipient = new PublicKey(
    "TmYrwibiy2seJZnsi9cGvioixVsh21Q2XmVrVXy9eDH",
  );

  // Fetch ALT
  updateStatus("Setting up Address Lookup Table...");
  const lookupTableAccount = await fetchALT(connection, altAddress);

  // Serialize instruction data for Anchor's CloakSol instruction
  // Format: discriminator + NullifierInputs + ZkProof + ExtData
  const serializedData = serializeCloakInstruction({
    nullifiers: {
      nullifier0: proofToSubmit.inputNullifiers[0],
      nullifier1: proofToSubmit.inputNullifiers[1],
    },
    proof: {
      proofA: proofToSubmit.proofA,
      proofB: proofToSubmit.proofB,
      proofC: proofToSubmit.proofC,
      root: proofToSubmit.root,
      inputNullifiers: proofToSubmit.inputNullifiers,
      outputCommitments: proofToSubmit.outputCommitments,
      publicAmount: proofToSubmit.publicAmount,
      extDataHash: proofToSubmit.extDataHash,
    },
    extData: {
      recipient: recipient,
      extAmount: BigInt(extAmount),
      relayer: feeRecipient, // Relayer address
      fee: BigInt(feeAmountLamports),
      encryptedOutput1: padToFixedLength(encryptedOutput1, 86),
      encryptedOutput2: padToFixedLength(encryptedOutput2, 86),
      mint: new PublicKey(inputs[0].mintAddress),
    },
  });

  // Create deposit instruction with correct Anchor account order for CloakSol:
  // 1. signer (mut, signer)
  // 2. stealth_vault (mut) - merkle_tree PDA
  // 3. vault_token_account (mut) - tree_token PDA
  // 4. recipient (mut)
  // 5. nullifier0 (init, mut)
  // 6. nullifier1 (init, mut)
  // 7. system_program
  const depositInstruction = new TransactionInstruction({
    keys: [
      { pubkey: publicKey, isSigner: true, isWritable: true }, // signer
      { pubkey: treeAccount, isSigner: false, isWritable: true }, // stealth_vault
      { pubkey: treeTokenAccount, isSigner: false, isWritable: true }, // vault_token_account
      { pubkey: recipient, isSigner: false, isWritable: true }, // recipient
      { pubkey: nullifier0PDA, isSigner: false, isWritable: true }, // nullifier0
      { pubkey: nullifier1PDA, isSigner: false, isWritable: true }, // nullifier1
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // system_program
    ],
    programId,
    data: serializedData,
  });

  // Set compute budget
  const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
    units: 1_000_000,
  });

  // Create versioned transaction
  updateStatus("Creating transaction...");
  const recentBlockhash = await connection.getLatestBlockhash("confirmed");

  const messageV0 = new TransactionMessage({
    payerKey: publicKey,
    recentBlockhash: recentBlockhash.blockhash,
    instructions: [modifyComputeUnits, depositInstruction],
  }).compileToV0Message([lookupTableAccount]);

  let versionedTransaction = new VersionedTransaction(messageV0);

  // Simulate transaction BEFORE asking user to sign
  updateStatus("Simulating transaction...");
  try {
    const simulation = await connection.simulateTransaction(
      versionedTransaction,
      {
        sigVerify: false, // Don't verify signatures since it's not signed yet
        replaceRecentBlockhash: true, // Use latest blockhash for simulation
        commitment: "confirmed",
      },
    );

    if (simulation.value.err) {
      logger.error("Transaction simulation failed:", simulation.value.err);
      logger.error("Simulation logs:", simulation.value.logs);

      // Extract meaningful error from logs
      const logs = simulation.value.logs || [];
      const errorLog = logs.find(
        (log) =>
          log.includes("Error") ||
          log.includes("failed") ||
          log.includes("Custom"),
      );

      throw new Error(
        `Transaction simulation failed: ${JSON.stringify(simulation.value.err)}${errorLog ? ` - ${errorLog}` : ""}`,
      );
    }

    logger.debug("Simulation successful. Logs:", simulation.value.logs);
  } catch (simError) {
    if (
      simError instanceof Error &&
      simError.message.includes("Transaction simulation failed")
    ) {
      throw simError;
    }
    const errMsg =
      simError instanceof Error ? simError.message : String(simError);
    logger.error(`[SIMULATE] Error: ${errMsg}`);
    logger.error(
      `[SIMULATE] Instruction data size: ${serializedData.length} bytes`,
    );
    throw new Error(`Failed to simulate transaction: ${errMsg}`);
  }

  // Sign transaction
  updateStatus("Signing transaction...");
  versionedTransaction = await transactionSigner(versionedTransaction);

  // Serialize and relay
  const serializedTransaction = Buffer.from(
    versionedTransaction.serialize(),
  ).toString("base64");

  updateStatus("Submitting transaction to relayer...");
  const signature = await relayDepositToIndexer(
    serializedTransaction,
    relayerUrl,
    getAuthToken,
  );

  // Wait for confirmation
  updateStatus("Waiting for confirmation...");
  // Use the 86-byte format (matching on-chain storage format)
  const paddedOutput1 = padToFixedLength(encryptedOutput1, 86);
  const encryptedOutputStr = Buffer.from(paddedOutput1).toString("hex");

  logger.debug(`Original encryptedOutput1 length: ${encryptedOutput1.length}`);
  logger.debug(`Padded output length: ${paddedOutput1.length}`);
  logger.debug(
    `Checking UTXO with hex (first 40 chars): ${encryptedOutputStr.slice(0, 40)}...`,
  );
  logger.debug(`Full hex length: ${encryptedOutputStr.length}`);

  let retryTimes = 0;
  const start = Date.now();

  while (true) {
    await new Promise((resolve) => setTimeout(resolve, 2000));

    const res = await fetch(
      `${relayerUrl}/utxos/check?hex=${encryptedOutputStr}`,
    );
    const resJson = (await res.json()) as {
      success: boolean;
      data: { exists: boolean; treeIndex?: number };
    };

    if (resJson.success && resJson.data?.exists) {
      const duration = ((Date.now() - start) / 1000).toFixed(2);
      logger.debug(`Deposit confirmed in ${duration} seconds`);
      updateStatus("Deposit confirmed!");

      return {
        signature,
        amount: BigInt(amountLamports),
        commitment: outputCommitments[0],
      };
    }

    if (retryTimes >= 10) {
      throw new Error(
        "Transaction confirmation timeout. Refresh to see latest balance.",
      );
    }
    retryTimes++;
  }
}

/**
 * SPL Token Deposit parameters
 */
export interface DepositTokenParams {
  publicKey: PublicKey;
  connection: Connection;
  amount: number; // In token base units (e.g., USDC has 6 decimals, so 1 USDC = 1_000_000)
  mint: PublicKey; // SPL token mint address
  storage: IStorage;
  encryptionService: EncryptionService;
  zkAssetsPath: string;
  lightWasm: LightWasm;
  transactionSigner: TransactionSigner;
  programId?: PublicKey;
  altAddress?: PublicKey;
  relayerUrl?: string;
  onStatusChange?: (status: string) => void;
  getAuthToken?: AuthTokenGetter;
  tokenName?: TokenName; // For relayer API calls (e.g., 'USDC')
}

/**
 * Serialize the cloak_token instruction data for Anchor
 * Format: discriminator (8) + NullifierInputs + ZkProof + ExtData
 * Note: output_commitments removed from ExtData (using proof.output_commitments instead)
 */
function serializeCloakTokenInstruction(params: {
  nullifiers: {
    nullifier0: Uint8Array;
    nullifier1: Uint8Array;
  };
  proof: {
    proofA: Uint8Array;
    proofB: Uint8Array;
    proofC: Uint8Array;
    root: Uint8Array;
    inputNullifiers: Uint8Array[];
    outputCommitments: Uint8Array[];
    publicAmount: Uint8Array;
    extDataHash: Uint8Array;
  };
  extData: {
    recipient: PublicKey;
    extAmount: bigint;
    relayer: PublicKey;
    fee: bigint;
    encryptedOutput1: Uint8Array;
    encryptedOutput2: Uint8Array;
    mint: PublicKey;
  };
}): Buffer {
  const { nullifiers, proof, extData } = params;

  // Same structure as CloakSol but with CLOAK_TOKEN discriminator
  // ExtData: 32 + 16 + 32 + 8 + 86 + 86 + 32 = 292 (removed output_commitments: 64)
  // Total: 8 + 64 + 480 + 292 = 844
  const totalSize = 8 + 64 + 480 + 292;
  const buffer = Buffer.alloc(totalSize);
  let offset = 0;

  // 1. Discriminator for cloak_token
  buffer.set(CLOAK_TOKEN_IX_DISCRIMINATOR, offset);
  offset += 8;

  // 2. NullifierInputs
  buffer.set(nullifiers.nullifier0, offset);
  offset += 32;
  buffer.set(nullifiers.nullifier1, offset);
  offset += 32;

  // 3. ZkProof
  buffer.set(proof.proofA, offset);
  offset += 64;
  buffer.set(proof.proofB, offset);
  offset += 128;
  buffer.set(proof.proofC, offset);
  offset += 64;
  buffer.set(proof.root, offset);
  offset += 32;
  buffer.set(proof.inputNullifiers[0], offset);
  offset += 32;
  buffer.set(proof.inputNullifiers[1], offset);
  offset += 32;
  buffer.set(proof.outputCommitments[0], offset);
  offset += 32;
  buffer.set(proof.outputCommitments[1], offset);
  offset += 32;
  buffer.set(proof.publicAmount, offset);
  offset += 32;
  buffer.set(proof.extDataHash, offset);
  offset += 32;

  // 4. ExtData (output_commitments removed - using proof.output_commitments on-chain)
  buffer.set(extData.recipient.toBytes(), offset);
  offset += 32;
  const extAmountBN = new BN(extData.extAmount.toString());
  const extAmountBytes = extAmountBN.toTwos(128).toArray("le", 16);
  buffer.set(extAmountBytes, offset);
  offset += 16;
  buffer.set(extData.relayer.toBytes(), offset);
  offset += 32;
  const feeBN = new BN(extData.fee.toString());
  const feeBytes = feeBN.toArray("le", 8);
  buffer.set(feeBytes, offset);
  offset += 8;
  buffer.set(extData.encryptedOutput1, offset);
  offset += 86;
  buffer.set(extData.encryptedOutput2, offset);
  offset += 86;
  buffer.set(extData.mint.toBytes(), offset);
  offset += 32;

  return buffer;
}

/**
 * Deposit SPL tokens into the privacy pool
 */
export async function depositToken({
  publicKey,
  connection,
  amount,
  mint,
  storage,
  encryptionService,
  zkAssetsPath,
  lightWasm,
  transactionSigner,
  programId = DEFAULT_PROGRAM_ID,
  altAddress = DEFAULT_ALT_ADDRESS,
  relayerUrl = RELAYER_API_URL,
  onStatusChange,
  getAuthToken,
  tokenName,
}: DepositTokenParams): Promise<DepositResult> {
  const updateStatus = (status: string) => {
    logger.info(status);
    onStatusChange?.(status);
  };

  // Fetch relayer config
  updateStatus("Fetching relayer config...");
  const relayerConfig = await getRelayerConfig(relayerUrl);
  const feeRecipient = new PublicKey(relayerConfig.fee_recipient);
  const feeAmount = 0; // Deposits are free

  logger.debug(`User wallet: ${publicKey.toString()}`);
  logger.debug(`Token mint: ${mint.toString()}`);
  logger.debug(`Deposit amount: ${amount} base units`);

  // Get token vault accounts
  const { stealthVault } = getTokenVaultAccounts(mint, programId);

  // Get user's token account (ATA)
  const userTokenAccount = getAssociatedTokenAddress(mint, publicKey);

  // Get pool's token account (ATA for stealthVault)
  const poolTokenAccount = getAssociatedTokenAddress(mint, stealthVault);

  logger.debug(`Stealth vault: ${stealthVault.toString()}`);
  logger.debug(`User token account: ${userTokenAccount.toString()}`);
  logger.debug(`Pool token account: ${poolTokenAccount.toString()}`);

  // Check user's token balance
  updateStatus("Checking token balance...");
  try {
    const tokenAccountInfo =
      await connection.getTokenAccountBalance(userTokenAccount);
    const balance = Number(tokenAccountInfo.value.amount);
    logger.debug(`User token balance: ${balance}`);

    if (balance < amount) {
      throw new Error(
        `Insufficient token balance: ${balance}. Need at least ${amount}.`,
      );
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes("Insufficient")) {
      throw err;
    }
    throw new Error(
      `Token account not found. Make sure you have ${tokenName || "tokens"} in your wallet.`,
    );
  }

  // Create merkle tree
  const tree = new MerkleTree(MERKLE_TREE_DEPTH, lightWasm);

  // Get current tree state from relayer
  updateStatus("Fetching tree state...");
  logger.info(`[TREE-STATE] Fetching for mint: ${mint.toString()}`);
  const { root: apiRoot, nextIndex: currentNextIndex } =
    await queryRemoteTreeState(mint.toString(), relayerUrl);

  logger.info(
    `[TREE-STATE] API returned: root=${apiRoot.slice(0, 20)}..., nextIndex=${currentNextIndex}`,
  );

  // Get UTXO keypair
  const utxoPrivateKey = encryptionService.getUtxoPrivateKey("v2");
  const utxoKeypair = new Keypair(utxoPrivateKey, lightWasm);

  // Fetch existing UTXOs for this token
  updateStatus("Fetching existing UTXOs...");
  const existingUnspentUtxos = await getUtxos({
    connection,
    publicKey,
    encryptionService,
    storage,
    lightWasm,
    programId,
    relayerUrl,
    mint: mint.toString(), // Pass mint address to filter UTXOs
  });

  // Filter for this specific token AND validate index is within tree bounds
  const tokenUtxos = existingUnspentUtxos.filter((utxo) => {
    if (!utxo || !utxo.amount) return false;
    // Match by mint address
    if (utxo.mintAddress !== mint.toString()) return false;
    // Validate index is within tree bounds (index must be < nextIndex)
    if (utxo.index !== undefined && utxo.index >= currentNextIndex) {
      logger.warn(
        `[DEPOSIT] Discarding invalid UTXO: index=${utxo.index} >= nextIndex=${currentNextIndex} (corrupted cache)`,
      );
      return false;
    }
    return true;
  });

  // Calculate amounts and create inputs/outputs
  let extAmount: number;
  let outputAmount: string;
  let inputs: Utxo[];
  let inputMerklePathIndices: number[];
  let inputMerklePathElements: string[][];
  let root: string;

  if (tokenUtxos.length === 0) {
    // Fresh deposit - no existing token UTXOs
    extAmount = amount;
    outputAmount = new BN(amount).sub(new BN(feeAmount)).toString();

    logger.info(`[DEPOSIT] Fresh deposit (no existing UTXOs for this mint)`);
    logger.info(
      `[DEPOSIT] Using root: ${apiRoot.slice(0, 20)}..., outputs at indices: ${currentNextIndex}, ${currentNextIndex + 1}`,
    );
    root = apiRoot;

    // Use dummy UTXOs as inputs (zero amounts, with correct mint)
    inputs = [
      new Utxo({
        lightWasm,
        keypair: utxoKeypair,
        mintAddress: mint.toString(),
      }),
      new Utxo({
        lightWasm,
        keypair: utxoKeypair,
        mintAddress: mint.toString(),
      }),
    ];

    inputMerklePathIndices = inputs.map((input) => input.index || 0);
    inputMerklePathElements = inputs.map(() => [
      ...new Array(tree.levels).fill("0"),
    ]);
  } else {
    // Deposit with consolidation of existing token UTXOs
    root = apiRoot;

    const firstUtxo = tokenUtxos[0];
    const firstUtxoAmount = firstUtxo.amount;
    const secondUtxoAmount =
      tokenUtxos.length > 1 ? tokenUtxos[1].amount : new BN(0);

    logger.info(
      `[DEPOSIT] Consolidation deposit (found ${tokenUtxos.length} existing UTXOs)`,
    );
    logger.info(
      `[DEPOSIT] First UTXO: index=${firstUtxo.index}, amount=${firstUtxoAmount.toString()}`,
    );
    logger.info(
      `[DEPOSIT] Using root: ${root.slice(0, 20)}..., outputs at indices: ${currentNextIndex}, ${currentNextIndex + 1}`,
    );

    extAmount = amount;
    outputAmount = firstUtxoAmount
      .add(secondUtxoAmount)
      .add(new BN(amount))
      .sub(new BN(feeAmount))
      .toString();

    const secondUtxo =
      tokenUtxos.length > 1
        ? tokenUtxos[1]
        : new Utxo({
            lightWasm,
            keypair: utxoKeypair,
            amount: "0",
            mintAddress: mint.toString(),
          });

    inputs = [firstUtxo, secondUtxo];

    // Fetch Merkle proofs
    const firstUtxoCommitment = await firstUtxo.getCommitment();
    const firstUtxoMerkleProof = await fetchMerkleProof(
      firstUtxoCommitment,
      mint.toString(),
      relayerUrl,
    );

    let secondUtxoMerkleProof;
    if (secondUtxo.amount.gt(new BN(0))) {
      const secondUtxoCommitment = await secondUtxo.getCommitment();
      secondUtxoMerkleProof = await fetchMerkleProof(
        secondUtxoCommitment,
        mint.toString(),
        relayerUrl,
      );
    }

    inputMerklePathIndices = [
      firstUtxo.index || 0,
      secondUtxo.amount.gt(new BN(0)) ? secondUtxo.index || 0 : 0,
    ];

    inputMerklePathElements = [
      firstUtxoMerkleProof.pathElements,
      secondUtxo.amount.gt(new BN(0))
        ? secondUtxoMerkleProof!.pathElements
        : [...new Array(tree.levels).fill("0")],
    ];
  }

  // Calculate public amount for circuit
  const publicAmountForCircuit = new BN(extAmount)
    .sub(new BN(feeAmount))
    .add(FIELD_SIZE)
    .mod(FIELD_SIZE);

  // Create outputs with correct mint
  const outputs = [
    new Utxo({
      lightWasm,
      amount: outputAmount,
      keypair: utxoKeypair,
      index: currentNextIndex,
      mintAddress: mint.toString(),
    }),
    new Utxo({
      lightWasm,
      amount: "0",
      keypair: utxoKeypair,
      index: currentNextIndex + 1,
      mintAddress: mint.toString(),
    }),
  ];

  // Generate nullifiers and commitments
  const inputNullifiers = await Promise.all(
    inputs.map((x) => x.getNullifier()),
  );
  const outputCommitments = await Promise.all(
    outputs.map((x) => x.getCommitment()),
  );

  // Encrypt UTXOs
  updateStatus("Encrypting UTXOs...");
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
    recipient: new PublicKey("TmYrwibiy2seJZnsi9cGvioixVsh21Q2XmVrVXy9eDH"),
    extAmount: new BN(extAmount),
    encryptedOutput1,
    encryptedOutput2,
    fee: new BN(feeAmount),
    feeRecipient: feeRecipient,
    mintAddress: mint,
  };

  const calculatedExtDataHash = getExtDataHash(extData);

  // Create circuit input
  const input = {
    root,
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

  // Generate ZK proof
  updateStatus("Generating ZK proof...");
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
    inputNullifiers: [
      new Uint8Array(inputsInBytes[3]),
      new Uint8Array(inputsInBytes[4]),
    ],
    outputCommitments: [
      new Uint8Array(inputsInBytes[5]),
      new Uint8Array(inputsInBytes[6]),
    ],
  };

  // Find nullifier PDAs
  const [nullifier0PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier0"), Buffer.from(proofToSubmit.inputNullifiers[0])],
    programId,
  );
  const [nullifier1PDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("nullifier1"), Buffer.from(proofToSubmit.inputNullifiers[1])],
    programId,
  );

  // Fetch ALT
  updateStatus("Setting up Address Lookup Table...");
  const lookupTableAccount = await fetchALT(connection, altAddress);

  // Validate sizes before serialization
  const paddedOutput1 = padToFixedLength(encryptedOutput1, 86);
  const paddedOutput2 = padToFixedLength(encryptedOutput2, 86);

  logger.info(
    `[SERIALIZE] Field sizes: proofA=${proofToSubmit.proofA.length}, proofB=${proofToSubmit.proofB.length}, proofC=${proofToSubmit.proofC.length}, root=${proofToSubmit.root.length}, pubAmount=${proofToSubmit.publicAmount.length}, extHash=${proofToSubmit.extDataHash.length}`,
  );
  logger.info(
    `[SERIALIZE] Nullifiers: n0=${proofToSubmit.inputNullifiers[0].length}, n1=${proofToSubmit.inputNullifiers[1].length}, out0=${proofToSubmit.outputCommitments[0].length}, out1=${proofToSubmit.outputCommitments[1].length}`,
  );
  logger.info(
    `[SERIALIZE] EncryptedOutputs: e1=${paddedOutput1.length}, e2=${paddedOutput2.length}`,
  );

  // Serialize instruction data for CloakToken
  const serializedData = serializeCloakTokenInstruction({
    nullifiers: {
      nullifier0: proofToSubmit.inputNullifiers[0],
      nullifier1: proofToSubmit.inputNullifiers[1],
    },
    proof: {
      proofA: proofToSubmit.proofA,
      proofB: proofToSubmit.proofB,
      proofC: proofToSubmit.proofC,
      root: proofToSubmit.root,
      inputNullifiers: proofToSubmit.inputNullifiers,
      outputCommitments: proofToSubmit.outputCommitments,
      publicAmount: proofToSubmit.publicAmount,
      extDataHash: proofToSubmit.extDataHash,
    },
    extData: {
      recipient: new PublicKey("TmYrwibiy2seJZnsi9cGvioixVsh21Q2XmVrVXy9eDH"),
      extAmount: BigInt(extAmount),
      relayer: feeRecipient,
      fee: BigInt(feeAmount),
      encryptedOutput1: paddedOutput1,
      encryptedOutput2: paddedOutput2,
      mint: mint,
    },
  });

  // Create deposit instruction with CloakToken account order:
  // 1. signer (mut, signer)
  // 2. stealth_vault (mut) - PDA seeded with [merkle_tree, mint]
  // 3. mint
  // 4. signer_token_account (mut) - user's ATA
  // 5. pool_token_account (mut) - pool's ATA
  // 6. recipient_token_account (mut) - for withdrawals
  // 7. nullifier0 (init, mut)
  // 8. nullifier1 (init, mut)
  // 9. token_program
  // 10. associated_token_program
  // 11. system_program
  const depositInstruction = new TransactionInstruction({
    keys: [
      { pubkey: publicKey, isSigner: true, isWritable: true },
      { pubkey: stealthVault, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: userTokenAccount, isSigner: false, isWritable: true },
      { pubkey: poolTokenAccount, isSigner: false, isWritable: true },
      { pubkey: userTokenAccount, isSigner: false, isWritable: true }, // recipient_token_account (use user's for deposit)
      { pubkey: nullifier0PDA, isSigner: false, isWritable: true },
      { pubkey: nullifier1PDA, isSigner: false, isWritable: true },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      {
        pubkey: ASSOCIATED_TOKEN_PROGRAM_ID,
        isSigner: false,
        isWritable: false,
      },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId,
    data: serializedData,
  });

  // Set compute budget
  const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
    units: 1_000_000,
  });

  // Create versioned transaction
  updateStatus("Creating transaction...");
  const recentBlockhash = await connection.getLatestBlockhash("confirmed");

  logger.info(
    `[TX] ALT has ${lookupTableAccount.state.addresses.length} addresses`,
  );
  logger.info(
    `[TX] Instruction has ${depositInstruction.keys.length} accounts`,
  );
  logger.info(
    `[TX] Instruction data size: ${depositInstruction.data.length} bytes`,
  );

  // Check if all instruction accounts are in ALT
  const altAddresses = lookupTableAccount.state.addresses.map((a) =>
    a.toBase58(),
  );
  for (const key of depositInstruction.keys) {
    if (!altAddresses.includes(key.pubkey.toBase58())) {
      logger.warn(`[TX] Account NOT in ALT: ${key.pubkey.toBase58()}`);
    }
  }

  let messageV0;
  try {
    messageV0 = new TransactionMessage({
      payerKey: publicKey,
      recentBlockhash: recentBlockhash.blockhash,
      instructions: [modifyComputeUnits, depositInstruction],
    }).compileToV0Message([lookupTableAccount]);
    logger.info(`[TX] V0 message compiled successfully`);
  } catch (compileErr) {
    const errMsg =
      compileErr instanceof Error ? compileErr.message : String(compileErr);
    logger.error(`[TX] Failed to compile V0 message: ${errMsg}`);
    throw new Error(`Failed to compile transaction: ${errMsg}`);
  }

  let versionedTransaction;
  try {
    versionedTransaction = new VersionedTransaction(messageV0);
    logger.info(`[TX] VersionedTransaction created successfully`);
  } catch (vtxErr) {
    const errMsg = vtxErr instanceof Error ? vtxErr.message : String(vtxErr);
    logger.error(`[TX] Failed to create VersionedTransaction: ${errMsg}`);
    throw new Error(`Failed to create transaction: ${errMsg}`);
  }

  // Simulate transaction
  updateStatus("Simulating transaction...");

  // Try to serialize the transaction first to check for encoding issues
  try {
    const serializedTx = versionedTransaction.serialize();
    logger.info(
      `[TX] Transaction serialized successfully: ${serializedTx.length} bytes`,
    );
  } catch (serializeErr) {
    const errMsg =
      serializeErr instanceof Error
        ? serializeErr.message
        : String(serializeErr);
    logger.error(`[TX] Failed to serialize transaction: ${errMsg}`);
    // Log more details about the message
    logger.error(`[TX] Message version: ${messageV0.version}`);
    logger.error(
      `[TX] Static account keys: ${messageV0.staticAccountKeys.length}`,
    );
    logger.error(
      `[TX] Address table lookups: ${messageV0.addressTableLookups.length}`,
    );
    if (messageV0.addressTableLookups.length > 0) {
      for (const lookup of messageV0.addressTableLookups) {
        logger.error(
          `[TX] Lookup: table=${lookup.accountKey.toBase58()}, writable=${lookup.writableIndexes.length}, readonly=${lookup.readonlyIndexes.length}`,
        );
        logger.error(
          `[TX] Writable indexes: ${JSON.stringify(Array.from(lookup.writableIndexes))}`,
        );
        logger.error(
          `[TX] Readonly indexes: ${JSON.stringify(Array.from(lookup.readonlyIndexes))}`,
        );
      }
    }
    // Log all static account keys
    logger.error(
      `[TX] Static keys: ${messageV0.staticAccountKeys.map((k) => k.toBase58()).join(", ")}`,
    );
    // Log compiled instructions with more detail
    for (let i = 0; i < messageV0.compiledInstructions.length; i++) {
      const ix = messageV0.compiledInstructions[i];
      logger.error(
        `[TX] Instruction ${i}: programIdIndex=${ix.programIdIndex}, accountKeyIndexes=${JSON.stringify(Array.from(ix.accountKeyIndexes))}, dataLen=${ix.data.length}`,
      );
      // Check if data length matches expected
      if (i === 1 && ix.data.length !== 908) {
        logger.error(
          `[TX] MISMATCH: Expected 908 bytes, got ${ix.data.length}`,
        );
      }
      // Log first and last bytes of instruction data
      if (ix.data.length > 0) {
        logger.error(
          `[TX] Instruction ${i} data first 16 bytes: ${Array.from(
            ix.data.slice(0, 16),
          )
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(" ")}`,
        );
        logger.error(
          `[TX] Instruction ${i} data last 16 bytes: ${Array.from(
            ix.data.slice(-16),
          )
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(" ")}`,
        );
      }
    }
    // Try to serialize just the message to see where the error is
    try {
      const msgBytes = messageV0.serialize();
      logger.error(`[TX] Message serialized OK: ${msgBytes.length} bytes`);
    } catch (msgErr) {
      logger.error(
        `[TX] Message serialization also failed: ${msgErr instanceof Error ? msgErr.message : String(msgErr)}`,
      );
    }
    throw new Error(`Transaction serialization failed: ${errMsg}`);
  }

  try {
    const simulation = await connection.simulateTransaction(
      versionedTransaction,
      {
        sigVerify: false,
        replaceRecentBlockhash: true, // Use latest blockhash for simulation
        commitment: "confirmed",
      },
    );

    if (simulation.value.err) {
      logger.error("Transaction simulation failed:", simulation.value.err);
      logger.error("Simulation logs:", simulation.value.logs);

      const logs = simulation.value.logs || [];
      const errorLog = logs.find(
        (log) =>
          log.includes("Error") ||
          log.includes("failed") ||
          log.includes("Custom"),
      );

      throw new Error(
        `Transaction simulation failed: ${JSON.stringify(simulation.value.err)}${errorLog ? ` - ${errorLog}` : ""}`,
      );
    }

    logger.debug("Simulation successful. Logs:", simulation.value.logs);
  } catch (simError) {
    if (
      simError instanceof Error &&
      simError.message.includes("Transaction simulation failed")
    ) {
      throw simError;
    }
    if (
      simError instanceof Error &&
      simError.message.includes("Transaction serialization failed")
    ) {
      throw simError;
    }
    const errMsg =
      simError instanceof Error ? simError.message : String(simError);
    logger.error(`[SIMULATE] Error: ${errMsg}`);
    logger.error(
      `[SIMULATE] Instruction data size: ${serializedData.length} bytes`,
    );
    throw new Error(`Failed to simulate transaction: ${errMsg}`);
  }

  // Sign transaction
  updateStatus("Signing transaction...");
  versionedTransaction = await transactionSigner(versionedTransaction);

  // Serialize and relay
  const serializedTransaction = Buffer.from(
    versionedTransaction.serialize(),
  ).toString("base64");

  updateStatus("Submitting transaction to relayer...");
  const signature = await relayDepositToIndexer(
    serializedTransaction,
    relayerUrl,
    getAuthToken,
  );

  // Wait for confirmation
  updateStatus("Waiting for confirmation...");
  const encryptedOutputStr = Buffer.from(paddedOutput1).toString("hex");

  logger.debug(
    `Checking token UTXO with hex (first 40 chars): ${encryptedOutputStr.slice(0, 40)}...`,
  );

  let retryTimes = 0;
  const start = Date.now();

  while (true) {
    await new Promise((resolve) => setTimeout(resolve, 2000));

    // Pass mint address to check endpoint
    let checkUrl = `${relayerUrl}/utxos/check?hex=${encryptedOutputStr}`;
    checkUrl += `&mint=${encodeURIComponent(mint.toString())}`;

    const res = await fetch(checkUrl);
    const resJson = (await res.json()) as {
      success: boolean;
      data: { exists: boolean; treeIndex?: number };
    };

    if (resJson.success && resJson.data?.exists) {
      const duration = ((Date.now() - start) / 1000).toFixed(2);
      logger.debug(`Token deposit confirmed in ${duration} seconds`);
      updateStatus("Token deposit confirmed!");

      return {
        signature,
        amount: BigInt(amount),
        commitment: outputCommitments[0],
      };
    }

    if (retryTimes >= 10) {
      throw new Error(
        "Transaction confirmation timeout. Refresh to see latest balance.",
      );
    }
    retryTimes++;
  }
}
