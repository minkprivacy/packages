/**
 * Private Inbox Manager for Privacy SDK
 *
 * Private Inboxes are stealth addresses that:
 * 1. Receive tokens from any source (DEX, airdrops, etc.)
 * 2. Auto-forward incoming deposits to the privacy pool
 * 3. Support multiple inboxes per (zkPubkey, mint) pair
 */

import type { LightWasm } from "@lightprotocol/hasher.rs";
import { Connection, PublicKey } from "@solana/web3.js";
import BN from "bn.js";
import { Keypair } from "../crypto/keypair.js";
import type { AuthTokenGetter } from "../types/index.js";
import {
  DEFAULT_PROGRAM_ID,
  DEFAULT_ZK_ASSETS_PATH,
  FIELD_SIZE,
  MERKLE_TREE_DEPTH,
  SOL_MINT_ADDRESS,
} from "../crypto/constants.js";
import {
  deriveBlinding,
  deriveEncPrivKey,
  deriveEncPubKey,
  deriveEncryptionKey,
  ecdhSharedSecret,
  encryptNoteV3,
  generateEphemeralKeypair,
  secureZeroKey,
} from "../crypto/ecdh.js";
import {
  bytesToHex,
  getExtDataHash,
  getMintAddressField,
  queryRemoteTreeState,
} from "../operations/helpers.js";
import { ConsoleLogger } from '../logger/console.js';
import { parseProofToBytesArray, prove } from "../proofs/prover.js";

const logger = new ConsoleLogger({ prefix: '[Mink]', minLevel: 'info' });

/**
 * Inbox status
 */
export enum InboxStatus {
  Active = 0,
  Paused = 1,
}

/**
 * Private Inbox configuration
 */
export interface PrivateInbox {
  /** PDA address of the inbox */
  address: PublicKey;
  /** Owner's ZK public key */
  zkPubkey: BN;
  /** Owner's X25519 encryption public key for ECDH */
  encPubkey?: Uint8Array;
  /** Token mint */
  mint: PublicKey;
  /** Inbox nonce (for multiple inboxes) */
  nonce: number;
  /** Whether auto-forward is enabled */
  autoForward: boolean;
  /** Forward fee in basis points */
  forwardFeeBps: number;
  /** Pending balance waiting to be forwarded */
  pendingBalance: BN;
  /** Total amount forwarded to pool */
  totalForwarded: BN;
  /** Inbox status */
  status: InboxStatus;
}

/**
 * Parameters for creating a new inbox
 */
export interface CreateInboxParams {
  /** Token mint (defaults to SOL) */
  mint?: PublicKey;
  /** Enable auto-forward (defaults to true) */
  autoForward?: boolean;
  /** Forward fee in basis points (defaults to protocol default) */
  forwardFeeBps?: number;
  /** ZK assets path for proof generation (defaults to config) */
  zkAssetsPath?: string;
}

/**
 * Inbox registration proof for on-chain verification
 */
export interface InboxRegistrationProofData {
  /** Groth16 proof A point (G1) */
  proofA: number[];
  /** Groth16 proof B point (G2) */
  proofB: number[];
  /** Groth16 proof C point (G1) */
  proofC: number[];
  /** Message hash for anti-replay */
  messageHash: number[];
}

/**
 * Inbox configuration per (zkPubkey, mint)
 */
export interface InboxConfig {
  /** Associated ZK public key */
  zkPubkey: BN;
  /** Token mint */
  mint: PublicKey;
  /** Default forward fee for new inboxes */
  defaultForwardFeeBps: number;
  /** Minimum amount to trigger auto-forward */
  minForwardAmount: BN;
  /** Number of inboxes created */
  inboxCount: number;
}

/**
 * Result of generating a forward proof
 */
export interface ForwardProofResult {
  /** Parsed proof bytes for on-chain verification */
  proof: {
    proofA: number[];
    proofB: number[];
    proofC: number[];
  };
  /** Nullifier inputs for PDA derivation */
  nullifiers: {
    nullifier0: Uint8Array;
    nullifier1: Uint8Array;
  };
  /** Root used for the proof */
  root: Uint8Array;
  /** Public amount (positive for deposit) */
  publicAmount: Uint8Array;
  /** External data hash */
  extDataHash: Uint8Array;
  /** Input nullifiers for ZkProof struct */
  inputNullifiers: Uint8Array[];
  /** Output commitments */
  outputCommitments: Uint8Array[];
  /** External data for the transaction */
  extData: {
    recipient: PublicKey;
    extAmount: bigint;
    relayer: PublicKey;
    fee: bigint;
    encryptedOutput1: Uint8Array;
    encryptedOutput2: Uint8Array;
    mint: PublicKey;
  };
  /** Commitment values (for DB storage) */
  commitment0: string;
  commitment1: string;
}

// PDA Seeds
const PRIVATE_INBOX_SEED = Buffer.from("private_inbox");
const INBOX_CONFIG_SEED = Buffer.from("inbox_config");
const USER_IDENTITY_SEED = Buffer.from("user_identity");

/**
 * Manager for Private Inbox operations
 */
export class PrivateInboxManager {
  private lightWasm: LightWasm;
  private connection: Connection;
  private programId: PublicKey;
  private spendingKeypair: Keypair;
  private relayerUrl: string;
  private getAuthToken?: AuthTokenGetter;

  // Cache for sync access
  private cachedInboxes: PrivateInbox[] = [];

  constructor(params: {
    lightWasm: LightWasm;
    connection: Connection;
    programId?: PublicKey;
    spendingKeypair: Keypair;
    relayerUrl: string;
    getAuthToken?: AuthTokenGetter;
  }) {
    this.lightWasm = params.lightWasm;
    this.connection = params.connection;
    this.programId = params.programId || DEFAULT_PROGRAM_ID;
    this.spendingKeypair = params.spendingKeypair;
    this.relayerUrl = params.relayerUrl;
    this.getAuthToken = params.getAuthToken;
  }

  /**
   * Get the ZK public key as bytes
   */
  getZkPubkeyBytes(): Uint8Array {
    return new Uint8Array(this.spendingKeypair.pubkey.toArray("be", 32));
  }

  /**
   * Get the ZK public key as hex string (64 chars, padded)
   * Used for relayer API calls
   */
  getZkPubkeyHex(): string {
    return this.spendingKeypair.pubkey.toString(16).padStart(64, "0");
  }

  /**
   * Get the X25519 encryption public key for ECDH
   *
   * This key is derived from the spending private key and used for:
   * 1. Storing in inbox registration (enc_pubkey field)
   * 2. Enabling relayer to encrypt blinding values during forward
   * 3. Allowing owner to decrypt and recover UTXO blinding values
   *
   * @returns X25519 public key (32 bytes)
   */
  getEncPubKey(): Uint8Array {
    const encPrivKey = deriveEncPrivKey(this.spendingKeypair.privkey);
    return deriveEncPubKey(encPrivKey);
  }

  /**
   * Get the X25519 encryption private key for ECDH
   *
   * WARNING: This is sensitive material. Only use for decryption.
   *
   * @returns X25519 private key (32 bytes)
   */
  getEncPrivKey(): Uint8Array {
    return deriveEncPrivKey(this.spendingKeypair.privkey);
  }

  /**
   * Derive the inbox config PDA
   */
  deriveInboxConfigPDA(mint: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [INBOX_CONFIG_SEED, this.getZkPubkeyBytes(), mint.toBuffer()],
      this.programId,
    );
  }

  /**
   * Derive a private inbox PDA
   */
  deriveInboxPDA(mint: PublicKey, nonce: number): [PublicKey, number] {
    const nonceBuffer = Buffer.alloc(8);
    nonceBuffer.writeBigUInt64LE(BigInt(nonce));

    return PublicKey.findProgramAddressSync(
      [
        PRIVATE_INBOX_SEED,
        this.getZkPubkeyBytes(),
        mint.toBuffer(),
        nonceBuffer,
      ],
      this.programId,
    );
  }

  /**
   * Derive user identity PDA
   */
  deriveUserIdentityPDA(): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [USER_IDENTITY_SEED, this.getZkPubkeyBytes()],
      this.programId,
    );
  }

  /**
   * Generate a ZK proof for inbox registration
   * Proves ownership of the zkPubkey without revealing the private key
   *
   * @param mint - Token mint for the inbox
   * @param nonce - Inbox nonce
   * @param slot - Current Solana slot (for anti-replay)
   * @param zkAssetsPath - Path/URL to ZK circuit assets
   */
  async generateInboxProof(
    mint: PublicKey,
    nonce: number,
    slot: number,
    zkAssetsPath: string = DEFAULT_ZK_ASSETS_PATH,
  ): Promise<InboxRegistrationProofData> {
    // 1. Calculate messageHash = Poseidon(mint_bytes_as_field, slot, nonce)
    // This binds the proof to specific registration parameters for anti-replay
    const mintBytes = mint.toBuffer();
    // Convert mint to field element (take first 31 bytes to stay in field)
    const mintField = new BN(mintBytes.slice(0, 31)).mod(FIELD_SIZE);

    const messageHash = this.lightWasm.poseidonHashString([
      mintField.toString(),
      slot.toString(),
      nonce.toString(),
    ]);

    logger.debug(
      `Generating inbox proof: mint=${mint.toBase58()}, nonce=${nonce}, slot=${slot}`,
    );
    logger.debug(`  messageHash=${messageHash}`);

    // 2. Prepare circuit inputs
    const circuitInput = {
      // Public inputs
      zkPubkey: this.spendingKeypair.pubkey.toString(),
      messageHash: messageHash,
      // Private input
      privateKey: this.spendingKeypair.privkey.toString(),
    };

    // 3. Generate proof using inbox_registration circuit
    const wasmUrl = `${zkAssetsPath}/inbox_registration.wasm`;
    const zkeyUrl = `${zkAssetsPath}/inbox_registration.zkey`;

    logger.debug(`Loading circuit from ${wasmUrl}`);

    const { proof } = await prove(circuitInput, wasmUrl, zkeyUrl);

    // 4. Parse proof to byte arrays
    const { proofA, proofB, proofC } = parseProofToBytesArray(proof);

    // 5. Convert messageHash to bytes (big-endian, 32 bytes)
    const messageHashBN = new BN(messageHash);
    const messageHashBytes = Array.from(messageHashBN.toArray("be", 32));

    logger.debug(`Inbox proof generated successfully`);

    return {
      proofA,
      proofB,
      proofC,
      messageHash: messageHashBytes,
    };
  }

  /**
   * Create a new Private Inbox with ZK proof of ownership
   *
   * If an inbox already exists for this mint, returns the existing one.
   * Use `forceCreate: true` to create additional inboxes (higher nonce).
   *
   * @param params - Creation parameters
   */
  async createInbox(
    params: CreateInboxParams = {},
  ): Promise<{ inbox: PrivateInbox; signature: string }> {
    const mint = params.mint || new PublicKey(SOL_MINT_ADDRESS);
    const autoForward = params.autoForward ?? true;
    const forwardFeeBps = params.forwardFeeBps;
    const zkAssetsPath = params.zkAssetsPath || DEFAULT_ZK_ASSETS_PATH;

    // Get current inbox count to determine nonce
    const config = await this.getInboxConfig(mint);
    const nonce = config ? config.inboxCount : 0;

    // Check if user already has an inbox for this mint
    // If so, return the first existing one instead of creating duplicate
    if (nonce > 0) {
      logger.debug(`User already has ${nonce} inbox(es) for mint ${mint.toBase58()}`);

      // Try to fetch the first inbox (nonce 0)
      const existingInbox = await this.getInbox(mint, 0);
      if (existingInbox) {
        logger.info(`Returning existing inbox at nonce 0 instead of creating new one`);
        // Add to cache if not already there
        if (!this.cachedInboxes.find(i => i.address.equals(existingInbox.address))) {
          this.cachedInboxes.push(existingInbox);
        }
        return { inbox: existingInbox, signature: 'existing' };
      }
    }

    // Also check on-chain if the PDA at nonce 0 already exists
    // (handles case where config doesn't exist but inbox does)
    const [checkPDA] = this.deriveInboxPDA(mint, 0);
    const existingAccount = await this.connection.getAccountInfo(checkPDA);
    if (existingAccount) {
      logger.debug(`Inbox PDA already exists at ${checkPDA.toBase58()}, fetching data...`);
      const existingInbox = await this.getInbox(mint, 0);
      if (existingInbox) {
        logger.info(`Returning existing inbox instead of creating duplicate`);
        if (!this.cachedInboxes.find(i => i.address.equals(existingInbox.address))) {
          this.cachedInboxes.push(existingInbox);
        }
        return { inbox: existingInbox, signature: 'existing' };
      }
    }

    // Get current slot for anti-replay
    const slot = await this.connection.getSlot();

    // Derive PDAs for relayer
    const [inboxPDA] = this.deriveInboxPDA(mint, nonce);
    const [configPDA] = this.deriveInboxConfigPDA(mint);
    const [identityPDA] = this.deriveUserIdentityPDA();

    // Derive X25519 encryption public key for ECDH
    const encPubkey = this.getEncPubKey();

    logger.debug(
      `Creating inbox at ${inboxPDA.toBase58()} with nonce ${nonce}`,
    );

    // Generate ZK proof of ownership
    logger.debug("Generating ZK proof for inbox registration...");
    const proof = await this.generateInboxProof(
      mint,
      nonce,
      slot,
      zkAssetsPath,
    );

    // Submit via the relayer API with proof and PDAs
    const result = await this.submitToRelayer("inbox/create", {
      zkPubkey: this.getZkPubkeyHex(),
      encPubkey: Array.from(encPubkey),
      mint: mint.toBase58(),
      nonce,
      autoForward,
      forwardFeeBps,
      // PDAs for instruction building
      inboxPDA: inboxPDA.toBase58(),
      configPDA: configPDA.toBase58(),
      identityPDA: identityPDA.toBase58(),
      // ZK proof data
      proof: {
        proofA: proof.proofA,
        proofB: proof.proofB,
        proofC: proof.proofC,
        messageHash: proof.messageHash,
      },
    });

    const inbox: PrivateInbox = {
      address: inboxPDA,
      zkPubkey: this.spendingKeypair.pubkey,
      encPubkey,
      mint,
      nonce,
      autoForward,
      forwardFeeBps: forwardFeeBps ?? 100, // Default 1%
      pendingBalance: new BN(0),
      totalForwarded: new BN(0),
      status: InboxStatus.Active,
    };

    // Add to cache
    this.cachedInboxes.push(inbox);

    return { inbox, signature: result.signature };
  }

  /**
   * Get inbox configuration for a mint
   */
  async getInboxConfig(mint: PublicKey): Promise<InboxConfig | null> {
    const [configPDA] = this.deriveInboxConfigPDA(mint);

    try {
      const accountInfo = await this.connection.getAccountInfo(configPDA);
      if (!accountInfo) {
        return null;
      }

      // Parse account data
      // Note: In production, use Anchor's deserialization
      const data = accountInfo.data;
      const offset = 8; // Skip discriminator

      return {
        zkPubkey: new BN(Array.from(data.slice(offset, offset + 32)), "be"),
        mint: new PublicKey(data.slice(offset + 32, offset + 64)),
        defaultForwardFeeBps: data.readUInt16LE(offset + 64),
        minForwardAmount: new BN(data.slice(offset + 66, offset + 74), "le"),
        inboxCount: Number(data.readBigUInt64LE(offset + 74)),
      };
    } catch (error) {
      logger.debug(`Failed to fetch inbox config: ${error}`);
      return null;
    }
  }

  /**
   * Get pending inboxes with balance above threshold
   *
   * This method fetches inboxes that have pending balance waiting to be forwarded.
   * Used for auto-forward functionality.
   *
   * @param minAmount - Minimum pending balance in lamports (default: 1_000_000 = 0.001 SOL)
   */
  async getPendingInboxes(
    minAmount: bigint = BigInt(1_000_000),
  ): Promise<PrivateInbox[]> {
    try {
      const zkPubkey = this.getZkPubkeyHex();

      // Get auth token
      const token = this.getAuthToken ? await this.getAuthToken() : null;
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
        logger.info('[getPendingInboxes] Using auth token');
      } else {
        logger.warn('[getPendingInboxes] No auth token available');
      }

      const queryParams = new URLSearchParams({
        zkPubkey,
        minAmount: minAmount.toString(),
      });

      const url = `${this.relayerUrl}/inbox/pending?${queryParams.toString()}`;
      logger.info(`[getPendingInboxes] Fetching from: ${url}`);

      const response = await fetch(url, { headers });
      logger.info(`[getPendingInboxes] Response status: ${response.status}`);

      if (!response.ok) {
        const errorText = await response.text();
        logger.warn(`[getPendingInboxes] API error: ${errorText}`);
        throw new Error(`Failed to fetch pending inboxes: ${response.status}`);
      }

      const result = (await response.json()) as {
        success: boolean;
        data: {
          inboxes: Array<{
            address: string;
            zkPubkey: string;
            mint: string;
            nonce: number;
            autoForward: boolean;
            forwardFeeBps: number;
            pendingBalance: string;
            totalForwarded: string;
            status: string | number;
          }>;
        };
      };

      if (!result.success) {
        throw new Error("API returned error");
      }

      return result.data.inboxes.map((inbox) => ({
        address: new PublicKey(inbox.address),
        zkPubkey: this.spendingKeypair.pubkey,
        mint: new PublicKey(inbox.mint),
        nonce: inbox.nonce,
        autoForward: inbox.autoForward,
        forwardFeeBps: inbox.forwardFeeBps,
        pendingBalance: new BN(inbox.pendingBalance),
        totalForwarded: new BN(inbox.totalForwarded),
        status:
          typeof inbox.status === "string"
            ? inbox.status === "active"
              ? InboxStatus.Active
              : InboxStatus.Paused
            : (inbox.status as InboxStatus),
      }));
    } catch (error) {
      logger.error(`Failed to fetch pending inboxes: ${error}`);
      return [];
    }
  }

  /**
   * Discover inboxes directly on-chain by scanning PDAs
   *
   * This is a fallback when the relayer API is unavailable or hasn't indexed yet.
   * It uses the InboxConfig to know how many inboxes exist, then fetches each one.
   *
   * @param mint - Token mint to discover inboxes for
   * @returns Array of discovered inboxes
   */
  async discoverInboxesOnChain(mint: PublicKey): Promise<PrivateInbox[]> {
    const discovered: PrivateInbox[] = [];

    try {
      // Get inbox count from on-chain config
      const config = await this.getInboxConfig(mint);
      const inboxCount = config?.inboxCount ?? 0;

      if (inboxCount === 0) {
        logger.debug(`No inboxes found on-chain for mint ${mint.toBase58()}`);
        return [];
      }

      logger.debug(`Discovering ${inboxCount} inboxes on-chain for mint ${mint.toBase58()}`);

      // Fetch each inbox by nonce
      for (let nonce = 0; nonce < inboxCount; nonce++) {
        const inbox = await this.getInbox(mint, nonce);
        if (inbox) {
          discovered.push(inbox);
        }
      }

      logger.debug(`Discovered ${discovered.length} inboxes on-chain`);
      return discovered;
    } catch (error) {
      logger.error(`Failed to discover inboxes on-chain: ${error}`);
      return [];
    }
  }

  /**
   * Get all inboxes for the user
   *
   * First tries the relayer API (faster, indexed data).
   * Falls back to on-chain discovery if API fails or returns empty.
   *
   * @param mint - Optional mint filter
   */
  async getInboxes(mint?: PublicKey): Promise<PrivateInbox[]> {
    let inboxes: PrivateInbox[] = [];

    // Try relayer API first
    try {
      const token = this.getAuthToken ? await this.getAuthToken() : null;
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
        logger.info('[getInboxes] Using auth token');
      } else {
        logger.warn('[getInboxes] No auth token available');
      }

      const queryParams = new URLSearchParams({
        zkPubkey: this.getZkPubkeyHex(),
      });
      if (mint) {
        queryParams.append("mint", mint.toBase58());
      }

      const url = `${this.relayerUrl}/inbox/list?${queryParams.toString()}`;
      logger.info(`[getInboxes] Fetching from: ${url}`);

      const response = await fetch(url, { headers });
      logger.info(`[getInboxes] Response status: ${response.status}`);

      if (response.ok) {
        const result = (await response.json()) as {
          success: boolean;
          data: {
            inboxes: Array<{
              address: string;
              mint: string;
              nonce: number;
              autoForward: boolean;
              forwardFeeBps: number;
              pendingBalance: string;
              totalForwarded: string;
              status: string | number;
            }>;
          };
        };

        if (result.success && result.data.inboxes.length > 0) {
          inboxes = result.data.inboxes.map((inbox) => ({
            address: new PublicKey(inbox.address),
            zkPubkey: this.spendingKeypair.pubkey,
            mint: new PublicKey(inbox.mint),
            nonce: inbox.nonce,
            autoForward: inbox.autoForward,
            forwardFeeBps: inbox.forwardFeeBps,
            pendingBalance: new BN(inbox.pendingBalance),
            totalForwarded: new BN(inbox.totalForwarded),
            status:
              typeof inbox.status === "string"
                ? inbox.status === "active"
                  ? InboxStatus.Active
                  : InboxStatus.Paused
                : (inbox.status as InboxStatus),
          }));

          logger.info(`[getInboxes] Fetched ${inboxes.length} inboxes from API`);
        } else {
          logger.info(`[getInboxes] API returned empty or failed: success=${result.success}, count=${result.data?.inboxes?.length ?? 0}`);
        }
      } else {
        const errorText = await response.text();
        logger.warn(`[getInboxes] API error ${response.status}: ${errorText}`);
      }
    } catch (error) {
      logger.warn(`[getInboxes] Relayer API failed: ${error}`);
    }

    // Fallback to on-chain discovery if API returned empty or failed
    if (inboxes.length === 0) {
      logger.info("[getInboxes] API returned no inboxes, trying on-chain discovery...");

      // If mint specified, only discover for that mint
      // Otherwise, discover for SOL (most common)
      const targetMint = mint || new PublicKey(SOL_MINT_ADDRESS);
      inboxes = await this.discoverInboxesOnChain(targetMint);
    }

    // Update cache
    this.cachedInboxes = inboxes;

    return inboxes;
  }

  /**
   * Get all cached inboxes (sync)
   *
   * Returns inboxes from the local cache. Call getInboxes() to refresh.
   */
  getAllInboxes(): PrivateInbox[] {
    return this.cachedInboxes;
  }

  /**
   * Refresh a specific inbox from on-chain data
   *
   * @param inbox - The inbox to refresh
   * @returns Updated inbox data
   */
  async refreshInbox(inbox: PrivateInbox): Promise<PrivateInbox> {
    const refreshed = await this.getInbox(inbox.mint, inbox.nonce);
    if (!refreshed) {
      throw new Error("Inbox not found on-chain");
    }

    // Update cache
    const index = this.cachedInboxes.findIndex(
      (i) => i.address.equals(inbox.address)
    );
    if (index >= 0) {
      this.cachedInboxes[index] = refreshed;
    } else {
      this.cachedInboxes.push(refreshed);
    }

    return refreshed;
  }

  /**
   * Get a specific inbox by nonce
   */
  async getInbox(mint: PublicKey, nonce: number): Promise<PrivateInbox | null> {
    const [inboxPDA] = this.deriveInboxPDA(mint, nonce);

    try {
      const accountInfo = await this.connection.getAccountInfo(inboxPDA);
      if (!accountInfo) {
        return null;
      }

      // Parse account data
      // Layout: discriminator(8) + zk_pubkey(32) + enc_pubkey(32) + mint(32) + nonce(8)
      //         + auto_forward(1) + forward_fee_bps(2) + pending_balance(8)
      //         + total_forwarded(8) + status(1) + bump(1)
      const data = accountInfo.data;
      const offset = 8; // Skip discriminator

      return {
        address: inboxPDA,
        zkPubkey: new BN(Array.from(data.slice(offset, offset + 32)), "be"),
        encPubkey: new Uint8Array(data.slice(offset + 32, offset + 64)),
        mint: new PublicKey(data.slice(offset + 64, offset + 96)),
        nonce: Number(data.readBigUInt64LE(offset + 96)),
        autoForward: data[offset + 104] === 1,
        forwardFeeBps: data.readUInt16LE(offset + 105),
        pendingBalance: new BN(data.slice(offset + 107, offset + 115), "le"),
        totalForwarded: new BN(data.slice(offset + 115, offset + 123), "le"),
        status: data[offset + 123] as InboxStatus,
      };
    } catch (error) {
      logger.debug(`Failed to fetch inbox: ${error}`);
      return null;
    }
  }

  /**
   * Generate ZK proof for forward_to_pool
   *
   * This treats the forward as a "deposit" from the circuit's perspective:
   * - 2 inputs with zero amount (padding, no merkle proof needed)
   * - 2 outputs: real commitment + zero padding commitment
   * - publicAmount is positive (deposit into pool)
   *
   * @param inbox - The inbox to forward from
   * @param netAmount - Net amount after fees (must be calculated by caller)
   * @param relayer - Relayer public key (for fee recipient)
   * @param zkAssetsPath - Path to ZK circuit assets
   */
  async generateForwardProof(params: {
    inbox: PrivateInbox;
    netAmount: bigint;
    relayer: PublicKey;
    zkAssetsPath?: string;
  }): Promise<ForwardProofResult> {
    const { inbox, netAmount, relayer } = params;
    const zkAssetsPath = params.zkAssetsPath || DEFAULT_ZK_ASSETS_PATH;

    logger.debug(
      `Generating forward proof for inbox ${inbox.address.toBase58()}, netAmount=${netAmount}`,
    );

    // 1. Get current tree state from relayer
    const { root, nextIndex } = await queryRemoteTreeState(
      inbox.mint.toBase58(),
      this.relayerUrl,
    );
    logger.debug(
      `Tree state: root=${root.slice(0, 20)}..., nextIndex=${nextIndex}`,
    );

    // 2. Get mint field element
    const mintField = getMintAddressField(inbox.mint);

    // 3. Generate ephemeral keypair and derive shared secret FIRST
    // This is needed to derive blindings deterministically for V3 format
    const ephemeralKeypair = generateEphemeralKeypair();
    const encPubkeyBytes = inbox.encPubkey || this.getEncPubKey();
    const sharedSecret = ecdhSharedSecret(
      ephemeralKeypair.privateKey,
      encPubkeyBytes,
    );
    const encKey = deriveEncryptionKey(sharedSecret);

    // 4. Generate blindings
    // Input blindings can be random (they're for zero-amount padding inputs)
    const inBlinding0 = this.generateRandomFieldElement();
    const inBlinding1 = this.generateRandomFieldElement();
    // OUTPUT blindings MUST be derived from ECDH shared secret!
    // This ensures they can be recovered during decryption via deriveBlindingFromV3
    // Use the SAME blinding for both outputs - commitments are still unique due to different amounts
    const outBlinding = deriveBlinding(sharedSecret).toString();
    const outBlinding0 = outBlinding;
    const outBlinding1 = outBlinding;

    // 5. Get ZK pubkey
    const zkPubkey = this.spendingKeypair.pubkey.toString();
    const zkPrivkey = this.spendingKeypair.privkey.toString();

    // 6. Calculate input commitments (zero amount, padding)
    const inCommitment0 = this.lightWasm.poseidonHashString([
      "0",
      zkPubkey,
      inBlinding0,
      mintField,
    ]);
    const inCommitment1 = this.lightWasm.poseidonHashString([
      "0",
      zkPubkey,
      inBlinding1,
      mintField,
    ]);

    // 7. Calculate input nullifiers (for zero amount inputs)
    // signature = Poseidon(privkey, commitment, pathIndex)
    // nullifier = Poseidon(commitment, pathIndex, signature)
    const sig0 = this.lightWasm.poseidonHashString([
      zkPrivkey,
      inCommitment0,
      "0",
    ]);
    const sig1 = this.lightWasm.poseidonHashString([
      zkPrivkey,
      inCommitment1,
      "0",
    ]);
    const nullifier0 = this.lightWasm.poseidonHashString([
      inCommitment0,
      "0",
      sig0,
    ]);
    const nullifier1 = this.lightWasm.poseidonHashString([
      inCommitment1,
      "0",
      sig1,
    ]);

    // 8. Calculate output commitments using ECDH-derived blindings
    const outCommitment0 = this.lightWasm.poseidonHashString([
      netAmount.toString(),
      zkPubkey,
      outBlinding0,
      mintField,
    ]);
    // Second output is zero padding
    const outCommitment1 = this.lightWasm.poseidonHashString([
      "0",
      zkPubkey,
      outBlinding1,
      mintField,
    ]);

    logger.debug(
      `Output commitments: c0=${outCommitment0.slice(0, 20)}..., c1=${outCommitment1.slice(0, 20)}...`,
    );

    // 9. Create encrypted outputs
    try {

      // Encrypt output 0 (real amount)
      const encryptedOutput1 = await encryptNoteV3(
        ephemeralKeypair.publicKey,
        encKey,
        { amount: netAmount, index: nextIndex },
      );

      // Encrypt output 1 (zero padding) - MUST be properly encrypted, not all zeros!
      // Otherwise backfill.service.ts will treat it as "legacy" and corrupt the UTXO.
      // Even though amount is 0, we need valid encrypted output for merkle proof consistency.
      const encryptedOutput2 = await encryptNoteV3(
        ephemeralKeypair.publicKey,
        encKey,
        { amount: BigInt(0), index: nextIndex + 1 },
      );

      // 9. Build extData
      const extData = {
        recipient: relayer, // For deposits, recipient doesn't matter
        extAmount: netAmount,
        relayer,
        fee: BigInt(0), // Forward fee is handled separately on-chain
        encryptedOutput1,
        encryptedOutput2,
        mint: inbox.mint,
      };

      // 10. Calculate extDataHash
      const extDataHashBytes = getExtDataHash({
        recipient: extData.recipient,
        extAmount: extData.extAmount.toString(),
        encryptedOutput1,
        encryptedOutput2,
        fee: "0",
        feeRecipient: extData.relayer,
        mintAddress: extData.mint,
      });
      const extDataHash = new BN(extDataHashBytes).mod(FIELD_SIZE).toString();

      // 11. Calculate publicAmount as field element (positive = deposit)
      // For ZK circuit, publicAmount needs to be in field representation
      const publicAmountBN = new BN(netAmount.toString());
      const publicAmount = publicAmountBN.toString();

      // 12. Build empty merkle paths (for zero inputs, we use dummy paths)
      // inPathIndices is just the leaf index for each input (not a binary path)
      // inPathElements is the sibling hashes along the path
      const emptyPathElements = Array(MERKLE_TREE_DEPTH).fill("0");

      // 13. Build circuit input
      const circuitInput = {
        // Public inputs
        root,
        publicAmount,
        extDataHash,
        inputNullifier: [nullifier0, nullifier1],
        outputCommitment: [outCommitment0, outCommitment1],

        // Private inputs
        inPrivateKey: [zkPrivkey, zkPrivkey],
        inAmount: ["0", "0"],
        inBlinding: [inBlinding0, inBlinding1],
        mintAddress: mintField,
        inPathIndices: [0, 0], // Leaf indices for dummy inputs
        inPathElements: [emptyPathElements, emptyPathElements],
        outAmount: [netAmount.toString(), "0"],
        outBlinding: [outBlinding0, outBlinding1],
        outPubkey: [zkPubkey, zkPubkey],
      };

      logger.debug("Circuit input prepared, generating proof...");

      // 14. Generate ZK proof
      const { proof, publicSignals } = await prove(
        circuitInput,
        `${zkAssetsPath}/stealth.wasm`,
        `${zkAssetsPath}/stealth.zkey`,
      );

      // 15. Parse proof to bytes array
      const { proofA, proofB, proofC } = parseProofToBytesArray(proof);

      // 16. Parse public signals to bytes - MUST use publicSignals from circuit, not input values!
      // Public signals order: [root, publicAmount, extDataHash, nullifier0, nullifier1, commitment0, commitment1]
      const publicSignalsBytes = publicSignals.map((signal) => {
        const bn = new BN(signal);
        return new Uint8Array(bn.toArray("be", 32));
      });

      const rootBytes = publicSignalsBytes[0];
      const publicAmountBytes = publicSignalsBytes[1];
      const extDataHashBytesArray = publicSignalsBytes[2];
      const nullifier0Bytes = publicSignalsBytes[3];
      const nullifier1Bytes = publicSignalsBytes[4];
      const outCommitment0Bytes = publicSignalsBytes[5];
      const outCommitment1Bytes = publicSignalsBytes[6];

      logger.debug("Forward proof generated successfully");

      return {
        proof: { proofA, proofB, proofC },
        nullifiers: {
          nullifier0: nullifier0Bytes,
          nullifier1: nullifier1Bytes,
        },
        root: rootBytes,
        publicAmount: publicAmountBytes,
        extDataHash: extDataHashBytesArray,
        inputNullifiers: [nullifier0Bytes, nullifier1Bytes],
        outputCommitments: [outCommitment0Bytes, outCommitment1Bytes],
        extData,
        commitment0: outCommitment0,
        commitment1: outCommitment1,
      };
    } finally {
      // Securely clear ephemeral private key
      secureZeroKey(ephemeralKeypair.privateKey);
    }
  }

  /**
   * Forward inbox balance to pool with ZK proof
   *
   * This is the main entry point for forwarding inbox balance.
   * It generates a ZK proof locally and sends it to the relayer.
   *
   * @param inbox - The inbox to forward from
   * @param amount - Amount to forward (optional, uses actual lamport balance minus rent)
   * @param zkAssetsPath - Optional path to ZK assets
   */
  async forwardToPool(
    inbox: PrivateInbox,
    zkAssetsPath?: string,
  ): Promise<{ signature: string; amountForwarded: BN; treeIndex: number }> {
    // 1. Get ACTUAL lamport balance from on-chain (must match what program sees)
    // The on-chain program uses: lamports - rent_exempt_minimum
    const inboxLamports = await this.connection.getBalance(inbox.address);

    // Get rent exempt minimum from Solana (same as Rent::get()?.minimum_balance in Rust)
    // PrivateInbox::LEN = 8 + 32 + 32 + 32 + 8 + 1 + 2 + 8 + 8 + 1 + 1 = 133 bytes
    const PRIVATE_INBOX_LEN = 133;
    const rentExemptMinimum = await this.connection.getMinimumBalanceForRentExemption(
      PRIVATE_INBOX_LEN,
    );

    // Forwardable amount = lamports - rent (same calculation as on-chain)
    const forwardableAmount = inboxLamports > rentExemptMinimum
      ? inboxLamports - rentExemptMinimum
      : 0;

    if (forwardableAmount === 0) {
      throw new Error("No balance to forward (inbox balance below rent minimum)");
    }

    // 2. Calculate fee and net amount (same logic as on-chain)
    // On-chain: fee = (amount * fee_bps) / 10_000
    const feeBps = BigInt(inbox.forwardFeeBps);
    const fee = (BigInt(forwardableAmount) * feeBps) / BigInt(10_000);
    const netAmount = BigInt(forwardableAmount) - fee;

    logger.debug(
      `Forward calculation: inboxLamports=${inboxLamports}, rent=${rentExemptMinimum}, ` +
      `forwardable=${forwardableAmount}, feeBps=${feeBps}, fee=${fee}, netAmount=${netAmount}`,
    );

    if (netAmount <= BigInt(0)) {
      throw new Error("Net amount is zero or negative after fee deduction");
    }

    // 3. Generate ZK proof
    const proofResult = await this.generateForwardProof({
      inbox,
      netAmount,
      relayer: new PublicKey(await this.getRelayerAddress()),
      zkAssetsPath,
    });

    // 4. Send proof to relayer
    const result = await this.submitToRelayer("inbox/forward-with-proof", {
      inboxAddress: inbox.address.toBase58(),
      // Nullifiers
      nullifier0: bytesToHex(proofResult.nullifiers.nullifier0),
      nullifier1: bytesToHex(proofResult.nullifiers.nullifier1),
      // ZkProof
      proofA: Array.from(new Uint8Array(proofResult.proof.proofA)),
      proofB: Array.from(new Uint8Array(proofResult.proof.proofB)),
      proofC: Array.from(new Uint8Array(proofResult.proof.proofC)),
      root: bytesToHex(proofResult.root),
      inputNullifiers: proofResult.inputNullifiers.map((n) => bytesToHex(n)),
      outputCommitments: proofResult.outputCommitments.map((c) =>
        bytesToHex(c),
      ),
      publicAmount: bytesToHex(proofResult.publicAmount),
      extDataHash: bytesToHex(proofResult.extDataHash),
      // ExtData
      recipient: proofResult.extData.recipient.toBase58(),
      extAmount: proofResult.extData.extAmount.toString(),
      relayer: proofResult.extData.relayer.toBase58(),
      fee: proofResult.extData.fee.toString(),
      encryptedOutput1: bytesToHex(proofResult.extData.encryptedOutput1),
      encryptedOutput2: bytesToHex(proofResult.extData.encryptedOutput2),
      mint: proofResult.extData.mint.toBase58(),
    });

    return {
      signature: result.signature,
      amountForwarded: new BN(netAmount.toString()),
      treeIndex: result.treeIndex as number,
    };
  }

  /**
   * Get the relayer's public key address
   */
  private async getRelayerAddress(): Promise<string> {
    // Fetch relayer config from API
    const response = await fetch(`${this.relayerUrl}/config`);
    if (!response.ok) {
      throw new Error("Failed to fetch relayer config");
    }
    const config = (await response.json()) as {
      success: boolean;
      data: { relayer_pubkey: string };
    };
    if (!config.success || !config.data.relayer_pubkey) {
      throw new Error("Relayer pubkey not available in config");
    }
    return config.data.relayer_pubkey;
  }

  /**
   * Generate a random field element for blinding
   */
  private generateRandomFieldElement(): string {
    const bytes = new Uint8Array(31); // 31 bytes to ensure it's within field
    crypto.getRandomValues(bytes);
    const bn = new BN(Array.from(bytes), "be");
    return bn.mod(FIELD_SIZE).toString();
  }

  /**
   * Get the receive address for an inbox
   * This is the address that external parties should send tokens to
   */
  getReceiveAddress(inbox: PrivateInbox): string {
    return inbox.address.toBase58();
  }

  /**
   * Format inbox address for display
   * Includes checksum and human-readable prefix
   */
  formatReceiveAddress(inbox: PrivateInbox): string {
    const base58 = inbox.address.toBase58();
    // Add mink: prefix for clarity
    return `mink:inbox:${base58}`;
  }

  /**
   * Parse a formatted receive address
   */
  static parseReceiveAddress(formatted: string): PublicKey {
    let address = formatted;
    if (formatted.startsWith("mink:inbox:")) {
      address = formatted.slice("mink:inbox:".length);
    }
    return new PublicKey(address);
  }

  /**
   * Update inbox settings
   */
  async updateInbox(
    inbox: PrivateInbox,
    updates: {
      autoForward?: boolean;
      forwardFeeBps?: number;
      status?: InboxStatus;
    },
  ): Promise<{ signature: string }> {
    const result = await this.submitToRelayer("inbox/update", {
      inboxAddress: inbox.address.toBase58(),
      ...updates,
    });

    return { signature: result.signature };
  }

  /**
   * Get pending deposits for an inbox
   */
  async getPendingDeposits(inbox: PrivateInbox): Promise<{
    balance: BN;
    lastUpdated: Date;
  }> {
    // Refresh inbox data
    const refreshed = await this.getInbox(inbox.mint, inbox.nonce);
    if (!refreshed) {
      throw new Error("Inbox not found");
    }

    return {
      balance: refreshed.pendingBalance,
      lastUpdated: new Date(),
    };
  }

  /**
   * Submit request to relayer API
   */
  private async submitToRelayer(
    endpoint: string,
    data: Record<string, unknown>,
  ): Promise<{ signature: string; [key: string]: unknown }> {
    const token = this.getAuthToken ? await this.getAuthToken() : null;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const response = await fetch(`${this.relayerUrl}/${endpoint}`, {
      method: "POST",
      headers,
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Relayer request failed: ${response.status} - ${errorText}`,
      );
    }

    const result = (await response.json()) as {
      success: boolean;
      data: { signature: string; [key: string]: unknown };
    };

    if (!result.success) {
      throw new Error("Relayer returned error response");
    }

    return result.data;
  }
}
