/**
 * UTXO (Unspent Transaction Output) module for Privacy SDK (Browser)
 *
 * Provides UTXO functionality for private transactions.
 * Based on Tornado Cash Nova UTXO implementation.
 */

import BN from 'bn.js';
import { PublicKey } from '@solana/web3.js';
import { ethers } from 'ethers';
import type { LightWasm } from '@lightprotocol/hasher.rs';
import { Keypair } from '../crypto/keypair.js';
import { getMintAddressField } from '../operations/helpers.js';
import { SOL_MINT_ADDRESS } from '../crypto/constants.js';

export interface UtxoParams {
  lightWasm: LightWasm;
  amount?: BN | number | string;
  keypair?: Keypair;
  blinding?: BN | number | string;
  index?: number;
  mintAddress?: string;
  version?: 'v1' | 'v2' | 'v3';
  /** Optional pre-computed commitment from DB (avoids recomputation issues) */
  commitment?: string;
}

/**
 * UTXO represents an unspent transaction output in the privacy pool
 *
 * Contains:
 * - amount: Value in lamports or token base units
 * - blinding: Random value for commitment hiding
 * - keypair: Owner's ZK keypair
 * - index: Position in Merkle tree (0 if not yet inserted)
 * - mintAddress: Token mint (SOL or SPL token)
 */
export class Utxo {
  amount: BN;
  blinding: BN;
  keypair: Keypair;
  index: number;
  mintAddress: string;
  version: 'v1' | 'v2' | 'v3';
  private lightWasm: LightWasm;
  /** Pre-computed commitment from DB (if available) */
  private _commitment?: string;

  constructor({
    lightWasm,
    amount = new BN(0),
    keypair,
    blinding = new BN(Math.floor(Math.random() * 1000000000)),
    index = 0,
    mintAddress = SOL_MINT_ADDRESS,
    version = 'v2',
    commitment,
  }: UtxoParams) {
    this.amount = new BN(amount.toString());
    this.blinding = new BN(blinding.toString());
    this.lightWasm = lightWasm;
    this.keypair = keypair || new Keypair(ethers.Wallet.createRandom().privateKey, lightWasm);
    this.index = index;
    this.mintAddress = mintAddress;
    this.version = version;
    this._commitment = commitment;
  }

  /**
   * Set the commitment directly (from DB/API)
   * Use this when you have the commitment from the API instead of recomputing
   */
  setCommitment(commitment: string): void {
    this._commitment = commitment;
  }

  /**
   * Get the commitment hash for this UTXO
   *
   * commitment = Poseidon(amount, pubkey, blinding, mintAddressField)
   *
   * If a pre-computed commitment was provided (from DB), returns that instead
   * to avoid recomputation issues.
   */
  async getCommitment(): Promise<string> {
    // If we have a pre-computed commitment from DB, use it
    if (this._commitment) {
      return this._commitment;
    }

    const mintAddressField = getMintAddressField(new PublicKey(this.mintAddress));

    const commitment = this.lightWasm.poseidonHashString([
      this.amount.toString(),
      this.keypair.pubkey.toString(),
      this.blinding.toString(),
      mintAddressField,
    ]);

    return commitment;
  }

  /**
   * Get the nullifier for this UTXO
   *
   * nullifier = Poseidon(commitment, index, signature)
   * Used to prevent double-spending
   */
  async getNullifier(): Promise<string> {
    const commitment = await this.getCommitment();
    const signature = this.keypair.sign(commitment, new BN(this.index).toString());

    return this.lightWasm.poseidonHashString([
      commitment,
      new BN(this.index).toString(),
      signature,
    ]);
  }

  /**
   * Check if this UTXO has zero amount (empty UTXO)
   */
  isEmpty(): boolean {
    return this.amount.isZero();
  }

  /**
   * Serialize UTXO to JSON-compatible object
   */
  toJSON(): {
    amount: string;
    blinding: string;
    index: number;
    mintAddress: string;
    version: 'v1' | 'v2' | 'v3';
    pubkey: string;
  } {
    return {
      amount: this.amount.toString(),
      blinding: this.blinding.toString(),
      index: this.index,
      mintAddress: this.mintAddress,
      version: this.version,
      pubkey: this.keypair.pubkey.toString(),
    };
  }

  /**
   * Get UTXO details for debugging
   */
  async getDebugInfo(): Promise<Record<string, unknown>> {
    const utxoData: Record<string, unknown> = {
      amount: this.amount.toString(),
      blinding: this.blinding.toString(),
      index: this.index,
      mintAddress: this.mintAddress,
      keypair: {
        pubkey: this.keypair.pubkey.toString(),
      },
    };

    try {
      utxoData.commitment = await this.getCommitment();
      utxoData.nullifier = await this.getNullifier();
    } catch (error) {
      utxoData.error = error instanceof Error ? error.message : String(error);
    }

    return utxoData;
  }
}

/**
 * Create an empty UTXO (zero amount)
 */
export function createEmptyUtxo(lightWasm: LightWasm, mintAddress?: string): Utxo {
  return new Utxo({
    lightWasm,
    amount: new BN(0),
    mintAddress: mintAddress || SOL_MINT_ADDRESS,
  });
}
