/**
 * Keypair module for Privacy SDK (Browser)
 *
 * Provides cryptographic keypair functionality for ZK proofs.
 * Based on Tornado Cash Nova keypair implementation.
 */

import BN from 'bn.js';
import { ethers } from 'ethers';
import type { LightWasm } from '@lightprotocol/hasher.rs';
import { FIELD_SIZE } from './constants.js';

/**
 * ZK Keypair for UTXO ownership
 *
 * Uses Poseidon hash for public key derivation.
 * Private key is a random 31-byte value within the field size.
 */
export class Keypair {
  public privkey: BN;
  public pubkey: BN;
  private lightWasm: LightWasm;

  constructor(privkeyHex: string, lightWasm: LightWasm) {
    const rawDecimal = BigInt(privkeyHex);
    this.privkey = new BN((rawDecimal % BigInt(FIELD_SIZE.toString())).toString());
    this.lightWasm = lightWasm;
    // Compute pubkey as Poseidon hash of privkey
    this.pubkey = new BN(this.lightWasm.poseidonHashString([this.privkey.toString()]));
  }

  /**
   * Sign a message using keypair private key
   *
   * @param commitment - The commitment hash
   * @param merklePath - The merkle path index
   * @returns Signature as Poseidon hash
   */
  sign(commitment: string, merklePath: string): string {
    return this.lightWasm.poseidonHashString([
      this.privkey.toString(),
      commitment,
      merklePath,
    ]);
  }

  /**
   * Generate a new random keypair
   */
  static async generateNew(lightWasm: LightWasm): Promise<Keypair> {
    // Use ethers.js to generate a random private key
    // This is compatible with browser environments
    const wallet = ethers.Wallet.createRandom();
    return new Keypair(wallet.privateKey, lightWasm);
  }

  /**
   * Create keypair from existing private key hex
   */
  static fromPrivateKey(privkeyHex: string, lightWasm: LightWasm): Keypair {
    return new Keypair(privkeyHex, lightWasm);
  }

  /**
   * Serialize keypair to JSON-compatible object
   */
  toJSON(): { privkey: string; pubkey: string } {
    return {
      privkey: this.privkey.toString(),
      pubkey: this.pubkey.toString(),
    };
  }
}
