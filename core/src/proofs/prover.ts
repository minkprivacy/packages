/**
 * ZK Proof Generation Utilities for Browser
 *
 * Adapted from privacycash SDK for browser environments.
 * Uses URLs to load circuit files instead of filesystem paths.
 */

import * as anchor from '@coral-xyz/anchor';
import { groth16 } from 'snarkjs';
// @ts-ignore - ffjavascript doesn't have proper types
import { utils } from 'ffjavascript';
import { FIELD_SIZE } from '../crypto/constants.js';
import { ConsoleLogger } from '../logger/console.js';
import BN from 'bn.js';

const logger = new ConsoleLogger({ prefix: '[Mink]', minLevel: 'info' });

// BN254 base field modulus (p) for G1 point negation
// p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
const BN254_FIELD_MODULUS = new BN(
  '21888242871839275222246405745257275088696311157297823662689037894645226208583'
);

// Type definitions
interface Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

interface FullProveResult {
  proof: Proof;
  publicSignals: string[];
}

// Cast groth16 to expected type
const groth16Typed = groth16 as {
  fullProve: (
    input: unknown,
    wasmFile: string,
    zkeyFile: string,
    logger?: unknown,
    wtnsCalcOptions?: { singleThread?: boolean },
    proverOptions?: { singleThread?: boolean }
  ) => Promise<FullProveResult>;
};

/**
 * Generates a ZK proof using snarkjs
 * Browser version uses URLs for circuit files
 *
 * @param input The circuit inputs to generate a proof for
 * @param wasmUrl URL to the .wasm circuit file
 * @param zkeyUrl URL to the .zkey proving key file
 * @param options Optional proof generation options
 * @returns A proof object with formatted proof elements and public signals
 */
export async function prove(
  input: unknown,
  wasmUrl: string,
  zkeyUrl: string,
  options?: { singleThread?: boolean }
): Promise<FullProveResult> {
  // In browser, snarkjs can fetch from URLs directly
  // Use single-threaded mode by default in browser for better compatibility
  const useSingleThread = options?.singleThread ?? true;
  const singleThreadOpts = useSingleThread ? { singleThread: true } : undefined;

  return await groth16Typed.fullProve(
    utils.stringifyBigInts(input),
    wasmUrl,
    zkeyUrl,
    undefined, // logger
    singleThreadOpts, // wtnsCalcOptions
    singleThreadOpts  // proverOptions
  );
}

/**
 * Generates a ZK proof using base path (convenience wrapper)
 *
 * @param input The circuit inputs
 * @param basePath Base path/URL for circuit files (without extension)
 * @param options Optional proof generation options
 */
export async function proveWithBasePath(
  input: unknown,
  basePath: string,
  options?: { singleThread?: boolean }
): Promise<FullProveResult> {
  return prove(
    input,
    `${basePath}.wasm`,
    `${basePath}.zkey`,
    options
  );
}

/**
 * Negate a G1 point y-coordinate for Groth16 verification
 * The verifier expects proof_a to be negated by the client
 * y_neg = field_modulus - y
 */
function negateG1Y(yBytes: number[]): number[] {
  // Convert bytes (big-endian) to BN
  const y = new BN(yBytes);
  // Negate: y_neg = p - y
  const yNeg = BN254_FIELD_MODULUS.sub(y);
  // Convert back to 32-byte big-endian array
  const result = yNeg.toArray('be', 32);
  return result;
}

/**
 * Parse proof to bytes array for on-chain verification
 * NOTE: proof_a is automatically negated as required by the Solana BN254 verifier
 */
export function parseProofToBytesArray(
  proof: Proof,
  compressed: boolean = false
): {
  proofA: number[];
  proofB: number[];
  proofC: number[];
} {
  const mydata = JSON.parse(JSON.stringify(proof));

  try {
    for (const i in mydata) {
      if (i === 'pi_a' || i === 'pi_c') {
        for (const j in mydata[i]) {
          mydata[i][j] = Array.from(
            utils.leInt2Buff(utils.unstringifyBigInts(mydata[i][j]), 32)
          ).reverse();
        }
      } else if (i === 'pi_b') {
        for (const j in mydata[i]) {
          for (const z in mydata[i][j]) {
            mydata[i][j][z] = Array.from(
              utils.leInt2Buff(utils.unstringifyBigInts(mydata[i][j][z]), 32)
            );
          }
        }
      }
    }

    if (compressed) {
      const proofA = mydata.pi_a[0];
      const proofAIsPositive = !yElementIsPositiveG1(new anchor.BN(mydata.pi_a[1]));
      proofA[0] = addBitmaskToByte(proofA[0], proofAIsPositive);

      const proofB = mydata.pi_b[0].flat().reverse();
      const proofBY = mydata.pi_b[1].flat().reverse();
      const proofBIsPositive = yElementIsPositiveG2(
        new anchor.BN(proofBY.slice(0, 32)),
        new anchor.BN(proofBY.slice(32, 64))
      );
      proofB[0] = addBitmaskToByte(proofB[0], proofBIsPositive);

      const proofC = mydata.pi_c[0];
      const proofCIsPositive = yElementIsPositiveG1(new anchor.BN(mydata.pi_c[1]));
      proofC[0] = addBitmaskToByte(proofC[0], proofCIsPositive);

      return { proofA, proofB, proofC };
    }

    // IMPORTANT: Negate proof_a's y-coordinate as required by Solana Groth16 verifier
    // The verifier comment says: "proof_a should already be negated by the client"
    const proofA_x = mydata.pi_a[0];
    const proofA_y = negateG1Y(mydata.pi_a[1]); // Negate y-coordinate

    return {
      proofA: [proofA_x, proofA_y].flat(),
      proofB: [
        mydata.pi_b[0].flat().reverse(),
        mydata.pi_b[1].flat().reverse(),
      ].flat(),
      proofC: [mydata.pi_c[0], mydata.pi_c[1]].flat(),
    };
  } catch (error) {
    logger.error('Error while parsing the proof:', error);
    throw error;
  }
}

/**
 * Parse public signals to bytes array
 */
export function parseToBytesArray(publicSignals: string[]): number[][] {
  try {
    const publicInputsBytes: number[][] = [];

    for (const signal of publicSignals) {
      const ref: number[] = Array.from(
        utils.leInt2Buff(utils.unstringifyBigInts(signal), 32) as Uint8Array
      ).reverse() as number[];
      publicInputsBytes.push(ref);
    }

    return publicInputsBytes;
  } catch (error) {
    logger.error('Error while parsing public inputs:', error);
    throw error;
  }
}

/**
 * Check if y element is positive in G1
 */
function yElementIsPositiveG1(yElement: anchor.BN): boolean {
  return yElement.lte(FIELD_SIZE.sub(yElement));
}

/**
 * Check if y element is positive in G2
 */
function yElementIsPositiveG2(yElement1: anchor.BN, yElement2: anchor.BN): boolean {
  const fieldMidpoint = FIELD_SIZE.div(new anchor.BN(2));

  if (yElement1.lt(fieldMidpoint)) {
    return true;
  } else if (yElement1.gt(fieldMidpoint)) {
    return false;
  }

  return yElement2.lt(fieldMidpoint);
}

/**
 * Add bitmask to byte for compressed proof
 */
function addBitmaskToByte(byte: number, yIsPositive: boolean): number {
  if (!yIsPositive) {
    return byte | (1 << 7);
  }
  return byte;
}

export type { Proof, FullProveResult };
