# Proofs Module

`@minkprivacy/core/proofs`

ZK proof generation using Groth16 (snarkjs) for browser environments.

## Usage

```typescript
import { prove, proveWithBasePath, parseProofToBytesArray } from '@minkprivacy/core/proofs';
import type { Proof, FullProveResult } from '@minkprivacy/core/proofs';

// Generate proof from URLs
const result = await prove(
  circuitInput,                              // circuit-specific input object
  'https://cdn.example.com/stealth.wasm',    // compiled circuit
  'https://cdn.example.com/stealth.zkey',    // proving key
  { singleThread: true },                    // default for browser
);

// Or with base path (appends .wasm and .zkey)
const result = await proveWithBasePath(circuitInput, 'https://cdn.example.com/stealth');

// Parse proof to bytes for Solana instruction
const { proofA, proofB, proofC } = parseProofToBytesArray(result.proof);
// proofA: 64 bytes (G1 point, negated for Solana verifier)
// proofB: 128 bytes (G2 point)
// proofC: 64 bytes (G1 point)
```

## Circuit Input (Stealth Circuit)

The stealth circuit proves a valid UTXO state transition:

```typescript
const circuitInput = {
  root,                // Merkle root (decimal string)
  inputNullifier,      // [nullifier0, nullifier1] — spent UTXO nullifiers
  outputCommitment,    // [commitment0, commitment1] — new UTXO commitments
  publicAmount,        // (extAmount - fee + FIELD_SIZE) % FIELD_SIZE
  extDataHash,         // Hash of external data (recipient, amounts, etc.)

  // Input UTXOs (2)
  inAmount,            // [amount0, amount1]
  inBlinding,          // [blinding0, blinding1]
  inPrivateKey,        // [privkey0, privkey1]
  inPathIndices,       // [index0, index1]
  inPathElements,      // [[path0...], [path1...]]

  // Output UTXOs (2)
  outAmount,           // [amount0, amount1]
  outBlinding,         // [blinding0, blinding1]
  outPubkey,           // [pubkey0, pubkey1]

  // Mint
  mintAddress,         // field element representation of mint
};
```

## Proof Negation

`parseProofToBytesArray` automatically negates the proof A point's y-coordinate. This is required by the Solana BN254 Groth16 verifier:

```
y_negated = BN254_FIELD_MODULUS - y
```

The BN254 base field modulus:
```
21888242871839275222246405745257275088696311157297823662689037894645226208583
```

## Types

```typescript
interface Proof {
  pi_a: string[];      // G1 point [x, y, z]
  pi_b: string[][];    // G2 point [[x0, x1], [y0, y1], [z0, z1]]
  pi_c: string[];      // G1 point [x, y, z]
  protocol: string;    // "groth16"
  curve: string;       // "bn128"
}

interface FullProveResult {
  proof: Proof;
  publicSignals: string[];
}
```
