# Private Inbox Module

`@minkprivacy/core/inbox`

Stealth addresses that receive tokens from any source (DEX, airdrops, transfers) and forward them into the privacy pool.

## Overview

```
External sender → Inbox PDA → forward_to_pool → Privacy Pool
                  (stealth)    (ZK proof)       (shielded UTXO)
```

1. User creates an inbox — a PDA derived from their ZK public key
2. Anyone can send tokens to the inbox address
3. User (or auto-forward) moves inbox balance into the pool with a ZK proof

## Usage

```typescript
import { PrivateInboxManager, InboxStatus } from '@minkprivacy/core/inbox';
import type { PrivateInbox, CreateInboxParams } from '@minkprivacy/core/inbox';

const manager = new PrivateInboxManager({
  lightWasm,
  connection,
  spendingKeypair,  // Keypair from EncryptionService
  relayerUrl,
  programId,        // optional
  getAuthToken,     // optional
});

// Create inbox
const { inbox, signature } = await manager.createInbox({
  mint: SOL_MINT,         // optional (default SOL)
  autoForward: true,      // optional
  forwardFeeBps: 50,      // optional
  zkAssetsPath: '...',    // optional
});

// Get receive address to share
const address = manager.getReceiveAddress(inbox);
const formatted = manager.formatReceiveAddress(inbox);
// → "mink:inbox:AbCdEf..."

// List inboxes
const inboxes = await manager.getInboxes();
const pending = await manager.getPendingInboxes(1_000_000n); // min 0.001 SOL

// Forward to pool
const { signature, amountForwarded, treeIndex } = await manager.forwardToPool(inbox);

// Refresh state
const updated = await manager.refreshInbox(inbox);

// Update settings
await manager.updateInbox(inbox, { autoForward: false, status: InboxStatus.Paused });
```

## `PrivateInbox` Interface

```typescript
interface PrivateInbox {
  address: PublicKey;        // PDA address
  zkPubkey: BN;              // Owner's ZK public key
  encPubkey?: Uint8Array;    // X25519 key for ECDH
  mint: PublicKey;           // Token mint
  nonce: number;             // Inbox nonce
  autoForward: boolean;
  forwardFeeBps: number;
  pendingBalance: BN;
  totalForwarded: BN;
  status: InboxStatus;       // Active | Paused
}
```

## How Registration Works

1. Manager derives `zkPubkey` and `encPubkey` from spending keypair
2. Generates a ZK proof proving ownership of the private key behind `zkPubkey`
3. `messageHash = Poseidon(mint_as_field, slot, nonce)` — prevents replay
4. Proof is submitted on-chain to create the inbox PDA

## How Forward Works

1. Reads `pendingBalance` from the inbox account
2. Generates 2 output UTXOs (real amount + empty change)
3. Output blindings derived via ECDH (not random) — so the owner can reconstruct them
4. Generates ZK proof with 2 zero-amount padding inputs
5. Submits to relayer which executes the on-chain instruction

## PDA Derivation

```
inboxPDA     = findProgramAddress([b"private_inbox", zkPubkeyBytes, mintBytes, nonceBytes], programId)
inboxConfig  = findProgramAddress([b"inbox_config", zkPubkeyBytes, mintBytes], programId)
userIdentity = findProgramAddress([b"user_identity", zkPubkeyBytes], programId)
```
