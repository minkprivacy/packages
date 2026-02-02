# Viewing Keys Module

`@minkprivacy/core/viewing-keys`

Scoped viewing keys allow third parties (auditors, compliance tools) to view transaction details without spending authority.

## Usage

```typescript
import { ViewingKeyManager, ViewingScope } from '@minkprivacy/core/viewing-keys';
import type { ViewingKey, SerializedViewingKey } from '@minkprivacy/core/viewing-keys';

const vkm = new ViewingKeyManager(lightWasm, spendingKeypair);
// or
const vkm = ViewingKeyManager.fromSpendingKey(lightWasm, spendingPrivKeyHex);

// Derive a scoped viewing key
const vk = vkm.deriveViewingKey(ViewingScope.Full);

// Serialize for sharing
const serialized = vkm.serializeViewingKey(vk);
serialized.base58   // base58 string (66 bytes encoded)
serialized.url      // "mink://view/..."
serialized.qr       // same as base58 (for QR codes)

// Deserialize
const parsed = ViewingKeyManager.deserializeViewingKey(serialized.base58);
// { version, scope, zkPubkey, viewingKey }
```

## Scopes

| Scope | Value | Access |
|-------|-------|--------|
| `ViewingScope.Proxy` | 0 | Private Inbox only |
| `ViewingScope.Pool` | 1 | Privacy Pool only |
| `ViewingScope.Full` | 2 | Both inbox and pool |

`Full` scope can access everything. Others require exact match:

```typescript
ViewingKeyManager.canAccess(vk, ViewingScope.Pool); // true if vk.scope is Pool or Full
```

## Derivation

```
masterViewingKey  = Poseidon(spendingPrivateKey, domain)
scopedViewingKey  = Poseidon(masterViewingKey, scope)
keyHash           = Poseidon(viewingKey)
```

## Verification

```typescript
// Client-side: check serialized key belongs to expected ZK pubkey
ViewingKeyManager.verifySerializedViewingKey(base58, expectedZkPubkey);

// Check key hash matches (for on-chain proof verification)
vkm.verifyViewingKeyHash(viewingKey, expectedHash);

// Generate ZK proof for on-chain verification
const proof = await vkm.generateViewingKeyProof(ViewingScope.Full, zkAssetsPath);
```

## Serialization Format

| Offset | Size | Content |
|--------|------|---------|
| 0 | 1 byte | Version (currently 1) |
| 1 | 1 byte | Scope (0, 1, or 2) |
| 2 | 32 bytes | ZK public key |
| 34 | 32 bytes | Viewing key |

Total: 66 bytes, encoded as base58.
