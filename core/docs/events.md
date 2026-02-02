# Events

`MinkSDK` emits typed events you can subscribe to.

```typescript
sdk.on('deposit:confirmed', ({ signature, amount, commitment }) => { ... });
sdk.off('deposit:confirmed', handler);
```

## Event List

### Lifecycle

| Event | Payload |
|-------|---------|
| `initialized` | `{ timestamp }` |
| `disposed` | `{ timestamp }` |
| `keysDerived` | `{ zkPubkey }` |

### Deposit

| Event | Payload |
|-------|---------|
| `deposit:start` | `{ amount, token? }` |
| `deposit:proofGenerated` | `{ amount }` |
| `deposit:submitted` | `{ signature, amount }` |
| `deposit:confirmed` | `{ signature, amount, commitment }` |
| `deposit:error` | `{ error: MinkError }` |

### Withdraw

| Event | Payload |
|-------|---------|
| `withdraw:start` | `{ amount, recipient }` |
| `withdraw:proofGenerated` | `{ amount }` |
| `withdraw:submitted` | `{ jobId, amount }` |
| `withdraw:confirmed` | `{ signature, amount, fee }` |
| `withdraw:error` | `{ error: MinkError }` |

### Inbox

| Event | Payload |
|-------|---------|
| `inbox:created` | `{ address, nonce }` |
| `inbox:create:proofGenerating` | `{ nonce }` |
| `inbox:create:proofGenerated` | `{ nonce }` |
| `inbox:create:submitting` | `{ address, nonce }` |
| `inbox:forward:start` | `{ inboxAddress, amount }` |
| `inbox:forward:proofGenerating` | `{ inboxAddress, amount }` |
| `inbox:forward:proofGenerated` | `{ inboxAddress }` |
| `inbox:forward:submitting` | `{ inboxAddress }` |
| `inbox:forward:confirmed` | `{ signature, amount }` |

### Other

| Event | Payload |
|-------|---------|
| `balance:updated` | `{ lamports, token? }` |
| `auth:authenticated` | `{ walletAddress }` |
| `auth:expired` | `{ walletAddress }` |
| `status:changed` | `{ status }` |
| `error` | `{ error: MinkError }` |
