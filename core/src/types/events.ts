/**
 * SDK Event Types
 * @module types/events
 */

import type { MinkError } from '../errors/base.js';

/**
 * All possible SDK event types
 */
export type MinkEventType =
  // Lifecycle events
  | 'initialized'
  | 'disposed'
  | 'keysDerived'

  // Deposit events
  | 'deposit:start'
  | 'deposit:proofGenerated'
  | 'deposit:submitted'
  | 'deposit:confirmed'
  | 'deposit:error'

  // Withdraw events
  | 'withdraw:start'
  | 'withdraw:proofGenerated'
  | 'withdraw:submitted'
  | 'withdraw:confirmed'
  | 'withdraw:error'

  // Inbox events
  | 'inbox:created'
  | 'inbox:create:proofGenerating'
  | 'inbox:create:proofGenerated'
  | 'inbox:create:submitting'
  | 'inbox:forward:start'
  | 'inbox:forward:proofGenerating'
  | 'inbox:forward:proofGenerated'
  | 'inbox:forward:submitting'
  | 'inbox:forward:confirmed'

  // Balance events
  | 'balance:updated'

  // Auth events
  | 'auth:authenticated'
  | 'auth:expired'

  // Status events
  | 'status:changed'

  // General error event
  | 'error';

/**
 * Event payload for each event type
 */
export interface MinkEventPayloads {
  // Lifecycle
  initialized: { timestamp: number };
  disposed: { timestamp: number };
  keysDerived: { zkPubkey: string };

  // Deposit
  'deposit:start': { amount: bigint; token?: string };
  'deposit:proofGenerated': { amount: bigint };
  'deposit:submitted': { signature: string; amount: bigint };
  'deposit:confirmed': { signature: string; amount: bigint; commitment: string };
  'deposit:error': { error: MinkError };

  // Withdraw
  'withdraw:start': { amount: bigint; recipient: string };
  'withdraw:proofGenerated': { amount: bigint };
  'withdraw:submitted': { jobId: string; amount: bigint };
  'withdraw:confirmed': { signature: string; amount: bigint; fee: bigint };
  'withdraw:error': { error: MinkError };

  // Inbox
  'inbox:created': { address: string; nonce: number };
  'inbox:create:proofGenerating': { nonce: number };
  'inbox:create:proofGenerated': { nonce: number };
  'inbox:create:submitting': { address: string; nonce: number };
  'inbox:forward:start': { inboxAddress: string; amount: bigint };
  'inbox:forward:proofGenerating': { inboxAddress: string; amount: bigint };
  'inbox:forward:proofGenerated': { inboxAddress: string };
  'inbox:forward:submitting': { inboxAddress: string };
  'inbox:forward:confirmed': { signature: string; amount: bigint };

  // Balance
  'balance:updated': { lamports: bigint; token?: string };

  // Auth
  'auth:authenticated': { walletAddress: string };
  'auth:expired': { walletAddress: string };

  // Status
  'status:changed': { status: string };

  // Error
  error: { error: MinkError };
}

/**
 * Event handler type
 */
export type MinkEventHandler<E extends MinkEventType> = (
  payload: MinkEventPayloads[E]
) => void;

/**
 * Event listener options
 */
export interface EventListenerOptions {
  /** Only trigger once */
  once?: boolean;
}
