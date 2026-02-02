/**
 * useAutoForward Hook
 *
 * Automatically detects and forwards pending inbox balances to the privacy pool.
 * Polls for pending inboxes every 10 seconds and executes forward for each one.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import type { PrivateInbox } from '@minkprivacy/core';

import { useMinkContext } from '../provider/context.js';

// Minimum amount to trigger auto-forward (0.001 SOL = 1,000,000 lamports)
const MIN_FORWARD_AMOUNT = BigInt(1_000_000);

// Polling interval in milliseconds (30 seconds)
const POLL_INTERVAL = 30_000;

export interface ForwardResult {
  success: boolean;
  inbox: PrivateInbox;
  amount?: number;
  signature?: string;
  error?: string;
}

export interface UseAutoForwardReturn {
  /** Whether auto-forward is currently processing */
  isForwarding: boolean;
  /** Whether generating ZK proof */
  isGeneratingProof: boolean;
  /** Timestamp of last successful forward */
  lastForwardTime: Date | null;
  /** Result of the most recent forward operation */
  forwardResult: ForwardResult | null;
  /** Clear the forward result (dismiss toast) */
  clearForwardResult: () => void;
  /** Manually trigger a check for pending inboxes */
  checkPending: () => Promise<void>;
  /** Enable/disable auto-forward polling */
  setEnabled: (enabled: boolean) => void;
  /** Whether auto-forward is enabled */
  isEnabled: boolean;
}

export interface UseAutoForwardOptions {
  /** Minimum amount to trigger forward (default: 0.001 SOL) */
  minAmount?: bigint;
  /** Polling interval in ms (default: 10000) */
  pollInterval?: number;
  /** Auto-clear success result after ms (default: 5000) */
  successClearDelay?: number;
  /** Auto-clear error result after ms (default: 8000) */
  errorClearDelay?: number;
  /** Start with auto-forward enabled (default: true) */
  startEnabled?: boolean;
}

/**
 * Hook for automatic inbox forwarding
 *
 * @example
 * ```tsx
 * function AutoForwardStatus() {
 *   const { isForwarding, forwardResult, clearForwardResult } = useAutoForward();
 *
 *   return (
 *     <div>
 *       {isForwarding && <span>Forwarding...</span>}
 *       {forwardResult?.success && (
 *         <div>
 *           Forwarded {forwardResult.amount} SOL
 *           <button onClick={clearForwardResult}>Dismiss</button>
 *         </div>
 *       )}
 *     </div>
 *   );
 * }
 * ```
 */
export function useAutoForward(options: UseAutoForwardOptions = {}): UseAutoForwardReturn {
  const { sdk, isInitialized } = useMinkContext();

  const {
    minAmount = MIN_FORWARD_AMOUNT,
    pollInterval = POLL_INTERVAL,
    successClearDelay = 5000,
    errorClearDelay = 8000,
    startEnabled = true,
  } = options;

  const [isEnabled, setEnabled] = useState(startEnabled);
  const [isForwarding, setIsForwarding] = useState(false);
  const [isGeneratingProof, setIsGeneratingProof] = useState(false);
  const [lastForwardTime, setLastForwardTime] = useState<Date | null>(null);
  const [forwardResult, setForwardResult] = useState<ForwardResult | null>(null);

  // Ref to track if we're currently processing (prevent overlapping checks)
  const isProcessingRef = useRef(false);

  // Clear forward result (for dismissing toast)
  const clearForwardResult = useCallback(() => {
    setForwardResult(null);
  }, []);

  // Check and forward pending inboxes
  const checkAndForward = useCallback(async () => {
    // Only run if SDK is initialized and enabled
    if (!isInitialized || !sdk || !isEnabled || isProcessingRef.current) {
      return;
    }

    isProcessingRef.current = true;

    try {
      // Fetch pending inboxes
      const pendingInboxes = await sdk.inbox.getPendingInboxes(minAmount);

      if (pendingInboxes.length === 0) {
        return;
      }

      // Process each inbox with pending balance
      for (const inbox of pendingInboxes) {
        // Check if inbox has sufficient pending balance
        const pendingAmount = BigInt(inbox.pendingBalance.toString());
        if (pendingAmount < minAmount) {
          continue;
        }

        // Skip if auto-forward is disabled on this inbox
        if (!inbox.autoForward) {
          continue;
        }

        setIsForwarding(true);
        setIsGeneratingProof(true);

        try {
          const signature = await sdk.inbox.forward(inbox);

          // Success
          setLastForwardTime(new Date());
          const amountSOL = Number(inbox.pendingBalance.toString()) / 1_000_000_000;

          setForwardResult({
            success: true,
            inbox,
            amount: amountSOL,
            signature,
          });

          // Auto-clear success result
          setTimeout(() => {
            setForwardResult((prev) =>
              prev?.signature === signature ? null : prev
            );
          }, successClearDelay);
        } catch (error) {

          setForwardResult({
            success: false,
            inbox,
            error: error instanceof Error ? error.message : 'Forward failed',
          });

          // Auto-clear error result
          setTimeout(() => {
            setForwardResult((prev) =>
              prev?.inbox.address.toBase58() === inbox.address.toBase58() && !prev.success
                ? null
                : prev
            );
          }, errorClearDelay);
        } finally {
          setIsGeneratingProof(false);
        }
      }
    } catch {
      // Silently handle polling errors
    } finally {
      setIsForwarding(false);
      isProcessingRef.current = false;
    }
  }, [isInitialized, sdk, isEnabled, minAmount, successClearDelay, errorClearDelay]);

  // Subscribe to SDK events for proof generation progress
  useEffect(() => {
    if (!sdk || !isInitialized) return;

    const handleProofGenerating = () => {
      setIsGeneratingProof(true);
    };

    const handleProofGenerated = () => {
      setIsGeneratingProof(false);
    };

    sdk.on('inbox:forward:proofGenerating', handleProofGenerating);
    sdk.on('inbox:forward:proofGenerated', handleProofGenerated);

    return () => {
      sdk.off('inbox:forward:proofGenerating', handleProofGenerating);
      sdk.off('inbox:forward:proofGenerated', handleProofGenerated);
    };
  }, [sdk, isInitialized]);

  // Set up polling interval
  useEffect(() => {
    if (!isInitialized || !sdk || !isEnabled) {
      return;
    }

    // Execute immediately on mount
    checkAndForward();

    // Set up polling
    const interval = setInterval(checkAndForward, pollInterval);

    return () => {
      clearInterval(interval);
    };
  }, [isInitialized, sdk, isEnabled, pollInterval, checkAndForward]);

  return {
    isForwarding,
    isGeneratingProof,
    lastForwardTime,
    forwardResult,
    clearForwardResult,
    checkPending: checkAndForward,
    setEnabled,
    isEnabled,
  };
}

export default useAutoForward;
