/**
 * useMinkInbox Hook
 * @module hooks/useMinkInbox
 *
 * Hook for managing private inboxes.
 */

import { useState, useCallback, useEffect } from 'react';
import type {
  PrivateInbox,
  CreateInboxParams,
  MinkError as MinkErrorType,
} from '@minkprivacy/core';

import { useMinkContext } from '../provider/context.js';
import type { UseInboxResult } from '../types/index.js';

/**
 * Hook for managing private inboxes
 *
 * @returns Inbox state and methods
 *
 * @example
 * ```tsx
 * import { useMinkInbox } from '@minkprivacy/react';
 *
 * function InboxManager() {
 *   const { inboxes, isLoading, create, forward } = useMinkInbox();
 *
 *   const handleCreate = async () => {
 *     const { inbox, signature } = await create();
 *     console.log('Created inbox:', inbox.address.toBase58());
 *   };
 *
 *   return (
 *     <div>
 *       <button onClick={handleCreate}>Create Inbox</button>
 *       {inboxes.map((inbox) => (
 *         <div key={inbox.address.toBase58()}>
 *           {inbox.address.toBase58()}
 *           <button onClick={() => forward(inbox)}>Forward</button>
 *         </div>
 *       ))}
 *     </div>
 *   );
 * }
 * ```
 */
export function useMinkInbox(): UseInboxResult {
  const { sdk, isInitialized } = useMinkContext();

  const [inboxes, setInboxes] = useState<PrivateInbox[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isGeneratingProof, setIsGeneratingProof] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<MinkErrorType | null>(null);

  // Fetch inboxes from API/on-chain
  const fetchInboxes = useCallback(async () => {
    if (!sdk || !isInitialized) return;

    setIsLoading(true);
    try {
      // This calls getInboxes() which tries API first, then falls back to on-chain discovery
      const fetchedInboxes = await sdk.inbox.getInboxes();
      setInboxes(fetchedInboxes);
    } catch (err) {
      // Fall back to cached inboxes
      setInboxes(sdk.inbox.getAllInboxes());
    } finally {
      setIsLoading(false);
    }
  }, [sdk, isInitialized]);

  // Load inboxes when initialized - fetch from API/on-chain, not just cache
  useEffect(() => {
    if (sdk && isInitialized) {
      // First show cached inboxes immediately
      setInboxes(sdk.inbox.getAllInboxes());
      // Then fetch fresh data from API/on-chain
      fetchInboxes();
    } else {
      setInboxes([]);
    }
  }, [sdk, isInitialized, fetchInboxes]);

  // Subscribe to inbox events
  useEffect(() => {
    if (!sdk || !isInitialized) return;

    const handleInboxCreated = () => {
      setInboxes(sdk.inbox.getAllInboxes());
    };

    // Create progress events
    const handleCreateProofGenerating = () => {
      setIsGeneratingProof(true);
    };

    const handleCreateProofGenerated = () => {
      setIsGeneratingProof(false);
    };

    const handleCreateSubmitting = () => {
      setIsSubmitting(true);
    };

    // Forward progress events
    const handleForwardProofGenerating = () => {
      setIsGeneratingProof(true);
    };

    const handleForwardProofGenerated = () => {
      setIsGeneratingProof(false);
    };

    const handleForwardSubmitting = () => {
      setIsSubmitting(true);
    };

    const handleForwardConfirmed = () => {
      setIsSubmitting(false);
    };

    // Subscribe to events
    sdk.on('inbox:created', handleInboxCreated);
    sdk.on('inbox:create:proofGenerating', handleCreateProofGenerating);
    sdk.on('inbox:create:proofGenerated', handleCreateProofGenerated);
    sdk.on('inbox:create:submitting', handleCreateSubmitting);
    sdk.on('inbox:forward:proofGenerating', handleForwardProofGenerating);
    sdk.on('inbox:forward:proofGenerated', handleForwardProofGenerated);
    sdk.on('inbox:forward:submitting', handleForwardSubmitting);
    sdk.on('inbox:forward:confirmed', handleForwardConfirmed);

    return () => {
      sdk.off('inbox:created', handleInboxCreated);
      sdk.off('inbox:create:proofGenerating', handleCreateProofGenerating);
      sdk.off('inbox:create:proofGenerated', handleCreateProofGenerated);
      sdk.off('inbox:create:submitting', handleCreateSubmitting);
      sdk.off('inbox:forward:proofGenerating', handleForwardProofGenerating);
      sdk.off('inbox:forward:proofGenerated', handleForwardProofGenerated);
      sdk.off('inbox:forward:submitting', handleForwardSubmitting);
      sdk.off('inbox:forward:confirmed', handleForwardConfirmed);
    };
  }, [sdk, isInitialized]);

  const create = useCallback(async (
    params?: CreateInboxParams
  ): Promise<{ inbox: PrivateInbox; signature: string }> => {
    if (!sdk || !isInitialized) {
      throw new Error('SDK not initialized');
    }

    setIsLoading(true);
    setError(null);

    try {
      const result = await sdk.inbox.create(params);
      setInboxes(sdk.inbox.getAllInboxes());
      return result;
    } catch (err) {
      setError(err as MinkErrorType);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [sdk, isInitialized]);

  const forward = useCallback(async (inbox: PrivateInbox): Promise<string> => {
    if (!sdk || !isInitialized) {
      throw new Error('SDK not initialized');
    }

    setIsLoading(true);
    setError(null);

    try {
      const signature = await sdk.inbox.forward(inbox);
      return signature;
    } catch (err) {
      setError(err as MinkErrorType);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [sdk, isInitialized]);

  const refresh = useCallback(async (inbox: PrivateInbox): Promise<PrivateInbox> => {
    if (!sdk || !isInitialized) {
      throw new Error('SDK not initialized');
    }

    setIsLoading(true);
    setError(null);

    try {
      const updated = await sdk.inbox.refresh(inbox);
      setInboxes(sdk.inbox.getAllInboxes());
      return updated;
    } catch (err) {
      setError(err as MinkErrorType);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [sdk, isInitialized]);

  return {
    inboxes,
    isLoading,
    isGeneratingProof,
    isSubmitting,
    error,
    create,
    forward,
    refresh,
    fetchInboxes,
  };
}
