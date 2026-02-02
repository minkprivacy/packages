/**
 * Mink Provider
 * @module provider/MinkProvider
 *
 * Main context provider for the Mink SDK in React applications.
 */

import React, { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { useWallet } from '@solana/wallet-adapter-react';
import { createMinkSDK, MinkSDK, MinkError, MinkNotInitializedError, MinkErrorCode } from '@minkprivacy/core';

import { MinkContext } from './context.js';
import type { MinkProviderProps, MinkContextValue, OperationStatus } from '../types/index.js';
import { requestCache } from '../cache/manager.js';

/**
 * Mink Provider Component
 *
 * Provides the Mink SDK to child components via React context.
 * Handles wallet connection and SDK initialization.
 *
 * @example
 * ```tsx
 * import { MinkProvider } from '@minkprivacy/react';
 *
 * function App() {
 *   return (
 *     <WalletProvider>
 *       <MinkProvider config={{ network: 'devnet' }}>
 *         <MyApp />
 *       </MinkProvider>
 *     </WalletProvider>
 *   );
 * }
 * ```
 */
export function MinkProvider({
  config,
  children,
  autoInitialize = true,
}: MinkProviderProps): React.ReactElement {
  const wallet = useWallet();
  const { publicKey, signMessage, signTransaction, connected } = wallet;

  const [sdk, setSdk] = useState<MinkSDK | null>(null);
  const [isInitialized, setIsInitialized] = useState(false);
  const [isInitializing, setIsInitializing] = useState(false);
  const [error, setError] = useState<MinkError | null>(null);
  const [status, setStatus] = useState<OperationStatus>('idle');

  // Track if we've already created the SDK instance
  const sdkRef = useRef<MinkSDK | null>(null);
  const initPromiseRef = useRef<Promise<void> | null>(null);

  // Create SDK instance (but don't initialize yet)
  useEffect(() => {
    if (!sdkRef.current) {
      sdkRef.current = createMinkSDK(config);
      setSdk(sdkRef.current);
    }

    return () => {
      if (sdkRef.current) {
        sdkRef.current.dispose();
        sdkRef.current = null;
        setSdk(null);
        setIsInitialized(false);
        requestCache.clear();
      }
    };
  }, [config]);

  // Initialize SDK with wallet
  const initialize = useCallback(async (): Promise<void> => {
    if (!sdkRef.current) {
      throw new MinkNotInitializedError('SDK not created');
    }

    if (!connected || !publicKey || !signMessage || !signTransaction) {
      throw new MinkNotInitializedError('Wallet not connected or missing required features');
    }

    // Return existing promise if initialization is in progress
    if (initPromiseRef.current) {
      return initPromiseRef.current;
    }

    // Skip if already initialized
    if (sdkRef.current.isInitialized()) {
      setIsInitialized(true);
      return;
    }

    setIsInitializing(true);
    setStatus('initializing');
    setError(null);

    const initPromise = (async () => {
      try {
        await sdkRef.current!.initialize({
          publicKey,
          signMessage,
          signTransaction,
          connected,
        });
        setIsInitialized(true);
        setStatus('idle');
      } catch (err) {
        const minkError = err instanceof MinkError
          ? err
          : new MinkError(
              err instanceof Error ? err.message : 'Initialization failed',
              MinkErrorCode.UNKNOWN_ERROR,
              { cause: err instanceof Error ? err : undefined }
            );
        setError(minkError);
        setStatus('error');
        throw minkError;
      } finally {
        setIsInitializing(false);
        initPromiseRef.current = null;
      }
    })();

    initPromiseRef.current = initPromise;
    return initPromise;
  }, [connected, publicKey, signMessage, signTransaction]);

  // Auto-initialize when wallet connects
  useEffect(() => {
    if (autoInitialize && connected && publicKey && signMessage && !isInitialized && !isInitializing) {
      initialize().catch(() => {
        // Error is already set in state
      });
    }
  }, [autoInitialize, connected, publicKey, signMessage, isInitialized, isInitializing, initialize]);

  // Reset state when wallet disconnects
  useEffect(() => {
    if (!connected && isInitialized) {
      setIsInitialized(false);
      setError(null);
      setStatus('idle');
      requestCache.clear();
      initPromiseRef.current = null;
    }
  }, [connected, isInitialized]);

  // Subscribe to SDK events for status updates
  useEffect(() => {
    if (!sdk) return;

    const handleDepositStart = () => setStatus('depositing');
    const handleDepositEnd = () => setStatus('idle');
    const handleWithdrawStart = () => setStatus('withdrawing');
    const handleWithdrawEnd = () => setStatus('idle');
    const handleError = () => setStatus('error');

    sdk.on('deposit:start', handleDepositStart);
    sdk.on('deposit:confirmed', handleDepositEnd);
    sdk.on('deposit:error', handleError);
    sdk.on('withdraw:start', handleWithdrawStart);
    sdk.on('withdraw:confirmed', handleWithdrawEnd);
    sdk.on('withdraw:error', handleError);

    return () => {
      sdk.off('deposit:start', handleDepositStart);
      sdk.off('deposit:confirmed', handleDepositEnd);
      sdk.off('deposit:error', handleError);
      sdk.off('withdraw:start', handleWithdrawStart);
      sdk.off('withdraw:confirmed', handleWithdrawEnd);
      sdk.off('withdraw:error', handleError);
    };
  }, [sdk]);

  const contextValue = useMemo<MinkContextValue>(() => ({
    sdk,
    isInitialized,
    isInitializing,
    error,
    initialize,
    status,
  }), [sdk, isInitialized, isInitializing, error, initialize, status]);

  return (
    <MinkContext.Provider value={contextValue}>
      {children}
    </MinkContext.Provider>
  );
}
