/**
 * useMinkAuth Hook
 * @module hooks/useMinkAuth
 *
 * Hook for managing authentication with the relayer.
 */

import { useState, useCallback, useEffect } from 'react';
import { useWallet } from '@solana/wallet-adapter-react';
import type { MinkError as MinkErrorType } from '@minkprivacy/core';

import { useMinkContext } from '../provider/context.js';
import type { UseAuthResult } from '../types/index.js';

/**
 * Hook for managing relayer authentication
 *
 * @returns Auth state and methods
 *
 * @example
 * ```tsx
 * import { useMinkAuth } from '@minkprivacy/react';
 *
 * function AuthButton() {
 *   const { isAuthenticated, isAuthenticating, authenticate, logout } = useMinkAuth();
 *
 *   if (isAuthenticated) {
 *     return <button onClick={logout}>Logout</button>;
 *   }
 *
 *   return (
 *     <button onClick={authenticate} disabled={isAuthenticating}>
 *       {isAuthenticating ? 'Authenticating...' : 'Authenticate'}
 *     </button>
 *   );
 * }
 * ```
 */
export function useMinkAuth(): UseAuthResult {
  const { sdk, isInitialized } = useMinkContext();
  const { publicKey, signMessage } = useWallet();

  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [error, setError] = useState<MinkErrorType | null>(null);

  // Check initial auth state
  useEffect(() => {
    if (sdk && isInitialized) {
      setIsAuthenticated(sdk.auth.isAuthenticated());
    } else {
      setIsAuthenticated(false);
    }
  }, [sdk, isInitialized]);

  // Subscribe to auth events
  useEffect(() => {
    if (!sdk) return;

    const handleAuthenticated = () => {
      setIsAuthenticated(true);
      setIsAuthenticating(false);
    };

    const handleExpired = () => {
      setIsAuthenticated(false);
    };

    sdk.on('auth:authenticated', handleAuthenticated);
    sdk.on('auth:expired', handleExpired);

    return () => {
      sdk.off('auth:authenticated', handleAuthenticated);
      sdk.off('auth:expired', handleExpired);
    };
  }, [sdk]);

  const authenticate = useCallback(async (): Promise<boolean> => {
    if (!sdk || !isInitialized || !signMessage || !publicKey) {
      return false;
    }

    setIsAuthenticating(true);
    setError(null);

    try {
      const success = await sdk.auth.authenticate(signMessage, publicKey.toBase58());
      setIsAuthenticated(success);
      return success;
    } catch (err) {
      setError(err as MinkErrorType);
      return false;
    } finally {
      setIsAuthenticating(false);
    }
  }, [sdk, isInitialized, signMessage, publicKey]);

  const logout = useCallback((): void => {
    if (sdk && isInitialized) {
      sdk.auth.logout();
      setIsAuthenticated(false);
    }
  }, [sdk, isInitialized]);

  return {
    isAuthenticated,
    isAuthenticating,
    error,
    authenticate,
    logout,
  };
}
