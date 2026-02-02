/**
 * useMinkBalance Hook
 * @module hooks/useMinkBalance
 *
 * Hook for querying private balances with caching and deduplication.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useWallet } from '@solana/wallet-adapter-react';
import type { BalanceResult, TokenBalanceResult, MinkError as MinkErrorType } from '@minkprivacy/core';

import { useMinkContext } from '../provider/context.js';
import { requestCache, balanceKey, tokenBalanceKey } from '../cache/index.js';
import type { UseBalanceOptions, UseBalanceResult } from '../types/index.js';

/**
 * Hook to get private balance
 *
 * Supports caching, deduplication, and auto-refetch.
 *
 * @param options - Balance options
 * @returns Balance result
 *
 * @example
 * ```tsx
 * import { useMinkBalance } from '@minkprivacy/react';
 *
 * function BalanceDisplay() {
 *   const { balance, isLoading, refetch } = useMinkBalance();
 *
 *   if (isLoading) return <div>Loading...</div>;
 *
 *   return (
 *     <div>
 *       Balance: {balance?.sol} SOL
 *       <button onClick={refetch}>Refresh</button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useMinkBalance(options: UseBalanceOptions = {}): UseBalanceResult {
  const { token, refetchInterval = 0, enabled = true } = options;
  const { sdk, isInitialized } = useMinkContext();
  const { publicKey } = useWallet();

  const [balance, setBalance] = useState<BalanceResult | TokenBalanceResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isRefetching, setIsRefetching] = useState(false);
  const [error, setError] = useState<MinkErrorType | null>(null);

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const walletAddress = publicKey?.toBase58() ?? '';
  const cacheKey = token
    ? tokenBalanceKey(walletAddress, token)
    : balanceKey(walletAddress);

  const fetchBalance = useCallback(async (isRefetch = false): Promise<void> => {
    if (!sdk || !isInitialized || !walletAddress) {
      return;
    }

    if (isRefetch) {
      setIsRefetching(true);
    } else {
      setIsLoading(true);
    }
    setError(null);

    try {
      const result = await requestCache.fetch(cacheKey, async () => {
        if (token) {
          return sdk.getTokenBalance(token);
        }
        return sdk.getBalance();
      });
      setBalance(result);
    } catch (err) {
      setError(err as MinkErrorType);
    } finally {
      setIsLoading(false);
      setIsRefetching(false);
    }
  }, [sdk, isInitialized, walletAddress, cacheKey, token]);

  const refetch = useCallback(async (): Promise<void> => {
    requestCache.invalidate(cacheKey);
    await fetchBalance(true);
  }, [cacheKey, fetchBalance]);

  // Initial fetch
  useEffect(() => {
    if (enabled && isInitialized && walletAddress) {
      fetchBalance();
    }
  }, [enabled, isInitialized, walletAddress, fetchBalance]);

  // Auto-refetch interval
  useEffect(() => {
    if (refetchInterval > 0 && enabled && isInitialized) {
      intervalRef.current = setInterval(() => {
        refetch();
      }, refetchInterval);

      return () => {
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
        }
      };
    }
    return undefined;
  }, [refetchInterval, enabled, isInitialized, refetch]);

  // Clear on disconnect
  useEffect(() => {
    if (!walletAddress) {
      setBalance(null);
      setError(null);
    }
  }, [walletAddress]);

  return {
    balance,
    isLoading,
    isRefetching,
    error,
    refetch,
  };
}
