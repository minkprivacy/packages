/**
 * useMinkStatus Hook
 * @module hooks/useMinkStatus
 *
 * Hook for monitoring SDK operation status.
 */

import { useMemo } from 'react';
import { useMinkContext } from '../provider/context.js';
import type { UseStatusResult, OperationStatus } from '../types/index.js';

/**
 * Status messages for each operation state
 */
const STATUS_MESSAGES: Record<OperationStatus, string | null> = {
  idle: null,
  initializing: 'Initializing SDK...',
  depositing: 'Processing deposit...',
  withdrawing: 'Processing withdrawal...',
  scanning: 'Scanning for UTXOs...',
  error: 'An error occurred',
};

/**
 * Hook to monitor SDK operation status
 *
 * @returns Status information
 *
 * @example
 * ```tsx
 * import { useMinkStatus } from '@minkprivacy/react';
 *
 * function StatusIndicator() {
 *   const { status, isOperating, message } = useMinkStatus();
 *
 *   if (!isOperating) return null;
 *
 *   return (
 *     <div className="status-indicator">
 *       <Spinner />
 *       <span>{message}</span>
 *     </div>
 *   );
 * }
 * ```
 */
export function useMinkStatus(): UseStatusResult {
  const { status } = useMinkContext();

  return useMemo(() => ({
    status,
    isOperating: status !== 'idle' && status !== 'error',
    message: STATUS_MESSAGES[status],
  }), [status]);
}
