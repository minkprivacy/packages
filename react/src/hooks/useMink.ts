/**
 * useMink Hook
 * @module hooks/useMink
 *
 * Main hook for accessing the Mink SDK.
 */

import { useMinkContext } from '../provider/context.js';
import type { MinkContextValue } from '../types/index.js';

/**
 * Hook to access the Mink SDK
 *
 * Provides access to the SDK instance and initialization state.
 *
 * @returns Mink context value
 *
 * @example
 * ```tsx
 * import { useMink } from '@minkprivacy/react';
 *
 * function MyComponent() {
 *   const { sdk, isInitialized, initialize } = useMink();
 *
 *   if (!isInitialized) {
 *     return <button onClick={initialize}>Initialize</button>;
 *   }
 *
 *   return <div>SDK is ready!</div>;
 * }
 * ```
 */
export function useMink(): MinkContextValue {
  return useMinkContext();
}
