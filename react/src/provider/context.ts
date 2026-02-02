/**
 * Mink React Context
 * @module provider/context
 */

import { createContext, useContext } from 'react';
import type { MinkContextValue } from '../types/index.js';

/**
 * Mink SDK context
 */
export const MinkContext = createContext<MinkContextValue | null>(null);

/**
 * Hook to access Mink context
 *
 * @throws Error if used outside MinkProvider
 * @returns Mink context value
 */
export function useMinkContext(): MinkContextValue {
  const context = useContext(MinkContext);
  if (!context) {
    throw new Error('useMinkContext must be used within a MinkProvider');
  }
  return context;
}
