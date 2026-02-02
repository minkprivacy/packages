/**
 * useMinkEvents Hook
 * @module hooks/useMinkEvents
 *
 * Hook for subscribing to SDK events.
 */

import { useEffect, useRef, type DependencyList } from 'react';
import type { MinkEventType, MinkEventPayloads } from '@minkprivacy/core';

import { useMinkContext } from '../provider/context.js';

/**
 * Event handler type
 */
export type MinkEventHandler<E extends MinkEventType> = (data: MinkEventPayloads[E]) => void;

/**
 * Hook to subscribe to Mink SDK events
 *
 * Automatically handles subscription cleanup on unmount.
 *
 * @param event - Event type to subscribe to
 * @param handler - Event handler function
 * @param deps - Optional dependency list
 *
 * @example
 * ```tsx
 * import { useMinkEvents } from '@minkprivacy/react';
 *
 * function TransactionListener() {
 *   useMinkEvents('deposit:confirmed', (data) => {
 *     console.log('Deposit confirmed:', data.signature);
 *   });
 *
 *   useMinkEvents('withdraw:confirmed', (data) => {
 *     console.log('Withdrawal confirmed:', data.signature);
 *   });
 *
 *   return null;
 * }
 * ```
 */
export function useMinkEvents<E extends MinkEventType>(
  event: E,
  handler: MinkEventHandler<E>,
  deps: DependencyList = []
): void {
  const { sdk } = useMinkContext();
  const handlerRef = useRef(handler);

  // Update handler ref on each render
  useEffect(() => {
    handlerRef.current = handler;
  }, [handler]);

  // Subscribe to events
  useEffect(() => {
    if (!sdk) return;

    const wrappedHandler = (data: MinkEventPayloads[E]) => {
      handlerRef.current(data);
    };

    sdk.on(event, wrappedHandler);

    return () => {
      sdk.off(event, wrappedHandler);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sdk, event, ...deps]);
}

/**
 * Hook to subscribe to multiple Mink SDK events
 *
 * @param handlers - Map of event types to handlers
 * @param deps - Optional dependency list
 *
 * @example
 * ```tsx
 * import { useMinkEventHandlers } from '@minkprivacy/react';
 *
 * function StatusMonitor() {
 *   useMinkEventHandlers({
 *     'deposit:start': () => setStatus('depositing'),
 *     'deposit:confirmed': () => setStatus('idle'),
 *     'withdraw:start': () => setStatus('withdrawing'),
 *     'withdraw:confirmed': () => setStatus('idle'),
 *   });
 *
 *   return null;
 * }
 * ```
 */
export function useMinkEventHandlers(
  handlers: Partial<{ [E in MinkEventType]: MinkEventHandler<E> }>,
  deps: DependencyList = []
): void {
  const { sdk } = useMinkContext();
  const handlersRef = useRef(handlers);

  // Update handlers ref on each render
  useEffect(() => {
    handlersRef.current = handlers;
  }, [handlers]);

  // Subscribe to all events
  useEffect(() => {
    if (!sdk) return;

    const wrappedHandlers = new Map<MinkEventType, (data: unknown) => void>();

    for (const [event, handler] of Object.entries(handlersRef.current)) {
      if (typeof handler === 'function') {
        const wrappedHandler = (data: unknown) => {
          const currentHandler = handlersRef.current[event as MinkEventType];
          if (typeof currentHandler === 'function') {
            (currentHandler as (data: unknown) => void)(data);
          }
        };
        wrappedHandlers.set(event as MinkEventType, wrappedHandler);
        sdk.on(event as MinkEventType, wrappedHandler);
      }
    }

    return () => {
      for (const [event, handler] of wrappedHandlers) {
        sdk.off(event, handler);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sdk, ...deps]);
}
