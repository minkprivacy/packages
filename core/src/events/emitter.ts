/**
 * Typed Event Emitter
 * @module events/emitter
 */

type EventHandler<T = unknown> = (payload: T) => void;

interface ListenerEntry<T = unknown> {
  handler: EventHandler<T>;
  once: boolean;
}

/**
 * Type-safe event emitter
 */
export class TypedEventEmitter<
  TEvents extends { [K in keyof TEvents]: unknown } = Record<string, unknown>
> {
  private listeners = new Map<keyof TEvents, ListenerEntry[]>();

  /**
   * Subscribe to an event
   */
  on<E extends keyof TEvents>(
    event: E,
    handler: EventHandler<TEvents[E]>
  ): () => void {
    const entries = this.listeners.get(event) ?? [];
    const entry: ListenerEntry = { handler: handler as EventHandler, once: false };
    entries.push(entry);
    this.listeners.set(event, entries);

    // Return unsubscribe function
    return () => this.off(event, handler);
  }

  /**
   * Subscribe to an event (fires once)
   */
  once<E extends keyof TEvents>(
    event: E,
    handler: EventHandler<TEvents[E]>
  ): () => void {
    const entries = this.listeners.get(event) ?? [];
    const entry: ListenerEntry = { handler: handler as EventHandler, once: true };
    entries.push(entry);
    this.listeners.set(event, entries);

    return () => this.off(event, handler);
  }

  /**
   * Unsubscribe from an event
   */
  off<E extends keyof TEvents>(
    event: E,
    handler: EventHandler<TEvents[E]>
  ): void {
    const entries = this.listeners.get(event);
    if (!entries) return;

    const filtered = entries.filter((e) => e.handler !== handler);
    if (filtered.length === 0) {
      this.listeners.delete(event);
    } else {
      this.listeners.set(event, filtered);
    }
  }

  /**
   * Emit an event
   */
  emit<E extends keyof TEvents>(event: E, payload: TEvents[E]): void {
    const entries = this.listeners.get(event);
    if (!entries) return;

    const remaining: ListenerEntry[] = [];
    for (const entry of entries) {
      entry.handler(payload);
      if (!entry.once) {
        remaining.push(entry);
      }
    }

    if (remaining.length === 0) {
      this.listeners.delete(event);
    } else {
      this.listeners.set(event, remaining);
    }
  }

  /**
   * Remove all listeners for an event (or all events)
   */
  removeAllListeners(event?: keyof TEvents): void {
    if (event) {
      this.listeners.delete(event);
    } else {
      this.listeners.clear();
    }
  }

  /**
   * Get listener count for an event
   */
  listenerCount(event: keyof TEvents): number {
    return this.listeners.get(event)?.length ?? 0;
  }
}
