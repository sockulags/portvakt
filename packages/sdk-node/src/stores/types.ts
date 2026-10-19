/**
 * Server-side storage of BFF sessions and pending logins. The SDK hands a store opaque values
 * only: keys are SHA-256 hashes of the random ids in the cookies (a store dump cannot be turned
 * into a working cookie) and values are AES-256-GCM ciphertexts (tokens and profile claims never
 * reach the store in the clear).
 */
export interface SessionStore {
  /** The value stored under `key`, or `undefined` when there is none or it expired. */
  get(key: string): Promise<string | undefined>;
  /** Stores (or replaces) the value until `expiresAt`. */
  set(key: string, value: string, expiresAt: Date): Promise<void>;
  destroy(key: string): Promise<void>;
  /**
   * Runs `fn` while holding an exclusive lock on `key` across every process sharing the store
   * (refresh token rotation must not race between replicas). The SDK always serialises
   * refreshes within one process; stores shared by several processes should implement this.
   */
  withLock?<T>(key: string, fn: () => Promise<T>): Promise<T>;
}
