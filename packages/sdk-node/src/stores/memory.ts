import { consoleLogger, type PortvaktLogger } from "../logger.js";
import type { SessionStore } from "./types.js";

export interface MemoryStoreOptions {
  /** Most sessions kept; the ones expiring first are dropped beyond it. Default 10,000. */
  readonly maxEntries?: number;
  readonly logger?: PortvaktLogger;
}

/**
 * Sessions in this process's memory: for development, tests and single-instance demos. Sessions
 * are lost on restart and not shared between replicas; it logs a warning with
 * NODE_ENV=production. Use {@link PgSessionStore} (or your own {@link SessionStore}) there.
 */
export class MemoryStore implements SessionStore {
  readonly #entries = new Map<string, { readonly value: string; readonly expiresAt: number }>();
  readonly #maxEntries: number;
  #writes = 0;

  constructor(options: MemoryStoreOptions = {}) {
    this.#maxEntries = options.maxEntries ?? 10_000;
    if (process.env.NODE_ENV === "production") {
      (options.logger ?? consoleLogger).warn(
        {},
        "MemoryStore is in use with NODE_ENV=production: sessions are lost on restart and not shared between instances",
      );
    }
  }

  get(key: string): Promise<string | undefined> {
    const entry = this.#entries.get(key);
    if (entry === undefined) return Promise.resolve(undefined);
    if (entry.expiresAt <= Date.now()) {
      this.#entries.delete(key);
      return Promise.resolve(undefined);
    }
    return Promise.resolve(entry.value);
  }

  set(key: string, value: string, expiresAt: Date): Promise<void> {
    this.#entries.delete(key);
    this.#entries.set(key, { value, expiresAt: expiresAt.getTime() });
    this.#writes += 1;
    if (this.#writes % 100 === 0 || this.#entries.size > this.#maxEntries) this.#sweep();
    return Promise.resolve();
  }

  destroy(key: string): Promise<void> {
    this.#entries.delete(key);
    return Promise.resolve();
  }

  /** Number of stored (possibly expired) entries. */
  get size(): number {
    return this.#entries.size;
  }

  #sweep(): void {
    const now = Date.now();
    for (const [key, entry] of this.#entries) {
      if (entry.expiresAt <= now) this.#entries.delete(key);
    }
    if (this.#entries.size <= this.#maxEntries) return;
    const byExpiry = [...this.#entries].sort((a, b) => a[1].expiresAt - b[1].expiresAt);
    for (const [key] of byExpiry.slice(0, this.#entries.size - this.#maxEntries)) {
      this.#entries.delete(key);
    }
  }
}
