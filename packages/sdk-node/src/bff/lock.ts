/**
 * One holder per key at a time within this process: callers for the same key run one after
 * another, in arrival order. Used to serialise refresh token rotation per session.
 */
export class KeyedMutex {
  readonly #tails = new Map<string, Promise<void>>();

  async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.#tails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous.then(() => current);
    this.#tails.set(key, tail);
    await previous;
    try {
      return await fn();
    } finally {
      release();
      if (this.#tails.get(key) === tail) this.#tails.delete(key);
    }
  }

  /** Keys with a holder or waiters (tests). */
  get size(): number {
    return this.#tails.size;
  }
}
