import pg from "pg";
import type { Logger } from "../logging/logger.js";
import {
  CHANGE_CHANNEL,
  parseChangeEvent,
  type ChangeEvent,
} from "../repositories/change-events.js";

export interface ChangeListenerOptions {
  /** Runtime role connection string. */
  readonly url: string;
  readonly logger: Logger;
  readonly onEvent: (event: ChangeEvent) => Promise<void> | void;
  /**
   * Called after the connection was re-established: notifications sent while it was down are
   * lost, so everything cached must be treated as stale.
   */
  readonly onResync: () => Promise<void> | void;
  readonly channel?: string;
  /** `application_name` of the connection (default `portvakt-listener`). */
  readonly applicationName?: string;
}

const MIN_BACKOFF_MS = 500;
/** Detaches every handler but keeps a no-op error listener: an unhandled error event would crash. */
async function discard(client: pg.Client): Promise<void> {
  client.removeAllListeners();
  client.on("error", () => undefined);
  await client.end().catch(() => undefined);
}

const MAX_BACKOFF_MS = 30_000;

/**
 * LISTENs for change notifications on a dedicated connection (a pooled one would drop the
 * subscription when released) and reconnects with exponential backoff. The periodic reload is
 * the safety net for anything missed while disconnected.
 */
export class ChangeListener {
  readonly #options: ChangeListenerOptions;
  #client: pg.Client | undefined;
  #stopped = true;
  #retry: NodeJS.Timeout | undefined;
  #backoff = MIN_BACKOFF_MS;
  #connecting: Promise<void> | undefined;

  constructor(options: ChangeListenerOptions) {
    this.#options = options;
  }

  get connected(): boolean {
    return this.#client !== undefined;
  }

  /** Connects and subscribes. Throws if the first connection fails. */
  async start(): Promise<void> {
    this.#stopped = false;
    await this.#connect();
  }

  async stop(): Promise<void> {
    this.#stopped = true;
    if (this.#retry !== undefined) clearTimeout(this.#retry);
    this.#retry = undefined;
    await this.#connecting?.catch(() => undefined);
    const client = this.#client;
    this.#client = undefined;
    if (client !== undefined) await discard(client);
  }

  async #connect(): Promise<void> {
    const client = new pg.Client({
      connectionString: this.#options.url,
      application_name: this.#options.applicationName ?? "portvakt-listener",
      connectionTimeoutMillis: 10_000,
      keepAlive: true,
    });
    const lost = (error?: Error): void => {
      if (this.#client !== client) return;
      this.#client = undefined;
      void discard(client);
      if (this.#stopped) return;
      this.#options.logger.warn({ err: error }, "change listener connection lost; reconnecting");
      this.#scheduleReconnect();
    };
    client.on("error", lost);
    client.on("end", () => lost());
    client.on("notification", (message) => {
      if (message.channel !== this.#channel) return;
      const event = parseChangeEvent(message.payload);
      if (event === null) {
        this.#options.logger.warn("ignored a malformed change notification");
        return;
      }
      void Promise.resolve()
        .then(() => this.#options.onEvent(event))
        .catch((error: unknown) => {
          this.#options.logger.error({ err: error }, "change notification handler failed");
        });
    });
    this.#connecting = (async () => {
      await client.connect();
      // The channel is a fixed identifier, never input.
      await client.query(`LISTEN ${this.#channel}`);
    })();
    try {
      await this.#connecting;
    } catch (error) {
      await discard(client);
      throw error;
    } finally {
      this.#connecting = undefined;
    }
    if (this.#stopped) {
      await discard(client);
      return;
    }
    this.#client = client;
    this.#backoff = MIN_BACKOFF_MS;
  }

  #scheduleReconnect(): void {
    const delay = this.#backoff;
    this.#backoff = Math.min(this.#backoff * 2, MAX_BACKOFF_MS);
    this.#retry = setTimeout(() => {
      this.#retry = undefined;
      void this.#connect()
        .then(() => {
          if (this.#client === undefined) return;
          this.#options.logger.info("change listener reconnected");
          return this.#options.onResync();
        })
        .catch((error: unknown) => {
          if (this.#stopped) return;
          this.#options.logger.warn({ err: error }, "change listener reconnect failed");
          this.#scheduleReconnect();
        });
    }, delay);
    this.#retry.unref();
  }

  get #channel(): string {
    return this.#options.channel ?? CHANGE_CHANNEL;
  }
}
