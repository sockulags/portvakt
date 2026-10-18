import type { Logger } from "../logging/logger.js";

export interface PeriodicTaskOptions {
  readonly name: string;
  readonly intervalSeconds: number;
  readonly run: () => Promise<void>;
  readonly logger: Logger;
  /** Run once right after `start()` instead of waiting a full interval. */
  readonly runImmediately?: boolean;
}

/**
 * Runs a task every `intervalSeconds`, never overlapping itself. Failures are logged and the
 * schedule continues. Timers are unref'd so they never keep the process alive; `stop()` cancels
 * the next run and waits for a run in progress.
 */
export class PeriodicTask {
  readonly #options: PeriodicTaskOptions;
  #timer: NodeJS.Timeout | undefined;
  #running: Promise<void> | undefined;
  #stopped = true;

  constructor(options: PeriodicTaskOptions) {
    if (!(options.intervalSeconds > 0)) throw new TypeError("intervalSeconds must be positive");
    this.#options = options;
  }

  start(): void {
    if (!this.#stopped) return;
    this.#stopped = false;
    if (this.#options.runImmediately === true) this.#tick();
    else this.#schedule();
  }

  /** Runs the task now (unless a run is in progress, then waits for that one). */
  async runNow(): Promise<void> {
    if (this.#running !== undefined) return this.#running;
    this.#running = this.#execute().finally(() => {
      this.#running = undefined;
    });
    return this.#running;
  }

  async stop(): Promise<void> {
    this.#stopped = true;
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
    await this.#running;
  }

  #schedule(): void {
    if (this.#stopped) return;
    this.#timer = setTimeout(() => this.#tick(), this.#options.intervalSeconds * 1000);
    this.#timer.unref();
  }

  #tick(): void {
    this.#timer = undefined;
    void this.runNow().finally(() => this.#schedule());
  }

  async #execute(): Promise<void> {
    try {
      await this.#options.run();
    } catch (error) {
      this.#options.logger.error({ err: error, task: this.#options.name }, "periodic task failed");
    }
  }
}
