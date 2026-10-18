/**
 * In-process metrics: named counters with label sets, readable as a snapshot. M8 exposes them
 * in the Prometheus text format; until then they are read by tests and operations code. Label
 * values must never carry personal data (reason codes, ids of configuration only).
 */

export type Labels = Readonly<Record<string, string>>;

const NAME = /^[a-z_][a-z0-9_]*$/;

const keyOf = (labels: Labels): string =>
  JSON.stringify(Object.entries(labels).sort(([a], [b]) => a.localeCompare(b)));

export class Counter {
  readonly name: string;
  readonly help: string;
  readonly #values = new Map<string, { readonly labels: Labels; value: number }>();

  constructor(name: string, help: string) {
    this.name = name;
    this.help = help;
  }

  inc(labels: Labels = {}, by = 1): void {
    if (!(by > 0)) throw new RangeError("counters only increase");
    const key = keyOf(labels);
    const entry = this.#values.get(key);
    if (entry === undefined) this.#values.set(key, { labels: { ...labels }, value: by });
    else entry.value += by;
  }

  /** The value for exactly these labels (0 when never incremented). */
  get(labels: Labels = {}): number {
    return this.#values.get(keyOf(labels))?.value ?? 0;
  }

  samples(): { readonly labels: Labels; readonly value: number }[] {
    return [...this.#values.values()].map(({ labels, value }) => ({ labels, value }));
  }
}

export class MetricRegistry {
  readonly #counters = new Map<string, Counter>();

  /** The counter `name`, created on first use. */
  counter(name: string, help: string): Counter {
    if (!NAME.test(name)) throw new Error(`invalid metric name ${name}`);
    let counter = this.#counters.get(name);
    if (counter === undefined) {
      counter = new Counter(name, help);
      this.#counters.set(name, counter);
    }
    return counter;
  }

  counters(): Counter[] {
    return [...this.#counters.values()];
  }
}

/** Metric names used across the server. */
export const METRICS = {
  /** Upstream callbacks refused before any interaction is known (unknown or foreign state). */
  federationCallbackRejected: "portvakt_federation_callback_rejected_total",
  /** SAML IdP metadata refreshes (`outcome` success or failure, `reason` of a failure). */
  samlMetadataRefresh: "portvakt_saml_metadata_refresh_total",
  /** SAML single logout messages (`direction`, `outcome`). */
  samlLogout: "portvakt_saml_logout_total",
} as const;
