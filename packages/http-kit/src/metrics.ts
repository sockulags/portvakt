/**
 * In-process metrics in the Prometheus text exposition format (version 0.0.4): counters, gauges,
 * histograms and collectors (values read at scrape time). Label values must never carry personal
 * data or tenant-controlled free text: reason codes, route templates, status codes and
 * configuration ids (login method ids, tenant slugs) only.
 *
 * Every metric keeps at most {@link MAX_SERIES} label sets; further ones are dropped (and counted
 * in `<registry prefix>_metric_series_dropped_total`), so a label that turns out to be unbounded
 * cannot exhaust memory.
 */

export type Labels = Readonly<Record<string, string>>;

export interface Sample {
  readonly labels: Labels;
  readonly value: number;
}

export type MetricType = "counter" | "gauge" | "histogram";

const NAME = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const LABEL = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
/** Label sets kept per metric. */
export const MAX_SERIES = 2000;

/** Default latency buckets (seconds): 5 ms to 30 s. */
export const DEFAULT_BUCKETS: readonly number[] = [
  0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
];

const keyOf = (labels: Labels): string =>
  JSON.stringify(Object.entries(labels).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));

function checkLabels(labels: Labels): void {
  for (const name of Object.keys(labels)) {
    if (!LABEL.test(name) || name.startsWith("__") || name === "le") {
      throw new Error(`invalid label name ${name}`);
    }
  }
}

const escapeLabel = (value: string): string =>
  value.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
const escapeHelp = (value: string): string => value.replace(/\\/g, "\\\\").replace(/\n/g, "\\n");

function formatValue(value: number): string {
  if (Number.isNaN(value)) return "NaN";
  if (value === Infinity) return "+Inf";
  if (value === -Infinity) return "-Inf";
  return String(value);
}

function formatLabels(labels: Labels, extra?: readonly [string, string]): string {
  const entries = Object.entries(labels).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  if (extra !== undefined) entries.push([extra[0], extra[1]]);
  if (entries.length === 0) return "";
  return `{${entries.map(([name, value]) => `${name}="${escapeLabel(value)}"`).join(",")}}`;
}

/** Series storage shared by the metric kinds: bounded, keyed by the sorted label set. */
class Series<T> {
  readonly #values = new Map<string, { readonly labels: Labels; value: T }>();
  readonly #onDrop: () => void;

  constructor(onDrop: () => void) {
    this.#onDrop = onDrop;
  }

  /** The entry for `labels`, created with `initial()`; `undefined` once the cap is reached. */
  entry(labels: Labels, initial: () => T): { readonly labels: Labels; value: T } | undefined {
    const key = keyOf(labels);
    let entry = this.#values.get(key);
    if (entry === undefined) {
      if (this.#values.size >= MAX_SERIES) {
        this.#onDrop();
        return undefined;
      }
      checkLabels(labels);
      entry = { labels: { ...labels }, value: initial() };
      this.#values.set(key, entry);
    }
    return entry;
  }

  peek(labels: Labels): T | undefined {
    return this.#values.get(keyOf(labels))?.value;
  }

  delete(labels: Labels): void {
    this.#values.delete(keyOf(labels));
  }

  clear(): void {
    this.#values.clear();
  }

  all(): { readonly labels: Labels; readonly value: T }[] {
    return [...this.#values.values()];
  }
}

abstract class Metric {
  readonly name: string;
  readonly help: string;
  abstract readonly type: MetricType;

  constructor(name: string, help: string) {
    this.name = name;
    this.help = help;
  }

  abstract render(): string[] | Promise<string[]>;
}

export class Counter extends Metric {
  readonly type = "counter";
  readonly #series: Series<number>;

  constructor(name: string, help: string, onDrop: () => void = () => undefined) {
    super(name, help);
    this.#series = new Series(onDrop);
  }

  inc(labels: Labels = {}, by = 1): void {
    if (!(by > 0)) throw new RangeError("counters only increase");
    const entry = this.#series.entry(labels, () => 0);
    if (entry !== undefined) entry.value += by;
  }

  /** The value for exactly these labels (0 when never incremented). */
  get(labels: Labels = {}): number {
    return this.#series.peek(labels) ?? 0;
  }

  samples(): Sample[] {
    return this.#series.all().map(({ labels, value }) => ({ labels, value }));
  }

  render(): string[] {
    return this.samples().map(
      ({ labels, value }) => `${this.name}${formatLabels(labels)} ${value}`,
    );
  }
}

export class Gauge extends Metric {
  readonly type = "gauge";
  readonly #series: Series<number>;

  constructor(name: string, help: string, onDrop: () => void = () => undefined) {
    super(name, help);
    this.#series = new Series(onDrop);
  }

  set(labels: Labels, value: number): void {
    const entry = this.#series.entry(labels, () => 0);
    if (entry !== undefined) entry.value = value;
  }

  inc(labels: Labels = {}, by = 1): void {
    const entry = this.#series.entry(labels, () => 0);
    if (entry !== undefined) entry.value += by;
  }

  dec(labels: Labels = {}, by = 1): void {
    this.inc(labels, -by);
  }

  get(labels: Labels = {}): number {
    return this.#series.peek(labels) ?? 0;
  }

  /** Replaces every series (a gauge refreshed from a snapshot, such as key states). */
  replace(samples: readonly Sample[]): void {
    this.#series.clear();
    for (const { labels, value } of samples) this.set(labels, value);
  }

  render(): string[] {
    return this.#series
      .all()
      .map(({ labels, value }) => `${this.name}${formatLabels(labels)} ${formatValue(value)}`);
  }
}

interface HistogramValue {
  readonly counts: number[];
  sum: number;
  count: number;
}

export class Histogram extends Metric {
  readonly type = "histogram";
  readonly buckets: readonly number[];
  readonly #series: Series<HistogramValue>;

  constructor(
    name: string,
    help: string,
    buckets: readonly number[] = DEFAULT_BUCKETS,
    onDrop: () => void = () => undefined,
  ) {
    super(name, help);
    const sorted = [...buckets].sort((a, b) => a - b);
    if (sorted.length === 0 || sorted.some((bound, i) => i > 0 && bound === sorted[i - 1])) {
      throw new Error(`invalid buckets for ${name}`);
    }
    this.buckets = sorted;
    this.#series = new Series(onDrop);
  }

  observe(labels: Labels, value: number): void {
    if (!Number.isFinite(value)) return;
    const entry = this.#series.entry(labels, () => ({
      counts: this.buckets.map(() => 0),
      sum: 0,
      count: 0,
    }));
    if (entry === undefined) return;
    const { value: histogram } = entry;
    for (let i = 0; i < this.buckets.length; i += 1) {
      if (value <= (this.buckets[i] ?? Infinity))
        histogram.counts[i] = (histogram.counts[i] ?? 0) + 1;
    }
    histogram.sum += value;
    histogram.count += 1;
  }

  /** Starts a timer; the returned function observes the elapsed seconds with `labels`. */
  startTimer(): (labels: Labels) => number {
    const started = performance.now();
    return (labels) => {
      const seconds = (performance.now() - started) / 1000;
      this.observe(labels, seconds);
      return seconds;
    };
  }

  /** Observations recorded with exactly these labels. */
  count(labels: Labels = {}): number {
    return this.#series.peek(labels)?.count ?? 0;
  }

  render(): string[] {
    const lines: string[] = [];
    for (const { labels, value } of this.#series.all()) {
      this.buckets.forEach((bound, i) => {
        lines.push(
          `${this.name}_bucket${formatLabels(labels, ["le", formatValue(bound)])} ${value.counts[i] ?? 0}`,
        );
      });
      lines.push(`${this.name}_bucket${formatLabels(labels, ["le", "+Inf"])} ${value.count}`);
      lines.push(`${this.name}_sum${formatLabels(labels)} ${formatValue(value.sum)}`);
      lines.push(`${this.name}_count${formatLabels(labels)} ${value.count}`);
    }
    return lines;
  }
}

/** A metric whose samples are read when scraped (pool sizes, key ages, process figures). */
class Collected extends Metric {
  readonly type: "counter" | "gauge";
  readonly #collect: () => readonly Sample[] | Promise<readonly Sample[]>;

  constructor(
    name: string,
    help: string,
    type: "counter" | "gauge",
    collect: () => readonly Sample[] | Promise<readonly Sample[]>,
  ) {
    super(name, help);
    this.type = type;
    this.#collect = collect;
  }

  async render(): Promise<string[]> {
    const samples = await this.#collect();
    return samples.slice(0, MAX_SERIES).map(({ labels, value }) => {
      checkLabels(labels);
      return `${this.name}${formatLabels(labels)} ${formatValue(value)}`;
    });
  }
}

export interface MetricRegistryOptions {
  /** Prefix of the registry's own metrics (`{prefix}_metric_series_dropped_total`). */
  readonly prefix?: string;
}

export class MetricRegistry {
  readonly #metrics = new Map<string, Metric>();
  readonly #dropped: Counter;

  constructor(options: MetricRegistryOptions = {}) {
    const name = `${options.prefix ?? "portvakt"}_metric_series_dropped_total`;
    this.#dropped = new Counter(name, "Label sets dropped because a metric reached its cap");
    this.#metrics.set(name, this.#dropped);
  }

  #register<T extends Metric>(metric: T, kind: abstract new (...args: never[]) => T): T {
    if (!NAME.test(metric.name)) throw new Error(`invalid metric name ${metric.name}`);
    const existing = this.#metrics.get(metric.name);
    if (existing !== undefined) {
      if (!(existing instanceof kind)) {
        throw new Error(`metric ${metric.name} is registered as a ${existing.type}`);
      }
      return existing;
    }
    this.#metrics.set(metric.name, metric);
    return metric;
  }

  readonly #onDrop = (metric: string) => () => this.#dropped.inc({ metric });

  /** The counter `name`, created on first use. */
  counter(name: string, help: string): Counter {
    return this.#register(new Counter(name, help, this.#onDrop(name)), Counter);
  }

  gauge(name: string, help: string): Gauge {
    return this.#register(new Gauge(name, help, this.#onDrop(name)), Gauge);
  }

  histogram(name: string, help: string, buckets?: readonly number[]): Histogram {
    return this.#register(new Histogram(name, help, buckets, this.#onDrop(name)), Histogram);
  }

  /** A metric read at scrape time; a failing collector only drops its own samples. */
  collect(
    name: string,
    help: string,
    type: "counter" | "gauge",
    collect: () => readonly Sample[] | Promise<readonly Sample[]>,
  ): void {
    if (!NAME.test(name)) throw new Error(`invalid metric name ${name}`);
    if (this.#metrics.has(name)) throw new Error(`metric ${name} is already registered`);
    this.#metrics.set(name, new Collected(name, help, type, collect));
  }

  /** The counters (tests and operations code read them directly). */
  counters(): Counter[] {
    return [...this.#metrics.values()].filter((metric) => metric instanceof Counter);
  }

  /** The metric `name`, if registered. */
  get(name: string): Counter | Gauge | Histogram | undefined {
    const metric = this.#metrics.get(name);
    return metric instanceof Counter || metric instanceof Gauge || metric instanceof Histogram
      ? metric
      : undefined;
  }

  /** Every metric in the Prometheus text format. */
  async render(): Promise<string> {
    const blocks: string[] = [];
    for (const metric of this.#metrics.values()) {
      let lines: string[];
      try {
        lines = await metric.render();
      } catch {
        lines = [];
      }
      blocks.push(
        `# HELP ${metric.name} ${escapeHelp(metric.help)}\n# TYPE ${metric.name} ${metric.type}${
          lines.length > 0 ? `\n${lines.join("\n")}` : ""
        }`,
      );
    }
    return `${blocks.join("\n")}\n`;
  }
}

/** The content type of {@link MetricRegistry.render}. */
export const PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";
