import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { PROMETHEUS_CONTENT_TYPE, type MetricRegistry } from "./metrics.js";

/** Seconds buckets for HTTP latency. */
const HTTP_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30];

export interface HttpMetricsOptions {
  /** Metric name prefix: `{prefix}_http_requests_total`, `{prefix}_http_request_duration_seconds`. */
  readonly prefix: string;
  /**
   * The route template of a finished request (`/t/{slug}/token`), never the raw path: raw paths
   * carry ids and tenant-chosen text. Unknown routes should map to a fixed value such as `other`.
   */
  readonly routeOf: (req: IncomingMessage, res: ServerResponse) => string;
}

const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

/** Middleware counting requests and their latency by method, route template and status. */
export function httpMetricsMiddleware(registry: MetricRegistry, options: HttpMetricsOptions) {
  const requests = registry.counter(
    `${options.prefix}_http_requests_total`,
    "HTTP requests by method, route template and status code",
  );
  const duration = registry.histogram(
    `${options.prefix}_http_request_duration_seconds`,
    "HTTP request latency by method, route template and status code",
    HTTP_BUCKETS,
  );
  return (req: IncomingMessage, res: ServerResponse, next: () => void): void => {
    const stop = duration.startTimer();
    res.once("finish", () => {
      const labels = {
        method: METHODS.has(req.method ?? "") ? (req.method ?? "") : "other",
        route: options.routeOf(req, res),
        status: String(res.statusCode),
      };
      requests.inc(labels);
      stop(labels);
    });
    next();
  };
}

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export interface MetricsHandlerOptions {
  /** Bearer token required to scrape (`Authorization: Bearer <token>`); none: unprotected. */
  readonly token?: string | undefined;
}

/**
 * `GET /metrics` in the Prometheus text format. With a token, anything else gets 401 (no body
 * hinting at the metrics). Never cached.
 */
export function metricsHandler(registry: MetricRegistry, options: MetricsHandlerOptions = {}) {
  const expected = options.token === undefined ? undefined : `Bearer ${options.token}`;
  return (req: IncomingMessage, res: ServerResponse): void => {
    res.setHeader("Cache-Control", "no-store");
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.statusCode = 405;
      res.setHeader("Allow", "GET, HEAD");
      res.end();
      return;
    }
    const auth = req.headers.authorization;
    if (expected !== undefined && (auth === undefined || !safeEqual(auth, expected))) {
      res.statusCode = 401;
      res.setHeader("WWW-Authenticate", 'Bearer realm="metrics"');
      res.end();
      return;
    }
    registry.render().then(
      (body) => {
        res.statusCode = 200;
        res.setHeader("Content-Type", PROMETHEUS_CONTENT_TYPE);
        res.end(req.method === "HEAD" ? undefined : body);
      },
      () => {
        res.statusCode = 500;
        res.end();
      },
    );
  };
}

/**
 * Process metrics under the conventional names: CPU seconds, resident memory, heap, start time,
 * event loop delay. Returns a function that stops the event loop monitor.
 */
export function registerProcessMetrics(registry: MetricRegistry): () => void {
  const loop = monitorEventLoopDelay({ resolution: 20 });
  loop.enable();
  const startTime = Math.round((Date.now() - performance.now()) / 1000);
  registry.collect("process_cpu_user_seconds_total", "User CPU time", "counter", () => [
    { labels: {}, value: process.cpuUsage().user / 1e6 },
  ]);
  registry.collect("process_cpu_system_seconds_total", "System CPU time", "counter", () => [
    { labels: {}, value: process.cpuUsage().system / 1e6 },
  ]);
  registry.collect("process_resident_memory_bytes", "Resident memory size", "gauge", () => [
    { labels: {}, value: process.memoryUsage.rss() },
  ]);
  registry.collect("nodejs_heap_size_used_bytes", "V8 heap used", "gauge", () => [
    { labels: {}, value: process.memoryUsage().heapUsed },
  ]);
  registry.collect("nodejs_heap_size_total_bytes", "V8 heap total", "gauge", () => [
    { labels: {}, value: process.memoryUsage().heapTotal },
  ]);
  registry.collect("process_start_time_seconds", "Process start (Unix time)", "gauge", () => [
    { labels: {}, value: startTime },
  ]);
  registry.collect(
    "nodejs_eventloop_delay_p99_seconds",
    "Event loop delay, 99th percentile since the last scrape",
    "gauge",
    () => {
      const value = loop.percentile(99) / 1e9;
      loop.reset();
      return [{ labels: {}, value: Number.isFinite(value) ? value : 0 }];
    },
  );
  return () => loop.disable();
}
