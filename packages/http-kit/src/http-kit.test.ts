import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  contextFor,
  currentRequest,
  httpMetricsMiddleware,
  ipRateLimitKey,
  logIds,
  MAX_SERIES,
  MetricRegistry,
  metricsHandler,
  outsideRequest,
  parseRateLimit,
  parseTraceparent,
  RateLimiterSet,
  registerProcessMetrics,
  requestContextMiddleware,
  runWithRequest,
  TokenBucketLimiter,
  traceparentOf,
} from "./index.js";

describe("MetricRegistry", () => {
  it("renders counters, gauges, histograms and collectors in the Prometheus text format", async () => {
    const registry = new MetricRegistry({ prefix: "test" });
    registry.counter("test_events_total", "Events").inc({ reason: 'a"b\\c\nd' }, 2);
    registry.gauge("test_level", "Level").set({}, 1.5);
    const histogram = registry.histogram("test_seconds", "Latency", [0.1, 1]);
    histogram.observe({ route: "/x" }, 0.05);
    histogram.observe({ route: "/x" }, 0.5);
    histogram.observe({ route: "/x" }, 5);
    registry.collect("test_collected", "Collected", "gauge", () => [
      { labels: { state: "active" }, value: 3 },
    ]);
    const text = await registry.render();
    expect(text).toContain("# TYPE test_events_total counter");
    expect(text).toContain('test_events_total{reason="a\\"b\\\\c\\nd"} 2');
    expect(text).toContain("test_level 1.5");
    expect(text).toContain('test_seconds_bucket{route="/x",le="0.1"} 1');
    expect(text).toContain('test_seconds_bucket{route="/x",le="1"} 2');
    expect(text).toContain('test_seconds_bucket{route="/x",le="+Inf"} 3');
    expect(text).toContain('test_seconds_count{route="/x"} 3');
    expect(text).toContain('test_collected{state="active"} 3');
    expect(text.endsWith("\n")).toBe(true);
  });

  it("returns the same metric for the same name and refuses a different kind", () => {
    const registry = new MetricRegistry();
    expect(registry.counter("a_total", "A")).toBe(registry.counter("a_total", "A"));
    expect(() => registry.gauge("a_total", "A")).toThrow(/registered as a counter/);
    expect(() => registry.counter("bad-name", "x")).toThrow(/invalid metric name/);
    expect(() => registry.counter("b_total", "B").inc({ "bad-label": "x" })).toThrow(/label/);
  });

  it("caps the label sets of a metric and counts what it drops", () => {
    const registry = new MetricRegistry({ prefix: "test" });
    const counter = registry.counter("test_capped_total", "Capped");
    for (let i = 0; i < MAX_SERIES + 5; i += 1) counter.inc({ id: String(i) });
    expect(counter.samples()).toHaveLength(MAX_SERIES);
    expect(
      registry.counter("test_metric_series_dropped_total", "").get({ metric: "test_capped_total" }),
    ).toBe(5);
  });

  it("drops the samples of a failing collector only", async () => {
    const registry = new MetricRegistry();
    registry.collect("broken", "Broken", "gauge", () => {
      throw new Error("down");
    });
    registry.gauge("fine", "Fine").set({}, 1);
    const text = await registry.render();
    expect(text).toContain("# TYPE broken gauge");
    expect(text).toContain("fine 1");
  });

  it("registers process metrics", async () => {
    const registry = new MetricRegistry();
    const stop = registerProcessMetrics(registry);
    try {
      const text = await registry.render();
      expect(text).toMatch(/process_resident_memory_bytes \d+/);
      expect(text).toMatch(/process_cpu_user_seconds_total [\d.e-]+/);
      expect(text).toContain("nodejs_eventloop_delay_p99_seconds");
    } finally {
      stop();
    }
  });
});

describe("rate limits", () => {
  it("keys IPv6 addresses by /64 and IPv4 (also IPv4-mapped) by the address", () => {
    expect(ipRateLimitKey("192.0.2.7")).toBe("192.0.2.7");
    expect(ipRateLimitKey("::ffff:192.0.2.7")).toBe("192.0.2.7");
    expect(ipRateLimitKey("2001:db8:1:2:3:4:5:6")).toBe("2001:db8:1:2::/64");
    expect(ipRateLimitKey("2001:DB8:0001:0002::9")).toBe("2001:db8:1:2::/64");
    expect(ipRateLimitKey("2001:db8::1")).toBe("2001:db8:0:0::/64");
    expect(ipRateLimitKey("fe80::1%eth0")).toBe("fe80:0:0:0::/64");
    expect(ipRateLimitKey("::1")).toBe("0:0:0:0::/64");
    expect(ipRateLimitKey("64:ff9b::192.0.2.1")).toBe("64:ff9b:0:0::/64");
    expect(ipRateLimitKey("unknown")).toBe("unknown");
    expect(ipRateLimitKey("1::2::3")).toBe("1::2::3");
  });

  it("parses limit specifications", () => {
    expect(parseRateLimit("60/1m")).toEqual({ capacity: 60, periodSeconds: 60 });
    expect(parseRateLimit("10/30s")).toEqual({ capacity: 10, periodSeconds: 30 });
    expect(parseRateLimit("5/m")).toEqual({ capacity: 5, periodSeconds: 60 });
    expect(parseRateLimit("1000/1h")).toEqual({ capacity: 1000, periodSeconds: 3600 });
    expect(parseRateLimit("off")).toBeNull();
    expect(parseRateLimit("0")).toBeNull();
    for (const bad of ["", "60", "60/0s", "0/1m", "x/1m", "60/1d", "-1/1m"]) {
      expect(parseRateLimit(bad)).toBeUndefined();
    }
  });

  it("allows a burst, refuses with Retry-After, and refills over time", () => {
    let now = 0;
    const limiter = new TokenBucketLimiter({ capacity: 3, periodSeconds: 60 }, { now: () => now });
    expect([1, 2, 3].map(() => limiter.take("ip").allowed)).toEqual([true, true, true]);
    const refused = limiter.take("ip");
    expect(refused).toEqual({ allowed: false, retryAfterSeconds: 20 });
    // Other keys have their own bucket.
    expect(limiter.take("other").allowed).toBe(true);
    now += 20_000;
    expect(limiter.take("ip").allowed).toBe(true);
    expect(limiter.take("ip").allowed).toBe(false);
  });

  it("keeps a bounded number of buckets, evicting the least recently used", () => {
    const limiter = new TokenBucketLimiter({ capacity: 1, periodSeconds: 60 }, { maxKeys: 2 });
    limiter.take("a");
    limiter.take("b");
    limiter.take("a");
    limiter.take("c");
    expect(limiter.size).toBe(2);
    // "b" was evicted (least recently used), so it starts full again; "a" is still empty.
    expect(limiter.take("b").allowed).toBe(true);
    expect(limiter.take("c").allowed).toBe(false);
  });

  it("stops at the first refusal of a set, without draining later buckets", () => {
    const set = new RateLimiterSet({
      ip: { capacity: 1, periodSeconds: 60 },
      client: { capacity: 2, periodSeconds: 60 },
      off: null,
    });
    expect(set.enabled("off")).toBe(false);
    const checks = [
      ["ip", "1.2.3.4"],
      ["client", "app"],
      ["off", "x"],
    ] as const;
    expect(set.check(checks)).toEqual({ allowed: true });
    expect(set.check(checks)).toMatchObject({ allowed: false, limit: "ip" });
    expect(
      set.check([
        ["ip", "5.6.7.8"],
        ["client", "app"],
      ]),
    ).toEqual({ allowed: true });
    expect(
      set.check([
        ["ip", "9.9.9.9"],
        ["client", "app"],
      ]),
    ).toMatchObject({
      allowed: false,
      limit: "client",
    });
  });
});

describe("request context", () => {
  const valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

  it("parses W3C traceparent headers", () => {
    expect(parseTraceparent(valid)).toEqual({
      traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
      parentId: "00f067aa0ba902b7",
      flags: "01",
    });
    for (const bad of [
      undefined,
      "",
      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
      "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
      "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
      "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
      `${valid}-extra`,
    ]) {
      expect(parseTraceparent(bad)).toBeUndefined();
    }
    // A later version may carry more fields.
    expect(parseTraceparent(`01-${valid.slice(3)}-more`)?.traceId).toBe(
      "4bf92f3577b34da6a3ce929d0e0e4736",
    );
  });

  it("continues an incoming trace with a span of its own, or starts one", () => {
    const continued = contextFor({ traceparent: valid });
    expect(continued.traceId).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
    expect(continued.parentSpanId).toBe("00f067aa0ba902b7");
    expect(continued.spanId).toMatch(/^[0-9a-f]{16}$/);
    expect(continued.spanId).not.toBe("00f067aa0ba902b7");
    expect(continued.requestId).toBe(continued.traceId);
    expect(traceparentOf(continued)).toBe(
      `00-4bf92f3577b34da6a3ce929d0e0e4736-${continued.spanId}-01`,
    );

    const fresh = contextFor({ traceparent: "garbage", requestId: "req-1" });
    expect(fresh.traceId).toMatch(/^[0-9a-f]{32}$/);
    expect(fresh.parentSpanId).toBeUndefined();
    expect(fresh.requestId).toBe("req-1");
    expect(contextFor({ requestId: "bad id with spaces" }).requestId).toMatch(/^[0-9a-f]{32}$/);
  });

  it("puts the ids on log lines inside a request only", async () => {
    const context = contextFor({ requestId: "req-1" });
    expect(logIds()).toEqual({});
    const inside = await runWithRequest(context, async () => {
      await new Promise((resolve) => setTimeout(resolve, 1));
      return logIds();
    });
    expect(inside).toEqual({ requestId: "req-1", traceId: context.traceId });
    // A timer armed during a request but run outside it (background work).
    const later = await runWithRequest(
      context,
      () =>
        new Promise<ReturnType<typeof logIds>>((resolve) => {
          outsideRequest(() => setTimeout(() => resolve(logIds()), 1));
        }),
    );
    expect(later).toEqual({});
  });
});

describe("HTTP middleware", () => {
  let server: Server | undefined;
  afterEach(async () => {
    await new Promise((resolve) => server?.close(resolve));
    server = undefined;
  });

  async function serve(handler: Parameters<typeof createServer>[1]): Promise<string> {
    server = createServer(handler);
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  it("propagates the request context and counts requests by route template", async () => {
    const registry = new MetricRegistry();
    const context = requestContextMiddleware();
    const metrics = httpMetricsMiddleware(registry, { prefix: "t", routeOf: () => "/x/{id}" });
    const base = await serve((req, res) => {
      context(req, res, () =>
        metrics(req, res, () => {
          setTimeout(() => res.end(currentRequest()?.traceId ?? "none"), 1);
        }),
      );
    });
    const response = await fetch(`${base}/x/123`, {
      headers: { traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" },
    });
    expect(await response.text()).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
    expect(response.headers.get("x-request-id")).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
    expect(response.headers.get("traceparent")).toMatch(
      /^00-4bf92f3577b34da6a3ce929d0e0e4736-[0-9a-f]{16}-01$/,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(
      registry
        .counter("t_http_requests_total", "")
        .get({ method: "GET", route: "/x/{id}", status: "200" }),
    ).toBe(1);
  });

  it("protects the metrics endpoint with a bearer token", async () => {
    const registry = new MetricRegistry();
    registry.counter("x_total", "X").inc();
    const base = await serve(metricsHandler(registry, { token: "s3cret-token-0123456789abcdef" }));
    expect((await fetch(base)).status).toBe(401);
    expect((await fetch(base, { headers: { authorization: "Bearer wrong" } })).status).toBe(401);
    const ok = await fetch(base, {
      headers: { authorization: "Bearer s3cret-token-0123456789abcdef" },
    });
    expect(ok.status).toBe(200);
    expect(ok.headers.get("content-type")).toContain("text/plain; version=0.0.4");
    expect(ok.headers.get("cache-control")).toBe("no-store");
    expect(await ok.text()).toContain("x_total 1");
    expect((await fetch(base, { method: "POST" })).status).toBe(405);
  });
});
