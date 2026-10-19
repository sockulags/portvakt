import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

/**
 * The request a piece of work belongs to, available anywhere below the request's handler
 * through {@link currentRequest} (AsyncLocalStorage): loggers add the ids to every line, error
 * responses carry them, and outgoing calls to Portvakt's own services propagate the trace.
 *
 * Tracing follows W3C Trace Context: a valid incoming `traceparent` keeps its trace id (the
 * caller's span becomes the parent), otherwise a new trace starts. Each request gets its own span
 * id. `requestId` is a well-formed incoming `X-Request-Id`, otherwise the trace id.
 */
export interface RequestContext {
  readonly requestId: string;
  /** 32 lowercase hex characters. */
  readonly traceId: string;
  /** This request's span: 16 lowercase hex characters. */
  readonly spanId: string;
  /** The caller's span, when a `traceparent` came in. */
  readonly parentSpanId?: string;
  /** The trace flags (`01` sampled). */
  readonly flags: string;
}

const storage = new AsyncLocalStorage<RequestContext>();

const TRACEPARENT = /^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(?:-.*)?$/;
const REQUEST_ID = /^[A-Za-z0-9._-]{1,128}$/;
const ZERO_TRACE = "0".repeat(32);
const ZERO_SPAN = "0".repeat(16);

export interface ParsedTraceparent {
  readonly traceId: string;
  readonly parentId: string;
  readonly flags: string;
}

/** A valid W3C `traceparent` header (version 00, or a later version's prefix); else undefined. */
export function parseTraceparent(header: string | undefined): ParsedTraceparent | undefined {
  if (header === undefined || header.length > 512) return undefined;
  const match = TRACEPARENT.exec(header.trim());
  if (match === null) return undefined;
  const [, version = "", traceId = "", parentId = "", flags = ""] = match;
  if (version === "ff" || traceId === ZERO_TRACE || parentId === ZERO_SPAN) return undefined;
  // Version 00 has exactly four fields.
  if (version === "00" && header.trim().length !== 55) return undefined;
  return { traceId, parentId, flags };
}

export const newSpanId = (): string => randomBytes(8).toString("hex");
const newTraceId = (): string => randomUUID().replace(/-/g, "");

/** The context for a request with these headers. */
export function contextFor(headers: {
  readonly traceparent?: string | undefined;
  readonly requestId?: string | undefined;
}): RequestContext {
  const parent = parseTraceparent(headers.traceparent);
  const traceId = parent?.traceId ?? newTraceId();
  const requestId =
    headers.requestId !== undefined && REQUEST_ID.test(headers.requestId)
      ? headers.requestId
      : traceId;
  return {
    requestId,
    traceId,
    spanId: newSpanId(),
    ...(parent === undefined ? {} : { parentSpanId: parent.parentId }),
    flags: parent?.flags ?? "01",
  };
}

/** The `traceparent` value naming `context`'s span (for responses and outgoing calls). */
export const traceparentOf = (context: RequestContext, spanId = context.spanId): string =>
  `00-${context.traceId}-${spanId}-${context.flags}`;

/** The context of the request being handled, if any. */
export const currentRequest = (): RequestContext | undefined => storage.getStore();

/** Runs `fn` as part of `context`. */
export const runWithRequest = <T>(context: RequestContext, fn: () => T): T =>
  storage.run(context, fn);

/**
 * Runs `fn` outside any request context: for timers and background work started while handling
 * a request, whose later log lines must not carry that request's ids.
 */
export const outsideRequest = <T>(fn: () => T): T => storage.exit(fn);

/** The ids a log line carries (pino `mixin`): empty outside a request. */
export function logIds(): { readonly requestId?: string; readonly traceId?: string } {
  const context = storage.getStore();
  return context === undefined ? {} : { requestId: context.requestId, traceId: context.traceId };
}

const header = (req: IncomingMessage, name: string): string | undefined => {
  const value = req.headers[name];
  return typeof value === "string" ? value : undefined;
};

/**
 * Middleware: derives the request's context from `traceparent` and `X-Request-Id`, echoes
 * `X-Request-Id` and this request's `traceparent` in the response, and runs the rest of the
 * chain inside the context.
 */
export function requestContextMiddleware() {
  return (req: IncomingMessage, res: ServerResponse, next: () => void): void => {
    const context = contextFor({
      traceparent: header(req, "traceparent"),
      requestId: header(req, "x-request-id"),
    });
    res.setHeader("X-Request-Id", context.requestId);
    res.setHeader("traceparent", traceparentOf(context));
    storage.run(context, next);
  };
}
