import { pino, type DestinationStream, type Logger } from "pino";
import type { LogLevel } from "../config/index.js";

export type { Logger };

/**
 * Fields that never reach the log output. Defence in depth: callers must not log personal data,
 * tokens or secrets in the first place (see CLAUDE.md), but if a request or an object carrying
 * them slips into a log call, the value of every key named last in these paths is censored at
 * any depth ({@link REDACTED_KEYS}).
 */
export const REDACTED_PATHS: readonly string[] = [
  "req.headers.authorization",
  "req.headers.cookie",
  "req.headers['dpop']",
  "res.headers['set-cookie']",
  "headers.authorization",
  "headers.cookie",
  "*.password",
  "*.client_secret",
  "*.clientSecret",
  "*.secret",
  "*.token",
  "*.access_token",
  "*.refresh_token",
  "*.id_token",
  "*.id_token_hint",
  "*.code",
  "*.code_verifier",
  "*.client_assertion",
  "*.login_hint",
  "*.pin",
  "*.email",
  "*.name",
];

export interface SerializedError {
  readonly type: string;
  readonly message: string;
  readonly code?: string;
  readonly stack?: string;
  readonly cause?: SerializedError;
}

/**
 * Error serializer that keeps type, message, code and stack only. pino's standard serializer
 * copies every enumerable property; a Postgres error carries `detail` and `where`, which can
 * contain row values (personal data), so those are dropped.
 */
export function serializeError(error: unknown, depth = 0): SerializedError {
  if (!(error instanceof Error)) return { type: typeof error, message: "non-error thrown" };
  const code = (error as { code?: unknown }).code;
  return {
    type: error.name,
    message: error.message,
    ...(typeof code === "string" ? { code } : {}),
    ...(error.stack === undefined ? {} : { stack: error.stack }),
    ...(error.cause !== undefined && depth < 3
      ? { cause: serializeError(error.cause, depth + 1) }
      : {}),
  };
}

export interface LoggerOptions {
  readonly level: LogLevel;
  /** Defaults to stdout. Tests pass a stream to capture output. */
  readonly destination?: DestinationStream;
  readonly base?: Record<string, string>;
}

const CENSOR = "[redacted]";

/**
 * Keys whose values are censored wherever they appear in a log object, at any depth and in any
 * letter case: the final key of every path in {@link REDACTED_PATHS}.
 */
export const REDACTED_KEYS: ReadonlySet<string> = new Set(
  REDACTED_PATHS.map((path) => {
    const last = /([^.'"[\]]+)['"]?\]?$/.exec(path)?.[1] ?? path;
    return last.toLowerCase();
  }),
);

const MAX_DEPTH = 10;

/**
 * Copies a log object with the value of every {@link REDACTED_KEYS} key censored, at any depth.
 * Errors are left to the error serializer (which keeps type, message, code and stack only).
 */
export function redactKeys(value: unknown, depth = 0, seen = new WeakSet<object>()): unknown {
  if (value === null || typeof value !== "object" || value instanceof Error) return value;
  if (depth >= MAX_DEPTH || seen.has(value)) return CENSOR;
  seen.add(value);
  if (Array.isArray(value)) return value.map((item) => redactKeys(item, depth + 1, seen));
  if (value instanceof Date || Buffer.isBuffer(value)) return value;
  const copy: Record<string, unknown> = {};
  for (const [key, inner] of Object.entries(value)) {
    copy[key] = REDACTED_KEYS.has(key.toLowerCase()) ? CENSOR : redactKeys(inner, depth + 1, seen);
  }
  return copy;
}

/** Structured JSON logger (one object per line). */
export function createLogger(options: LoggerOptions): Logger {
  const settings = {
    level: options.level,
    base: { service: "portvakt", ...options.base },
    serializers: {
      err: serializeError,
      // `error` is also used for OAuth error codes (strings): only Errors are serialized.
      error: (value: unknown) => (value instanceof Error ? serializeError(value) : value),
    },
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
      level: (label: string) => ({ level: label }),
      // Runs before the serializers, so serialized errors keep their (non-personal) fields.
      log: (object: Record<string, unknown>) => redactKeys(object) as Record<string, unknown>,
    },
  };
  return options.destination === undefined ? pino(settings) : pino(settings, options.destination);
}
