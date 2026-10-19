/**
 * The logger the SDK writes to. pino and similar loggers fit as they are (`(details, message)`).
 * The SDK never logs tokens, cookies, session ids or personal data: details carry error codes,
 * client ids and timings only.
 */
export interface PortvaktLogger {
  debug(details: Record<string, unknown>, message: string): void;
  info(details: Record<string, unknown>, message: string): void;
  warn(details: Record<string, unknown>, message: string): void;
  error(details: Record<string, unknown>, message: string): void;
}

/** Default logger: warnings and errors to the console, nothing else. */
export const consoleLogger: PortvaktLogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: (details, message) => {
    console.warn(`[portvakt] ${message}`, details);
  },
  error: (details, message) => {
    console.error(`[portvakt] ${message}`, details);
  },
};

/** A logger that drops everything (tests). */
export const silentLogger: PortvaktLogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

/** Type and code of an error, never its message's request data or a stack with values. */
export function errorDetails(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    const code = (error as { code?: unknown }).code;
    const oauthError = (error as { error?: unknown }).error;
    return {
      errorType: error.name,
      ...(typeof code === "string" ? { code } : {}),
      ...(typeof oauthError === "string" ? { oauthError } : {}),
    };
  }
  return { errorType: typeof error };
}
