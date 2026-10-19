/** Base class of every error the SDK throws on purpose. `code` is stable and safe to show. */
export class PortvaktError extends Error {
  readonly code: string;
  /** The HTTP status the SDK's middleware answers with for this error. */
  readonly status: number;

  constructor(code: string, message: string, status: number, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
    this.code = code;
    this.status = status;
  }
}

/** The configuration passed to the SDK is invalid. The message lists the problems. */
export class PortvaktConfigError extends PortvaktError {
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super("invalid_config", `Invalid Portvakt SDK configuration:\n- ${issues.join("\n- ")}`, 500);
    this.issues = issues;
  }
}

/**
 * Portvakt could not be reached (network error, timeout or a 5xx answer), or asked to retry
 * later (429, or the OAuth error `temporarily_unavailable`).
 */
export class PortvaktUnavailableError extends PortvaktError {
  /** Portvakt's `Retry-After` in seconds, when it sent one (the SDK's 503 passes it on). */
  readonly retryAfterSeconds: number | undefined;

  constructor(
    message = "Portvakt is unavailable",
    options?: ErrorOptions & { readonly retryAfterSeconds?: number | undefined },
  ) {
    super("portvakt_unavailable", message, 503, options);
    this.retryAfterSeconds = options?.retryAfterSeconds;
  }
}

/**
 * Why a BFF session ended or does not exist: `no_session`, `session_expired` (the broker
 * session's `session_exp`, the BFF's own maximum age or its idle timeout), `refresh_failed`
 * (Portvakt refused the refresh token: revoked, replayed or the broker session ended) and
 * `outage_grace_exceeded` (Portvakt stayed unreachable longer than the outage grace).
 */
export type SessionEndReason =
  "no_session" | "session_expired" | "refresh_failed" | "outage_grace_exceeded";

/** The request has no (longer a) valid BFF session: the person must sign in again. */
export class LoginRequiredError extends PortvaktError {
  readonly reason: SessionEndReason;

  constructor(reason: SessionEndReason) {
    super("login_required", `Sign-in required (${reason})`, 401);
    this.reason = reason;
  }
}

/** The login callback failed (state, PKCE, nonce, an error from Portvakt, a bad ID token). */
export class LoginFailedError extends PortvaktError {
  constructor(code: string, message: string, status = 400, options?: ErrorOptions) {
    super(code, message, status, options);
  }
}
