import type { NextFunction, Request, RequestHandler, Response } from "express";
import { errors as joseErrors, jwtVerify } from "jose";
import { z } from "zod";
import { formatIssues, type ResolvedConfig } from "./config.js";
import { PortvaktConfigError, PortvaktError, PortvaktUnavailableError } from "./errors.js";
import type { JwksCache } from "./jwks.js";
import { UnknownKeyError } from "./jwks.js";
import { errorDetails } from "./logger.js";
import { acrAtLeast, principalFromAccessToken, type Principal } from "./principal.js";

/** What a route requires of the access token (see {@link AccessTokenValidator.middleware}). */
export interface AccessTokenRequirements {
  /** The token's `aud`: this API's client_id (Portvakt issues one audience per token). */
  readonly audience: string;
  /** Person tokens must carry every one of these roles. */
  readonly roles?: readonly string[];
  /** Person tokens must carry at least one of these roles. */
  readonly anyRole?: readonly string[];
  /** Person tokens must have an acr at least this high (acr ranking of the client). */
  readonly acr?: string;
  /**
   * Accept client_credentials tokens: `true` for any application of the tenant, or a list of
   * allowed client_ids. Default false. Role and acr requirements apply to person tokens only;
   * a service principal never has roles.
   */
  readonly allowService?: boolean | readonly string[];
  /**
   * Accept person tokens that act for another party (`rep`). Default true. The application must
   * still authorise every action on behalf of `rep.sub` with its own rules.
   */
  readonly allowRepresentation?: boolean;
}

const requirementsSchema = z
  .object({
    audience: z.string().min(1).max(255),
    roles: z.array(z.string().min(1).max(255)).max(100).optional(),
    anyRole: z.array(z.string().min(1).max(255)).min(1).max(100).optional(),
    acr: z.string().min(1).max(255).optional(),
    allowService: z.union([z.boolean(), z.array(z.string().min(1).max(255)).max(100)]).optional(),
    allowRepresentation: z.boolean().optional(),
  })
  .strict();

/** RFC 6750 error codes (and RFC 9470's `insufficient_user_authentication`). */
export type BearerErrorCode =
  "invalid_request" | "invalid_token" | "insufficient_scope" | "insufficient_user_authentication";

/**
 * A refused bearer token. `error` and `description` are safe to send to the caller: they never
 * name which claim or key failed beyond the category.
 */
export class AccessTokenError extends PortvaktError {
  readonly error: BearerErrorCode | undefined;
  readonly description: string | undefined;
  /** Machine-readable detail for the JSON body (`missing_role`, `representation_not_allowed`). */
  readonly reason: string | undefined;
  readonly acrValues: string | undefined;

  constructor(
    status: 400 | 401 | 403,
    error: BearerErrorCode | undefined,
    description: string | undefined,
    extra: { readonly reason?: string; readonly acrValues?: string } = {},
  ) {
    super(error ?? "missing_token", description ?? "An access token is required", status);
    this.error = error;
    this.description = description;
    this.reason = extra.reason;
    this.acrValues = extra.acrValues;
  }
}

const TOKEN = /^[A-Za-z0-9\-._~+/]+=*$/;
const MAX_TOKEN_LENGTH = 16_384;
const invalid = (description = "The access token is invalid") =>
  new AccessTokenError(401, "invalid_token", description);

/** The bearer token of a request: exactly one `Authorization: Bearer` header, nothing else. */
export function bearerTokenOf(req: Request): string | undefined {
  const header = req.headers.authorization;
  if (header === undefined || header === "") return undefined;
  const match = /^Bearer +(\S+) *$/i.exec(header);
  if (match === null) {
    throw new AccessTokenError(400, "invalid_request", "The Authorization header is malformed");
  }
  const token = match[1]!;
  if (token.length > MAX_TOKEN_LENGTH || !TOKEN.test(token)) throw invalid();
  return token;
}

const principals = new WeakMap<Request, Principal>();

/** The principal {@link AccessTokenValidator.middleware} attached to the request, if any. */
export function accessTokenPrincipal(req: Request): Principal | undefined {
  return principals.get(req);
}

/**
 * Access token validation with jose: signature with Portvakt's ES256 keys only (no `none`, no
 * HMAC), header `typ: at+jwt`, `iss` exactly the configured tenant issuer (the signing keys are
 * shared by every tenant, so a token of another tenant verifies but is refused here), `aud`, and
 * `exp`/`nbf`/`iat` with the configured clock skew.
 */
export class AccessTokenValidator {
  readonly #config: ResolvedConfig;
  readonly #jwks: JwksCache;

  constructor(config: ResolvedConfig, jwks: JwksCache) {
    this.#config = config;
    this.#jwks = jwks;
  }

  /** Validates a token for `audience`; throws {@link AccessTokenError} or unavailable. */
  async verify(token: string, audience: string): Promise<Principal> {
    if (token.length > MAX_TOKEN_LENGTH || token.split(".").length !== 3) throw invalid();
    let payload: Record<string, unknown>;
    try {
      const verified = await jwtVerify(token, (header) => this.#jwks.keyFor(header), {
        algorithms: ["ES256"],
        typ: "at+jwt",
        issuer: this.#config.issuer,
        audience,
        clockTolerance: this.#config.clockSkewSeconds,
        requiredClaims: ["iss", "aud", "exp", "iat", "sub", "client_id"],
      });
      payload = verified.payload;
    } catch (error) {
      if (error instanceof PortvaktUnavailableError) throw error;
      if (error instanceof joseErrors.JWTExpired) throw invalid("The access token has expired");
      if (!(error instanceof UnknownKeyError) && !(error instanceof joseErrors.JOSEError)) {
        this.#config.logger.warn(errorDetails(error), "access token validation failed");
      }
      throw invalid();
    }
    if (
      typeof payload.iat === "number" &&
      payload.iat > nowSeconds() + this.#config.clockSkewSeconds
    ) {
      throw invalid();
    }
    const principal = principalFromAccessToken(payload);
    if (principal === null) throw invalid();
    return principal;
  }

  /** Checks a verified principal against the route's requirements. */
  authorize(principal: Principal, requirements: AccessTokenRequirements): void {
    if (principal.isService) {
      const allowed = requirements.allowService;
      const ok =
        allowed === true || (Array.isArray(allowed) && allowed.includes(principal.clientId));
      if (!ok) {
        throw new AccessTokenError(
          403,
          "insufficient_scope",
          "A person's access token is required",
          {
            reason: "service_not_allowed",
          },
        );
      }
      return;
    }
    if (principal.rep !== undefined && requirements.allowRepresentation === false) {
      throw new AccessTokenError(
        403,
        "insufficient_scope",
        "Acting on behalf of another party is not allowed here",
        { reason: "representation_not_allowed" },
      );
    }
    const missing = (requirements.roles ?? []).some((role) => !principal.roles.includes(role));
    const anyRole = requirements.anyRole;
    if (
      missing ||
      (anyRole !== undefined && !anyRole.some((role) => principal.roles.includes(role)))
    ) {
      throw new AccessTokenError(403, "insufficient_scope", "A required role is missing", {
        reason: "missing_role",
      });
    }
    const acr = requirements.acr;
    if (acr !== undefined && !acrAtLeast(principal.acr, acr, this.#config.acrRanking)) {
      throw new AccessTokenError(
        401,
        "insufficient_user_authentication",
        "A higher authentication level is required",
        { reason: "acr_not_met", acrValues: acr },
      );
    }
  }

  /** Express middleware: validates the bearer token and attaches the principal. */
  middleware(input: AccessTokenRequirements): RequestHandler {
    const parsed = requirementsSchema.safeParse(input);
    if (!parsed.success)
      throw new PortvaktConfigError(formatIssues(parsed.error, "requireAccessToken"));
    const requirements = input;
    return (req: Request, res: Response, next: NextFunction) => {
      void (async () => {
        try {
          const token = bearerTokenOf(req);
          if (token === undefined) throw new AccessTokenError(401, undefined, undefined);
          const principal = await this.verify(token, requirements.audience);
          this.authorize(principal, requirements);
          principals.set(req, principal);
          next();
        } catch (error) {
          if (error instanceof AccessTokenError) {
            sendBearerError(res, error);
            return;
          }
          if (error instanceof PortvaktUnavailableError) {
            res.status(503).set("Retry-After", "5").set("Cache-Control", "no-store").json({
              error: "temporarily_unavailable",
              error_description: "The token cannot be validated right now",
            });
            return;
          }
          next(error);
        }
      })();
    };
  }
}

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

/** A 400/401/403 with `WWW-Authenticate: Bearer ...` (RFC 6750 section 3) and a JSON body. */
export function sendBearerError(res: Response, error: AccessTokenError): void {
  const params = [
    'realm="portvakt"',
    ...(error.error === undefined ? [] : [`error="${error.error}"`]),
    ...(error.error === undefined || error.description === undefined
      ? []
      : [`error_description="${error.description}"`]),
    ...(error.acrValues === undefined
      ? []
      : [`acr_values="${error.acrValues.replace(/["\\]/g, "")}"`]),
  ];
  res
    .status(error.status)
    .set("WWW-Authenticate", `Bearer ${params.join(", ")}`)
    .set("Cache-Control", "no-store")
    .json({
      error: error.error ?? "missing_token",
      error_description: error.description ?? "An access token is required",
      ...(error.reason === undefined ? {} : { reason: error.reason }),
      ...(error.acrValues === undefined ? {} : { acr_values: error.acrValues }),
    });
}
