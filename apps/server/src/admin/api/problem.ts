import type { Response } from "express";
import { z } from "zod";
import {
  ApplicationNotInTenantError,
  ConflictError,
  InvalidIdError,
  InvalidReferenceError,
  InvalidStateTransitionError,
  NotFoundError,
  TransitionNotDueError,
  UndeclaredAttributeKeyError,
  UndeclaredRoleError,
  ValidationError,
} from "../../repositories/errors.js";

/**
 * Errors of the admin API as RFC 9457 problem details (`application/problem+json`). `code` is a
 * stable machine-readable code; `title` is a fixed English text per code; `errors` lists the
 * fields of a validation failure. Nothing from the request or the database is echoed beyond
 * field paths and fixed messages, and internals (SQL, stack traces) never leave the server.
 */
export const PROBLEM_CODES = {
  unauthorized: { status: 401, title: "Authentication required" },
  invalid_token: { status: 401, title: "The access token is invalid" },
  forbidden: { status: 403, title: "Not allowed" },
  service_token_not_allowed: { status: 403, title: "Service tokens cannot administer" },
  representation_not_allowed: {
    status: 403,
    title: "Tokens issued when representing cannot administer",
  },
  not_found: { status: 404, title: "Not found" },
  method_not_allowed: { status: 405, title: "Method not allowed" },
  conflict: { status: 409, title: "Conflicts with the current state" },
  self_lockout: { status: 409, title: "The change would lock the administrators out" },
  in_use: { status: 409, title: "Still in use; disable it instead" },
  last_identity: { status: 409, title: "The person's only identity; delete the person instead" },
  precondition_failed: { status: 412, title: "The resource was changed by someone else" },
  payload_too_large: { status: 413, title: "The request body is too large" },
  unsupported_media_type: { status: 415, title: "The request body must be JSON" },
  validation_failed: { status: 400, title: "The request is invalid" },
  invalid_json: { status: 400, title: "The request body is not valid JSON" },
  precondition_required: { status: 428, title: "If-Match is required" },
  unavailable: { status: 503, title: "Temporarily unavailable" },
  internal_error: { status: 500, title: "Internal error" },
} as const satisfies Record<string, { status: number; title: string }>;

export type ProblemCode = keyof typeof PROBLEM_CODES;

export interface FieldError {
  readonly field: string;
  readonly message: string;
}

export class ApiError extends Error {
  readonly code: ProblemCode;
  readonly status: number;
  readonly detail: string | undefined;
  readonly errors: readonly FieldError[] | undefined;

  constructor(
    code: ProblemCode,
    options: { readonly detail?: string; readonly errors?: readonly FieldError[] } = {},
  ) {
    super(PROBLEM_CODES[code].title);
    this.name = "ApiError";
    this.code = code;
    this.status = PROBLEM_CODES[code].status;
    this.detail = options.detail;
    this.errors = options.errors;
  }
}

export const notFound = (): ApiError => new ApiError("not_found");

/** A validation failure naming fields: `fieldError("slug", "immutable")`. */
export const fieldError = (field: string, message: string): ApiError =>
  new ApiError("validation_failed", { errors: [{ field, message }] });

export const problemSchema = z
  .object({
    type: z.string(),
    title: z.string(),
    status: z.number().int(),
    code: z.enum(Object.keys(PROBLEM_CODES) as [ProblemCode, ...ProblemCode[]]),
    detail: z.string().optional(),
    errors: z.array(z.object({ field: z.string(), message: z.string() })).optional(),
  })
  .meta({ id: "Problem" });
export type Problem = z.infer<typeof problemSchema>;

export const PROBLEM_TYPE_PREFIX = "urn:portvakt:problem:";

export function problemOf(error: ApiError): Problem {
  return {
    type: `${PROBLEM_TYPE_PREFIX}${error.code}`,
    title: PROBLEM_CODES[error.code].title,
    status: error.status,
    code: error.code,
    ...(error.detail === undefined ? {} : { detail: error.detail }),
    ...(error.errors === undefined ? {} : { errors: [...error.errors] }),
  };
}

export function sendProblem(res: Response, error: ApiError): void {
  res.status(error.status).set("Cache-Control", "no-store").type("application/problem+json");
  if (error.status === 401) {
    res.set(
      "WWW-Authenticate",
      error.code === "invalid_token"
        ? 'Bearer realm="portvakt-admin", error="invalid_token"'
        : 'Bearer realm="portvakt-admin"',
    );
  }
  res.send(JSON.stringify(problemOf(error)));
}

/** Field errors of a zod failure (paths and zod's fixed messages, never input values). */
export function zodFieldErrors(error: z.ZodError, prefix = ""): FieldError[] {
  const fieldOf = (path: readonly PropertyKey[]): string =>
    [prefix, ...path.map(String)].filter((part) => part !== "").join(".") || "body";
  return error.issues.flatMap((issue) =>
    // One error per unknown (or immutable) field, named.
    issue.code === "unrecognized_keys"
      ? issue.keys.map((key) => ({
          field: fieldOf([...issue.path, key]),
          message: "unknown or immutable field",
        }))
      : [{ field: fieldOf(issue.path), message: issue.message }],
  );
}

/** Splits repository validation messages (`field: message`) into field errors. */
function repositoryFieldErrors(error: ValidationError): FieldError[] {
  return error.issues.map((issue) => {
    const separator = issue.indexOf(": ");
    return separator > 0
      ? { field: issue.slice(0, separator), message: issue.slice(separator + 2) }
      : { field: "body", message: issue };
  });
}

/**
 * Maps errors of repositories and services to problems. Anything unknown is an internal error
 * (logged by the caller, never described to the client).
 */
export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  if (error instanceof InvalidIdError) return notFound();
  if (error instanceof UndeclaredRoleError)
    return fieldError("role", "not declared by the application");
  if (error instanceof UndeclaredAttributeKeyError) {
    return fieldError("key", "not declared by the application");
  }
  if (error instanceof ApplicationNotInTenantError) {
    return fieldError("applicationId", "not attached to the tenant");
  }
  if (error instanceof ValidationError) {
    return new ApiError("validation_failed", { errors: repositoryFieldErrors(error) });
  }
  if (error instanceof NotFoundError) return notFound();
  if (error instanceof ConflictError) return new ApiError("conflict");
  if (error instanceof InvalidReferenceError) {
    return new ApiError("validation_failed", {
      errors: [{ field: "body", message: "references a record that does not exist in the tenant" }],
    });
  }
  if (error instanceof InvalidStateTransitionError || error instanceof TransitionNotDueError) {
    return new ApiError("conflict");
  }
  return new ApiError("internal_error");
}
