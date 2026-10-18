import type { z } from "zod";

/** Base class for errors raised by repositories. Messages never contain personal data. */
export class RepositoryError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class NotFoundError extends RepositoryError {
  readonly entity: string;

  constructor(entity: string) {
    super(`${entity} not found`);
    this.entity = entity;
  }
}

/** A uniqueness constraint was violated (for example a duplicate tenant slug). */
export class ConflictError extends RepositoryError {
  readonly constraint: string | undefined;

  constructor(message: string, constraint?: string, options?: ErrorOptions) {
    super(message, options);
    this.constraint = constraint;
  }
}

/** A referenced row does not exist, or exists in another tenant. */
export class InvalidReferenceError extends RepositoryError {
  readonly constraint: string | undefined;

  constructor(message: string, constraint?: string, options?: ErrorOptions) {
    super(message, options);
    this.constraint = constraint;
  }
}

/** Input failed validation (zod or a database CHECK constraint). */
export class ValidationError extends RepositoryError {
  readonly issues: readonly string[];

  constructor(issues: readonly string[], options?: ErrorOptions) {
    super(`Invalid input: ${issues.join("; ")}`, options);
    this.issues = issues;
  }
}

/** The role is not declared by the application. */
export class UndeclaredRoleError extends RepositoryError {
  readonly applicationId: string;
  readonly role: string;

  constructor(applicationId: string, role: string) {
    super(`Role "${role}" is not declared by application ${applicationId}`);
    this.applicationId = applicationId;
    this.role = role;
  }
}

/** The attribute key is not declared by the application. */
export class UndeclaredAttributeKeyError extends RepositoryError {
  readonly applicationId: string;
  readonly key: string;

  constructor(applicationId: string, key: string) {
    super(`Attribute key "${key}" is not declared by application ${applicationId}`);
    this.applicationId = applicationId;
    this.key = key;
  }
}

/** The application is not attached to the tenant. */
export class ApplicationNotInTenantError extends RepositoryError {
  constructor(applicationId: string) {
    super(`Application ${applicationId} is not attached to the tenant`);
  }
}

export class InvalidStateTransitionError extends RepositoryError {
  constructor(entity: string, from: string, to: string) {
    super(`${entity} cannot move from ${from} to ${to}`);
  }
}

/** The transition is allowed, but not yet: a timing guard (for example publish-ahead) applies. */
export class TransitionNotDueError extends RepositoryError {
  constructor(entity: string, to: string) {
    super(`${entity} is not due to become ${to} yet`);
  }
}

/** An id argument is not a well-formed UUID; nothing can match it. */
export class InvalidIdError extends ValidationError {
  readonly field: string;

  constructor(field: string) {
    super([`${field}: must be a UUID`]);
    this.field = field;
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validates id arguments before they reach SQL (a malformed id would otherwise surface as a
 * Postgres cast error). Throws {@link InvalidIdError} naming the first bad field.
 */
export function requireUuids(ids: Readonly<Record<string, string | null | undefined>>): void {
  for (const [field, value] of Object.entries(ids)) {
    if (value !== null && value !== undefined && !(typeof value === "string" && UUID.test(value))) {
      throw new InvalidIdError(field);
    }
  }
}

export function parseInput<S extends z.ZodType>(schema: S, input: unknown): z.output<S> {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new ValidationError(
      result.error.issues.map((issue) => `${issue.path.join(".") || "input"}: ${issue.message}`),
    );
  }
  return result.data;
}

interface PgError {
  code: string;
  constraint?: string;
}

function isPgError(error: unknown): error is PgError {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof error.code === "string" &&
    "severity" in error
  );
}

/**
 * Translates Postgres integrity errors into repository errors. Only the constraint name is kept;
 * the server's message can contain row values and is dropped.
 */
export function translateDbError(error: unknown): unknown {
  if (!isPgError(error)) return error;
  switch (error.code) {
    case "23505":
      return new ConflictError("A conflicting record already exists", error.constraint, {
        cause: error,
      });
    case "23503":
      return new InvalidReferenceError("A referenced record does not exist", error.constraint, {
        cause: error,
      });
    case "23514":
    case "23502":
    case "22P02":
      return new ValidationError([`database constraint ${error.constraint ?? error.code}`], {
        cause: error,
      });
    default:
      return error;
  }
}

/** Runs `fn` and rethrows database integrity errors as repository errors. */
export async function mapDbErrors<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    throw translateDbError(error);
  }
}
