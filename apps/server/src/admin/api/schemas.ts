import { z } from "zod";

/** Shared building blocks of the admin API's request and response schemas. */

export const isoDateTime = z.iso.datetime({ offset: true });
export const uuid = z.uuid();
export const etag = z.string().describe("Entity tag of this version; send it as If-Match.");

export const tenantParams = z.object({ tenantId: z.uuid() });

/**
 * An object that refuses unknown fields with a field error each (immutable fields such as a
 * tenant's slug included), instead of one error for the whole body.
 */
export function strictBody<S extends z.ZodRawShape>(shape: S): z.ZodObject<S> {
  // Typed without the catch-all's index signature: unknown keys never pass parsing anyway.
  return z.object(shape).catchall(z.never({ error: "unknown or immutable field" }));
}

/** A list response. */
export const listOf = <T extends z.ZodType>(item: T) => z.object({ items: z.array(item) });

export const iso = (date: Date): string => date.toISOString();
export const isoOrNull = (date: Date | null): string | null =>
  date === null ? null : date.toISOString();

/**
 * Free text an administrator writes into the audit log (a rotation reason) must not carry
 * personal data: refused when it contains something that looks like a personal identity
 * number, a long number or an email address.
 */
export const auditReasonSchema = z
  .string()
  .trim()
  .min(1)
  .max(500)
  .refine((value) => !/[\p{Cc}]/u.test(value), "must not contain control characters")
  .refine(
    (value) =>
      !/\d{6,8}[-+ ]?\d{4}/.test(value) &&
      !/\d{9,}/.test(value) &&
      !/[^\s@]+@[^\s@]+\.[^\s@]+/.test(value),
    "must not contain personal data (identity numbers, long numbers or email addresses)",
  );
