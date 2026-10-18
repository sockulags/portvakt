import { z } from "zod";

/** Shared zod building blocks for domain input validation. */

export const uuidSchema = z.uuid();

export const tenantSlugSchema = z
  .string()
  .regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/, "lowercase letters, digits and hyphens");

export const displayNameSchema = z.string().trim().min(1).max(200);

export const clientIdSchema = z.string().regex(/^[A-Za-z0-9._~-]{3,128}$/);

export const roleNameSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/);

export const attributeKeySchema = z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,63}$/);

/** Absolute http(s) URL without a fragment (OIDC redirect URIs must not carry one). */
export const absoluteUrlSchema = z
  .string()
  .max(2000)
  .refine((value) => {
    try {
      const url = new URL(value);
      return (url.protocol === "https:" || url.protocol === "http:") && url.hash === "";
    } catch {
      return false;
    }
  }, "must be an absolute http(s) URL without a fragment");

export const emailDomainSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/,
    "must be a domain name such as example.com",
  );

export const positiveSecondsSchema = z.number().int().positive().max(2_147_483_647);

/** JSON value accepted in free-form details (audit). */
export type JsonValue =
  string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
export const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(jsonValueSchema),
    z.record(z.string(), jsonValueSchema),
  ]),
);
