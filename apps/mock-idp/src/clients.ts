import { existsSync, readFileSync } from "node:fs";
import { z } from "zod";

/**
 * `entra` (single tenant), `entra-mt` (multi-tenant: configured as
 * `{publicUrl}/entra-mt/organizations/v2.0`, discovery issuer with `{tenantid}`) and `bankid`.
 */
export const ISSUER_KINDS = ["entra", "entra-mt", "bankid"] as const;
export type IssuerKind = (typeof ISSUER_KINDS)[number];

const url = z.string().refine((value) => {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}, "must be an http(s) URL");

/**
 * A relying party of a mock issuer (Portvakt's login method). Either exact `redirect_uris`, or
 * (development convenience) `redirect_uri_prefixes` that every redirect URI starting with them
 * matches, such as `http://localhost:3000/t/` for every login method of a local Portvakt.
 */
export const mockClientSchema = z
  .object({
    issuer: z.enum(ISSUER_KINDS),
    client_id: z.string().min(1).max(255),
    client_secret: z.string().min(1).max(512).optional(),
    token_endpoint_auth_method: z
      .enum(["client_secret_basic", "client_secret_post", "private_key_jwt"])
      .default("client_secret_basic"),
    /** For private_key_jwt: where the client's public keys are (Portvakt's federation JWKS). */
    jwks_uri: url.optional(),
    redirect_uris: z.array(url).default([]),
    redirect_uri_prefixes: z.array(url).default([]),
    /** Test aid: ID tokens for this client never carry auth_time (even when max_age asks). */
    omit_auth_time: z.boolean().default(false),
  })
  .strict()
  .refine(
    (client) => client.redirect_uris.length > 0 || client.redirect_uri_prefixes.length > 0,
    "redirect_uris or redirect_uri_prefixes is required",
  )
  .refine(
    (client) =>
      client.token_endpoint_auth_method === "private_key_jwt"
        ? client.jwks_uri !== undefined
        : client.client_secret !== undefined,
    "client_secret (secret methods) or jwks_uri (private_key_jwt) is required",
  );
export type MockClientInput = z.input<typeof mockClientSchema>;
export type MockClient = z.output<typeof mockClientSchema>;

/** Development clients when MOCK_IDP_CLIENTS is not set: any login method of a local Portvakt. */
export const DEV_CLIENTS: readonly MockClientInput[] = [
  {
    issuer: "entra",
    client_id: "portvakt-dev",
    client_secret: "dev-only-entra-client-secret",
    redirect_uri_prefixes: ["http://localhost:3000/t/"],
  },
  {
    issuer: "bankid",
    client_id: "portvakt-dev",
    client_secret: "dev-only-bankid-client-secret",
    redirect_uri_prefixes: ["http://localhost:3000/t/"],
  },
];

/** MOCK_IDP_CLIENTS: inline JSON (an array) or the path of a JSON file with one. */
export function parseClients(value: string | undefined): MockClient[] {
  if (value === undefined || value.trim() === "") {
    return DEV_CLIENTS.map((client) => mockClientSchema.parse(client));
  }
  const text = value.trim().startsWith("[")
    ? value
    : existsSync(value)
      ? readFileSync(value, "utf8")
      : (() => {
          throw new Error("MOCK_IDP_CLIENTS: neither a JSON array nor an existing file");
        })();
  return z.array(mockClientSchema).parse(JSON.parse(text));
}
