import { createHash, generateKeyPairSync } from "node:crypto";
import { z } from "zod";

export const SIGNING_ALGORITHMS = ["ES256"] as const;
export type SigningAlgorithm = (typeof SIGNING_ALGORITHMS)[number];

const base64url = z.string().regex(/^[A-Za-z0-9_-]+$/);

/** Public EC P-256 JWK as published in JWKS. Rejects any private member. */
export const publicJwkSchema = z
  .object({
    kty: z.literal("EC"),
    crv: z.literal("P-256"),
    x: base64url,
    y: base64url,
    kid: z.string().min(1),
    alg: z.enum(SIGNING_ALGORITHMS),
    use: z.literal("sig"),
  })
  .strict();
export type PublicJwk = z.infer<typeof publicJwkSchema>;

export const privateJwkSchema = publicJwkSchema.extend({ d: base64url }).strict();
export type PrivateJwk = z.infer<typeof privateJwkSchema>;

export interface GeneratedSigningKey {
  readonly kid: string;
  readonly alg: SigningAlgorithm;
  readonly publicJwk: PublicJwk;
  readonly privateJwk: PrivateJwk;
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url) of an EC key. */
export function ecThumbprint(jwk: { crv: string; kty: string; x: string; y: string }): string {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return createHash("sha256").update(canonical).digest("base64url");
}

/** Generates an ES256 signing key; the kid is the RFC 7638 thumbprint. */
export function generateSigningKey(alg: SigningAlgorithm = "ES256"): GeneratedSigningKey {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const exported = z
    .object({
      kty: z.literal("EC"),
      crv: z.literal("P-256"),
      x: base64url,
      y: base64url,
      d: base64url,
    })
    .parse(privateKey.export({ format: "jwk" }));
  const kid = ecThumbprint(exported);
  const publicJwk: PublicJwk = {
    kty: "EC",
    crv: "P-256",
    x: exported.x,
    y: exported.y,
    kid,
    alg,
    use: "sig",
  };
  return { kid, alg, publicJwk, privateJwk: { ...publicJwk, d: exported.d } };
}
