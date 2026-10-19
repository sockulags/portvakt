import { z } from "zod";
import { idTokenClaimsSchema } from "../principal.js";

/** What a BFF session holds; sealed (AES-256-GCM) before it reaches the store. */
export const sessionDataSchema = z
  .object({
    v: z.literal(1),
    /** Epoch seconds. */
    createdAt: z.number().int(),
    lastSeenAt: z.number().int(),
    /** Absolute end: the ID token's `session_exp`, capped by the BFF's own maximum age. */
    endsAt: z.number().int(),
    /** Validated ID token claims (the principal is derived from them on every load). */
    claims: idTokenClaimsSchema,
    idToken: z.string().min(1),
    accessToken: z.string().min(1),
    accessTokenExpiresAt: z.number().int(),
    refreshToken: z.string().min(1).optional(),
    csrfToken: z.string().min(32),
    /** Since when refreshes fail because Portvakt is unreachable (outage grace). */
    outageSince: z.number().int().optional(),
  })
  .strict();
export type SessionData = z.infer<typeof sessionDataSchema>;

export const LOGIN_KINDS = ["login", "step_up", "select_representation"] as const;
export type LoginKind = (typeof LOGIN_KINDS)[number];

/** A pending login (between `/login` and `/callback`); sealed in the store, single use. */
export const loginTransactionSchema = z
  .object({
    v: z.literal(1),
    kind: z.enum(LOGIN_KINDS),
    state: z.string().min(1),
    nonce: z.string().min(1),
    codeVerifier: z.string().min(43),
    returnTo: z.string().min(1),
    acr: z.string().min(1).optional(),
    createdAt: z.number().int(),
  })
  .strict();
export type LoginTransaction = z.infer<typeof loginTransactionSchema>;
