import type { PrivateJwk, PublicJwk, SigningAlgorithm } from "../crypto/jwk.js";

export const SIGNING_KEY_STATES = ["next", "active", "retiring", "retired"] as const;
export type SigningKeyState = (typeof SIGNING_KEY_STATES)[number];

/** States whose public key is published in JWKS. */
export const PUBLISHED_KEY_STATES: readonly SigningKeyState[] = ["next", "active", "retiring"];

export interface SigningKey {
  readonly kid: string;
  readonly alg: SigningAlgorithm;
  readonly state: SigningKeyState;
  readonly publicJwk: PublicJwk;
  readonly createdAt: Date;
  readonly activatedAt: Date | null;
  readonly retiringAt: Date | null;
  readonly retiredAt: Date | null;
  /**
   * A `next` key from a manual rotation: when it becomes active (published until then). Keys of
   * the scheduled rotation have none and activate KEY_PUBLISH_AHEAD after creation.
   */
  readonly activateAt: Date | null;
}

/** A published key together with its decrypted private JWK, for loading into the provider. */
export interface SigningKeyMaterial extends SigningKey {
  readonly privateJwk: PrivateJwk;
}

/**
 * Emergency path for a compromised key: skips the timing guard. Always recorded as an audit event.
 * Keys are never deleted; a forced retirement still only erases the private part.
 */
export interface ForcedTransition {
  readonly force: true;
  readonly actor: { readonly type: "person" | "system"; readonly id: string | null };
  /** Short reason for the audit log. No personal data. */
  readonly reason: string;
}

/** `next` -> `active` is allowed once the key has been published for `publishAheadSeconds`. */
export type ActivationPolicy = { readonly publishAheadSeconds: number } | ForcedTransition;

/** `retiring` -> `retired` is allowed once the key has been retiring for `retireAfterSeconds`. */
export type RetirementPolicy = { readonly retireAfterSeconds: number } | ForcedTransition;
