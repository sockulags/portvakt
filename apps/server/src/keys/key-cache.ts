import type { PrivateJwk } from "../crypto/jwk.js";
import type { SigningKeyState } from "../domain/signing-key.js";
import type { SigningKeyRepository } from "../repositories/signing-keys.js";

/** Order in the provider key store. oidc-provider signs with the first matching key. */
const STATE_RANK: Readonly<Record<SigningKeyState, number>> = {
  active: 0,
  next: 1,
  retiring: 2,
  retired: 3,
};

export interface LoadedKeys {
  /** Changes whenever a key is added or changes state; providers are rebuilt on a change. */
  readonly version: string;
  /** The key that signs ID tokens and access tokens. */
  readonly activeKid: string;
  /**
   * Private JWKs for the provider's `jwks` setting, active key first, then the `next` key (so
   * verifiers can fetch it before it signs) and `retiring` keys (so tokens they signed stay
   * verifiable). oidc-provider publishes the public parts of all of them in JWKS and signs with
   * the first key matching the algorithm, which is why the order matters.
   */
  readonly jwks: { readonly keys: readonly PrivateJwk[] };
  readonly kids: readonly { readonly kid: string; readonly state: SigningKeyState }[];
}

/**
 * The published signing keys of this replica, decrypted once and shared by every tenant
 * provider. Reloaded on a change notification and periodically, so replicas converge.
 * Holds private keys: never log it.
 */
export class SigningKeyCache {
  readonly #repository: SigningKeyRepository;
  #current: LoadedKeys | undefined;

  constructor(repository: SigningKeyRepository) {
    this.#repository = repository;
  }

  /** The loaded keys, or `undefined` before the first successful load with an active key. */
  get current(): LoadedKeys | undefined {
    return this.#current;
  }

  get ready(): boolean {
    return this.#current !== undefined;
  }

  /**
   * Loads the published keys. Returns whether the key set changed. Without an active key the
   * previous key set is kept (signing must never stop because of a transient state) and the
   * method throws, so the caller notices.
   */
  async reload(): Promise<boolean> {
    const material = await this.#repository.loadMaterial();
    const sorted = [...material].sort(
      (a, b) =>
        STATE_RANK[a.state] - STATE_RANK[b.state] || b.createdAt.getTime() - a.createdAt.getTime(),
    );
    const active = sorted.find((key) => key.state === "active");
    if (active === undefined) throw new Error("No active signing key");
    const kids = sorted.map((key) => ({ kid: key.kid, state: key.state }));
    const version = kids.map((key) => `${key.kid}:${key.state}`).join(",");
    if (this.#current?.version === version) return false;
    this.#current = {
      version,
      activeKid: active.kid,
      jwks: { keys: sorted.map((key) => key.privateJwk) },
      kids,
    };
    return true;
  }
}
