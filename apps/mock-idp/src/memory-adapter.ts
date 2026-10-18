import type { Adapter, AdapterPayload } from "oidc-provider";

/** Models removed with their grant (as oidc-provider's own memory adapter does). */
const GRANT_BOUND = new Set([
  "AccessToken",
  "AuthorizationCode",
  "RefreshToken",
  "DeviceCode",
  "BackchannelAuthenticationRequest",
]);

interface Entry {
  readonly payload: AdapterPayload;
  readonly expiresAt: number | undefined;
}

/**
 * In-memory oidc-provider storage, one store per mock issuer (so two issuers in one process
 * never see each other's sessions or codes). Development and tests only.
 */
export class MemoryStore {
  readonly #entries = new Map<string, Entry>();

  adapterFor(model: string): Adapter {
    const key = (id: string): string => `${model}:${id}`;
    const live = (id: string): Entry | undefined => {
      const entry = this.#entries.get(key(id));
      if (entry === undefined) return undefined;
      if (entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
        this.#entries.delete(key(id));
        return undefined;
      }
      return entry;
    };
    const findBy = (field: "uid" | "userCode", value: string): AdapterPayload | undefined => {
      for (const [entryKey, entry] of this.#entries) {
        if (entryKey.startsWith(`${model}:`) && entry.payload[field] === value) {
          return live(entryKey.slice(model.length + 1))?.payload;
        }
      }
      return undefined;
    };
    return {
      upsert: (id, payload, expiresIn) => {
        this.#entries.set(key(id), {
          payload: { ...payload },
          expiresAt: expiresIn === undefined ? undefined : Date.now() + expiresIn * 1000,
        });
        return Promise.resolve();
      },
      find: (id) => Promise.resolve(live(id)?.payload),
      findByUid: (uid) => Promise.resolve(findBy("uid", uid)),
      findByUserCode: (userCode) => Promise.resolve(findBy("userCode", userCode)),
      consume: (id) => {
        const entry = live(id);
        if (entry !== undefined) {
          this.#entries.set(key(id), {
            ...entry,
            payload: { ...entry.payload, consumed: Math.floor(Date.now() / 1000) },
          });
        }
        return Promise.resolve();
      },
      destroy: (id) => {
        this.#entries.delete(key(id));
        return Promise.resolve();
      },
      revokeByGrantId: (grantId) => {
        for (const [entryKey, entry] of this.#entries) {
          const entryModel = entryKey.slice(0, entryKey.indexOf(":"));
          if (GRANT_BOUND.has(entryModel) && entry.payload.grantId === grantId) {
            this.#entries.delete(entryKey);
          }
        }
        return Promise.resolve();
      },
    };
  }
}
