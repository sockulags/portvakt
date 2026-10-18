import { createHmac, hkdfSync } from "node:crypto";
import type { MasterKeys } from "../config/index.js";
import { masterKeyId } from "./envelope.js";

/**
 * Keyed blind index for equality lookups on encrypted personal data (personal identity numbers,
 * organisation numbers). The index is HMAC-SHA256 over `<purpose>:<canonical value>` with a key
 * derived from the master key by HKDF, so it reveals nothing without the master key and differs
 * per purpose.
 *
 * Each stored index records the id of the master key it was derived from. Lookups try every
 * configured master key (current and previous), so rows indexed before a master key rotation are
 * still found until the re-wrap command re-indexes them under the current key.
 */

export type BlindIndexPurpose = "pin" | "orgnr";

const INFO = "portvakt/blind-index/v1";

export interface IndexValue {
  readonly index: string;
  /** Id of the master key the index key was derived from. */
  readonly keyId: string;
}

interface IndexKey {
  readonly keyId: string;
  readonly key: Buffer;
}

function deriveIndexKey(masterKey: Buffer): IndexKey {
  const key = Buffer.from(hkdfSync("sha256", masterKey, Buffer.alloc(0), INFO, 32));
  return { keyId: masterKeyId(masterKey), key };
}

export class BlindIndex {
  readonly currentKeyId: string;
  readonly #keys: readonly IndexKey[];

  private constructor(keys: readonly IndexKey[]) {
    const [current] = keys;
    if (current === undefined) throw new TypeError("At least one master key is required");
    this.currentKeyId = current.keyId;
    this.#keys = keys;
  }

  static fromMasterKeys(keys: MasterKeys): BlindIndex {
    return new BlindIndex([keys.current, ...keys.previous].map(deriveIndexKey));
  }

  /** Index under the current master key, for storing. */
  compute(purpose: BlindIndexPurpose, canonicalValue: string): IndexValue {
    const [current] = this.#keys as [IndexKey];
    return { index: this.#hmac(current.key, purpose, canonicalValue), keyId: current.keyId };
  }

  /** Index under every configured master key, for lookups (current first). */
  candidates(purpose: BlindIndexPurpose, canonicalValue: string): string[] {
    return this.#keys.map((key) => this.#hmac(key.key, purpose, canonicalValue));
  }

  #hmac(key: Buffer, purpose: BlindIndexPurpose, value: string): string {
    return createHmac("sha256", key).update(`${purpose}:${value}`, "utf8").digest("base64url");
  }
}
