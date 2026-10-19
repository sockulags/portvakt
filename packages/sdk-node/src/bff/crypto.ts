import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { PortvaktConfigError } from "../errors.js";

const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const VERSION = "v1";

const b64url = (buffer: Buffer): string => buffer.toString("base64url");

/** A random identifier: 32 bytes, base64url (session ids, login transaction ids, CSRF tokens). */
export const randomId = (): string => b64url(randomBytes(32));

/** The store key of an id: its SHA-256, so stored keys cannot be replayed as cookies. */
export const storeKey = (prefix: string, id: string): string =>
  `${prefix}:${b64url(createHash("sha256").update(id).digest())}`;

/** Constant-time comparison of two strings. */
export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/**
 * AES-256-GCM sealing of session values with a key ring: the first key seals, every key opens
 * (key rotation). A sealed value is `v1.{key id}.{iv}.{ciphertext and tag}`; the store key is
 * the additional authenticated data, so a value cannot be moved to another session.
 */
export class Sealer {
  readonly #keys: readonly { readonly id: string; readonly key: Buffer }[];

  constructor(keys: readonly string[]) {
    const issues: string[] = [];
    const parsed = keys.map((value, index) => {
      const key = Buffer.from(value, "base64");
      if (key.length !== KEY_BYTES || key.toString("base64") !== value.replace(/\s/g, "")) {
        issues.push(`encryptionKey[${index}]: must be 32 random bytes, base64-encoded`);
      }
      return { id: createHash("sha256").update(key).digest("hex").slice(0, 8), key };
    });
    if (parsed.length === 0) issues.push("encryptionKey: at least one key is required");
    if (new Set(parsed.map((key) => key.id)).size !== parsed.length) {
      issues.push("encryptionKey: keys must differ");
    }
    if (issues.length > 0) throw new PortvaktConfigError(issues);
    this.#keys = parsed;
  }

  seal(plaintext: string, aad: string): string {
    const { id, key } = this.#keys[0]!;
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(Buffer.from(aad));
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return [VERSION, id, b64url(iv), b64url(Buffer.concat([ciphertext, cipher.getAuthTag()]))].join(
      ".",
    );
  }

  /** The plaintext, or `undefined` for anything that does not open (tampered, unknown key). */
  open(sealed: string, aad: string): string | undefined {
    const [version, id, ivPart, body, ...rest] = sealed.split(".");
    if (version !== VERSION || rest.length > 0 || ivPart === undefined || body === undefined) {
      return undefined;
    }
    const entry = this.#keys.find((candidate) => candidate.id === id);
    if (entry === undefined) return undefined;
    const iv = Buffer.from(ivPart, "base64url");
    const data = Buffer.from(body, "base64url");
    if (iv.length !== IV_BYTES || data.length < TAG_BYTES) return undefined;
    try {
      const decipher = createDecipheriv("aes-256-gcm", entry.key, iv, {
        authTagLength: TAG_BYTES,
      });
      decipher.setAAD(Buffer.from(aad));
      decipher.setAuthTag(data.subarray(data.length - TAG_BYTES));
      return Buffer.concat([
        decipher.update(data.subarray(0, data.length - TAG_BYTES)),
        decipher.final(),
      ]).toString("utf8");
    } catch {
      return undefined;
    }
  }
}

/**
 * HMAC-SHA256 signed cookie values (`{value}.{signature}`): the first secret signs, every secret
 * verifies (rotation).
 */
export class CookieSigner {
  readonly #secrets: readonly string[];

  constructor(secrets: readonly string[]) {
    this.#secrets = secrets;
  }

  sign(value: string): string {
    return `${value}.${this.#mac(this.#secrets[0]!, value)}`;
  }

  /** The signed value, or `undefined` when the signature does not verify with any secret. */
  verify(signed: string): string | undefined {
    const separator = signed.lastIndexOf(".");
    if (separator <= 0) return undefined;
    const value = signed.slice(0, separator);
    const signature = signed.slice(separator + 1);
    return this.#secrets.some((secret) => safeEqual(this.#mac(secret, value), signature))
      ? value
      : undefined;
  }

  #mac(secret: string, value: string): string {
    return b64url(createHmac("sha256", secret).update(value).digest());
  }
}
