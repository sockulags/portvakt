import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import type { MasterKeys } from "../config/index.js";

/**
 * Envelope encryption for secrets at rest (upstream client secrets, private signing JWKs).
 *
 * Each value gets its own random 256-bit data key (DEK). The plaintext is encrypted with the DEK
 * (AES-256-GCM); the DEK is wrapped with the master key (AES-256-GCM). The serialised form is
 *
 *     pv1.<masterKeyId>.<wrapIv>.<wrappedDek+tag>.<dataIv>.<ciphertext+tag>
 *
 * with every segment base64url encoded. The version prefix allows the format to evolve, and the
 * master key id tells which key wrapped the DEK, so MASTER_KEY can be rotated: values wrapped by a
 * key in MASTER_KEY_PREVIOUS still decrypt and can be re-wrapped with the current key without
 * touching the data ciphertext.
 *
 * Every encryption is bound to a caller-supplied context string (GCM additional authenticated
 * data), for example `login_method:<id>:client_secret`. A ciphertext copied to another row or
 * column fails to decrypt.
 */

export const ENVELOPE_VERSION = "pv1";

const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;
const SEGMENT = /^[A-Za-z0-9_-]+$/;

export type EnvelopeErrorCode = "malformed" | "unknown_key" | "authentication_failed";

/** Raised when a value cannot be decrypted. The message never contains key material or data. */
export class EnvelopeError extends Error {
  readonly code: EnvelopeErrorCode;

  constructor(code: EnvelopeErrorCode, message: string) {
    super(message);
    this.name = "EnvelopeError";
    this.code = code;
  }
}

/** Stable, non-reversible identifier of a master key (11 base64url characters). */
export function masterKeyId(key: Buffer): string {
  return createHmac("sha256", key)
    .update("portvakt/master-key-id/v1")
    .digest()
    .subarray(0, 8)
    .toString("base64url");
}

interface ParsedEnvelope {
  readonly keyId: string;
  readonly wrapIv: Buffer;
  readonly wrappedDek: Buffer;
  readonly dataIv: Buffer;
  readonly ciphertext: Buffer;
}

function parseEnvelope(value: string): ParsedEnvelope {
  const parts = value.split(".");
  if (parts.length !== 6 || parts[0] !== ENVELOPE_VERSION) {
    throw new EnvelopeError("malformed", "Unsupported or malformed envelope");
  }
  const [, keyId, wrapIv, wrappedDek, dataIv, ciphertext] = parts as [
    string,
    string,
    string,
    string,
    string,
    string,
  ];
  if (![keyId, wrapIv, wrappedDek, dataIv, ciphertext].every((part) => SEGMENT.test(part))) {
    throw new EnvelopeError("malformed", "Malformed envelope segment");
  }
  const parsed = {
    keyId,
    wrapIv: Buffer.from(wrapIv, "base64url"),
    wrappedDek: Buffer.from(wrappedDek, "base64url"),
    dataIv: Buffer.from(dataIv, "base64url"),
    ciphertext: Buffer.from(ciphertext, "base64url"),
  };
  if (
    parsed.wrapIv.length !== IV_BYTES ||
    parsed.dataIv.length !== IV_BYTES ||
    parsed.wrappedDek.length !== KEY_BYTES + TAG_BYTES ||
    parsed.ciphertext.length < TAG_BYTES
  ) {
    throw new EnvelopeError("malformed", "Malformed envelope lengths");
  }
  return parsed;
}

function seal(key: Buffer, iv: Buffer, plaintext: Uint8Array, aad: string): Buffer {
  const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, "utf8"));
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function open(key: Buffer, iv: Buffer, sealed: Buffer, aad: string): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(sealed.subarray(sealed.length - TAG_BYTES));
  try {
    return Buffer.concat([
      decipher.update(sealed.subarray(0, sealed.length - TAG_BYTES)),
      decipher.final(),
    ]);
  } catch {
    throw new EnvelopeError("authentication_failed", "Envelope authentication failed");
  }
}

const wrapAad = (keyId: string): string => `${ENVELOPE_VERSION}|wrap|${keyId}`;
const dataAad = (context: string): string => `${ENVELOPE_VERSION}|data|${context}`;

function assertContext(context: string): void {
  if (context.length === 0) throw new TypeError("Envelope context must not be empty");
}

export class SecretBox {
  readonly currentKeyId: string;
  readonly #current: Buffer;
  readonly #keys: ReadonlyMap<string, Buffer>;

  private constructor(current: Buffer, previous: readonly Buffer[]) {
    for (const key of [current, ...previous]) {
      if (key.length !== KEY_BYTES) throw new TypeError("Master keys must be 32 bytes");
    }
    this.#current = Buffer.from(current);
    this.currentKeyId = masterKeyId(current);
    const keys = new Map<string, Buffer>();
    for (const key of [current, ...previous]) {
      const id = masterKeyId(key);
      if (!keys.has(id)) keys.set(id, Buffer.from(key));
    }
    this.#keys = keys;
  }

  static fromMasterKeys(keys: MasterKeys): SecretBox {
    return new SecretBox(keys.current, keys.previous);
  }

  /** Encrypts `plaintext`, bound to `context`, under the current master key. */
  encrypt(plaintext: string | Uint8Array, context: string): string {
    assertContext(context);
    const dek = randomBytes(KEY_BYTES);
    try {
      const data = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext;
      const dataIv = randomBytes(IV_BYTES);
      const ciphertext = seal(dek, dataIv, data, dataAad(context));
      return this.#serialise(dek, dataIv, ciphertext);
    } finally {
      dek.fill(0);
    }
  }

  decrypt(envelope: string, context: string): Buffer {
    assertContext(context);
    const parsed = parseEnvelope(envelope);
    const dek = this.#unwrap(parsed);
    try {
      return open(dek, parsed.dataIv, parsed.ciphertext, dataAad(context));
    } finally {
      dek.fill(0);
    }
  }

  decryptString(envelope: string, context: string): string {
    const plaintext = this.decrypt(envelope, context);
    try {
      return plaintext.toString("utf8");
    } finally {
      plaintext.fill(0);
    }
  }

  /** Master key id that wrapped this envelope. */
  keyIdOf(envelope: string): string {
    return parseEnvelope(envelope).keyId;
  }

  /** True when the envelope was wrapped by a key other than the current master key. */
  needsRewrap(envelope: string): boolean {
    return this.keyIdOf(envelope) !== this.currentKeyId;
  }

  /**
   * Re-wraps the data key under the current master key. The data ciphertext is kept as is and is
   * verified against `context` first, so a corrupted value is never silently carried forward.
   */
  rewrap(envelope: string, context: string): string {
    assertContext(context);
    const parsed = parseEnvelope(envelope);
    const dek = this.#unwrap(parsed);
    try {
      open(dek, parsed.dataIv, parsed.ciphertext, dataAad(context)).fill(0);
      return this.#serialise(dek, parsed.dataIv, parsed.ciphertext);
    } finally {
      dek.fill(0);
    }
  }

  #serialise(dek: Buffer, dataIv: Buffer, ciphertext: Buffer): string {
    const wrapIv = randomBytes(IV_BYTES);
    const wrappedDek = seal(this.#current, wrapIv, dek, wrapAad(this.currentKeyId));
    return [
      ENVELOPE_VERSION,
      this.currentKeyId,
      wrapIv.toString("base64url"),
      wrappedDek.toString("base64url"),
      dataIv.toString("base64url"),
      ciphertext.toString("base64url"),
    ].join(".");
  }

  #unwrap(parsed: ParsedEnvelope): Buffer {
    const key = this.#keys.get(parsed.keyId);
    if (key === undefined) {
      throw new EnvelopeError("unknown_key", "Envelope was encrypted with an unknown master key");
    }
    return open(key, parsed.wrapIv, parsed.wrappedDek, wrapAad(parsed.keyId));
  }
}
