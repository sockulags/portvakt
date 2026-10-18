import { constants, createDecipheriv, privateDecrypt } from "node:crypto";
import {
  attribute,
  child,
  children,
  NS,
  parseXml,
  rootOf,
  textOf,
  XmlError,
  type XmlLimits,
} from "./xml.js";

/**
 * Decryption of `saml:EncryptedAssertion` (XML Encryption), with Node's crypto and an algorithm
 * allowlist:
 *
 * - key transport: `xmlenc#rsa-oaep-mgf1p` (OAEP with SHA-1 and MGF1-SHA1, the Deployment
 *   Profile's mandatory algorithm) and `xmlenc11#rsa-oaep` with a DigestMethod of SHA-1, SHA-256,
 *   SHA-384 or SHA-512 and an MGF of the same hash (Node's OAEP uses one hash for both, so a
 *   different MGF1 hash, or `rsa-oaep-mgf1p` with a non-SHA-1 digest, is refused);
 * - content: AES-128/192/256-GCM, and AES-128/192/256-CBC only when the caller allows it (the
 *   Response signature is required and verified, and the login method does not require GCM);
 * - at most {@link MAX_ENCRYPTED_KEYS} EncryptedKey candidates.
 *
 * RSA PKCS#1 v1.5, 3DES and everything else are refused. xml-encryption is not used: it falls
 * back to SHA-1 for the standard `xmlenc#sha256` DigestMethod and decrypts 3DES.
 */

export const KEY_TRANSPORT = {
  oaepMgf1p: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
  oaep: "http://www.w3.org/2009/xmlenc11#rsa-oaep",
} as const;

const OAEP_DIGESTS: Readonly<Record<string, string>> = {
  "http://www.w3.org/2000/09/xmldsig#sha1": "sha1",
  "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
  "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
  "http://www.w3.org/2001/04/xmlenc#sha512": "sha512",
};

const MGF: Readonly<Record<string, string>> = {
  "http://www.w3.org/2009/xmlenc11#mgf1sha1": "sha1",
  "http://www.w3.org/2009/xmlenc11#mgf1sha256": "sha256",
  "http://www.w3.org/2009/xmlenc11#mgf1sha384": "sha384",
  "http://www.w3.org/2009/xmlenc11#mgf1sha512": "sha512",
};

const XENC11 = "http://www.w3.org/2009/xmlenc11#";

/** At most this many EncryptedKey candidates (in KeyInfo and as siblings) are tried. */
export const MAX_ENCRYPTED_KEYS = 4;

interface ContentAlgorithm {
  readonly cipher:
    "aes-128-gcm" | "aes-192-gcm" | "aes-256-gcm" | "aes-128-cbc" | "aes-192-cbc" | "aes-256-cbc";
  readonly keyLength: number;
  readonly gcm: boolean;
}

export const CONTENT_ALGORITHMS: Readonly<Record<string, ContentAlgorithm>> = {
  "http://www.w3.org/2009/xmlenc11#aes128-gcm": { cipher: "aes-128-gcm", keyLength: 16, gcm: true },
  "http://www.w3.org/2009/xmlenc11#aes192-gcm": { cipher: "aes-192-gcm", keyLength: 24, gcm: true },
  "http://www.w3.org/2009/xmlenc11#aes256-gcm": { cipher: "aes-256-gcm", keyLength: 32, gcm: true },
  "http://www.w3.org/2001/04/xmlenc#aes128-cbc": {
    cipher: "aes-128-cbc",
    keyLength: 16,
    gcm: false,
  },
  "http://www.w3.org/2001/04/xmlenc#aes192-cbc": {
    cipher: "aes-192-cbc",
    keyLength: 24,
    gcm: false,
  },
  "http://www.w3.org/2001/04/xmlenc#aes256-cbc": {
    cipher: "aes-256-cbc",
    keyLength: 32,
    gcm: false,
  },
};

/** Why decryption failed (one reason for every cryptographic failure: no oracle). */
export class DecryptionError extends Error {
  readonly reason: "unsupported_encryption" | "decryption_failed" | "too_many_keys";

  constructor(reason: "unsupported_encryption" | "decryption_failed" | "too_many_keys") {
    super(reason);
    this.name = "DecryptionError";
    this.reason = reason;
  }
}

function base64Of(element: Element | undefined): Buffer {
  const cipherData = element === undefined ? undefined : child(element, NS.xenc, "CipherData");
  const value = cipherData === undefined ? undefined : child(cipherData, NS.xenc, "CipherValue");
  const text = value === undefined ? "" : textOf(value).replace(/\s+/g, "");
  if (text === "" || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
    throw new DecryptionError("decryption_failed");
  }
  return Buffer.from(text, "base64");
}

/** The OAEP hash of an EncryptedKey, or `undefined` for an algorithm that is refused. */
function oaepHashOf(encryptedKey: Element): string | undefined {
  const method = child(encryptedKey, NS.xenc, "EncryptionMethod");
  const algorithm = method === undefined ? undefined : attribute(method, "Algorithm");
  if (method === undefined) return undefined;
  const digestElement = child(method, NS.ds, "DigestMethod");
  const digestUri = digestElement === undefined ? undefined : attribute(digestElement, "Algorithm");
  const digest = digestUri === undefined ? "sha1" : OAEP_DIGESTS[digestUri];
  if (digest === undefined) return undefined;
  if (algorithm === KEY_TRANSPORT.oaepMgf1p) return digest === "sha1" ? "sha1" : undefined;
  if (algorithm !== KEY_TRANSPORT.oaep) return undefined;
  const mgfElement = child(method, XENC11, "MGF");
  const mgfUri = mgfElement === undefined ? undefined : attribute(mgfElement, "Algorithm");
  const mgf = mgfUri === undefined ? "sha1" : MGF[mgfUri];
  return mgf === digest ? digest : undefined;
}

/** EncryptedKeys of an EncryptedAssertion: in EncryptedData's KeyInfo, or siblings of it. */
function encryptedKeysOf(encryptedAssertion: Element, data: Element): Element[] {
  const keyInfo = child(data, NS.ds, "KeyInfo");
  return [
    ...(keyInfo === undefined ? [] : children(keyInfo, NS.xenc, "EncryptedKey")),
    ...children(encryptedAssertion, NS.xenc, "EncryptedKey"),
  ];
}

function oaepLabelOf(encryptedKey: Element): Buffer | undefined {
  const method = child(encryptedKey, NS.xenc, "EncryptionMethod");
  const params = method === undefined ? undefined : child(method, NS.xenc, "OAEPparams");
  return params === undefined ? undefined : Buffer.from(textOf(params), "base64");
}

/**
 * Decrypts an EncryptedAssertion with one of the SP's private keys (PEM, tried in order) and
 * returns the assertion's XML. Throws {@link DecryptionError}.
 */
export async function decryptAssertion(
  encryptedAssertion: Element,
  privateKeys: readonly string[],
  options: { readonly requireGcm: boolean; readonly limits: XmlLimits },
): Promise<string> {
  const data = child(encryptedAssertion, NS.xenc, "EncryptedData");
  if (data === undefined) throw new DecryptionError("decryption_failed");
  const methodElement = child(data, NS.xenc, "EncryptionMethod");
  const content =
    methodElement === undefined
      ? undefined
      : CONTENT_ALGORITHMS[attribute(methodElement, "Algorithm") ?? ""];
  if (content === undefined || (options.requireGcm && !content.gcm)) {
    throw new DecryptionError("unsupported_encryption");
  }
  const candidates = encryptedKeysOf(encryptedAssertion, data);
  // Bounded before any RSA operation: each candidate costs a private-key decryption per SP key.
  if (candidates.length > MAX_ENCRYPTED_KEYS) throw new DecryptionError("too_many_keys");
  if (candidates.length === 0) throw new DecryptionError("decryption_failed");

  let contentKey: Buffer | undefined;
  for (const encryptedKey of candidates) {
    const oaepHash = oaepHashOf(encryptedKey);
    if (oaepHash === undefined) throw new DecryptionError("unsupported_encryption");
    const wrapped = base64Of(encryptedKey);
    const oaepLabel = oaepLabelOf(encryptedKey);
    for (const key of privateKeys) {
      try {
        const unwrapped = privateDecrypt(
          {
            key,
            padding: constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash,
            ...(oaepLabel === undefined ? {} : { oaepLabel }),
          },
          wrapped,
        );
        if (unwrapped.length === content.keyLength) {
          contentKey = unwrapped;
          break;
        }
      } catch {
        // Another SP key (rotation overlap) may be the one.
      }
    }
    if (contentKey !== undefined) break;
  }
  if (contentKey === undefined) throw new DecryptionError("decryption_failed");

  const cipherText = base64Of(data);
  let plain: Buffer;
  try {
    if (content.gcm) {
      if (cipherText.length < 12 + 16) throw new DecryptionError("decryption_failed");
      const decipher = createDecipheriv(
        content.cipher as "aes-256-gcm",
        contentKey,
        cipherText.subarray(0, 12),
        {
          authTagLength: 16,
        },
      );
      decipher.setAuthTag(cipherText.subarray(cipherText.length - 16));
      plain = Buffer.concat([
        decipher.update(cipherText.subarray(12, cipherText.length - 16)),
        decipher.final(),
      ]);
    } else {
      if (cipherText.length < 32 || cipherText.length % 16 !== 0) {
        throw new DecryptionError("decryption_failed");
      }
      const decipher = createDecipheriv(content.cipher, contentKey, cipherText.subarray(0, 16));
      // XML Encryption padding: the last byte is the pad length, the others are arbitrary.
      decipher.setAutoPadding(false);
      const padded = Buffer.concat([decipher.update(cipherText.subarray(16)), decipher.final()]);
      const pad = padded[padded.length - 1] ?? 0;
      if (pad < 1 || pad > 16) throw new DecryptionError("decryption_failed");
      plain = padded.subarray(0, padded.length - pad);
    }
  } catch {
    throw new DecryptionError("decryption_failed");
  }
  const xml = plain.toString("utf8");
  try {
    const root = rootOf(await parseXml(xml, options.limits));
    if (root.localName !== "Assertion" || root.namespaceURI !== NS.saml) {
      throw new DecryptionError("decryption_failed");
    }
  } catch (error) {
    if (error instanceof XmlError && error.reason === "dtd_not_allowed") throw error;
    throw new DecryptionError("decryption_failed");
  }
  return xml;
}
