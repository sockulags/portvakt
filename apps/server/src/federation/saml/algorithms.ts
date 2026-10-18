import { createHash, createPublicKey, verify, type KeyLike, type KeyObject } from "node:crypto";
import {
  SignedXml,
  type CanonicalizationOrTransformationAlgorithm,
  type HashAlgorithm,
  type SignatureAlgorithm,
} from "xml-crypto";

/**
 * The XML signature and digest algorithms Portvakt accepts from IdPs (responses, assertions,
 * metadata, logout messages) and for the HTTP-Redirect binding: RSA and ECDSA with SHA-256,
 * SHA-384 or SHA-512 (the Deployment Profile makes RSA-SHA256 and ECDSA-SHA256 mandatory).
 * SHA-1 and MD5 are refused. The algorithms are xml-crypto's documented extension point
 * (`SignatureAlgorithms` / `HashAlgorithms` of a `SignedXml` instance); the cryptography itself is
 * Node's `crypto.sign` / `crypto.verify` (ECDSA values in the XMLDSig r||s form, IEEE P1363).
 */

type Hash = "sha256" | "sha384" | "sha512";
type KeyType = "rsa" | "ec";

/** Signature algorithm URI → hash and key type. */
export const SIGNATURE_ALGORITHMS: Readonly<Record<string, { hash: Hash; keyType: KeyType }>> = {
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": { hash: "sha256", keyType: "rsa" },
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": { hash: "sha384", keyType: "rsa" },
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": { hash: "sha512", keyType: "rsa" },
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": { hash: "sha256", keyType: "ec" },
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": { hash: "sha384", keyType: "ec" },
  "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": { hash: "sha512", keyType: "ec" },
};

/** Digest algorithm URI → hash. */
export const DIGEST_ALGORITHMS: Readonly<Record<string, Hash>> = {
  "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
  "http://www.w3.org/2001/04/xmldsig-more#sha384": "sha384",
  "http://www.w3.org/2001/04/xmlenc#sha512": "sha512",
};

/**
 * Canonicalization (SignedInfo) and transform algorithms accepted in signatures: exclusive c14n
 * and the enveloped-signature transform only. Sweden Connect IdPs (Shibboleth and the
 * Sweden Connect reference IdP) sign with exclusive c14n; inclusive c14n is not accepted.
 */
const TRANSFORMS = [
  "http://www.w3.org/2001/10/xml-exc-c14n#",
  "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
] as const;

/** A public key of the expected type, or `undefined` (wrong type, unparsable). */
export function publicKeyOf(key: KeyLike, keyType: KeyType): KeyObject | undefined {
  try {
    const parsed =
      typeof key === "object" && "asymmetricKeyType" in key ? key : createPublicKey(key);
    return parsed.asymmetricKeyType === keyType ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Verifies `signature` (raw bytes) over `data` with one of the allowlisted algorithms. A key of
 * the other type (an RSA certificate for an ECDSA algorithm) never verifies.
 */
export function verifyWithAlgorithm(
  algorithm: string,
  data: Buffer,
  key: KeyLike,
  signature: Buffer,
): boolean {
  const spec = SIGNATURE_ALGORITHMS[algorithm];
  if (spec === undefined) return false;
  const publicKey = publicKeyOf(key, spec.keyType);
  if (publicKey === undefined) return false;
  try {
    return verify(
      spec.hash,
      data,
      spec.keyType === "ec" ? { key: publicKey, dsaEncoding: "ieee-p1363" } : publicKey,
      signature,
    );
  } catch {
    return false;
  }
}

function signatureAlgorithm(uri: string): new () => SignatureAlgorithm {
  const spec = SIGNATURE_ALGORITHMS[uri];
  if (spec === undefined) throw new Error(`unknown algorithm ${uri}`);
  class Algorithm {
    // Verification only: Portvakt signs through node-saml (RSA-SHA256).
    getSignature(): string {
      throw new Error("signing is not supported by the verification algorithms");
    }

    verifySignature(material: string, key: KeyLike, signatureValue: string): boolean {
      return verifyWithAlgorithm(
        uri,
        Buffer.from(material, "utf8"),
        key,
        Buffer.from(signatureValue, "base64"),
      );
    }

    getAlgorithmName(): string {
      return uri;
    }
  }
  return Algorithm;
}

function hashAlgorithm(uri: string, hash: Hash): new () => HashAlgorithm {
  class Algorithm {
    getHash(xml: string): string {
      return createHash(hash).update(xml, "utf8").digest("base64");
    }

    getAlgorithmName(): string {
      return uri;
    }
  }
  return Algorithm;
}

const defaults = new SignedXml();

/**
 * A `SignedXml` for verification with only the allowlisted algorithms (SHA-1, MD5, HMAC and
 * comment-preserving canonicalization are refused) and `publicCert` as the only key: a
 * certificate in the signature's KeyInfo is never used.
 */
export function restrictedSignedXml(publicCert: string): SignedXml {
  const sig = new SignedXml({ publicCert });
  sig.SignatureAlgorithms = Object.fromEntries(
    Object.keys(SIGNATURE_ALGORITHMS).map((uri) => [uri, signatureAlgorithm(uri)]),
  );
  sig.HashAlgorithms = Object.fromEntries(
    Object.entries(DIGEST_ALGORITHMS).map(([uri, hash]) => [uri, hashAlgorithm(uri, hash)]),
  );
  const canonicalization: Record<string, new () => CanonicalizationOrTransformationAlgorithm> = {};
  for (const uri of TRANSFORMS) {
    const algorithm = (
      defaults.CanonicalizationAlgorithms as Record<
        string,
        new () => CanonicalizationOrTransformationAlgorithm
      >
    )[uri];
    if (algorithm !== undefined) canonicalization[uri] = algorithm;
  }
  sig.CanonicalizationAlgorithms = canonicalization;
  sig.getCertFromKeyInfo = () => null;
  return sig;
}
