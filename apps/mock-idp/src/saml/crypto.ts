import {
  constants,
  createCipheriv,
  publicEncrypt,
  randomBytes,
  sign,
  X509Certificate,
  type KeyLike,
} from "node:crypto";
import { SignedXml, type SignatureAlgorithm } from "xml-crypto";

/**
 * Signing and encryption of the mock SAML IdPs, with selectable algorithms so tests can send
 * what Portvakt must refuse (SHA-1, RSA PKCS#1 v1.5, 3DES) next to what it must accept (RSA and
 * ECDSA signatures, RSA-OAEP with SHA-1 or SHA-256, AES-GCM and AES-CBC). Development and tests
 * only.
 */

export type SignatureChoice = "rsa-sha256" | "rsa-sha1" | "ecdsa-sha256";
export type DigestChoice = "sha256" | "sha1";
export type KeyTransportChoice = "oaep-mgf1p" | "oaep-sha256" | "rsa-1_5";
export type ContentChoice = "aes256-gcm" | "aes128-cbc" | "aes192-cbc" | "3des";

export const SIGNATURE_URIS: Record<SignatureChoice, string> = {
  "rsa-sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  "rsa-sha1": "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
  "ecdsa-sha256": "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
};

const DIGEST_URIS: Record<DigestChoice, string> = {
  sha256: "http://www.w3.org/2001/04/xmlenc#sha256",
  sha1: "http://www.w3.org/2000/09/xmldsig#sha1",
};

const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/** ECDSA-SHA256 for xml-crypto (XMLDSig r||s values). */
class EcdsaSha256 {
  getSignature(signedInfo: string, privateKey: KeyLike): string {
    return sign("sha256", Buffer.from(signedInfo, "utf8"), {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    } as never).toString("base64");
  }

  verifySignature(): boolean {
    throw new Error("the mock does not verify ECDSA signatures");
  }

  getAlgorithmName(): string {
    return SIGNATURE_URIS["ecdsa-sha256"];
  }
}

export interface SigningKey {
  readonly privateKey: string;
  readonly certificate: string;
}

/**
 * Signs the element at `elementXPath` (enveloped, exclusive c14n), the signature placed after
 * its Issuer or as its first child. `keyInfoCertificate` puts another certificate in KeyInfo.
 */
export function signElement(
  xml: string,
  elementXPath: string,
  key: SigningKey,
  options: {
    readonly signature: SignatureChoice;
    readonly digest: DigestChoice;
    readonly placement: "afterIssuer" | "first";
    readonly keyInfoCertificate?: string;
  },
): string {
  const sig = new SignedXml({
    privateKey: key.privateKey,
    publicCert: options.keyInfoCertificate ?? key.certificate,
    signatureAlgorithm: SIGNATURE_URIS[options.signature],
    canonicalizationAlgorithm: EXC_C14N,
  });
  (sig.SignatureAlgorithms as Record<string, new () => SignatureAlgorithm>)[
    SIGNATURE_URIS["ecdsa-sha256"]
  ] = EcdsaSha256;
  sig.addReference({
    xpath: elementXPath,
    transforms: [ENVELOPED, EXC_C14N],
    digestAlgorithm: DIGEST_URIS[options.digest],
  });
  sig.computeSignature(xml, {
    location:
      options.placement === "afterIssuer"
        ? { reference: `${elementXPath}/*[local-name(.)='Issuer']`, action: "after" }
        : { reference: elementXPath, action: "prepend" },
  });
  return sig.getSignedXml();
}

/** Signs HTTP-Redirect binding octets (RSA-SHA256 or ECDSA-SHA256, base64). */
export function signRedirect(octets: string, privateKey: string, keyType: "rsa" | "ec"): string {
  return sign(
    "sha256",
    Buffer.from(octets, "utf8"),
    keyType === "ec" ? ({ key: privateKey, dsaEncoding: "ieee-p1363" } as never) : privateKey,
  ).toString("base64");
}

const CONTENT: Record<
  ContentChoice,
  { uri: string; cipher: string; keyLength: number; ivLength: number; gcm: boolean }
> = {
  "aes256-gcm": {
    uri: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
    cipher: "aes-256-gcm",
    keyLength: 32,
    ivLength: 12,
    gcm: true,
  },
  "aes128-cbc": {
    uri: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
    cipher: "aes-128-cbc",
    keyLength: 16,
    ivLength: 16,
    gcm: false,
  },
  "aes192-cbc": {
    uri: "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
    cipher: "aes-192-cbc",
    keyLength: 24,
    ivLength: 16,
    gcm: false,
  },
  "3des": {
    uri: "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
    cipher: "des-ede3-cbc",
    keyLength: 24,
    ivLength: 8,
    gcm: false,
  },
};

const XENC = "http://www.w3.org/2001/04/xmlenc#";
const XENC11 = "http://www.w3.org/2009/xmlenc11#";
const DS = "http://www.w3.org/2000/09/xmldsig#";

const pemBody = (pem: string): string =>
  pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");

/**
 * `<saml2:EncryptedAssertion>` of `assertionXml` for the SP's encryption certificate. With
 * `siblingKey`, the EncryptedKey is a sibling of EncryptedData referenced by a RetrievalMethod
 * (as some IdPs send it).
 */
export function encryptAssertion(
  assertionXml: string,
  certificate: string,
  options: {
    readonly content: ContentChoice;
    readonly keyTransport: KeyTransportChoice;
    readonly siblingKey: boolean;
  },
): string {
  const content = CONTENT[options.content];
  const key = randomBytes(content.keyLength);
  const iv = randomBytes(content.ivLength);
  const cipher = createCipheriv(content.cipher, key, iv);
  const encrypted = Buffer.concat([cipher.update(assertionXml, "utf8"), cipher.final()]);
  const cipherValue = content.gcm
    ? Buffer.concat([iv, encrypted, (cipher as unknown as { getAuthTag(): Buffer }).getAuthTag()])
    : Buffer.concat([iv, encrypted]);

  const publicKey = new X509Certificate(certificate).publicKey;
  const oaepHash = options.keyTransport === "oaep-sha256" ? "sha256" : "sha1";
  const wrapped = publicEncrypt(
    options.keyTransport === "rsa-1_5"
      ? { key: publicKey, padding: constants.RSA_PKCS1_PADDING }
      : { key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash },
    key,
  );
  const transport =
    options.keyTransport === "oaep-sha256"
      ? `<xenc:EncryptionMethod Algorithm="${XENC11}rsa-oaep"><ds:DigestMethod Algorithm="${XENC}sha256"/><xenc11:MGF xmlns:xenc11="${XENC11}" Algorithm="${XENC11}mgf1sha256"/></xenc:EncryptionMethod>`
      : options.keyTransport === "rsa-1_5"
        ? `<xenc:EncryptionMethod Algorithm="${XENC}rsa-1_5"/>`
        : `<xenc:EncryptionMethod Algorithm="${XENC}rsa-oaep-mgf1p"><ds:DigestMethod Algorithm="${DS}sha1"/></xenc:EncryptionMethod>`;
  const keyId = `_k${randomBytes(8).toString("hex")}`;
  const encryptedKey = `<xenc:EncryptedKey xmlns:xenc="${XENC}" xmlns:ds="${DS}"${options.siblingKey ? ` Id="${keyId}"` : ""}>${transport}<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${pemBody(certificate)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>${wrapped.toString("base64")}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>`;
  const keyInfo = options.siblingKey
    ? `<ds:KeyInfo xmlns:ds="${DS}"><ds:RetrievalMethod Type="${XENC}EncryptedKey" URI="#${keyId}"/></ds:KeyInfo>`
    : `<ds:KeyInfo xmlns:ds="${DS}">${encryptedKey}</ds:KeyInfo>`;
  const data = `<xenc:EncryptedData xmlns:xenc="${XENC}" Type="${XENC}Element"><xenc:EncryptionMethod Algorithm="${content.uri}"/>${keyInfo}<xenc:CipherData><xenc:CipherValue>${cipherValue.toString("base64")}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>`;
  return `<saml2:EncryptedAssertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">${data}${options.siblingKey ? encryptedKey : ""}</saml2:EncryptedAssertion>`;
}
