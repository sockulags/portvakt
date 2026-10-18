/**
 * Self-signed RSA certificates for the mock SAML IdPs (a copy of the server's generator: the
 * mock cannot depend on the server). Development and tests only.
 */
import { generateKeyPair, randomBytes, sign, X509Certificate } from "node:crypto";
import { promisify } from "node:util";
import { AsnConvert } from "@peculiar/asn1-schema";
import {
  AlgorithmIdentifier,
  AttributeTypeAndValue,
  AttributeValue,
  Certificate,
  Name,
  RelativeDistinguishedName,
  SubjectPublicKeyInfo,
  TBSCertificate,
  Validity,
  Version,
} from "@peculiar/asn1-x509";

/** sha256WithRSAEncryption (RFC 4055). */
const SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
const COMMON_NAME = "2.5.4.3";

const generateRsaKeyPair = promisify(generateKeyPair);
const generateEcKeyPair = promisify(generateKeyPair);
/** ecdsa-with-SHA256 (RFC 5758): no parameters. */
const ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";

/**
 * RSA key size of the mock IdP keys (development only; the Deployment Profile requires at
 * least 2048 bits).
 */
export const MOCK_KEY_BITS = 2048;

export interface SelfSignedKeyPair {
  /** PEM `CERTIFICATE`. */
  readonly certificate: string;
  /** PEM PKCS#8 `PRIVATE KEY`. */
  readonly privateKey: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
}

/**
 * A fresh RSA (or P-256 EC) key pair with a self-signed certificate (SAML metadata only carries the key; the
 * certificate's issuer and validity are informational, as the Deployment Profile allows). The
 * certificate is encoded with an ASN.1 library and signed by Node's crypto; nothing here
 * verifies signatures.
 */
export async function generateSelfSignedKeyPair(
  commonName: string,
  validitySeconds: number,
  now = new Date(),
  keyType: "rsa" | "ec" = "rsa",
): Promise<SelfSignedKeyPair> {
  if (!(validitySeconds > 0)) throw new RangeError("validitySeconds must be positive");
  const { publicKey, privateKey } =
    keyType === "ec"
      ? await generateEcKeyPair("ec", { namedCurve: "P-256" })
      : await generateRsaKeyPair("rsa", { modulusLength: MOCK_KEY_BITS });
  const spki = AsnConvert.parse(
    publicKey.export({ type: "spki", format: "der" }),
    SubjectPublicKeyInfo,
  );
  const name = new Name([
    new RelativeDistinguishedName([
      new AttributeTypeAndValue({
        type: COMMON_NAME,
        value: new AttributeValue({ utf8String: commonName.slice(0, 64) }),
      }),
    ]),
  ]);
  const algorithm =
    keyType === "ec"
      ? new AlgorithmIdentifier({ algorithm: ECDSA_WITH_SHA256 })
      : new AlgorithmIdentifier({ algorithm: SHA256_WITH_RSA, parameters: null });
  const serial = randomBytes(16);
  // A positive INTEGER whose first byte is never zero: DER needs the minimal encoding, and a
  // leading zero byte before a byte below 0x80 is not minimal (OpenSSL refuses it).
  serial[0] = ((serial[0] ?? 0) & 0x3f) | 0x40;
  // Whole seconds: X.509 times carry no fractions.
  const notBefore = new Date(Math.floor(now.getTime() / 1000) * 1000 - 60_000);
  const notAfter = new Date(notBefore.getTime() + 60_000 + validitySeconds * 1000);
  const tbs = new TBSCertificate({
    version: Version.v3,
    serialNumber: serial.buffer.slice(serial.byteOffset, serial.byteOffset + serial.byteLength),
    signature: algorithm,
    issuer: name,
    subject: name,
    validity: new Validity({ notBefore, notAfter }),
    subjectPublicKeyInfo: spki,
  });
  const tbsDer = Buffer.from(AsnConvert.serialize(tbs));
  const signature = sign("sha256", tbsDer, privateKey);
  const certificate = new Certificate({
    tbsCertificate: tbs,
    signatureAlgorithm: algorithm,
    signatureValue: signature.buffer.slice(
      signature.byteOffset,
      signature.byteOffset + signature.byteLength,
    ),
  });
  const der = Buffer.from(AsnConvert.serialize(certificate));
  return {
    certificate: derToPem(der),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    notBefore,
    notAfter,
  };
}

/** PEM `CERTIFICATE` of DER bytes, 64 characters per line. */
export function derToPem(der: Buffer): string {
  const lines = der.toString("base64").match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

/** The base64 body of a PEM certificate (what `ds:X509Certificate` carries). */
export function pemBody(pem: string): string {
  return pem
    .replace(/-----BEGIN CERTIFICATE-----/, "")
    .replace(/-----END CERTIFICATE-----/, "")
    .replace(/\s+/g, "");
}

/** PEM of a `ds:X509Certificate` value (base64 DER, whitespace allowed). */
export function base64ToPem(value: string): string {
  return derToPem(Buffer.from(value.replace(/\s+/g, ""), "base64"));
}

export interface CertificateInfo {
  readonly notBefore: Date;
  readonly notAfter: Date;
  /** SHA-256 fingerprint (colon-separated hex), safe to log. */
  readonly fingerprint: string;
  readonly keyType: string | undefined;
}

/** Parses a PEM certificate; throws on anything that is not one. */
export function certificateInfo(pem: string): CertificateInfo {
  const cert = new X509Certificate(pem);
  return {
    notBefore: new Date(cert.validFrom),
    notAfter: new Date(cert.validTo),
    fingerprint: cert.fingerprint256,
    keyType: cert.publicKey.asymmetricKeyType,
  };
}
