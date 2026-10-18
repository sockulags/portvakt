import { inflateRawSync } from "node:zlib";
import { SIGNATURE_ALGORITHMS, verifyWithAlgorithm } from "./algorithms.js";

/**
 * The HTTP-Redirect binding (SAML bindings 3.4), parsed from the raw query string itself:
 *
 * - binding keys (`SAMLRequest`, `SAMLResponse`, `RelayState`, `SigAlg`, `Signature`) count only
 *   as literally written; a token whose percent-decoded key is a binding key but is written
 *   differently (`SAML%52equest`), or a binding key given twice, refuses the whole message;
 * - exactly one of `SAMLRequest` / `SAMLResponse`;
 * - the signed octets are the received tokens `SAMLxxx=…[&RelayState=…]&SigAlg=…` in that order,
 *   and the message is decoded from the same token, so what is verified is what is read;
 * - signatures are verified with Node's crypto against the IdP's metadata certificates, with the
 *   allowlisted algorithms only (RSA or ECDSA with SHA-256/384/512).
 */

export const BINDING_KEYS = [
  "SAMLRequest",
  "SAMLResponse",
  "RelayState",
  "SigAlg",
  "Signature",
] as const;
type BindingKey = (typeof BINDING_KEYS)[number];

/** A refused redirect-binding message; the reason is a fixed code, safe to log. */
export class RedirectBindingError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(reason);
    this.name = "RedirectBindingError";
    this.reason = reason;
  }
}

export interface RedirectMessage {
  readonly kind: "SAMLRequest" | "SAMLResponse";
  /** The inflated XML message. */
  readonly xml: string;
  readonly relayState: string | undefined;
  readonly sigAlg: string | undefined;
  readonly signature: Buffer | undefined;
  /** The octets the signature covers (when signed). */
  readonly signedOctets: string | undefined;
}

/** application/x-www-form-urlencoded decoding of one value. */
function formDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    throw new RedirectBindingError("malformed_encoding");
  }
}

/** Largest inflated message (an SLO message is small; the Deployment Profile has no larger ones). */
const MAX_MESSAGE_BYTES = 64 * 1024;

/** Parses an HTTP-Redirect binding query (the part after `?`, exactly as received). */
export function parseRedirectBinding(rawQuery: string): RedirectMessage {
  if (rawQuery.length > 4 * MAX_MESSAGE_BYTES) throw new RedirectBindingError("too_large");
  const tokens = new Map<BindingKey, { readonly token: string; readonly value: string }>();
  for (const token of rawQuery.split("&")) {
    if (token === "") continue;
    const eq = token.indexOf("=");
    const key = eq < 0 ? token : token.slice(0, eq);
    const value = eq < 0 ? "" : token.slice(eq + 1);
    const decodedKey = formDecode(key);
    if (!(BINDING_KEYS as readonly string[]).includes(decodedKey)) continue;
    if (key !== decodedKey) throw new RedirectBindingError("encoded_key");
    const bindingKey = key as BindingKey;
    if (tokens.has(bindingKey)) throw new RedirectBindingError("duplicate_key");
    tokens.set(bindingKey, { token, value });
  }
  const request = tokens.get("SAMLRequest");
  const response = tokens.get("SAMLResponse");
  if ((request === undefined) === (response === undefined)) {
    throw new RedirectBindingError("message_count");
  }
  const kind = request === undefined ? "SAMLResponse" : "SAMLRequest";
  const message = (request ?? response)!;
  const relay = tokens.get("RelayState");
  const sigAlg = tokens.get("SigAlg");
  const signature = tokens.get("Signature");
  if ((sigAlg === undefined) !== (signature === undefined)) {
    throw new RedirectBindingError("signature_incomplete");
  }

  let xml: string;
  try {
    const deflated = Buffer.from(formDecode(message.value), "base64");
    xml = inflateRawSync(deflated, { maxOutputLength: MAX_MESSAGE_BYTES }).toString("utf8");
  } catch (error) {
    if (error instanceof RedirectBindingError) throw error;
    throw new RedirectBindingError("malformed_message");
  }
  return {
    kind,
    xml,
    relayState: relay === undefined ? undefined : formDecode(relay.value),
    sigAlg: sigAlg === undefined ? undefined : formDecode(sigAlg.value),
    signature:
      signature === undefined ? undefined : Buffer.from(formDecode(signature.value), "base64"),
    signedOctets:
      sigAlg === undefined
        ? undefined
        : [message.token, ...(relay === undefined ? [] : [relay.token]), sigAlg.token].join("&"),
  };
}

/** Whether a parsed message carries a valid signature by one of `certificates`. */
export function redirectSignatureValid(
  message: RedirectMessage,
  certificates: readonly string[],
): boolean {
  if (
    message.sigAlg === undefined ||
    message.signature === undefined ||
    message.signedOctets === undefined ||
    SIGNATURE_ALGORITHMS[message.sigAlg] === undefined
  ) {
    return false;
  }
  const data = Buffer.from(message.signedOctets, "utf8");
  return certificates.some((certificate) =>
    verifyWithAlgorithm(message.sigAlg!, data, certificate, message.signature!),
  );
}
