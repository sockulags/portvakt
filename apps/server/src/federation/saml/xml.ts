import {
  buildXmlBuilderObject,
  parseDomFromString,
  signXml,
} from "@node-saml/node-saml/lib/xml.js";
import { restrictedSignedXml } from "./algorithms.js";

/**
 * The XML primitives SAML login methods use: bounded parsing (node-saml's helper over
 * @xmldom/xmldom), linear DOM selection (no XPath on untrusted documents), signature
 * verification that returns only the signed bytes (xml-crypto with the allowlisted algorithms of
 * `algorithms.ts`), and enveloped signing (node-saml). Portvakt never verifies or canonicalises
 * signatures itself.
 *
 * node-saml exports its helpers from `lib/xml`, not from its index; this module is the only place
 * that imports them, so an upgrade has one place to check.
 */

export const NS = {
  md: "urn:oasis:names:tc:SAML:2.0:metadata",
  saml: "urn:oasis:names:tc:SAML:2.0:assertion",
  samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
  ds: "http://www.w3.org/2000/09/xmldsig#",
  xenc: "http://www.w3.org/2001/04/xmlenc#",
  mdattr: "urn:oasis:names:tc:SAML:metadata:attribute",
  mdui: "urn:oasis:names:tc:SAML:metadata:ui",
  shibmd: "urn:mace:shibboleth:metadata:1.0",
  alg: "urn:oasis:names:tc:SAML:metadata:algsupport",
  psc: "http://id.swedenconnect.se/authn/1.0/principal-selection/ns",
  xs: "http://www.w3.org/2001/XMLSchema",
  xsi: "http://www.w3.org/2001/XMLSchema-instance",
} as const;

export const BINDINGS = {
  redirect: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
  post: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
} as const;

/** Largest metadata document Portvakt parses. */
export const MAX_XML_BYTES = 10 * 1024 * 1024;

/**
 * Bounds of a parsed document, enforced before the DOM is built (size, and a lexical count of
 * elements and nesting) and again on it, so a hostile message (deep nesting, a flood of empty
 * elements) costs linear time and is refused early.
 */
export interface XmlLimits {
  readonly maxBytes: number;
  readonly maxElements: number;
  readonly maxDepth: number;
}

/** A SAML Response at the ACS. The element cap is configurable (SAML_XML_MAX_ELEMENTS). */
export const RESPONSE_LIMITS: XmlLimits = {
  maxBytes: 512 * 1024,
  maxElements: 20_000,
  maxDepth: 64,
};
/** A logout message at the SLO endpoint. */
export const LOGOUT_LIMITS: XmlLimits = { maxBytes: 64 * 1024, maxElements: 2_000, maxDepth: 64 };
/** IdP metadata (may be a federation aggregate). */
export const METADATA_LIMITS: XmlLimits = {
  maxBytes: MAX_XML_BYTES,
  maxElements: 2_000_000,
  maxDepth: 64,
};

export class XmlError extends Error {
  readonly reason: string;

  constructor(reason: string, message: string) {
    super(message);
    this.name = "XmlError";
    this.reason = reason;
  }
}

const LESS_THAN = 60;
const SLASH = 47;
const BANG = 33;
const QUESTION = 63;
const GREATER_THAN = 62;

/**
 * A lexical upper bound of the element count and nesting depth, in one pass over the text and
 * before any DOM is built: `<name` opens, `</` and `/>` close.
 */
function lexicalBounds(xml: string, limits: XmlLimits): void {
  let elements = 0;
  let depth = 0;
  for (let i = 0; i < xml.length; i += 1) {
    const char = xml.charCodeAt(i);
    if (char === LESS_THAN) {
      const next = xml.charCodeAt(i + 1);
      if (next === SLASH) depth -= 1;
      else if (next !== BANG && next !== QUESTION) {
        elements += 1;
        depth += 1;
        if (elements > limits.maxElements) {
          throw new XmlError("too_many_elements", "XML document with too many elements");
        }
        if (depth > limits.maxDepth) {
          throw new XmlError("too_deep", "XML document nested too deep");
        }
      }
    } else if (char === SLASH && xml.charCodeAt(i + 1) === GREATER_THAN) {
      depth -= 1;
    }
  }
}

/** Iterative pre-order walk over the elements below (and including) `root`. */
export function forEachElement(root: Node, visit: (element: Element) => void): void {
  const stack: Node[] = [root];
  for (let node = stack.pop(); node !== undefined; node = stack.pop()) {
    if (node.nodeType !== 1) continue;
    visit(node as Element);
    const nodes = node.childNodes;
    for (let i = nodes.length - 1; i >= 0; i -= 1) {
      const childNode = nodes[i];
      if (childNode !== undefined && childNode.nodeType === 1) stack.push(childNode);
    }
  }
}

/** Exact element count and depth of a parsed document (iterative, linear). */
function checkTree(root: Element, limits: XmlLimits): void {
  let elements = 0;
  const stack: [Node, number][] = [[root, 1]];
  for (let entry = stack.pop(); entry !== undefined; entry = stack.pop()) {
    const [node, depth] = entry;
    elements += 1;
    if (elements > limits.maxElements) {
      throw new XmlError("too_many_elements", "XML document with too many elements");
    }
    if (depth > limits.maxDepth) throw new XmlError("too_deep", "XML document nested too deep");
    const nodes = node.childNodes;
    for (let i = 0; i < nodes.length; i += 1) {
      const childNode = nodes[i];
      if (childNode !== undefined && childNode.nodeType === 1) stack.push([childNode, depth + 1]);
    }
  }
}

/**
 * Parses an XML document within `limits`. Documents with a DTD are refused (no entity
 * expansion; the Deployment Profile forbids DTDs), as are parse errors.
 */
export async function parseXml(
  xml: string,
  limits: XmlLimits = RESPONSE_LIMITS,
): Promise<Document> {
  if (xml.length > limits.maxBytes || Buffer.byteLength(xml, "utf8") > limits.maxBytes) {
    throw new XmlError("too_large", "XML document too large");
  }
  if (/<!DOCTYPE/i.test(xml) || /<!ENTITY/i.test(xml)) {
    throw new XmlError("dtd_not_allowed", "XML document with a DTD");
  }
  lexicalBounds(xml, limits);
  let doc: Document;
  try {
    doc = await parseDomFromString(xml);
  } catch {
    throw new XmlError("malformed", "XML document could not be parsed");
  }
  if (doc.documentElement === null) throw new XmlError("malformed", "XML document is empty");
  checkTree(doc.documentElement, limits);
  return doc;
}

/** The document element of a parsed document. */
export function rootOf(doc: Document): Element {
  if (doc.documentElement === null) throw new XmlError("malformed", "XML document is empty");
  return doc.documentElement;
}

export function isElement(node: Node, ns: string, localName: string): node is Element {
  return node.nodeType === 1 && node.localName === localName && node.namespaceURI === ns;
}

/** Child elements of `node` with the namespace and local name given (direct children only). */
export function children(node: Node, ns: string, localName: string): Element[] {
  const found: Element[] = [];
  const nodes = node.childNodes;
  for (let i = 0; i < nodes.length; i += 1) {
    const childNode = nodes[i];
    if (childNode !== undefined && isElement(childNode, ns, localName)) found.push(childNode);
  }
  return found;
}

/** The single child element, `undefined` when absent; throws when there are several. */
export function child(node: Node, ns: string, localName: string): Element | undefined {
  const found = children(node, ns, localName);
  if (found.length > 1) throw new XmlError("duplicate_element", `more than one ${localName}`);
  return found[0];
}

/** Descendant elements (any depth, not `node` itself) with the namespace and local name given. */
export function descendants(node: Node, ns: string, localName: string): Element[] {
  const found: Element[] = [];
  forEachElement(node, (element) => {
    if (element !== node && isElement(element, ns, localName)) found.push(element);
  });
  return found;
}

/** An attribute's value; `undefined` when absent or empty. */
export function attribute(element: Element, name: string): string | undefined {
  const value = element.getAttribute(name);
  return value === null || value === "" ? undefined : value;
}

/** Trimmed text content. */
export function textOf(element: Element): string {
  return (element.textContent ?? "").trim();
}

const ID_NAMES: ReadonlySet<string> = new Set(["ID", "Id", "id"]);

/** Elements carrying `id` in an ID-like attribute (`ID`, `Id`, `id`, in any namespace). */
function elementsWithId(root: Node, id: string): Element[] {
  const found: Element[] = [];
  forEachElement(root, (element) => {
    const attributes = element.attributes;
    for (let i = 0; i < attributes.length; i += 1) {
      const attr = attributes.item(i);
      if (attr === null) continue;
      const local = attr.localName ?? attr.name.slice(attr.name.indexOf(":") + 1);
      if (ID_NAMES.has(local) && attr.value === id) {
        found.push(element);
        return;
      }
    }
  });
  return found;
}

/** Why a signature was not accepted (fixed codes; the tests pin each check). */
export type SignatureRefusal =
  | "signature_count"
  | "too_many_transforms"
  | "missing_id"
  | "duplicate_id"
  | "reference_mismatch"
  | "invalid";

export type SignatureCheck =
  | { readonly ok: true; readonly signed: string }
  | { readonly ok: false; readonly reason: SignatureRefusal };

/**
 * Verifies `element`'s enveloped signature against one of `certificates` (PEM) with the
 * allowlisted algorithms (`algorithms.ts`) and returns the signed bytes; only those may be
 * trusted. The structural rules are node-saml's (`getVerifiedXml`), which defeat signature
 * wrapping: exactly one signature as a direct child, at most two transforms, exactly one
 * reference, to the element's own ID, and that ID on no other element (`ID`, `Id` or `id`, in any
 * namespace). The cryptography and canonicalization are xml-crypto's. Linear in the document.
 */
export function checkSignature(
  fullXml: string,
  element: Element,
  certificates: readonly string[],
): SignatureCheck {
  // xml-crypto expects XML-processor newline normalisation.
  const xml = fullXml.replace(/\r\n?/g, "\n");
  const signatures = children(element, NS.ds, "Signature");
  const signature = signatures[0];
  if (signatures.length !== 1 || signature === undefined) {
    return { ok: false, reason: "signature_count" };
  }
  if (descendants(signature, NS.ds, "Transform").length > 2) {
    return { ok: false, reason: "too_many_transforms" };
  }
  const id = element.getAttribute("ID");
  const documentElement = element.ownerDocument?.documentElement ?? null;
  if (id === null || id === "" || documentElement === null) {
    return { ok: false, reason: "missing_id" };
  }
  const referenced = elementsWithId(documentElement, id);
  if (referenced.length !== 1 || referenced[0] !== element) {
    return { ok: false, reason: "duplicate_id" };
  }
  for (const certificate of certificates) {
    const sig = restrictedSignedXml(certificate);
    try {
      sig.loadSignature(signature);
      const references = sig.getReferences();
      if (references.length !== 1 || references[0]?.uri !== `#${id}`) {
        return { ok: false, reason: "reference_mismatch" };
      }
      if (!sig.checkSignature(xml)) continue;
      const signed = sig.getSignedReferences();
      return signed.length === 1 && signed[0] !== undefined
        ? { ok: true, signed: signed[0] }
        : { ok: false, reason: "invalid" };
    } catch {
      // An unsupported algorithm or a failed reference: not valid with this certificate.
    }
  }
  return { ok: false, reason: "invalid" };
}

/** The signed bytes of `element`'s valid signature, or `null` (see {@link checkSignature}). */
export function verifiedXml(
  fullXml: string,
  element: Element,
  certificates: readonly string[],
): string | null {
  const result = checkSignature(fullXml, element, certificates);
  return result.ok ? result.signed : null;
}

/** Builds XML from an xmlbuilder object (`@attr`, `#text`), as node-saml does for requests. */
export function buildXml(object: Record<string, unknown>): string {
  return buildXmlBuilderObject(object, false);
}

/**
 * Signs the element selected by `elementXPath` with an enveloped RSA-SHA256 signature (SHA-256
 * digest, exclusive c14n), placed as its first child (after Issuer when `afterIssuer`).
 */
export function signEnveloped(
  xml: string,
  elementXPath: string,
  privateKey: string,
  certificate: string,
  options: { readonly afterIssuer?: boolean } = {},
): string {
  return signXml(
    xml,
    elementXPath,
    options.afterIssuer === true
      ? {
          reference: `${elementXPath}/*[local-name(.)='Issuer']`,
          action: "after",
        }
      : { reference: elementXPath, action: "prepend" },
    {
      privateKey,
      publicCert: certificate,
      signatureAlgorithm: "sha256",
      digestAlgorithm: "sha256",
    },
  );
}
