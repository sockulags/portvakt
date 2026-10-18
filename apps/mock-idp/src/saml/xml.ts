import { getVerifiedXml, parseDomFromString, xpath } from "@node-saml/node-saml/lib/xml.js";

/**
 * XML helpers of the mock SAML IdPs, from node-saml (as in the server; never import
 * `@xmldom/xmldom` or `xpath` types directly, their typings pull in lib.dom). Development and
 * tests only.
 */

export const NS = {
  md: "urn:oasis:names:tc:SAML:2.0:metadata",
  saml: "urn:oasis:names:tc:SAML:2.0:assertion",
  samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
  ds: "http://www.w3.org/2000/09/xmldsig#",
  mdattr: "urn:oasis:names:tc:SAML:metadata:attribute",
  shibmd: "urn:mace:shibboleth:metadata:1.0",
  psc: "http://id.swedenconnect.se/authn/1.0/principal-selection/ns",
  xs: "http://www.w3.org/2001/XMLSchema",
  xsi: "http://www.w3.org/2001/XMLSchema-instance",
} as const;

export const BINDING = {
  redirect: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
  post: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
} as const;

export const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

const ESCAPES: Readonly<Record<string, string>> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&apos;",
};

export const escapeXml = (value: string): string =>
  value.replace(/[&<>"']/g, (char) => ESCAPES[char] ?? char);

/** `<name a="v">children</name>` with escaped attribute values; children are trusted XML. */
export function el(
  name: string,
  attributes: Readonly<Record<string, string | undefined>>,
  ...children: string[]
): string {
  const attrs = Object.entries(attributes)
    .filter((entry): entry is [string, string] => entry[1] !== undefined)
    .map(([key, value]) => ` ${key}="${escapeXml(value)}"`)
    .join("");
  return children.length === 0
    ? `<${name}${attrs}/>`
    : `<${name}${attrs}>${children.join("")}</${name}>`;
}

/** An element with escaped text content. */
export const text = (
  name: string,
  attributes: Readonly<Record<string, string | undefined>>,
  value: string,
): string => el(name, attributes, escapeXml(value));

export async function parse(xml: string): Promise<Element> {
  const doc = await parseDomFromString(xml);
  if (doc.documentElement === null) throw new Error("empty XML document");
  return doc.documentElement;
}

export const children = (node: Node, ns: string, localName: string): Element[] =>
  xpath.selectElements(node, `./*[local-name()='${localName}' and namespace-uri()='${ns}']`);

export const descendants = (node: Node, ns: string, localName: string): Element[] =>
  xpath.selectElements(node, `.//*[local-name()='${localName}' and namespace-uri()='${ns}']`);

export const textOf = (element: Element | undefined): string => (element?.textContent ?? "").trim();

export const attr = (element: Element | undefined, name: string): string | undefined => {
  const value = element?.getAttribute(name);
  return value === null || value === undefined || value === "" ? undefined : value;
};

/** Whether `element` carries a valid enveloped signature by one of `certificates`. */
export function signatureValid(
  xml: string,
  element: Element,
  certificates: readonly string[],
): boolean {
  try {
    return getVerifiedXml(xml, element, [...certificates]) !== null;
  } catch {
    return false;
  }
}
