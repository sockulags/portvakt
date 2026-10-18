import { z } from "zod";
import { base64ToPem, certificateInfo } from "../../crypto/x509.js";
import {
  attribute,
  BINDINGS,
  child,
  children,
  descendants,
  METADATA_LIMITS,
  NS,
  parseXml,
  rootOf,
  textOf,
  verifiedXml,
  XmlError,
} from "./xml.js";

const SAML2_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";

/**
 * What Portvakt uses from an IdP's SAML metadata, as cached in `login_method_saml.metadata_cache`
 * (JSON, validated on every read). Taken from the IdP's EntityDescriptor in a (signature-checked)
 * metadata document, which may be a federation aggregate (EntitiesDescriptor).
 */
export const idpMetadataSchema = z
  .object({
    entityId: z.string().min(1).max(1024),
    /** Earliest validUntil of the document and the entity, epoch milliseconds. */
    validUntil: z.number().int().positive().nullable(),
    sso: z
      .object({
        redirect: z.url().nullable(),
        post: z.url().nullable(),
      })
      .strict(),
    slo: z
      .object({
        redirect: z.object({ location: z.url(), responseLocation: z.url() }).strict().nullable(),
        post: z.object({ location: z.url(), responseLocation: z.url() }).strict().nullable(),
      })
      .strict(),
    /** PEM certificates the IdP signs with (KeyDescriptor use="signing" or without use). */
    signingCertificates: z.array(z.string().min(1).max(16384)).min(1).max(20),
    /** `shibmd:Scope` values (literal scopes only): allowed scopes of orgAffiliation. */
    scopes: z.array(z.string().min(1).max(255)).max(100),
    /** Attribute names the IdP accepts in PrincipalSelection (RequestedPrincipalSelection). */
    principalSelection: z.array(z.string().min(1).max(255)).max(20),
    /** The IdP's entity categories (informational). */
    entityCategories: z.array(z.string().min(1).max(1024)).max(100),
  })
  .strict();
export type IdpMetadata = z.infer<typeof idpMetadataSchema>;

/** Why metadata was refused; the reason codes are safe to log and to store. */
export class MetadataError extends Error {
  readonly reason: string;

  constructor(reason: string, message: string) {
    super(message);
    this.name = "MetadataError";
    this.reason = reason;
  }
}

export interface ParseMetadataOptions {
  /** IdP entityID to find in the document. */
  readonly entityId: string;
  /** When set, the document must carry a valid signature by this certificate (PEM). */
  readonly signingCertificate: string | null;
  readonly now: Date;
}

function epochOf(value: string | undefined): number | null {
  if (value === undefined) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : Number.NaN;
}

function earliest(...values: (number | null)[]): number | null {
  const present = values.filter((value): value is number => value !== null);
  return present.length === 0 ? null : Math.min(...present);
}

function supportsSaml2(descriptor: Element): boolean {
  return (attribute(descriptor, "protocolSupportEnumeration") ?? "")
    .split(/\s+/)
    .includes(SAML2_PROTOCOL);
}

function endpoint(services: readonly Element[], binding: string): Element | undefined {
  return services.find((service) => attribute(service, "Binding") === binding);
}

function httpUrl(value: string | undefined): string | null {
  if (value === undefined) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
  } catch {
    return null;
  }
}

function signingCertificatesOf(descriptor: Element): string[] {
  const certificates: string[] = [];
  for (const key of children(descriptor, NS.md, "KeyDescriptor")) {
    const use = attribute(key, "use");
    if (use !== undefined && use !== "signing") continue;
    for (const cert of descendants(key, NS.ds, "X509Certificate")) {
      const pem = base64ToPem(textOf(cert));
      try {
        certificateInfo(pem);
      } catch {
        throw new MetadataError("invalid_certificate", "metadata certificate cannot be parsed");
      }
      if (!certificates.includes(pem)) certificates.push(pem);
    }
  }
  return certificates;
}

function extensionsOf(element: Element): Element | undefined {
  return child(element, NS.md, "Extensions");
}

/**
 * Parses IdP metadata (an EntityDescriptor or an aggregate EntitiesDescriptor) and returns what
 * Portvakt uses of the entity `options.entityId`. With a signing certificate, only a document
 * whose root carries a valid signature by it is accepted, and only the signed bytes are read.
 * Throws {@link MetadataError}.
 */
export async function parseIdpMetadata(
  xml: string,
  options: ParseMetadataOptions,
): Promise<IdpMetadata> {
  let doc: Document;
  try {
    doc = await parseXml(xml, METADATA_LIMITS);
  } catch (error) {
    if (error instanceof XmlError) throw new MetadataError(error.reason, error.message);
    throw error;
  }
  if (options.signingCertificate !== null) {
    const signed = verifiedXml(xml, rootOf(doc), [options.signingCertificate]);
    if (signed === null) {
      throw new MetadataError("signature_invalid", "metadata signature missing or invalid");
    }
    doc = await parseXml(signed, METADATA_LIMITS);
  }
  const root = rootOf(doc);
  let entity: Element | undefined;
  if (root.localName === "EntityDescriptor" && root.namespaceURI === NS.md) {
    entity = attribute(root, "entityID") === options.entityId ? root : undefined;
  } else if (root.localName === "EntitiesDescriptor" && root.namespaceURI === NS.md) {
    const matches = descendants(root, NS.md, "EntityDescriptor").filter(
      (candidate) => attribute(candidate, "entityID") === options.entityId,
    );
    if (matches.length > 1) {
      throw new MetadataError("duplicate_entity", "entityID listed more than once");
    }
    entity = matches[0];
  } else {
    throw new MetadataError("not_metadata", "not a SAML metadata document");
  }
  if (entity === undefined) {
    throw new MetadataError("entity_not_found", "IdP entityID not found in metadata");
  }

  // validUntil of the document root, every EntitiesDescriptor on the way and the entity.
  const validity: (number | null)[] = [];
  for (let node: Node | null = entity; node !== null && node.nodeType === 1;) {
    validity.push(epochOf(attribute(node as Element, "validUntil")));
    node = node.parentNode;
  }
  if (validity.some((value) => Number.isNaN(value))) {
    throw new MetadataError("invalid_valid_until", "metadata validUntil is not a date");
  }
  const validUntil = earliest(...validity);
  if (validUntil !== null && validUntil <= options.now.getTime()) {
    throw new MetadataError("expired", "metadata validUntil has passed");
  }

  const descriptors = children(entity, NS.md, "IDPSSODescriptor").filter(supportsSaml2);
  if (descriptors.length !== 1) {
    throw new MetadataError("no_idp_descriptor", "no single SAML 2.0 IDPSSODescriptor");
  }
  const descriptor = descriptors[0]!;
  const ssoServices = children(descriptor, NS.md, "SingleSignOnService");
  const ssoOf = (binding: string): string | null => {
    const service = endpoint(ssoServices, binding);
    return service === undefined ? null : httpUrl(attribute(service, "Location"));
  };
  const sso = { redirect: ssoOf(BINDINGS.redirect), post: ssoOf(BINDINGS.post) };
  if (sso.redirect === null && sso.post === null) {
    throw new MetadataError("no_sso_endpoint", "no HTTP-Redirect or HTTP-POST SSO endpoint");
  }
  const sloServices = children(descriptor, NS.md, "SingleLogoutService");
  const sloOf = (binding: string) => {
    const service = endpoint(sloServices, binding);
    if (service === undefined) return null;
    const location = httpUrl(attribute(service, "Location"));
    if (location === null) return null;
    return {
      location,
      responseLocation: httpUrl(attribute(service, "ResponseLocation")) ?? location,
    };
  };

  const signingCertificates = signingCertificatesOf(descriptor);
  if (signingCertificates.length === 0) {
    throw new MetadataError("no_signing_certificate", "IdP metadata has no signing certificate");
  }

  const descriptorExtensions = extensionsOf(descriptor);
  const scopes =
    descriptorExtensions === undefined
      ? []
      : children(descriptorExtensions, NS.shibmd, "Scope")
          .filter((scope) => attribute(scope, "regexp") !== "true")
          .map(textOf)
          .filter((scope) => scope.length > 0 && scope.length <= 255);
  const principalSelection =
    descriptorExtensions === undefined
      ? []
      : descendants(descriptorExtensions, NS.psc, "MatchValue")
          .map((match) => attribute(match, "Name"))
          .filter((name): name is string => name !== undefined);

  const entityExtensions = extensionsOf(entity);
  const entityCategories: string[] = [];
  if (entityExtensions !== undefined) {
    for (const attributes of children(entityExtensions, NS.mdattr, "EntityAttributes")) {
      for (const attr of children(attributes, NS.saml, "Attribute")) {
        if (attribute(attr, "Name") !== "http://macedir.org/entity-category") continue;
        for (const value of children(attr, NS.saml, "AttributeValue")) {
          const category = textOf(value);
          if (category.length > 0) entityCategories.push(category);
        }
      }
    }
  }

  const metadata = {
    entityId: options.entityId,
    validUntil,
    sso,
    slo: { redirect: sloOf(BINDINGS.redirect), post: sloOf(BINDINGS.post) },
    signingCertificates: signingCertificates.slice(0, 20),
    scopes: [...new Set(scopes)].slice(0, 100),
    principalSelection: [...new Set(principalSelection)].slice(0, 20),
    entityCategories: [...new Set(entityCategories)].slice(0, 100),
  };
  const parsed = idpMetadataSchema.safeParse(metadata);
  if (!parsed.success) throw new MetadataError("invalid_metadata", "metadata values out of range");
  return parsed.data;
}
