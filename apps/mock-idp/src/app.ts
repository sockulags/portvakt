import express, { type Express } from "express";
import {
  ISSUER_KINDS,
  mockClientSchema,
  type IssuerKind,
  type MockClient,
  type MockClientInput,
} from "./clients.js";
import { createMockIssuer, type MockIssuer } from "./issuer.js";
import { DEFAULT_PERSONAS_PATH, loadPersonas, type Personas } from "./personas.js";

export interface MockIdpOptions {
  /** Origin the issuers live under: `{publicUrl}/entra` and `{publicUrl}/bankid`. */
  readonly publicUrl: string;
  readonly personas?: Personas;
  readonly clients?: readonly (MockClient | MockClientInput)[];
}

export interface MockIdp {
  readonly app: Express;
  readonly personas: Personas;
  /** Issuer URL a login method configures for `kind`. */
  issuer(kind: IssuerKind): string;
  /** `aud` of the last private_key_jwt client assertion of a client at an issuer. */
  lastClientAssertionAudience(kind: IssuerKind, clientId: string): unknown;
  /** Registers (or replaces) a relying party of an issuer at runtime (tests). */
  registerClient(client: MockClientInput): void;
}

/**
 * Two upstream IdPs in one process, for development and tests only: `/entra` (employees, Entra
 * ID style: `oid`, `groups`, groups overage) and `/bankid` (citizens: personal identity number,
 * Swedish eID levels of assurance, protected identity). Never part of a production image.
 */
export async function createMockIdp(options: MockIdpOptions): Promise<MockIdp> {
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "The mock IdP is a development tool and refuses to run with NODE_ENV=production",
    );
  }
  const publicUrl = options.publicUrl.replace(/\/+$/, "");
  const personas = options.personas ?? loadPersonas(DEFAULT_PERSONAS_PATH);
  const issuers = new Map<IssuerKind, MockIssuer>();
  for (const kind of ISSUER_KINDS) {
    issuers.set(kind, await createMockIssuer({ kind, publicUrl, personas }));
  }
  const issuerOf = (kind: IssuerKind): MockIssuer => {
    const found = issuers.get(kind);
    if (found === undefined) throw new Error(`unknown issuer ${kind}`);
    return found;
  };
  const registerClient = (client: MockClientInput): void => {
    const parsed = mockClientSchema.parse(client);
    issuerOf(parsed.issuer).registerClient(parsed);
  };
  for (const client of options.clients ?? []) registerClient(client);

  const app = express();
  app.disable("x-powered-by");
  app.get("/healthz", (_req, res) => {
    res.set("Cache-Control", "no-store").json({ status: "ok" });
  });
  for (const issuer of issuers.values()) {
    for (const path of issuer.mountPaths) app.use(path, issuer.router);
  }
  app.use((_req, res) => {
    res.status(404).json({ error: "not_found" });
  });

  return {
    app,
    personas,
    issuer: (kind) => issuerOf(kind).configuredIssuer,
    lastClientAssertionAudience: (kind, clientId) =>
      issuerOf(kind).lastClientAssertionAudience(clientId),
    registerClient,
  };
}
