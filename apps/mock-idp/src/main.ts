import { createServer } from "node:http";
import { parseClients } from "./clients.js";
import { createMockIdp } from "./app.js";
import { DEFAULT_PERSONAS_PATH, loadPersonas, SAML_FLAVOURS } from "./personas.js";

/**
 * Development entry point. Environment:
 *
 * - MOCK_IDP_PORT (default 4500; not PORT, which the shared .env sets for the server),
 *   MOCK_IDP_PUBLIC_URL (default http://localhost:{MOCK_IDP_PORT});
 * - MOCK_IDP_PERSONAS: path of a personas file (default apps/mock-idp/personas.json);
 * - MOCK_IDP_CLIENTS: JSON array or path of a JSON file with the relying parties (default: one
 *   `portvakt-dev` client per issuer, accepting every redirect URI below
 *   http://localhost:3000/t/).
 */
async function main(): Promise<void> {
  if (process.env.NODE_ENV === "production") {
    console.error("The mock IdP is a development tool and refuses to run with NODE_ENV=production");
    process.exit(1);
  }
  const port = Number(process.env.MOCK_IDP_PORT ?? 4500);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error("MOCK_IDP_PORT: invalid port");
  const publicUrl = process.env.MOCK_IDP_PUBLIC_URL ?? `http://localhost:${port}`;
  const personas = loadPersonas(process.env.MOCK_IDP_PERSONAS ?? DEFAULT_PERSONAS_PATH);
  const clients = parseClients(process.env.MOCK_IDP_CLIENTS);
  const idp = await createMockIdp({ publicUrl, personas, clients });
  createServer(idp.app).listen(port, () => {
    console.log(`mock IdP issuers: ${idp.issuer("entra")} and ${idp.issuer("bankid")}`);
    for (const flavour of [...SAML_FLAVOURS, "ecdsa" as const]) {
      console.log(
        `  SAML IdP ${idp.saml(flavour).entityId} (metadata ${idp.saml(flavour).metadataUrl})`,
      );
    }
    for (const client of clients) {
      console.log(
        `  client ${client.client_id} at ${client.issuer} (${client.token_endpoint_auth_method})`,
      );
    }
  });
}

main().catch((error: unknown) => {
  console.error("mock IdP failed to start:", error instanceof Error ? error.message : error);
  process.exit(1);
});
