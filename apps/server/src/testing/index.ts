// The ambient XML DOM types the server compiles with; other workspaces import these helpers.
// eslint-disable-next-line @typescript-eslint/triple-slash-reference
/// <reference path="../types/xml-dom.d.ts" />
/**
 * Test helpers for other workspaces (`@portvakt/server/testing`): the SDK's and the demo
 * service's integration tests run an in-process Portvakt and mock IdP with them.
 */
export * from "./admin.js";
export * from "./federation.js";
export * from "./fixtures.js";
export * from "./oidc-flow.js";
export * from "./saml.js";
export * from "./test-database.js";
export * from "./test-server.js";
export { generateClientSecret } from "../crypto/secrets.js";
