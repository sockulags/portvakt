/**
 * @portvakt/sdk-node: Portvakt for Node and Express.
 *
 * - {@link createPortvaktClient}: one client per application and tenant issuer.
 * - `client.bff(...)`: backend-for-frontend login (server-side sessions, refresh, step-up,
 *   representation switch, logout) as an Express router with helpers.
 * - `client.requireAccessToken(...)`: access token validation for APIs.
 * - `client.clientCredentials(...)`: service-to-service tokens.
 */
export { createPortvaktClient, type PortvaktClient } from "./client.js";
export type { ClientAuthConfig, PortvaktClientConfig, ResolvedConfig } from "./config.js";
export type {
  BffHelpers,
  BffOptions,
  GetAccessTokenOptions,
  PortvaktBff,
  SessionInfo,
} from "./bff/bff.js";
export {
  AccessTokenError,
  accessTokenPrincipal,
  type AccessTokenRequirements,
  type BearerErrorCode,
} from "./access-token.js";
export {
  LoginFailedError,
  LoginRequiredError,
  PortvaktConfigError,
  PortvaktError,
  PortvaktUnavailableError,
  type SessionEndReason,
} from "./errors.js";
export { consoleLogger, silentLogger, type PortvaktLogger } from "./logger.js";
export {
  acrAtLeast,
  DEFAULT_ACR_RANKING,
  hasRole,
  type IdpKind,
  type PersonPrincipal,
  type Principal,
  type Representation,
  type ServicePrincipal,
} from "./principal.js";
export { resourceIndicatorFor, type ServiceTokenSource } from "./service-tokens.js";
export { MemoryStore, type MemoryStoreOptions } from "./stores/memory.js";
export {
  DEFAULT_SESSION_TABLE,
  migratePgSessionStore,
  pgSessionStoreSchema,
  PgSessionStore,
  type PgClientLike,
  type PgPoolLike,
  type PgQueryResultLike,
  type PgSessionStoreOptions,
} from "./stores/pg.js";
export type { SessionStore } from "./stores/types.js";
