import type { KeyRing } from "../crypto/keyring.js";
import type { Db } from "../db/database.js";
import { AccessRepository } from "./access.js";
import { ApplicationRepository } from "./applications.js";
import { AuditRepository } from "./audit.js";
import { FederationStateRepository } from "./federation-states.js";
import { LoginMethodRepository } from "./login-methods.js";
import { OidcPayloadRepository } from "./oidc-payloads.js";
import { PendingAssignmentRepository } from "./pending.js";
import { PersonRepository } from "./persons.js";
import { PartyRepository, RepresentationGrantRepository } from "./representation.js";
import { SamlRepository } from "./saml.js";
import { SigningKeyRepository } from "./signing-keys.js";
import { StatsRepository } from "./stats.js";
import { TenantRepository } from "./tenants.js";

export interface Repositories {
  readonly tenants: TenantRepository;
  readonly applications: ApplicationRepository;
  readonly loginMethods: LoginMethodRepository;
  readonly persons: PersonRepository;
  readonly access: AccessRepository;
  readonly parties: PartyRepository;
  readonly grants: RepresentationGrantRepository;
  readonly signingKeys: SigningKeyRepository;
  readonly audit: AuditRepository;
  readonly oidcPayloads: OidcPayloadRepository;
  readonly federationStates: FederationStateRepository;
  readonly saml: SamlRepository;
  readonly pending: PendingAssignmentRepository;
  readonly stats: StatsRepository;
}

export interface RepositoryOptions {
  /** SESSION_TTL: the longest session policy a login method may have. */
  readonly maxSessionSeconds?: number;
  /** ACR_RANKING: ranked acr values need an upstream acr mapping. */
  readonly acrRanking?: readonly string[];
}

/**
 * Builds every repository over `db`. Pass a transaction's `Db` to run several repository calls
 * atomically: `db.transaction((tx) => doWork(createRepositories(tx, keys)))`.
 */
export function createRepositories(
  db: Db,
  keys: KeyRing,
  options: RepositoryOptions = {},
): Repositories {
  return {
    tenants: new TenantRepository(db),
    applications: new ApplicationRepository(db, keys.secrets),
    loginMethods: new LoginMethodRepository(db, keys.secrets, options),
    persons: new PersonRepository(db, keys, options),
    access: new AccessRepository(db),
    parties: new PartyRepository(db, keys),
    grants: new RepresentationGrantRepository(db, keys),
    signingKeys: new SigningKeyRepository(db, keys.secrets),
    audit: new AuditRepository(db),
    oidcPayloads: new OidcPayloadRepository(db),
    federationStates: new FederationStateRepository(db, keys.secrets),
    saml: new SamlRepository(db, keys.secrets),
    pending: new PendingAssignmentRepository(db, keys),
    stats: new StatsRepository(db),
  };
}

export { AccessRepository } from "./access.js";
export { applicationSecretContext, ApplicationRepository } from "./applications.js";
export { AuditRepository, type AuditScope } from "./audit.js";
export {
  CHANGE_CHANNEL,
  changeEventSchema,
  emitChange,
  parseChangeEvent,
  type ChangeEvent,
} from "./change-events.js";
export * from "./errors.js";
export {
  FederationStateRepository,
  type CallbackRejection,
  type FederationCompletion,
  type PendingFederation,
} from "./federation-states.js";
export {
  asOidc,
  clientPrivateJwkContext,
  clientSecretContext,
  LoginMethodRepository,
  type LoginMethodClientKey,
} from "./login-methods.js";
export { OidcPayloadRepository, type PayloadIndexes, type StoredPayload } from "./oidc-payloads.js";
export {
  PendingAssignmentRepository,
  pendingAttributePinContext,
  pendingRolePinContext,
  resolvePending,
  type PendingMatch,
} from "./pending.js";
export { identityPinContext, PersonRepository, type PersonSummary } from "./persons.js";
export { PartyRepository, RepresentationGrantRepository } from "./representation.js";
export { rewrapAllSecrets, type RewrapResult } from "./rewrap.js";
export {
  SamlRepository,
  spKeyContext,
  type ExpiringSpCertificate,
  type MetadataCacheEntry,
  type NewSpKey,
  type SpKey,
  type SpKeyPair,
  type SpKeyPurpose,
  type SpKeyState,
} from "./saml.js";
export { privateJwkContext, SigningKeyRepository, type ActivationResult } from "./signing-keys.js";
export { platformAccess, type PlatformAccess } from "./guard.js";
export { StatsRepository, type ApplicationUsage, type LoginCounts } from "./stats.js";
export { TenantRepository } from "./tenants.js";
