import type { KeyRing } from "../crypto/keyring.js";
import type { Db } from "../db/database.js";
import { AccessRepository } from "./access.js";
import { ApplicationRepository } from "./applications.js";
import { AuditRepository } from "./audit.js";
import { LoginMethodRepository } from "./login-methods.js";
import { PersonRepository } from "./persons.js";
import { PartyRepository, RepresentationGrantRepository } from "./representation.js";
import { SigningKeyRepository } from "./signing-keys.js";
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
}

/**
 * Builds every repository over `db`. Pass a transaction's `Db` to run several repository calls
 * atomically: `db.transaction((tx) => doWork(createRepositories(tx, keys)))`.
 */
export function createRepositories(db: Db, keys: KeyRing): Repositories {
  return {
    tenants: new TenantRepository(db),
    applications: new ApplicationRepository(db, keys.secrets),
    loginMethods: new LoginMethodRepository(db, keys.secrets),
    persons: new PersonRepository(db, keys),
    access: new AccessRepository(db),
    parties: new PartyRepository(db, keys),
    grants: new RepresentationGrantRepository(db, keys),
    signingKeys: new SigningKeyRepository(db, keys.secrets),
    audit: new AuditRepository(db),
  };
}

export { AccessRepository } from "./access.js";
export { applicationSecretContext, ApplicationRepository } from "./applications.js";
export { AuditRepository, type AuditScope } from "./audit.js";
export * from "./errors.js";
export { clientSecretContext, LoginMethodRepository } from "./login-methods.js";
export { identityPinContext, PersonRepository } from "./persons.js";
export { PartyRepository, RepresentationGrantRepository } from "./representation.js";
export { rewrapAllSecrets, type RewrapResult } from "./rewrap.js";
export { privateJwkContext, SigningKeyRepository, type ActivationResult } from "./signing-keys.js";
export { TenantRepository } from "./tenants.js";
