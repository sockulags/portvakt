import type { LoginMethod } from "../domain/login-method.js";
import type { Tenant } from "../domain/tenant.js";
import type { LoginErrorCode } from "../login/ui-shell.js";
import type { UpstreamSession } from "../repositories/federation-states.js";
import type { MappedIdentity } from "./claim-mapping.js";

/** A login that cannot proceed; the code selects the login UI's error view. */
export class FederationError extends Error {
  readonly code: LoginErrorCode;

  constructor(code: LoginErrorCode, message: string) {
    super(message);
    this.name = "FederationError";
    this.code = code;
  }
}

export interface FailureContext {
  readonly tenantId: string;
  readonly loginMethodId?: string | undefined;
  readonly clientId?: string | undefined;
  /** Upstream error or status code (protocol value, never user data). */
  readonly upstreamError?: string | undefined;
  /** Why Portvakt refused the upstream answer (fixed reason code, never user data). */
  readonly detail?: string | undefined;
  /** The upstream protocol, for the login metrics (SAML failures name it). */
  readonly protocol?: "oidc" | "saml" | undefined;
}

/** What an upstream login established, ready for JIT provisioning and the completion hop. */
export interface UpstreamLoginResult {
  readonly tenant: Tenant;
  readonly interactionUid: string;
  /** The consumed `federation_states` row. */
  readonly stateHash: string;
  readonly method: LoginMethod;
  readonly mapped: MappedIdentity;
  /** The identity is keyed by the personal identity number's blind index (SAML). */
  readonly subjectFromPin: boolean;
  /** The acr the login asserts (ID token `acr`). */
  readonly acr: string;
  /** Epoch seconds of the upstream authentication. */
  readonly authTime: number;
  readonly upstreamSession?: UpstreamSession | undefined;
}
