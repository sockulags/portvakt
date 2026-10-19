import type { z } from "zod";
import type { AuditLog } from "../../audit/audit-log.js";
import type { AuditEvent } from "../../domain/audit.js";
import { certificateInfo, generateSelfSignedKeyPair } from "../../crypto/x509.js";
import {
  createSamlLoginMethodInputSchema,
  updateSamlLoginMethodInputSchema,
  type CreateSamlLoginMethodInput,
  type SamlLoginMethod,
  type UpdateSamlLoginMethodInput,
} from "../../domain/login-method.js";
import type { UiInfo } from "../../domain/saml.js";
import { parseInput, ValidationError } from "../../repositories/errors.js";
import type { Repositories } from "../../repositories/index.js";
import type {
  ExpiringSpCertificate,
  NewSpKey,
  SpKey,
  SpKeyPurpose,
} from "../../repositories/saml.js";
import { SP_KEY_PURPOSES } from "../../repositories/saml.js";
import { MetadataError, type IdpMetadata } from "./metadata.js";
import type { SamlFederation } from "./service.js";

/** Who changes a login method (the admin API passes the signed-in administrator). */
export interface AdminActor {
  readonly type: "person" | "application" | "system";
  readonly id: string | null;
}

const SYSTEM_ACTOR: AdminActor = { type: "system", id: null };

/** Validity of generated SP certificates (rotate before they expire; flagged 30 days ahead). */
export const SP_CERTIFICATE_VALIDITY_SECONDS = 2 * 365 * 24 * 3600;
/** The admin portal flags SP certificates expiring within this window (e2e scenario 11). */
export const SP_CERTIFICATE_WARNING_SECONDS = 30 * 24 * 3600;

export interface SamlLoginMethodAdminOptions {
  readonly repos: Repositories;
  readonly saml: SamlFederation;
  /** Production refuses metadata URLs over plain http. */
  readonly production: boolean;
  /** Writes the catalogue events (through `repos.audit`) and hands them to the audit sink. */
  readonly auditLog: AuditLog;
  /**
   * Inside a transaction (admin API): receives each written event, which the caller forwards to
   * the sink after the commit. Without it, events are forwarded at once (pool repositories).
   */
  readonly onWritten?: (event: AuditEvent) => void;
}

/**
 * Admin-facing operations on SAML login methods (the admin API, M6, calls these): create and
 * update with validation (the metadata is fetched or parsed, its signature checked when a
 * metadata signing certificate is configured, and it must list the IdP entityID; certificates
 * must parse and be valid; LoA URIs must be known unless `allowCustomLoa`), SP key rotation
 * with an overlap, and the SP certificate expiry report.
 */
export class SamlLoginMethodAdmin {
  readonly #options: SamlLoginMethodAdminOptions;

  constructor(options: SamlLoginMethodAdminOptions) {
    this.#options = options;
  }

  async create(
    tenantId: string,
    input: CreateSamlLoginMethodInput,
    actor: AdminActor = SYSTEM_ACTOR,
  ): Promise<SamlLoginMethod> {
    const data = parseInput(createSamlLoginMethodInputSchema, input);
    this.#checkProduction(data.saml);
    const metadata = await this.#checkedMetadata(data.saml);
    const spKeys = await Promise.all(SP_KEY_PURPOSES.map((purpose) => newSpKey(purpose)));
    const method = await this.#options.repos.loginMethods.createSaml(tenantId, input, {
      spKeys,
      metadataCache: metadata,
    });
    await this.#auditUnsigned(method, actor);
    return method;
  }

  /**
   * Updates a SAML login method. A changed IdP (entityID, metadata source or signing
   * certificate) is checked like at creation and replaces the cached metadata.
   */
  async update(
    tenantId: string,
    id: string,
    patch: UpdateSamlLoginMethodInput,
    actor: AdminActor = SYSTEM_ACTOR,
  ): Promise<SamlLoginMethod> {
    const data = parseInput(updateSamlLoginMethodInputSchema, patch);
    const current = await this.#options.repos.loginMethods.findById(tenantId, id);
    if (current?.protocol !== "saml")
      throw new ValidationError(["protocol: not a SAML login method"]);
    const change = data.saml ?? {};
    this.#checkProduction({
      metadataUrl: change.metadataUrl === undefined ? current.saml.metadataUrl : change.metadataUrl,
      metadataSigningCertificate:
        change.metadataSigningCertificate === undefined
          ? current.saml.metadataSigningCertificate
          : change.metadataSigningCertificate,
      allowUnsignedMetadata: change.allowUnsignedMetadata ?? current.saml.allowUnsignedMetadata,
      uiInfo: change.uiInfo ?? current.saml.uiInfo,
    });
    const updated = await this.#update(tenantId, id, patch, change, current);
    if (
      change.allowUnsignedMetadata === true ||
      (updated.saml.allowUnsignedMetadata && change.metadataUrl !== undefined)
    ) {
      await this.#auditUnsigned(updated, actor);
    }
    return updated;
  }

  async #update(
    tenantId: string,
    id: string,
    patch: UpdateSamlLoginMethodInput,
    change: NonNullable<z.output<typeof updateSamlLoginMethodInputSchema>["saml"]>,
    current: SamlLoginMethod,
  ): Promise<SamlLoginMethod> {
    const sourceChanged =
      change.idpEntityId !== undefined ||
      change.metadataUrl !== undefined ||
      change.metadataXml !== undefined ||
      change.metadataSigningCertificate !== undefined;
    if (!sourceChanged) return this.#options.repos.loginMethods.updateSaml(tenantId, id, patch);
    const metadata = await this.#checkedMetadata({
      idpEntityId: change.idpEntityId ?? current.saml.idpEntityId,
      metadataUrl: change.metadataUrl === undefined ? current.saml.metadataUrl : change.metadataUrl,
      metadataXml: change.metadataXml === undefined ? current.saml.metadataXml : change.metadataXml,
      metadataSigningCertificate:
        change.metadataSigningCertificate === undefined
          ? current.saml.metadataSigningCertificate
          : change.metadataSigningCertificate,
    });
    return this.#options.repos.loginMethods.updateSaml(tenantId, id, patch, {
      metadataCache: metadata,
    });
  }

  /**
   * What the admin portal should show as warnings for a SAML login method (M6): settings that
   * weaken the framework's guarantees, Deployment Profile recommendations not met, and SP
   * certificates expiring within 30 days.
   */
  async warningsFor(method: SamlLoginMethod, now = new Date()): Promise<string[]> {
    const { saml } = method;
    const warnings: string[] = [];
    if (saml.allowUnsignedMetadata) {
      warnings.push("saml.allowUnsignedMetadata: the IdP metadata is not signature-checked");
    }
    if (!saml.requireEncryptedAssertions) {
      warnings.push("saml.requireEncryptedAssertions: unencrypted assertions are accepted");
    }
    if (!saml.requireSignedResponse) {
      warnings.push(
        "saml.requireSignedResponse: the Deployment Profile requires a signed Response",
      );
    }
    if (saml.authnContextComparison === "minimum") {
      warnings.push("saml.authnContextComparison: the Deployment Profile allows only exact");
    }
    if (saml.uiInfo.logos.length === 0) {
      warnings.push("saml.uiInfo.logos: the Deployment Profile requires at least one logo");
    }
    if (saml.uiInfo.description === undefined) {
      warnings.push("saml.uiInfo.description: a Swedish description is recommended");
    }
    const expiring = await this.expiringSpCertificates(method.tenantId, undefined, now);
    for (const entry of expiring.filter((item) => item.loginMethodId === method.id)) {
      warnings.push(
        `spKeys.${entry.purpose}: the ${entry.state} certificate expires ${entry.notAfter.toISOString()}`,
      );
    }
    return warnings;
  }

  /** Production rules the Deployment Profile and Portvakt's policy make mandatory. */
  #checkProduction(settings: {
    readonly metadataUrl: string | null;
    readonly metadataSigningCertificate: string | null;
    readonly allowUnsignedMetadata: boolean;
    readonly uiInfo: UiInfo;
  }): void {
    if (!this.#options.production) return;
    const issues: string[] = [];
    if (
      settings.metadataUrl !== null &&
      settings.metadataSigningCertificate === null &&
      !settings.allowUnsignedMetadata
    ) {
      issues.push(
        "saml.metadataSigningCertificate: required for a metadata URL in production (or set allowUnsignedMetadata)",
      );
    }
    if (settings.uiInfo.logos.length === 0) {
      issues.push("saml.uiInfo.logos: the Deployment Profile requires at least one logo");
    }
    if (issues.length > 0) throw new ValidationError(issues);
  }

  /** Audits the decision to use unsigned metadata (on every save that makes or keeps it). */
  async #auditUnsigned(method: SamlLoginMethod, actor: AdminActor): Promise<void> {
    if (!method.saml.allowUnsignedMetadata) return;
    const { auditLog, onWritten, repos } = this.#options;
    const stored = await auditLog.recordIn(repos.audit, {
      tenantId: method.tenantId,
      actor,
      subject: { type: "login_method", id: method.id },
      action: "login_method.saml_unsigned_metadata_allowed",
      details: { loginMethodId: method.id },
    });
    if (onWritten === undefined) auditLog.forward([stored]);
    else onWritten(stored);
  }

  /**
   * Starts an SP key rotation: a `next` key per purpose, published in SP metadata next to the
   * active one. Give the IdP or federation time to pick it up, then {@link rotateSpKeys}.
   */
  async prepareSpKeyRotation(
    tenantId: string,
    loginMethodId: string,
    purposes: readonly SpKeyPurpose[] = SP_KEY_PURPOSES,
  ): Promise<SpKey[]> {
    const added: SpKey[] = [];
    for (const purpose of purposes) {
      added.push(
        await this.#options.repos.saml.addNextSpKey(
          tenantId,
          loginMethodId,
          await newSpKey(purpose),
        ),
      );
    }
    return added;
  }

  /**
   * Completes a rotation: next becomes active (signs, preferred for decryption), active becomes
   * previous (no longer published, still decrypts until the next rotation). Returns the
   * purposes that rotated.
   */
  async rotateSpKeys(
    tenantId: string,
    loginMethodId: string,
    purposes: readonly SpKeyPurpose[] = SP_KEY_PURPOSES,
  ): Promise<SpKeyPurpose[]> {
    const rotated: SpKeyPurpose[] = [];
    for (const purpose of purposes) {
      if (await this.#options.repos.saml.promoteNextSpKey(tenantId, loginMethodId, purpose)) {
        rotated.push(purpose);
      }
    }
    return rotated;
  }

  /** SP certificates (active or next) of the tenant expiring within `withinSeconds`. */
  async expiringSpCertificates(
    tenantId: string,
    withinSeconds = SP_CERTIFICATE_WARNING_SECONDS,
    now = new Date(),
  ): Promise<ExpiringSpCertificate[]> {
    return this.#options.repos.saml.listSpCertificatesExpiringBefore(
      tenantId,
      new Date(now.getTime() + withinSeconds * 1000),
    );
  }

  async #checkedMetadata(source: {
    readonly idpEntityId: string;
    readonly metadataUrl: string | null;
    readonly metadataXml: string | null;
    readonly metadataSigningCertificate: string | null;
  }): Promise<IdpMetadata> {
    const issues: string[] = [];
    if (source.metadataUrl !== null && this.#options.production) {
      if (new URL(source.metadataUrl).protocol !== "https:") {
        issues.push("saml.metadataUrl: must be https in production");
      }
    }
    if (source.metadataSigningCertificate !== null) {
      try {
        const info = certificateInfo(source.metadataSigningCertificate);
        if (info.notAfter.getTime() <= Date.now()) {
          issues.push("saml.metadataSigningCertificate: the certificate has expired");
        }
      } catch {
        issues.push("saml.metadataSigningCertificate: not a valid certificate");
      }
    }
    if (issues.length > 0) throw new ValidationError(issues);
    try {
      return await this.#options.saml.loadMetadata({
        idpEntityId: source.idpEntityId,
        metadataUrl: source.metadataUrl,
        metadataXml: source.metadataXml,
        signingCertificate: source.metadataSigningCertificate,
      });
    } catch (error) {
      if (error instanceof MetadataError) {
        throw new ValidationError([`saml.metadata: ${error.reason}`]);
      }
      throw error;
    }
  }
}

async function newSpKey(purpose: SpKeyPurpose): Promise<NewSpKey> {
  const pair = await generateSelfSignedKeyPair(
    `Portvakt SAML SP ${purpose}`,
    SP_CERTIFICATE_VALIDITY_SECONDS,
  );
  return {
    purpose,
    certificate: pair.certificate,
    privateKey: pair.privateKey,
    notAfter: pair.notAfter,
  };
}
