import * as client from "openid-client";
import { decodeJwt } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import type { OidcLoginMethod } from "../../domain/login-method.js";
import type { Tenant } from "../../domain/tenant.js";
import {
  adminCall,
  adminToken,
  createAdmin,
  setupAdminWorld,
  type AdminWorld,
} from "../../testing/admin.js";
import {
  authorizationRequest,
  createFederatedLoginMethod,
  FlowDriver,
  redeem,
  startTestIdp,
  type Landing,
} from "../../testing/federation.js";
import { createTenant, TEST_ORGNR } from "../../testing/fixtures.js";
import { discover } from "../../testing/oidc-flow.js";
import { startTestServer } from "../../testing/test-server.js";
import { ADMIN_CLIENT_ID, PLATFORM_ADMIN_ROLE, TENANT_ADMIN_ROLE } from "../constants.js";

/** Pending assignments resolve at real federated logins; representation tokens are refused. */

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

interface SamlView {
  readonly id: string;
  readonly etag: string;
  readonly saml: {
    readonly spMetadataUrl: string;
    readonly spKeys: readonly { readonly purpose: string; readonly state: string }[];
  };
  readonly warnings: readonly { readonly code: string }[];
}

/** Mock personas (apps/mock-idp/personas.json). */
const ANNA_OID = "6f1c8a52-3b7e-4d2a-9c41-8e2f5b7a1d03";
const SVEN_PIN = "191212121212";

describe.skipIf(ts === undefined)("admin sign-in through upstream IdPs", () => {
  let world: AdminWorld;
  let tenant: Tenant;
  let entra: OidcLoginMethod;
  let bankid: OidcLoginMethod;
  let platform: string;

  beforeAll(async () => {
    world = await setupAdminWorld(ts!);
    tenant = await createTenant(ts!.db.repos, "kommun");
    await ts!.db.repos.applications.enableForTenant(tenant.id, world.application.id);
    entra = await createFederatedLoginMethod(ts!, idp!, tenant, "entra");
    bankid = await createFederatedLoginMethod(ts!, idp!, tenant, "bankid", {
      trustPinForRepresentation: true,
      sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true },
    });
    const platformId = await createAdmin(world, world.system, world.systemMethod, [
      PLATFORM_ADMIN_ROLE,
    ]);
    platform = await adminToken(world, world.system, world.systemMethod, platformId);
  });

  /** Signs `persona` in to the admin portal of the tenant through `method`; the access token. */
  async function signIn(
    method: OidcLoginMethod,
    persona: string,
    representation?: (driver: FlowDriver, landing: Landing) => Promise<Landing>,
  ): Promise<string> {
    const config = await discover(
      ts!,
      tenant.slug,
      ADMIN_CLIENT_ID,
      client.ClientSecretBasic(world.secret),
    );
    const request = await authorizationRequest(
      config,
      `${world.adminUrl}/t/${tenant.slug}/auth/callback`,
    );
    const driver = new FlowDriver(ts!, idp!);
    let landing = await driver.follow(request.url.href);
    landing = await driver.chooseAndFollow(landing, { loginMethodId: method.id });
    landing = await driver.persona(landing, persona);
    if (representation !== undefined) landing = await representation(driver, landing);
    return (await redeem(config, request, landing)).access_token;
  }

  it("resolves a pending tenant-admin assignment for an upstream subject at the first login", async () => {
    const created = await adminCall<{ items: Record<string, unknown>[] }>(
      ts!,
      platform,
      "POST",
      `/tenants/${tenant.id}/role-assignments`,
      {
        body: {
          applicationId: world.application.id,
          role: TENANT_ADMIN_ROLE,
          target: { loginMethodId: entra.id, subject: ANNA_OID },
        },
      },
    );
    expect(created.body.items).toEqual([expect.objectContaining({ pending: true })]);
    const token = await signIn(entra, "anna-handlaggare");
    expect(decodeJwt(token).roles).toEqual([TENANT_ADMIN_ROLE]);
    const me = await adminCall(ts!, token, "GET", "/me");
    expect(me.body).toMatchObject({ platform: false, tenant: { id: tenant.id } });
    const events = await ts!.db.repos.audit.query(
      { tenantId: tenant.id },
      { actions: ["assignment.pending_resolved"] },
    );
    expect(events.events).toEqual([
      expect.objectContaining({
        subject: { type: "person", id: (me.body as { personId: string }).personId },
        details: expect.objectContaining({
          kind: "role",
          targetKind: "identity",
          name: TENANT_ADMIN_ROLE,
        }) as unknown,
      }),
    ]);
    const pending = await ts!.db.repos.pending.listRoles(tenant.id);
    expect(pending).toEqual([]);
  });

  it("resolves a pending assignment by personal identity number through a trusted method", async () => {
    await adminCall(ts!, platform, "POST", `/tenants/${tenant.id}/role-assignments`, {
      body: {
        applicationId: world.application.id,
        role: TENANT_ADMIN_ROLE,
        target: { pin: SVEN_PIN },
      },
    });
    const token = await signIn(bankid, "sven-medborgare");
    expect(decodeJwt(token).roles).toEqual([TENANT_ADMIN_ROLE]);
    expect((await adminCall(ts!, token, "GET", `/tenants/${tenant.id}/login-methods`)).status).toBe(
      200,
    );
  });

  it("creates a SAML login method with SP metadata, warnings and SP key rotation", async () => {
    const saml = idp!.idp.saml("bankid");
    const path = `/tenants/${tenant.id}/login-methods`;
    const created = await adminCall<SamlView>(ts!, platform, "POST", path, {
      body: {
        protocol: "saml",
        kind: "citizen",
        displayName: "BankID (SAML)",
        assertedAcr: "http://id.elegnamnden.se/loa/1.0/loa3",
        sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: false },
        saml: {
          idpEntityId: saml.entityId,
          metadataUrl: saml.metadataUrl,
          metadataSigningCertificate: saml.metadataSigningCertificate,
          requestedLoa: ["http://id.elegnamnden.se/loa/1.0/loa3"],
          subjectSource: "personalIdentityNumber",
        },
      },
    });
    expect(created.status).toBe(201);
    const method = created.body;
    expect(method.saml.spMetadataUrl).toBe(
      `${ts!.baseUrl}/t/${tenant.slug}/saml/${method.id}/metadata`,
    );
    expect((await fetch(method.saml.spMetadataUrl)).status).toBe(200);
    expect(method.saml.spKeys.map((key) => key.state)).toEqual(["active", "active"]);
    expect(method.warnings.map((warning) => warning.code)).toEqual(
      expect.arrayContaining(["saml_missing_logo", "saml_missing_description"]),
    );
    expect(JSON.stringify(method)).not.toContain("PRIVATE KEY");

    const base = `${path}/${method.id}/sp-keys`;
    const prepared = await adminCall<SamlView>(ts!, platform, "POST", `${base}/prepare`, {
      body: {},
      ifMatch: method.etag,
    });
    expect(prepared.status).toBe(200);
    expect(prepared.body.saml.spKeys.filter((key) => key.state === "next")).toHaveLength(2);
    const stale = await adminCall(ts!, platform, "POST", `${base}/rotate`, {
      body: {},
      ifMatch: method.etag,
    });
    expect(stale.status).toBe(412);
    const rotated = await adminCall<SamlView>(ts!, platform, "POST", `${base}/rotate`, {
      body: { purposes: ["signing"] },
      ifMatch: prepared.body.etag,
    });
    expect(rotated.body.saml.spKeys.map((key) => `${key.purpose}:${key.state}`).sort()).toEqual([
      "encryption:active",
      "encryption:next",
      "signing:active",
      "signing:previous",
    ]);
    const events = await ts!.db.repos.audit.query(
      { tenantId: tenant.id },
      { subjectId: method.id },
    );
    expect(events.events.map((event) => event.action)).toEqual([
      "admin.login_method.sp_keys_rotate",
      "admin.login_method.sp_keys_prepare",
      "admin.login_method.create",
    ]);
  });

  it("refuses an admin token issued while representing someone", async () => {
    const { repos } = ts!.db;
    await repos.applications.update(world.application.id, { representationMode: "optional" });
    try {
      const party = await repos.parties.create(tenant.id, {
        type: "organisation",
        identifier: TEST_ORGNR,
        displayName: "Bygg AB",
      });
      await repos.grants.create(tenant.id, {
        agent: { pin: SVEN_PIN },
        partyId: party.id,
        allApplications: true,
      });
      const token = await signIn(bankid, "sven-medborgare", (driver, landing) =>
        driver.chooseRepresentationAndFollow(landing, { partyId: party.id }),
      );
      expect(decodeJwt(token).rep).toMatchObject({ sub: party.id });
      const response = await adminCall(ts!, token, "GET", "/me");
      expect(response.status).toBe(403);
      expect(response.body).toMatchObject({ code: "representation_not_allowed" });
    } finally {
      await repos.applications.update(world.application.id, { representationMode: "none" });
    }
  });
});
