import * as client from "openid-client";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { ConfigError, loadConfig } from "../config/index.js";
import { federationCallbackPath } from "../federation/service.js";
import { adminCall } from "../testing/admin.js";
import { authorizationRequest, FlowDriver, redeem, startTestIdp } from "../testing/federation.js";
import { discover } from "../testing/oidc-flow.js";
import { startTestServer } from "../testing/test-server.js";
import { ADMIN_CLIENT_ID, PLATFORM_ADMIN_ROLE } from "./constants.js";

/** First start on an empty database (BOOTSTRAP_IDP_*), and the refusals around it. */

const ERIK_OID = "a3d9e0f4-71c2-4b8e-b5a6-2c4f9d1e8b77";
const ADMIN_URL = "http://admin.portvakt.test";
const ADMIN_SECRET = "test-admin-client-secret-0123456789abcdef";
const UPSTREAM_SECRET = "bootstrap-upstream-secret-0123456789";

const idp = await startTestIdp();
const ts = await startTestServer({
  env: {
    BOOTSTRAP_IDP_ISSUER: idp.issuer("entra"),
    BOOTSTRAP_IDP_CLIENT_ID: "bootstrap-client",
    BOOTSTRAP_IDP_CLIENT_SECRET: UPSTREAM_SECRET,
    BOOTSTRAP_IDP_SUBJECT_CLAIM: "oid",
    BOOTSTRAP_IDP_TRUST_EMAIL: "true",
    BOOTSTRAP_IDP_DISPLAY_NAME: "Mock Entra (admin)",
    BOOTSTRAP_ADMIN_SUBJECT: ERIK_OID,
    ADMIN_PUBLIC_URL: ADMIN_URL,
    ADMIN_CLIENT_SECRET: ADMIN_SECRET,
  },
});

describe.skipIf(ts === undefined)("bootstrap", () => {
  it("creates the system tenant, portvakt-admin, the login method and a pending platform admin", async () => {
    const { repos } = ts!.db;
    const system = await repos.tenants.findBySlug("system");
    expect(system).toMatchObject({ status: "active" });
    const application = await repos.applications.findByClientId(ADMIN_CLIENT_ID);
    expect(application).toMatchObject({
      redirectUris: [`${ADMIN_URL}/t/{tenant}/auth/callback`],
      postLogoutRedirectUris: [`${ADMIN_URL}/t/{tenant}/`],
      representationMode: "none",
    });
    expect(application!.roles.map((role) => role.role).sort()).toEqual([
      "platform-admin",
      "tenant-admin",
    ]);
    expect(await repos.applications.getClientSecret(application!.id)).toBe(ADMIN_SECRET);
    const [method] = await repos.loginMethods.list(system!.id);
    expect(method).toMatchObject({ protocol: "oidc", displayName: "Mock Entra (admin)" });
    const pending = await repos.pending.listRoles(system!.id);
    expect(pending).toEqual([
      expect.objectContaining({
        role: PLATFORM_ADMIN_ROLE,
        target: { kind: "identity", loginMethodId: method!.id, subject: ERIK_OID },
      }),
    ]);
    const events = await repos.audit.query(
      { tenantId: system!.id },
      { actions: ["admin.bootstrap"] },
    );
    expect(events.events).toHaveLength(1);
    expect(JSON.stringify(events.events)).not.toContain(ERIK_OID);
    expect(JSON.stringify(events.events)).not.toContain(UPSTREAM_SECRET);
  });

  it("never runs again once a tenant exists", async () => {
    expect(await ts!.portvakt.bootstrap()).toEqual({ ran: false, reason: "tenants_exist" });
    expect((await ts!.db.repos.tenants.list()).map((tenant) => tenant.slug)).toEqual(["system"]);
  });

  it("lets the bootstrap admin sign in as platform admin through the bootstrap IdP", async () => {
    const { repos } = ts!.db;
    const system = (await repos.tenants.findBySlug("system"))!;
    const [method] = await repos.loginMethods.list(system.id);
    idp.idp.registerClient({
      issuer: "entra",
      client_id: "bootstrap-client",
      client_secret: UPSTREAM_SECRET,
      token_endpoint_auth_method: "client_secret_basic",
      redirect_uris: [`${ts!.baseUrl}${federationCallbackPath("system", method!.id)}`],
    });
    const config = await discover(
      ts!,
      "system",
      ADMIN_CLIENT_ID,
      client.ClientSecretBasic(ADMIN_SECRET),
    );
    const request = await authorizationRequest(config, `${ADMIN_URL}/t/system/auth/callback`);
    const driver = new FlowDriver(ts!, idp);
    const landing = await driver.persona(await driver.follow(request.url.href), "erik-admin");
    const tokens = await redeem(config, request, landing);
    expect(decodeJwt(tokens.access_token).roles).toEqual([PLATFORM_ADMIN_ROLE]);
    const me = await adminCall(ts!, tokens.access_token, "GET", "/me");
    expect(me.body).toMatchObject({ platform: true, tenant: { slug: "system" } });
  });

  it("refuses a production bootstrap without ADMIN_CLIENT_SECRET or ADMIN_PUBLIC_URL", () => {
    const production = {
      NODE_ENV: "production",
      PUBLIC_URL: "https://login.example.org",
      DATABASE_URL: "postgres://app:Secr3t-app-pw@db.example.org/portvakt",
      MIGRATION_DATABASE_URL: "postgres://owner:Secr3t-owner-pw@db.example.org/portvakt",
      MASTER_KEY: Buffer.from("0123456789abcdefghijklmnopqrstuv").toString("base64"),
      COOKIE_KEYS: "a-production-cookie-key-with-enough-length-0123",
      METRICS_TOKEN: "a-production-metrics-token-0123456789abcdef",
      BOOTSTRAP_IDP_ISSUER: "https://login.microsoftonline.com/tenant/v2.0",
      BOOTSTRAP_IDP_CLIENT_ID: "portvakt",
      BOOTSTRAP_ADMIN_SUBJECT: ERIK_OID,
    };
    const issues = (() => {
      try {
        loadConfig(production);
        return [];
      } catch (error) {
        if (error instanceof ConfigError) return error.issues;
        throw error;
      }
    })();
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^ADMIN_CLIENT_SECRET: required in production/),
        expect.stringMatching(/^ADMIN_PUBLIC_URL: required in production/),
      ]),
    );
    expect(() =>
      loadConfig({
        ...production,
        ADMIN_PUBLIC_URL: "https://admin.example.org",
        ADMIN_CLIENT_SECRET: "a-production-admin-client-secret-0123456789",
      }),
    ).not.toThrow();
  });
});
