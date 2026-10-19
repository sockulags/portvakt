import * as client from "openid-client";
import { decodeJwt } from "jose";
import { afterAll, describe, expect, it } from "vitest";
import { ConfigError, DEV_COOKIE_KEYS, DEV_MASTER_KEYS, loadConfig } from "../config/index.js";
import { federationCallbackPath } from "../federation/service.js";
import { createLogger } from "../logging/logger.js";
import { createPortvakt } from "../server.js";
import { adminCall } from "../testing/admin.js";
import {
  authorizationRequest,
  FlowDriver,
  LOA2,
  LOA3,
  redeem,
  startTestIdp,
} from "../testing/federation.js";
import { discover } from "../testing/oidc-flow.js";
import { setupTestDatabase } from "../testing/test-database.js";
import { startTestServer } from "../testing/test-server.js";
import { ADMIN_CLIENT_ID, PLATFORM_ADMIN_ROLE } from "./constants.js";

/**
 * Bootstrap by personal identity number (BOOTSTRAP_ADMIN_PIN through an e-ID at loa3 or above),
 * and two instances bootstrapping one empty database at the same time.
 */

const SVEN_PIN = "191212121212";
const PIN_CLAIM = "https://id.oidc.se/claim/personalIdentityNumber";
const ADMIN_URL = "http://admin.portvakt.test";
const ADMIN_SECRET = "test-admin-client-secret-0123456789abcdef";
const UPSTREAM_SECRET = "bootstrap-bankid-secret-0123456789";

const idp = await startTestIdp();
const pinEnv = {
  BOOTSTRAP_IDP_ISSUER: idp.issuer("bankid"),
  BOOTSTRAP_IDP_CLIENT_ID: "bootstrap-bankid",
  BOOTSTRAP_IDP_CLIENT_SECRET: UPSTREAM_SECRET,
  BOOTSTRAP_IDP_KIND: "citizen",
  BOOTSTRAP_IDP_SCOPES: "openid profile",
  BOOTSTRAP_IDP_DISPLAY_NAME: "Mock BankID (admin)",
  BOOTSTRAP_IDP_ACR: LOA3,
  BOOTSTRAP_IDP_ACR_CLAIM: "acr",
  BOOTSTRAP_IDP_PIN_CLAIM: PIN_CLAIM,
  BOOTSTRAP_ADMIN_PIN: SVEN_PIN,
  ADMIN_PUBLIC_URL: ADMIN_URL,
  ADMIN_CLIENT_SECRET: ADMIN_SECRET,
};
const ts = await startTestServer({ env: pinEnv });

function issuesOf(env: NodeJS.ProcessEnv): string[] {
  try {
    loadConfig(env);
    return [];
  } catch (error) {
    if (error instanceof ConfigError) return [...error.issues];
    throw error;
  }
}

describe("BOOTSTRAP_ADMIN_PIN configuration", () => {
  const base = {
    NODE_ENV: "development",
    DATABASE_URL: "postgres://portvakt:portvakt@localhost:5433/portvakt",
    MASTER_KEY: DEV_MASTER_KEYS[0],
    COOKIE_KEYS: DEV_COOKIE_KEYS.join(","),
    ...pinEnv,
  };

  it("requires an asserted acr ranked at least loa3", () => {
    expect(issuesOf(base)).toEqual([]);
    for (const acr of [undefined, LOA2, "urn:example:unranked"]) {
      const env: NodeJS.ProcessEnv = { ...base, BOOTSTRAP_IDP_ACR: acr };
      expect(issuesOf(env)).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/^BOOTSTRAP_IDP_ACR: with BOOTSTRAP_ADMIN_PIN/),
        ]),
      );
    }
  });

  it("requires the pin and acr claims", () => {
    const env: NodeJS.ProcessEnv = {
      ...base,
      BOOTSTRAP_IDP_PIN_CLAIM: undefined,
      BOOTSTRAP_IDP_ACR_CLAIM: undefined,
    };
    expect(issuesOf(env)).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^BOOTSTRAP_IDP_PIN_CLAIM: required/),
        expect.stringMatching(/^BOOTSTRAP_IDP_ACR_CLAIM: required/),
      ]),
    );
  });
});

describe.skipIf(ts === undefined)("bootstrap by personal identity number", () => {
  it("creates a trusted method and a pending platform admin for the number", async () => {
    const { repos } = ts!.db;
    const system = (await repos.tenants.findBySlug("system"))!;
    const [method] = await repos.loginMethods.list(system.id);
    expect(method).toMatchObject({ kind: "citizen", trustPinForRepresentation: true });
    const pending = await repos.pending.listRoles(system.id);
    expect(pending).toEqual([
      expect.objectContaining({
        role: PLATFORM_ADMIN_ROLE,
        target: expect.objectContaining({ kind: "pin" }) as unknown,
      }),
    ]);
    const events = await repos.audit.query(
      { tenantId: system.id },
      { actions: ["admin.bootstrap"] },
    );
    expect(JSON.stringify(events.events)).not.toContain(SVEN_PIN);
  });

  it("makes the holder of the number platform admin at the first e-ID sign-in", async () => {
    const { repos } = ts!.db;
    const system = (await repos.tenants.findBySlug("system"))!;
    const [method] = await repos.loginMethods.list(system.id);
    idp.idp.registerClient({
      issuer: "bankid",
      client_id: "bootstrap-bankid",
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
    const landing = await driver.persona(await driver.follow(request.url.href), "sven-medborgare");
    const tokens = await redeem(config, request, landing);
    expect(decodeJwt(tokens.access_token).roles).toEqual([PLATFORM_ADMIN_ROLE]);
    const me = await adminCall(ts!, tokens.access_token, "GET", "/me");
    expect(me.body).toMatchObject({ platform: true, tenant: { slug: "system" } });
    expect(await repos.pending.listRoles(system.id)).toEqual([]);
  });

  it("bootstraps exactly once when two instances start on an empty database together", async () => {
    const db = await setupTestDatabase();
    const logger = createLogger({ level: "silent" });
    const instances = [0, 1].map(() =>
      createPortvakt({ config: ts!.config, pool: db!.pool, logger, keys: db!.keys }),
    );
    afterAll(async () => {
      await Promise.all(instances.map((instance) => instance.shutdown()));
    });
    const results = await Promise.all(instances.map((instance) => instance.bootstrap()));
    expect(results.filter((result) => result.ran)).toHaveLength(1);
    expect(results.filter((result) => !result.ran)).toEqual([
      { ran: false, reason: "tenants_exist" },
    ]);
    expect((await db!.repos.tenants.list()).map((tenant) => tenant.slug)).toEqual(["system"]);
    expect(await db!.repos.applications.list()).toHaveLength(1);
    const system = (await db!.repos.tenants.findBySlug("system"))!;
    expect(await db!.repos.pending.listRoles(system.id)).toHaveLength(1);
    const events = await db!.repos.audit.query(
      { tenantId: system.id },
      { actions: ["admin.bootstrap"] },
    );
    expect(events.events).toHaveLength(1);
  });
});
