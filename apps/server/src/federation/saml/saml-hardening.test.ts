import { deflateRawSync } from "node:zlib";
import * as client from "openid-client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createKeyRing } from "../../crypto/keyring.js";
import type { Tenant } from "../../domain/tenant.js";
import { ValidationError } from "../../repositories/errors.js";
import { createRepositories } from "../../repositories/index.js";
import { rewrapAllSecrets } from "../../repositories/rewrap.js";
import { createTenant } from "../../testing/fixtures.js";
import {
  authorizationRequest,
  FlowDriver,
  LOA3,
  redeem,
  startTestIdp,
  type Landing,
} from "../../testing/federation.js";
import { createTestClient, discoverWithSecret, type TestClient } from "../../testing/oidc-flow.js";
import { createSamlLoginMethod, spEntityId } from "../../testing/saml.js";
import { testMasterKeys } from "../../testing/test-database.js";
import { startTestServer } from "../../testing/test-server.js";
import { SamlLoginMethodAdmin } from "./admin.js";
import { parseRedirectBinding, RedirectBindingError } from "./redirect.js";
import { verifyWithAlgorithm } from "./algorithms.js";

const ts = await startTestServer();
const idp = ts === undefined ? undefined : await startTestIdp();

const POST_LOGOUT = "https://app.example.test/signed-out";

describe.skipIf(ts === undefined)("SAML hardening", () => {
  const { repos } = ts!.db;
  const db = ts!.db.db;

  afterEach(() => {
    vi.useRealTimers();
  });

  interface World {
    readonly tenant: Tenant;
    readonly app: TestClient;
    readonly config: client.Configuration;
    readonly redirectUri: string;
  }

  async function world(prefix: string, extraScopes: ("pin" | "hsa")[] = ["pin"]): Promise<World> {
    const tenant = await createTenant(repos, prefix);
    const app = await createTestClient(repos, tenant, {
      allowedExtraScopes: extraScopes,
      postLogoutRedirectUris: [POST_LOGOUT],
    });
    const config = await discoverWithSecret(ts!, tenant.slug, app);
    return { tenant, app, config, redirectUri: app.application.redirectUris[0]! };
  }

  async function signIn(
    w: World,
    persona: string | undefined,
    options: {
      readonly params?: Record<string, string>;
      readonly driver?: FlowDriver;
      readonly switch?: string;
    } = {},
  ) {
    const driver = options.driver ?? new FlowDriver(ts!, idp!);
    const request = await authorizationRequest(w.config, w.redirectUri, {
      scope: "openid profile pin",
      ...options.params,
    });
    let landing = await driver.follow(request.url.href);
    if (landing.kind === "idp_page" && persona !== undefined) {
      landing = await driver.persona(
        landing,
        persona,
        options.switch === undefined ? {} : { switch: options.switch },
      );
    }
    return { driver, request, landing };
  }

  async function signedIn(w: World, persona: string, options: Parameters<typeof signIn>[2] = {}) {
    const result = await signIn(w, persona, options);
    return { ...result, tokens: await redeem(w.config, result.request, result.landing) };
  }

  function expectError(landing: Landing, code: string): void {
    expect(landing.kind).toBe("login_ui");
    if (landing.kind !== "login_ui") return;
    expect(landing.bootstrap).toMatchObject({ view: "login", error: code });
  }

  async function sessionAlive(w: World, driver: FlowDriver): Promise<boolean> {
    const request = await authorizationRequest(w.config, w.redirectUri, { prompt: "none" });
    const landing = await driver.follow(request.url.href);
    if (landing.kind !== "app") throw new Error(`unexpected ${landing.kind}`);
    return landing.url.searchParams.get("code") !== null;
  }

  const audits = async (tenant: Tenant, action: string) =>
    (await repos.audit.query({ tenantId: tenant.id }, { actions: [action] })).events;
  const lastFailure = async (tenant: Tenant) => (await audits(tenant, "login.failure")).at(0);
  const mock = idp === undefined ? undefined : idp.idp;

  describe("HTTP-Redirect binding parsing (review item 1)", () => {
    it("refuses encoded binding keys, duplicates and two messages", () => {
      const message = encodeURIComponent(
        deflateRawSync(Buffer.from("<x/>", "utf8")).toString("base64"),
      );
      const reason = (query: string) => {
        try {
          parseRedirectBinding(query);
          return "accepted";
        } catch (error) {
          return error instanceof RedirectBindingError ? error.reason : "other";
        }
      };
      expect(reason(`SAML%52equest=${message}&SAMLResponse=${message}`)).toBe("encoded_key");
      expect(reason(`SAMLRequest=${message}&SAMLRequest=${message}`)).toBe("duplicate_key");
      expect(reason(`SAMLRequest=${message}&SAMLResponse=${message}`)).toBe("message_count");
      expect(reason(`SAMLRequest=${message}&SigAlg=x`)).toBe("signature_incomplete");
      expect(reason(`other=1&SAMLRequest=${message}`)).toBe("accepted");
    });

    it("refuses the signature-bypass probe: a forged SAML%52equest next to a signed message", async () => {
      const w = await world("hard-probe");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "freja");
      const { driver } = await signedIn(w, "freja-frida");
      const genuine = await mock!.saml("freja").initiateLogout(spEntityId(ts!, w.tenant, method), {
        nameId: "freja-nameid-0000000000000000",
      });
      const forged = encodeURIComponent(
        deflateRawSync(
          Buffer.from(
            `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_forged" Version="2.0" IssueInstant="${new Date().toISOString()}" Destination="${spEntityId(ts!, w.tenant, method)}/slo"><saml:Issuer>${mock!.saml("freja").entityId}</saml:Issuer><saml:NameID>freja-nameid-2a7c9e4b6d1f3058</saml:NameID></samlp:LogoutRequest>`,
            "utf8",
          ),
        ).toString("base64"),
      );
      // The genuine signed token renamed to SAMLResponse, the forged one under an encoded key.
      const probe = genuine
        .replace("?SAMLRequest=", `?SAML%52equest=${forged}&SAMLResponse=`)
        .replace(/SAMLResponse=/, "SAMLResponse=");
      const response = await driver.browser.request(probe);
      expect(response.status).toBe(400);
      const duplicate = genuine.replace("?SAMLRequest=", `?SAMLRequest=${forged}&SAMLRequest=`);
      expect((await driver.browser.request(duplicate)).status).toBe(400);
      expect(await sessionAlive(w, driver)).toBe(true);
    });
  });

  describe("IdP-initiated LogoutRequest (item 2)", () => {
    it("requires the SP's SLO URL as Destination and a recent IssueInstant, and accepts it once", async () => {
      vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
      const w = await world("hard-logout");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "freja");
      const entity = spEntityId(ts!, w.tenant, method);
      const freja = mock!.saml("freja");
      const { driver } = await signedIn(w, "freja-frida");
      const subject = { nameId: "freja-nameid-2a7c9e4b6d1f3058" };

      const elsewhere = await freja.initiateLogout(entity, subject, {
        destination: `${entity}/elsewhere`,
      });
      expect((await driver.browser.request(elsewhere)).status).toBe(400);
      const dtd = await freja.initiateLogout(entity, subject, { dtd: true });
      expect((await driver.browser.request(dtd)).status).toBe(400);
      const old = await freja.initiateLogout(entity, subject);
      vi.setSystemTime(Date.now() + 10 * 60_000);
      expect((await driver.browser.request(old)).status).toBe(400);
      vi.useRealTimers();
      expect(await sessionAlive(w, driver)).toBe(true);

      // Another person's NameID ends nothing.
      const other = await freja.initiateLogout(entity, { nameId: "freja-nameid-8e1b3d5f7a9c2046" });
      expect((await driver.browser.request(other)).status).toBe(303);
      expect((await audits(w.tenant, "session.logout"))[0]?.details).toMatchObject({
        initiator: "idp",
        sessions: 0,
      });
      expect(await sessionAlive(w, driver)).toBe(true);

      const valid = await freja.initiateLogout(entity, subject);
      expect((await driver.browser.request(valid)).status).toBe(303);
      expect(await sessionAlive(w, driver)).toBe(false);
      // The same signed LogoutRequest again: refused (replay cache).
      expect((await driver.browser.request(valid)).status).toBe(400);
    });

    it("answers a POST LogoutRequest over POST when the IdP has no HTTP-Redirect SLO (item 11)", async () => {
      const w = await world("hard-slo-post");
      const freja = mock!.saml("freja");
      freja.setSloBindings(["post"]);
      try {
        const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "freja");
        const entity = spEntityId(ts!, w.tenant, method);
        const { driver, tokens } = await signedIn(w, "freja-frida");
        const form = await freja.initiateLogoutPost(entity, {
          nameId: "freja-nameid-2a7c9e4b6d1f3058",
        });
        const landing = await driver.post(form);
        expect(landing.kind).toBe("other");
        if (landing.kind === "other")
          expect(landing.body).toContain('data-testid="idp-logged-out"');
        expect(freja.logoutResponses().at(-1)).toMatchObject({
          binding: "post",
          status: "urn:oasis:names:tc:SAML:2.0:status:Success",
        });
        expect(await sessionAlive(w, driver)).toBe(false);
        void tokens;

        // SP-initiated over POST: Portvakt's /logout page posts the LogoutRequest, the IdP
        // answers over POST, and the browser ends at the application.
        const second = await signedIn(w, "freja-frida");
        const url = client.buildEndSessionUrl(w.config, {
          id_token_hint: second.tokens.id_token!,
          post_logout_redirect_uri: POST_LOGOUT,
        });
        const html = await (await second.driver.browser.request(url.href)).text();
        const action = /<form id="op\.logoutForm" method="post" action="([^"]+)">/.exec(html)![1]!;
        const xsrf = /name="xsrf" value="([^"]+)"/.exec(html)![1]!;
        const end = await second.driver.follow(new URL(action, url).href, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ xsrf, logout: "yes" }).toString(),
        });
        expect(end.kind).toBe("app");
        expect(freja.logoutRequests().at(-1)).toMatchObject({ binding: "post" });
        expect(freja.logoutResponses().length).toBeGreaterThan(0);
      } finally {
        freja.setSloBindings(["redirect", "post"]);
      }
    });
  });

  describe("metadata (items 4, 5, 14)", () => {
    it("fails closed once validUntil has passed or the entity left a signed aggregate", async () => {
      vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
      const w = await world("hard-expired");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      vi.setSystemTime(Date.now() + 8 * 24 * 3600 * 1000);
      const expired = await signIn(w, "saml-sven");
      expectError(expired.landing, "upstream_unavailable");
      vi.useRealTimers();

      const removed = await world("hard-removed");
      const method = await createSamlLoginMethod(ts!, idp!, removed.tenant, "bankid");
      const bankid = mock!.saml("bankid");
      bankid.setMetadataMode("without-entity");
      try {
        const outcome = await ts!.portvakt.federation.saml.refreshMetadata(
          removed.tenant.id,
          method.id,
          {
            idpEntityId: method.saml.idpEntityId,
            metadataUrl: method.saml.metadataUrl,
            metadataXml: null,
            signingCertificate: method.saml.metadataSigningCertificate,
          },
        );
        expect(outcome).toEqual({ ok: false, reason: "entity_not_found" });
      } finally {
        bankid.setMetadataMode("signed");
      }
      const cache = await repos.saml.metadataCache(removed.tenant.id, method.id);
      expect(cache).toMatchObject({ metadata: null, error: "entity_not_found" });
      expectError((await signIn(removed, "saml-sven")).landing, "upstream_unavailable");
    });

    it("caps the age of cached metadata without validUntil", async () => {
      const w = await world("hard-maxage");
      const xml = (await (await fetch(mock!.saml("bankid").metadataUrl)).text())
        .replace(/ validUntil="[^"]+"/, "")
        .replace(/<(ds:)?Signature[\s\S]*<\/(ds:)?Signature>/, "");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        saml: { metadataUrl: null, metadataXml: xml, metadataSigningCertificate: null },
      });
      expect((await signedIn(w, "saml-sven")).tokens.claims()).toMatchObject({ acr: LOA3 });
      vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
      vi.setSystemTime(Date.now() + 8 * 24 * 3600 * 1000);
      expectError((await signIn(w, "saml-sven")).landing, "upstream_unavailable");
    });

    it("refuses unsigned metadata URLs and logo-less methods in production; audits the opt-out", async () => {
      const production = new SamlLoginMethodAdmin({
        repos,
        saml: ts!.portvakt.federation.saml,
        production: true,
      });
      const tenant = await createTenant(repos, "hard-prod");
      const bankid = mock!.saml("bankid");
      const base = {
        kind: "citizen" as const,
        displayName: "Production BankID",
        assertedAcr: LOA3,
        sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true },
      };
      const issues = async (saml: Record<string, unknown>) => {
        const error = await production
          .create(tenant.id, {
            ...base,
            saml: {
              idpEntityId: bankid.entityId,
              metadataUrl: bankid.metadataUrl,
              requestedLoa: [LOA3],
              subjectSource: "personalIdentityNumber",
              ...saml,
            },
          })
          .catch((caught: unknown) => caught);
        expect(error).toBeInstanceOf(ValidationError);
        return (error as ValidationError).issues;
      };
      expect(await issues({})).toEqual(
        expect.arrayContaining([
          "saml.metadataSigningCertificate: required for a metadata URL in production (or set allowUnsignedMetadata)",
          "saml.uiInfo.logos: the Deployment Profile requires at least one logo",
        ]),
      );
      const optedOut = await issues({
        allowUnsignedMetadata: true,
        uiInfo: { logos: [{ url: "https://cdn.example/logo.svg", width: 64, height: 64 }] },
      });
      expect(optedOut.join()).not.toContain("metadataSigningCertificate");
      expect(optedOut.join()).not.toContain("logos");

      // Outside production the opt-out saves, is audited and shows as a warning.
      const w = await world("hard-unsigned");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        saml: { metadataSigningCertificate: null, allowUnsignedMetadata: true },
      });
      expect(await audits(w.tenant, "login_method.saml_unsigned_metadata_allowed")).toHaveLength(1);
      expect(await ts!.portvakt.samlAdmin.warningsFor(method)).toEqual(
        expect.arrayContaining([
          "saml.allowUnsignedMetadata: the IdP metadata is not signature-checked",
        ]),
      );
    });

    it("never stores metadata fetched for a source that changed meanwhile", async () => {
      const w = await world("hard-race");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const metadata = (await repos.saml.metadataCache(w.tenant.id, method.id)).metadata!;
      const stored = await repos.saml.storeMetadata(w.tenant.id, method.id, metadata, {
        url: method.saml.metadataUrl,
        xml: null,
        signingCertificate: mock!.saml("freja").metadataSigningCertificate,
        entityId: method.saml.idpEntityId,
      });
      expect(stored).toBe(false);
    });

    it("refuses a metadata URL on a private address (SSRF guard, item 3)", async () => {
      const tenant = await createTenant(repos, "hard-ssrf");
      const error = await createSamlLoginMethod(ts!, idp!, tenant, "bankid", {
        saml: { metadataUrl: "http://10.255.255.1/metadata" },
      }).catch((caught: unknown) => caught);
      expect(error).toBeInstanceOf(ValidationError);
      expect((error as ValidationError).issues).toEqual(["saml.metadata: fetch_refused"]);
    });
  });

  describe("PrincipalSelection and the POST page (item 6)", () => {
    it("renders the HTTP-POST page once", async () => {
      const w = await world("hard-post-once");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        saml: { authnRequestBinding: "post" },
      });
      const driver = new FlowDriver(ts!, idp!);
      const request = await authorizationRequest(w.config, w.redirectUri);
      const first = await driver.browser.request(request.url.href);
      const interaction = new URL(first.headers.get("location")!, request.url).href;
      const toPost = (await driver.browser.request(interaction)).headers.get("location")!;
      expect(toPost).toContain("/post?RelayState=");
      expect((await driver.browser.request(toPost)).status).toBe(200);
      expect((await driver.browser.request(toPost)).status).toBe(404);
    });

    it("sends PrincipalSelection only where the IdP advertises it, and never without HTTP-POST", async () => {
      const w = await world("hard-principal");
      const xml = (await (await fetch(mock!.saml("bankid").metadataUrl)).text()).replace(
        /<(ds:)?Signature[\s\S]*<\/(ds:)?Signature>/,
        "",
      );
      const noPost = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        displayName: "No POST",
        saml: {
          metadataUrl: null,
          metadataSigningCertificate: null,
          metadataXml: xml.replace(
            /<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"[^>]*\/>/,
            "",
          ),
        },
      });
      const notAdvertised = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        displayName: "No PrincipalSelection",
        saml: {
          metadataUrl: null,
          metadataSigningCertificate: null,
          metadataXml: xml.replace(
            /<psc:RequestedPrincipalSelection>[\s\S]*<\/psc:RequestedPrincipalSelection>/,
            "",
          ),
        },
      });
      const driver = new FlowDriver(ts!, idp!);
      const request = await authorizationRequest(w.config, w.redirectUri);
      await driver.follow(request.url.href);
      const uid = new URL(
        driver.visited.find((url) => url.includes("/interaction/"))!,
      ).pathname.split("/")[4]!;
      const tp = (await ts!.portvakt.registry.get(w.tenant.slug))!;
      const interaction = {
        uid,
        prompt: "login",
        reasons: [],
        clientId: w.app.application.clientId,
        sessionAccountId: undefined,
        sessionUid: undefined,
        sessionAcr: undefined,
        stepUp: false,
        params: {
          acrValues: undefined,
          loginHint: undefined,
          uiLocales: undefined,
          maxAge: undefined,
        },
      };
      await expect(
        ts!.portvakt.federation.begin(tp, interaction, noPost, { principalPin: "191212121212" }),
      ).rejects.toThrow(/HTTP-POST/);
      const url = await ts!.portvakt.federation.begin(tp, interaction, notAdvertised, {
        principalPin: "191212121212",
      });
      // Not advertised: no PrincipalSelection, so the request may use HTTP-Redirect…
      expect(url.startsWith(`${mock!.saml("bankid").entityId}/sso?SAMLRequest=`)).toBe(true);
      const page = await driver.follow(url);
      expect(mock!.saml("bankid").requests().at(-1)!.principalPin).toBeUndefined();
      // …but the person must still be the expected one.
      expectError(await driver.persona(page, "saml-samuel"), "account_not_allowed");
    });
  });

  describe("algorithms (items 7, 8)", () => {
    it("accepts ECDSA-signed responses, assertions, metadata and logout messages", async () => {
      const w = await world("hard-ecdsa");
      const ecdsa = mock!.saml("ecdsa");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "freja", {
        saml: {
          idpEntityId: ecdsa.entityId,
          metadataUrl: ecdsa.metadataUrl,
          metadataSigningCertificate: ecdsa.metadataSigningCertificate,
        },
      });
      const { driver, tokens } = await signedIn(w, "freja-frida");
      expect(tokens.claims()).toMatchObject({ acr: LOA3, pin: "198507099805" });
      const url = await ecdsa.initiateLogout(spEntityId(ts!, w.tenant, method), {
        nameId: "freja-nameid-2a7c9e4b6d1f3058",
      });
      expect((await driver.browser.request(url)).status).toBe(303);
      expect(await sessionAlive(w, driver)).toBe(false);
      // An RSA algorithm never verifies with an EC key (and the reverse).
      expect(
        verifyWithAlgorithm(
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
          Buffer.from("x"),
          ecdsa.signingCertificate,
          Buffer.alloc(64),
        ),
      ).toBe(false);
    });

    const cases: readonly { switch: string; ok: boolean; detail?: string; requireGcm?: boolean }[] =
      [
        { switch: "sha1-signature", ok: false, detail: "signature_invalid" },
        { switch: "sha1-digest", ok: false, detail: "signature_invalid" },
        { switch: "rsa-1_5", ok: false, detail: "unsupported_encryption" },
        { switch: "3des", ok: false, detail: "unsupported_encryption" },
        { switch: "aes-cbc", ok: false, detail: "unsupported_encryption", requireGcm: true },
        { switch: "oaep-sha256", ok: true },
        { switch: "aes-cbc", ok: true },
        { switch: "aes192-cbc", ok: true },
        { switch: "sibling-key", ok: true },
      ];
    for (const testCase of cases) {
      it(`${testCase.ok ? "accepts" : "refuses"} "${testCase.switch}"${testCase.requireGcm === true ? " with requireGcm" : ""}`, async () => {
        const w = await world(`hard-${testCase.switch.slice(0, 8).replace(/[^a-z0-9-]/g, "-")}`);
        await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
          saml: { requireGcm: testCase.requireGcm ?? false },
        });
        const { landing, request } = await signIn(w, "saml-sven", { switch: testCase.switch });
        if (testCase.ok) {
          expect((await redeem(w.config, request, landing)).claims()).toMatchObject({
            pin: "191212121212",
          });
        } else {
          expectError(landing, "upstream_response_invalid");
          expect((await lastFailure(w.tenant))?.details).toMatchObject({ detail: testCase.detail });
        }
      });
    }

    it("advertises exactly the supported algorithms in SP metadata", async () => {
      const w = await world("hard-advertise");
      const gcm = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        saml: {
          requireGcm: true,
          uiInfo: {
            displayName: { sv: "E-tjänst", en: "E-service" },
            description: { sv: "Logga in i e-tjänsten" },
            logos: [{ url: "https://cdn.example/logo.svg", width: 120, height: 60 }],
          },
        },
      });
      const xml = await (await fetch(`${spEntityId(ts!, w.tenant, gcm)}/metadata`)).text();
      expect(xml).toContain("http://www.w3.org/2009/xmlenc11#aes256-gcm");
      expect(xml).not.toContain("aes128-cbc");
      expect(xml).not.toContain("tripledes");
      expect(xml).not.toContain("rsa-1_5");
      expect(xml).toContain("http://www.w3.org/2009/xmlenc11#mgf1sha256");
      expect(xml).toContain("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
      expect(xml).not.toContain("#rsa-sha1");
      // mdui:UIInfo (item 10).
      expect(xml).toContain('<mdui:DisplayName xml:lang="sv">E-tjänst</mdui:DisplayName>');
      expect(xml).toContain(
        '<mdui:Description xml:lang="sv">Logga in i e-tjänsten</mdui:Description>',
      );
      expect(xml).toContain(
        '<mdui:Logo width="120" height="60">https://cdn.example/logo.svg</mdui:Logo>',
      );
    });
  });

  describe("claims and identities (items 9, 12, 13, 15, 17)", () => {
    it("issues hsa_id and org_affiliation with scope hsa to an application allowed it", async () => {
      const w = await world("hard-hsa", ["hsa"]);
      await createSamlLoginMethod(ts!, idp!, w.tenant, "siths");
      const { tokens } = await signedIn(w, "siths-sara", { params: { scope: "openid hsa" } });
      expect(tokens.claims()).toMatchObject({
        hsa_id: "SE2321000016-1003",
        org_affiliation: ["sara@2321000016"],
      });
      const access = JSON.parse(
        Buffer.from(tokens.access_token.split(".")[1]!, "base64url").toString("utf8"),
      ) as Record<string, unknown>;
      expect(access).not.toHaveProperty("hsa_id");

      const other = await world("hard-hsa-none");
      await createSamlLoginMethod(ts!, idp!, other.tenant, "siths");
      const refused = await signIn(other, "siths-sara", { params: { scope: "openid hsa" } });
      expect(refused.landing.kind).toBe("app");
      if (refused.landing.kind === "app") {
        expect(refused.landing.url.searchParams.get("error")).toBe("invalid_scope");
      }
    });

    it("accepts orgAffiliation scopes configured on the login method", async () => {
      const w = await world("hard-scopes", ["hsa"]);
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "siths", {
        saml: { orgAffiliationScopes: ["9999999999"] },
      });
      await signedIn(w, "siths-lars", { params: { scope: "openid hsa" } });
      const identity = await repos.persons.findIdentity(
        w.tenant.id,
        method.id,
        "SE2321000016-2044",
      );
      expect(identity?.attributes.groups).toEqual(["lars@2321000016", "lars@9999999999"]);
    });

    it("refuses over-long values and tolerates hostile attribute names", async () => {
      const w = await world("hard-values");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const long = await signIn(w, "saml-sven", { switch: "long-nameid" });
      expectError(long.landing, "upstream_response_invalid");
      expect((await lastFailure(w.tenant))?.details).toMatchObject({ detail: "value_too_long" });
      const hostile = await signedIn(w, "saml-sven", { switch: "hostile-attributes" });
      expect(hostile.tokens.claims()).toMatchObject({ pin: "191212121212" });
    });

    it("keeps NameID and SessionIndex out of every stored payload in the clear", async () => {
      const w = await world("hard-nameid");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "freja");
      await signedIn(w, "freja-frida");
      const rows = await db.query<{ payload: string }>(
        `SELECT payload::text AS payload FROM oidc_payloads WHERE tenant_id = $1
         UNION ALL SELECT coalesce(completion::text, '') FROM federation_states WHERE tenant_id = $1`,
        [w.tenant.id],
      );
      expect(rows.length).toBeGreaterThan(0);
      for (const row of rows) expect(row.payload).not.toContain("freja-nameid-2a7c9e4b6d1f3058");
    });

    it("re-keys pin-index subjects on rewrap, only for pin-subject SAML methods", async () => {
      const w = await world("hard-rewrap");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const first = await signedIn(w, "saml-sven");
      // An identity of another method whose subject merely looks like a pin index.
      const prid = await createSamlLoginMethod(ts!, idp!, w.tenant, "freja", {
        displayName: "prid",
        assertedAcr: "http://id.swedenconnect.se/loa/1.0/loa3-nonresident",
        saml: {
          requestedLoa: ["http://id.swedenconnect.se/loa/1.0/loa3-nonresident"],
          subjectSource: "prid",
        },
      });
      await repos.persons.upsertFromLogin(w.tenant.id, {
        loginMethodId: prid.id,
        subject: "pin-index:not-a-pin-subject",
        acr: prid.assertedAcr,
        attributes: {},
        pin: "198507099805",
      });
      const newKey = Buffer.from("test-master-key-rotated-32-bytes", "utf8");
      const rotated = createKeyRing({ current: newKey, previous: [testMasterKeys.current] });
      await rewrapAllSecrets(db, rotated);
      const subjects = await db.query<{ login_method_id: string; subject: string }>(
        "SELECT login_method_id, subject FROM identities WHERE tenant_id = $1",
        [w.tenant.id],
      );
      expect(subjects.find((row) => row.login_method_id === method.id)?.subject).toBe(
        `pin-index:${rotated.index.compute("pin", "191212121212").index}`,
      );
      expect(subjects.find((row) => row.login_method_id === prid.id)?.subject).toBe(
        "pin-index:not-a-pin-subject",
      );
      const newOnly = createRepositories(db, createKeyRing({ current: newKey, previous: [] }));
      const relogin = await newOnly.persons.upsertFromLogin(w.tenant.id, {
        loginMethodId: method.id,
        subject: "ignored",
        subjectFromPin: true,
        acr: LOA3,
        attributes: {},
        pin: "191212121212",
      });
      expect(relogin.person.id).toBe(first.tokens.claims()!.sub);
      // Back to the test master key for the rest of the file.
      await rewrapAllSecrets(
        db,
        createKeyRing({ current: testMasterKeys.current, previous: [newKey] }),
      );
    });
  });

  describe("one check each (item 18)", () => {
    const cases: readonly { switch: string; code: string; detail?: string }[] = [
      {
        switch: "wrong-subject-in-response-to",
        code: "state_invalid",
        detail: "in_response_to_mismatch",
      },
      {
        switch: "wrong-recipient",
        code: "upstream_response_invalid",
        detail: "recipient_mismatch",
      },
      {
        switch: "wrong-destination",
        code: "upstream_response_invalid",
        detail: "destination_mismatch",
      },
      {
        switch: "no-destination",
        code: "upstream_response_invalid",
        detail: "destination_missing",
      },
      {
        switch: "old-issue-instant",
        code: "upstream_response_invalid",
        detail: "assertion_expired",
      },
      {
        switch: "wrong-assertion-issuer",
        code: "upstream_response_invalid",
        detail: "issuer_mismatch",
      },
      { switch: "unsolicited", code: "state_invalid", detail: "in_response_to_mismatch" },
      {
        switch: "forged-keyinfo",
        code: "upstream_response_invalid",
        detail: "response_not_signed",
      },
      { switch: "dtd", code: "upstream_response_invalid", detail: "dtd_not_allowed" },
    ];
    for (const testCase of cases) {
      it(`refuses "${testCase.switch}"`, async () => {
        const w = await world(`one-${testCase.switch.slice(0, 10)}`);
        await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
        const { landing, driver } = await signIn(w, "saml-sven", { switch: testCase.switch });
        expectError(landing, testCase.code);
        expect((await lastFailure(w.tenant))?.details).toMatchObject({
          reason: testCase.code,
          ...(testCase.detail === undefined ? {} : { detail: testCase.detail }),
        });
        expect(await sessionAlive(w, driver)).toBe(false);
      });
    }

    it("refuses a forged KeyInfo certificate on the assertion as well", async () => {
      const w = await world("one-keyinfo");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        saml: { requireSignedResponse: false },
      });
      const { landing } = await signIn(w, "saml-sven", { switch: "forged-keyinfo" });
      expectError(landing, "upstream_response_invalid");
      expect((await lastFailure(w.tenant))?.details).toMatchObject({ detail: "signature_invalid" });
    });

    it("reads a NameID with a comment inside as the whole value", async () => {
      const w = await world("one-comment");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "freja", {
        saml: { subjectSource: "nameId" },
      });
      await signedIn(w, "freja-frida", { switch: "comment-in-nameid" });
      expect(
        await repos.persons.findIdentity(w.tenant.id, method.id, "freja-nameid-2a7c9e4b6d1f3058"),
      ).not.toBeNull();
    });

    it("accepts one of several concurrent posts of one response", async () => {
      const w = await world("one-concurrent");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const driver = new FlowDriver(ts!, idp!);
      driver.holdSamlResponses = true;
      const held = await signIn(w, "saml-sven", { driver });
      if (held.landing.kind !== "auto_post") throw new Error("expected a held response");
      const form = held.landing.form;
      const statuses = await Promise.all(
        Array.from({ length: 5 }, () =>
          fetch(form.action, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams(form.fields).toString(),
            redirect: "manual",
          }).then((response) => response.headers.get("location") ?? ""),
        ),
      );
      expect(
        statuses.filter((location) => location.includes("/federation/complete?ref=")),
      ).toHaveLength(1);
      expect(await audits(w.tenant, "login.success")).toHaveLength(0);
    });

    it("cannot attach SAML settings to an OIDC login method (migration constraint)", async () => {
      const tenant = await createTenant(repos, "one-fk");
      const oidc = await repos.loginMethods.create(tenant.id, {
        kind: "employee",
        displayName: "OIDC",
        issuer: "https://idp.example/",
        clientId: "c",
        claimMapping: { subject: "sub" },
        assertedAcr: "urn:x",
        sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: true },
      });
      await expect(
        db.query(
          `INSERT INTO login_method_saml (tenant_id, login_method_id, idp_entity_id, metadata_xml,
             requested_loa, subject_source, attribute_mapping)
           VALUES ($1, $2, 'https://idp.example/saml', '<x/>', ARRAY['urn:x'], 'nameId', '{}')`,
          [tenant.id, oidc.id],
        ),
      ).rejects.toThrow(/foreign key/);
    });
  });
  describe("focused re-review (F1, F3)", () => {
    it("refuses AES-CBC when the Response signature is not required; GCM still works", async () => {
      const w = await world("rr-cbc");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid", {
        saml: { requireSignedResponse: false },
      });
      const metadata = await (await fetch(`${spEntityId(ts!, w.tenant, method)}/metadata`)).text();
      expect(metadata).toContain("aes256-gcm");
      expect(metadata).not.toMatch(/xmlenc#aes(128|192|256)-cbc/);
      const cbc = await signIn(w, "saml-sven", { switch: "aes-cbc" });
      expectError(cbc.landing, "upstream_response_invalid");
      expect((await lastFailure(w.tenant))?.details).toMatchObject({
        detail: "unsupported_encryption",
      });
      const gcm = await signIn(w, "saml-sven");
      expect((await redeem(w.config, gcm.request, gcm.landing)).claims()).toMatchObject({
        pin: "191212121212",
      });
    });

    const bomb = (root: string, count: number) =>
      Buffer.from(
        `<${root} xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x">${"<x/>".repeat(count)}</${root}>`,
      ).toString("base64");

    it("answers an oversized logout message on /slo fast without parsing it", async () => {
      const w = await world("rr-slo");
      const method = await createSamlLoginMethod(ts!, idp!, w.tenant, "freja");
      const slo = `${spEntityId(ts!, w.tenant, method)}/slo`;
      const started = performance.now();
      const post = await fetch(slo, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ SAMLRequest: bomb("samlp:LogoutRequest", 170_000) }).toString(),
        redirect: "manual",
      });
      const get = await fetch(
        `${slo}?SAMLRequest=${encodeURIComponent(
          deflateRawSync(Buffer.from(bomb("samlp:LogoutRequest", 170_000), "base64")).toString(
            "base64",
          ),
        )}`,
        { redirect: "manual" },
      );
      expect(performance.now() - started).toBeLessThan(1000);
      expect(post.status).toBe(400);
      expect(get.status).toBe(400);
    });

    it("refuses an element flood on the ACS fast, as an invalid response of a real interaction", async () => {
      const w = await world("rr-acs");
      await createSamlLoginMethod(ts!, idp!, w.tenant, "bankid");
      const driver = new FlowDriver(ts!, idp!);
      driver.holdSamlResponses = true;
      const held = await signIn(w, "saml-sven", { driver });
      if (held.landing.kind !== "auto_post") throw new Error("expected a held response");
      const started = performance.now();
      const response = await fetch(held.landing.form.action, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          ...held.landing.form.fields,
          SAMLResponse: bomb("samlp:Response", 20_001),
        }).toString(),
        redirect: "manual",
      });
      expect(performance.now() - started).toBeLessThan(1000);
      expect(response.status).toBe(303);
      expect((await lastFailure(w.tenant))?.details).toMatchObject({
        reason: "upstream_response_invalid",
        detail: "too_many_elements",
      });
    });
  });
});
