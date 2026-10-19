import type { AdminApi, Tenant } from "../../src/admin-api";
import { expect, tenantAdmin, test } from "../../src/fixtures";
import { DEMO_TENANT, METHODS, RUN_ID, SECRETS, URLS } from "../../src/env";
import { DemoPage } from "../../src/pages/demo";
import { LoginUi } from "../../src/pages/login-ui";
import { MockIdp } from "../../src/pages/mock-idp";
import { startAuthorization } from "../../src/rp";

/**
 * Scenario 8: isolation. Tenant Y (made here through the admin API, with its own Mock Entra
 * login method) next to the demo tenant X:
 * - a user signing in to X cannot use Y's login method, also by calling the URLs directly;
 * - an access token for Service A is refused by Service B's API (audience);
 * - the demo tenant's administrator sees no other tenant in the portal, and direct URLs to
 *   another tenant's resources answer "not found".
 */
let tenantY: Tenant;
let methodY: string;

async function setUpTenantY(api: AdminApi): Promise<void> {
  if (tenantY !== undefined) return;
  tenantY = await api.createTenant(`e2e-y-${RUN_ID}`, `Isolering Y ${RUN_ID}`);
  const method = await api.createLoginMethod(tenantY.id, {
    protocol: "oidc",
    kind: "employee",
    displayName: `Y Entra ${RUN_ID}`,
    issuer: `${URLS.mockIdp}/entra`,
    clientId: "portvakt-dev",
    clientSecret: "dev-only-entra-client-secret",
    scopes: ["openid", "profile", "email"],
    claimMapping: { subject: "oid", name: "name", email: "email" },
    assertedAcr: "urn:portvakt:acr:employee",
    homeRealmDomains: ["kommun.example"],
    sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true },
  });
  methodY = method.id;
}

test.beforeEach(async ({ platformAdmin }) => {
  await setUpTenantY(platformAdmin.api);
});

test("Scenario 8: a user signing in to tenant X cannot use a login method of tenant Y", async ({
  page,
}) => {
  const demo = new DemoPage(page, "A");
  const login = new LoginUi(page);
  await demo.startSignIn();
  await login.expectChooser(DEMO_TENANT);
  await expect(login.method(`Y Entra ${RUN_ID}`)).toHaveCount(0);
  const uid = login.interactionUid();

  // The login UI's own API, called from the page (cookies, same origin, CSRF token) with Y's id.
  const attempt = await page.evaluate(
    async ({ uid, methodId }) => {
      const base = `/t/demo/interaction/${uid}`;
      const details = (await (await fetch(`${base}/details`)).json()) as { csrfToken: string };
      const response = await fetch(`${base}/login`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-csrf-token": details.csrfToken },
        body: JSON.stringify({ loginMethodId: methodId }),
      });
      return { status: response.status, body: await response.json() };
    },
    { uid, methodId: methodY },
  );
  expect(attempt).toEqual({ status: 403, body: { error: "login_method_unavailable" } });

  // Y's method has no endpoints below X's issuer.
  const jwks = await page.request.get(
    `${URLS.portvakt}/t/${DEMO_TENANT}/federation/${methodY}/jwks`,
  );
  expect(jwks.status()).toBe(404);
  const callback = await page.goto(
    `${URLS.portvakt}/t/${DEMO_TENANT}/federation/${methodY}/callback?state=forged&code=forged`,
  );
  expect(callback?.status()).toBeGreaterThanOrEqual(400);
  await expect(page.getByTestId("signed-in-view")).toHaveCount(0);

  // The interaction itself still works with X's own method.
  await page.goto(`${URLS.portvakt}/t/${DEMO_TENANT}/interaction/${uid}`);
  await login.chooseMethod(METHODS.entra);
  await new MockIdp(page).choosePersona("entra", "e2e-emma");
  await demo.expectSignedIn();
});

test("Scenario 8: an access token for Service A is refused by Service B's API", async ({
  page,
}) => {
  const flow = await startAuthorization(page, {
    tenant: DEMO_TENANT,
    clientId: "service-a",
    clientSecret: SECRETS.serviceA,
    redirectUri: `${URLS.serviceA}/auth/callback`,
  });
  await new LoginUi(page).chooseMethod(METHODS.entra);
  await new MockIdp(page).choosePersona("entra", "e2e-emma");
  const tokens = await flow.finish();
  expect(tokens.accessClaims.aud).toBe("service-a");

  const headers = { authorization: `Bearer ${tokens.accessToken}`, accept: "application/json" };
  const atA = await page.request.get(`${URLS.serviceA}/api/whoami`, { headers });
  expect(atA.status()).toBe(200);
  const atB = await page.request.get(`${URLS.serviceB}/api/whoami`, { headers });
  expect(atB.status()).toBe(401);
  expect(atB.headers()["www-authenticate"]).toContain('error="invalid_token"');
});

test("Scenario 8: a tenant administrator cannot see other tenants in the admin portal", async ({
  browser,
  platformAdmin,
}) => {
  const system = await platformAdmin.api.tenant("system");
  const admin = await tenantAdmin(browser);
  try {
    const { page, portal, api } = admin;
    await portal.open("overview");
    await expect(page.getByTestId("tenant-name")).toHaveText("Demo kommun");
    await expect(page.getByTestId("tenant-switcher")).toHaveCount(0);
    await expect(
      page.getByRole("navigation").getByText("Organisationer", { exact: true }),
    ).toHaveCount(0);

    // Naming another tenant in the URL changes nothing: the portal stays in the admin's tenant.
    await page.goto(`${URLS.admin}/t/${DEMO_TENANT}/login-methods?tenant=${tenantY.id}`);
    await expect(page.getByTestId("tenant-name")).toHaveText("Demo kommun");
    await expect(page.getByText(`Y Entra ${RUN_ID}`)).toHaveCount(0);

    // Another tenant's login method by URL: not found.
    await page.goto(`${URLS.admin}/t/${DEMO_TENANT}/login-methods/${methodY}`);
    await expect(page.getByTestId("error-state")).toBeVisible();
    await expect(page.getByTestId("login-method-form")).toHaveCount(0);

    // The API behind it: other tenants do not exist for a tenant administrator.
    for (const tenant of [tenantY, system]) {
      expect((await api.raw("GET", `/tenants/${tenant.id}`)).status).toBe(404);
      expect((await api.raw("GET", `/tenants/${tenant.id}/login-methods`)).status).toBe(404);
    }
    expect((await api.raw("GET", `/tenants/${tenantY.id}/login-methods/${methodY}`)).status).toBe(
      404,
    );
    // The tenant list holds only the administrator's own tenant.
    const listed = await api.raw("GET", "/tenants");
    expect(listed.status).toBe(200);
    expect((listed.body as { items: { slug: string }[] }).items.map((item) => item.slug)).toEqual([
      DEMO_TENANT,
    ]);
  } finally {
    await admin.context.close();
  }
});
