import { expectAccessible } from "../../src/a11y";
import { expect, test } from "../../src/fixtures";
import { METHODS, RUN_ID, URLS } from "../../src/env";

/**
 * Accessibility gate (WCAG 2.1 AA, axe-core) for the admin portal: Översikt (with a warning, so
 * the warning list is checked too), the Inloggningsmetoder list, and the edit forms of an OIDC
 * and a SAML login method (the demo tenant's, read only).
 */
test("Accessibility: admin Översikt, Inloggningsmetoder list and edit forms", async ({
  platformAdmin,
  demoTenant,
}, testInfo) => {
  const { page, portal, api } = platformAdmin;
  const tenant = await api.createTenant(`e2e-a11y-${RUN_ID}`, `Tillgänglighet ${RUN_ID}`);
  await api.createLoginMethod(tenant.id, {
    protocol: "oidc",
    kind: "employee",
    displayName: `Snart utgången ${RUN_ID}`,
    issuer: `${URLS.mockIdp}/entra`,
    clientId: "portvakt-dev",
    clientSecret: "dev-only-entra-client-secret",
    scopes: ["openid", "profile"],
    claimMapping: { subject: "oid", name: "name" },
    assertedAcr: "urn:portvakt:acr:employee",
    secretExpiresAt: new Date(Date.now() + 5 * 86_400_000).toISOString(),
    sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true },
  });

  await portal.open("overview", { tenantId: tenant.id });
  await expect(page.getByTestId("warning-item")).toHaveCount(1);
  await expectAccessible(page, testInfo, "admin Översikt");

  await portal.open("login-methods", { tenantId: demoTenant.id });
  await expect(page.getByRole("button", { name: METHODS.entra, exact: true })).toBeVisible();
  await expectAccessible(page, testInfo, "admin Inloggningsmetoder list");

  for (const method of [METHODS.entra, METHODS.bankidSaml]) {
    const id = await api.loginMethodId(demoTenant.id, method);
    await portal.open("login-methods", { id, tenantId: demoTenant.id });
    await expect(page.getByTestId("login-method-form")).toBeVisible();
    await expect(page.getByTestId("field-displayName")).toHaveValue(method);
    await expectAccessible(page, testInfo, `admin login method form (${method})`);
  }
});
