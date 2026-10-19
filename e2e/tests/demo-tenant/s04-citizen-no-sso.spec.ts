import { expect, test } from "../../src/fixtures";
import { METHODS } from "../../src/env";
import { DemoPage } from "../../src/pages/demo";
import { LoginUi } from "../../src/pages/login-ui";
import { countUpstreamVisits, MockIdp } from "../../src/pages/mock-idp";

/**
 * Scenario 4: a citizen signs in with mock BankID over SAML (Swedish eID Framework attributes);
 * that login method has `allowSso = false` (seeded), so moving from Service A to Service B needs
 * a new sign-in: the login UI again and the IdP's page again (ForceAuthn).
 */
test("Scenario 4: a citizen with mock BankID over SAML (allowSso = false) signs in again moving from Service A to B", async ({
  page,
  platformAdmin,
  demoTenant,
}) => {
  await platformAdmin.api.setApplicationEnabled(demoTenant.id, "service-b", true);
  const a = new DemoPage(page, "A");
  const b = new DemoPage(page, "B");
  const login = new LoginUi(page);
  const idp = new MockIdp(page);

  await a.startSignIn();
  await login.chooseMethod(METHODS.bankidSaml);
  await idp.choosePersona("saml/bankid", "saml-samuel");
  await a.expectSignedIn();
  await expect(a.field("user-name")).toHaveText("Samuel Samordning");
  await expect(a.field("user-idp-kind")).toHaveText("Medborgare");
  await expect(a.field("user-acr")).toHaveText("Tillitsnivå 3");

  const upstream = countUpstreamVisits(page);
  await b.startSignIn();
  // No SSO: Portvakt asks again which method, and the IdP authenticates again.
  await login.chooseMethod(METHODS.bankidSaml);
  await idp.choosePersona("saml/bankid", "saml-samuel");
  await b.expectSignedIn();
  expect(upstream.count(), "a new upstream login for Service B").toBeGreaterThan(0);
  await expect(b.field("user-name")).toHaveText("Samuel Samordning");

  // Service A keeps its own session.
  await a.goto();
  await expect(a.signedIn).toBeVisible();
});
