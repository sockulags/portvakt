import { expect, test } from "../../src/fixtures";
import { JAVA, METHODS } from "../../src/env";
import { DemoPage } from "../../src/pages/demo";
import { LoginUi } from "../../src/pages/login-ui";
import { countUpstreamVisits, MockIdp } from "../../src/pages/mock-idp";

/**
 * Scenario 3: Service B is attached to the demo tenant but not enabled: sign-in is refused with
 * a friendly error page. The platform administrator enables it in the portal; the same employee
 * then reaches Service B without a new upstream login (SSO): no mock IdP page, no login UI.
 * Java variant: SSO from Service A into Tjänst C.
 */
test("Scenario 3: Service B is refused until a platform admin enables it, then the employee reaches it by SSO", async ({
  page,
  platformAdmin,
  demoTenant,
}) => {
  // The seeded state (attached, disabled), also when the suite runs again against one stack.
  await platformAdmin.api.setApplicationEnabled(demoTenant.id, "service-b", false);

  const a = new DemoPage(page, "A");
  const b = new DemoPage(page, "B");
  await a.startSignIn();
  await new LoginUi(page).chooseMethod(METHODS.entra);
  await new MockIdp(page).choosePersona("entra", "e2e-emma");
  await a.expectSignedIn();

  await b.startSignIn();
  const login = new LoginUi(page);
  await expect(login.errorView).toBeVisible();
  await expect(page.getByTestId("error-code")).toHaveAttribute("data-error", "app_unavailable");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();

  // The platform administrator enables Service B for the tenant in the portal.
  const portal = platformAdmin.portal;
  await portal.open("applications", { tenantId: demoTenant.id });
  const toggle = platformAdmin.page.getByTestId("application-toggle-service-b");
  await expect(toggle).not.toBeChecked();
  await portal.toggle("application-toggle-service-b");
  await expect(toggle).toBeChecked();

  // Now the same browser reaches Service B from its Portvakt session, without any upstream page.
  const upstream = countUpstreamVisits(page);
  await b.startSignIn();
  await b.expectSignedIn();
  expect(upstream.count(), "no mock IdP page during the SSO").toBe(0);
  await expect(login.view).toHaveCount(0);
  await expect(b.field("user-name")).toHaveText("Emma Ek");
  await b.expectRoles(["handlaggare"]);
});

test("Scenario 3 (Java): the employee signed in to Service A reaches Tjänst C by SSO", async ({
  page,
}) => {
  test.skip(!JAVA, "the Java demo is not running (--no-java)");
  const a = new DemoPage(page, "A");
  const c = new DemoPage(page, "C");
  await a.startSignIn();
  await new LoginUi(page).chooseMethod(METHODS.entra);
  await new MockIdp(page).choosePersona("entra", "e2e-jonas");
  await a.expectSignedIn();

  const upstream = countUpstreamVisits(page);
  await c.startSignIn();
  await c.expectSignedIn();
  expect(upstream.count(), "no mock IdP page during the SSO").toBe(0);
  await expect(new LoginUi(page).view).toHaveCount(0);
  await expect(c.field("user-name")).toHaveText("Jonas Berg");
  await c.expectRoles(["handlaggare"]);
});
