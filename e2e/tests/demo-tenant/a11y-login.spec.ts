import { expectAccessible } from "../../src/a11y";
import { expect, test } from "../../src/fixtures";
import { DEMO_TENANT, JAVA, METHODS, URLS } from "../../src/env";
import { DemoPage } from "../../src/pages/demo";
import { LoginUi } from "../../src/pages/login-ui";
import { MockIdp } from "../../src/pages/mock-idp";

/**
 * Accessibility gate (WCAG 2.1 AA, axe-core) for the pages people sign in through: Portvakt's
 * login method chooser, its representation chooser and an error page, and the demo's signed-in
 * page (TypeScript and Java).
 */
test("Accessibility: login method chooser, representation chooser and the demo's signed-in page", async ({
  page,
}, testInfo) => {
  const demo = new DemoPage(page, "A");
  const login = new LoginUi(page);
  await demo.startSignIn();
  await login.expectChooser(DEMO_TENANT);
  await expectAccessible(page, testInfo, "login method chooser");

  await login.chooseMethod(METHODS.bankidOidc);
  await new MockIdp(page).choosePersona("bankid", "sven-medborgare");
  await login.expectRepresentationChooser();
  await expectAccessible(page, testInfo, "representation chooser");

  await login.chooseRepresentation("self");
  await demo.expectSignedIn();
  await expect(demo.field("representation")).toHaveText("Dig själv");
  await expectAccessible(page, testInfo, "demo signed-in page (Tjänst A)");
});

test("Accessibility: the Java demo's signed-in page", async ({ page }, testInfo) => {
  test.skip(!JAVA, "the Java demo is not running (--no-java)");
  const demo = new DemoPage(page, "C");
  await demo.startSignIn();
  await new LoginUi(page).chooseMethod(METHODS.entra);
  // Not an e2e persona: scenario 2 needs those to sign in for the first time.
  await new MockIdp(page).choosePersona("entra", "anna-handlaggare");
  await demo.expectSignedIn();
  await expectAccessible(page, testInfo, "demo signed-in page (Tjänst C)");
});

test("Accessibility: an error page of the login UI", async ({ page }, testInfo) => {
  // An interaction that does not exist (expired, or a stale bookmark): the error view.
  const response = await page.goto(
    `${URLS.portvakt}/t/${DEMO_TENANT}/interaction/aGVsbG8tdGhpcy1kb2VzLW5vdC1leGlzdA`,
  );
  expect(response?.status()).toBe(404);
  await new LoginUi(page).expectError("interaction_expired");
  await expectAccessible(page, testInfo, "error page");
});
