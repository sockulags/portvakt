import { expect, test } from "../../src/fixtures";
import { ACCESS_TOKEN_DUE_MS, DEMO_TENANT, JAVA, METHODS, SECRETS, URLS } from "../../src/env";
import { DemoPage, type DemoName } from "../../src/pages/demo";
import { LoginUi } from "../../src/pages/login-ui";
import { MockIdp } from "../../src/pages/mock-idp";
import { decodeJwt, jwks, startAuthorization } from "../../src/rp";

/**
 * Scenario 9: key rotation from the admin portal (platform administrator). A rotation without
 * emergency publishes ahead: the portal shows "Ny nyckel publicerad, aktiveras HH:MM", the JWKS
 * lists the new key next to the active one at once, and the key becomes active after
 * KEY_MANUAL_PUBLISH_AHEAD (15 s on the e2e stack; the rotation job runs at that time). A session
 * signed in before the rotation keeps working: once its access token is due, its next API call
 * refreshes it, now signed with the new key, and the demo accepts both the refreshed ID token and
 * the access token. A fresh token carries the new kid. The same for the Java demo (Tjänst C).
 *
 * Regression (M7): the TypeScript SDK ended the session at that refresh when its BFF had
 * fetched the JWKS shortly before (openid-client's own JWKS cache), as here.
 *
 * Runs alone (project `key-rotation`, after every other project): the signing keys are shared
 * by all tenants.
 */
const cases: readonly { demo: DemoName; persona: string; title: string }[] = [
  { demo: "A", persona: "e2e-emma", title: "Service A" },
  { demo: "C", persona: "e2e-jonas", title: "Tjänst C (Java)" },
];

/** KEY_MANUAL_PUBLISH_AHEAD of the e2e stack plus a margin for the job and a page reload. */
const ACTIVATION_TIMEOUT_MS = 45_000;

for (const { demo: which, persona, title } of cases) {
  test(`Scenario 9: rotating the signing keys in the portal keeps ${title} sessions working and new tokens use the new key`, async ({
    page,
    platformAdmin,
  }) => {
    test.skip(which === "C" && !JAVA, "the Java demo is not running (--no-java)");
    test.setTimeout(120_000);
    const demo = new DemoPage(page, which);
    await demo.startSignIn();
    await new LoginUi(page).chooseMethod(METHODS.entra);
    await new MockIdp(page).choosePersona("entra", persona);
    await demo.expectSignedIn();

    // The platform administrator rotates the keys on the Nycklar page.
    const { page: adminPage, portal } = platformAdmin;
    await portal.open("keys");
    const oldKid = (await adminPage.getByTestId("key-active").textContent())?.trim() ?? "";
    expect(oldKid).not.toBe("");
    await adminPage.getByTestId("rotate-keys").click();
    await adminPage.getByTestId("rotate-reason").fill("Planerat byte (e2e scenario 9)");
    await adminPage.getByTestId("rotate-keys-dialog-confirm").click();

    // Published ahead: the portal names the activation time, the old key still signs.
    const scheduled = adminPage.getByTestId("keys-scheduled");
    await expect(scheduled).toBeVisible();
    await expect(scheduled).toContainText(/Ny nyckel publicerad, aktiveras \d{2}:\d{2}/);
    const newKid = (await scheduled.getAttribute("data-kid")) ?? "";
    expect(newKid).not.toBe("");
    expect(newKid).not.toBe(oldKid);
    await expect(adminPage.getByTestId("key-active")).toHaveText(oldKid);
    await expect(adminPage.getByTestId("key-next")).toHaveText(newKid);
    const publishedAhead = (await jwks(DEMO_TENANT)).map((key) => key.kid);
    expect(publishedAhead).toEqual(expect.arrayContaining([oldKid, newKid]));

    // After KEY_MANUAL_PUBLISH_AHEAD the rotation job activates it.
    await expect
      .poll(
        async () => {
          await portal.open("keys");
          return (await adminPage.getByTestId("key-active").textContent())?.trim();
        },
        { timeout: ACTIVATION_TIMEOUT_MS, intervals: [2000] },
      )
      .toBe(newKid);
    await expect(adminPage.getByTestId("keys-scheduled")).toHaveCount(0);
    // (Earlier rotations of the run may still be retiring too.)
    await expect(adminPage.getByTestId("key-retiring").filter({ hasText: oldKid })).toHaveCount(1);

    // The JWKS publishes both: tokens signed before the rotation still verify.
    const published = (await jwks(DEMO_TENANT)).map((key) => key.kid);
    expect(published).toEqual(expect.arrayContaining([oldKid, newKid]));

    // The session from before the rotation: once its token is due, the refresh brings tokens
    // signed with the new key, and the session goes on.
    await page.waitForTimeout(ACCESS_TOKEN_DUE_MS);
    const answer = await demo.callApi();
    expect(answer, "the session survives the rotation").not.toBe("session_ended");
    if (answer !== "session_ended") expect(answer.status).toBe(200);
    await demo.goto();
    await expect(demo.signedIn).toBeVisible();

    if (which !== "A") return;
    // A fresh token (the test as Service A) carries the new kid, and so does its ID token.
    const context = await page.context().browser()!.newContext({ locale: "sv-SE" });
    try {
      const fresh = await context.newPage();
      const flow = await startAuthorization(fresh, {
        tenant: DEMO_TENANT,
        clientId: "service-a",
        clientSecret: SECRETS.serviceA,
        redirectUri: `${URLS.serviceA}/auth/callback`,
      });
      await new LoginUi(fresh).chooseMethod(METHODS.entra);
      await new MockIdp(fresh).choosePersona("entra", persona);
      const tokens = await flow.finish();
      expect(tokens.accessHeader.kid).toBe(newKid);
      expect(decodeJwt(tokens.idToken).header.kid).toBe(newKid);
      const whoami = await fresh.request.get(`${URLS.serviceA}/api/whoami`, {
        headers: { authorization: `Bearer ${tokens.accessToken}` },
      });
      expect(whoami.status()).toBe(200);
    } finally {
      await context.close();
    }
  });
}
