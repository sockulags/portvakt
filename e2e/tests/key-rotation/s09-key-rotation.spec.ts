import { expect, test } from "../../src/fixtures";
import { DEMO_TENANT, JAVA, METHODS, SECRETS, URLS } from "../../src/env";
import { DemoPage, type DemoName } from "../../src/pages/demo";
import { LoginUi } from "../../src/pages/login-ui";
import { MockIdp } from "../../src/pages/mock-idp";
import { decodeJwt, jwks, startAuthorization } from "../../src/rp";

/**
 * Scenario 9: key rotation from the admin portal (platform administrator). A session signed in
 * just before the rotation keeps working: its next API call refreshes the token (e2e tokens are
 * always due), now signed with the new key, and the demo accepts both the refreshed ID token and
 * the access token at once. The JWKS publishes the new key next to the old (retiring) one, and a
 * fresh token carries the new kid. The same for the Java demo (Tjänst C).
 *
 * Regression (M7): the TypeScript SDK ended the session at that refresh when its BFF had
 * fetched the JWKS less than 60 s before (openid-client's own JWKS cache), as here, where the
 * login comes right before the rotation.
 *
 * Runs alone (project `key-rotation`, after every other project): the signing keys are shared
 * by all tenants.
 */
const cases: readonly { demo: DemoName; persona: string; title: string }[] = [
  { demo: "A", persona: "e2e-emma", title: "Service A" },
  { demo: "C", persona: "e2e-jonas", title: "Tjänst C (Java)" },
];

for (const { demo: which, persona, title } of cases) {
  test(`Scenario 9: rotating the signing keys in the portal keeps ${title} sessions working and new tokens use the new key`, async ({
    page,
    platformAdmin,
  }) => {
    test.skip(which === "C" && !JAVA, "the Java demo is not running (--no-java)");
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
    await expect(adminPage.getByTestId("keys-rotated")).toBeVisible();
    const newKid = (await adminPage.getByTestId("key-active").textContent())?.trim() ?? "";
    expect(newKid).not.toBe("");
    expect(newKid).not.toBe(oldKid);
    // (Earlier rotations of the run may still be retiring too.)
    await expect(adminPage.getByTestId("key-retiring").filter({ hasText: oldKid })).toHaveCount(1);

    // The JWKS publishes both: tokens signed before the rotation still verify.
    const published = (await jwks(DEMO_TENANT)).map((key) => key.kid);
    expect(published).toEqual(expect.arrayContaining([oldKid, newKid]));

    // The session from before the rotation: refreshed with the new key, and still signed in.
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
