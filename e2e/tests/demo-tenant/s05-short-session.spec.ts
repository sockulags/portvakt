import { expect, test } from "../../src/fixtures";
import { LOA3, RUN_ID, URLS } from "../../src/env";
import { DemoPage } from "../../src/pages/demo";
import { LoginUi } from "../../src/pages/login-ui";
import { countUpstreamVisits, MockIdp } from "../../src/pages/mock-idp";

/**
 * Scenario 5: a short citizen session expires on schedule. The scenario's own login method (mock
 * BankID over OIDC) gets a 20 s session policy through the admin API; Service A's session ends
 * with the broker session (`session_exp`), and signing in again needs a new login. The wait is
 * computed from the session end the BFF reports, plus a second of margin (times are whole
 * seconds), so it is as short as the policy allows.
 */
const MAX_AGE_SECONDS = 20;

test("Scenario 5: a short citizen session expires on schedule and Service A requires sign-in again", async ({
  page,
  platformAdmin,
  demoTenant,
}) => {
  const api = platformAdmin.api;
  const displayName = `E2E kort session ${RUN_ID}`;
  const created = await api.createLoginMethod(demoTenant.id, {
    protocol: "oidc",
    kind: "citizen",
    displayName,
    issuer: `${URLS.mockIdp}/bankid`,
    clientId: "portvakt-dev",
    clientSecret: "dev-only-bankid-client-secret",
    scopes: ["openid", "profile"],
    claimMapping: {
      subject: "sub",
      name: "name",
      pin: "https://id.oidc.se/claim/personalIdentityNumber",
      acr: "acr",
    },
    assertedAcr: LOA3,
    linkByPin: true,
    sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true },
  });
  const policy = await api.send<{ etag: string }>(
    "PUT",
    `/tenants/${demoTenant.id}/login-methods/${created.id}/session-policy`,
    {
      body: { maxAgeSeconds: MAX_AGE_SECONDS, idleSeconds: MAX_AGE_SECONDS, allowSso: true },
      etag: created.etag,
    },
  );

  try {
    const demo = new DemoPage(page, "A");
    const login = new LoginUi(page);
    await demo.startSignIn();
    await login.chooseMethod(displayName);
    await new MockIdp(page).choosePersona("bankid", "samuel-samordning");
    await demo.expectSignedIn();
    await expect(demo.field("user-idp-kind")).toHaveText("Medborgare");

    const session = await demo.session();
    expect(session.authenticated).toBe(true);
    const endsAt = Date.parse(session.sessionEndsAt!);
    const remaining = endsAt - Date.now();
    expect(remaining, "the session ends within the policy's max age").toBeLessThanOrEqual(
      MAX_AGE_SECONDS * 1000,
    );
    expect(remaining).toBeGreaterThan(0);

    await page.waitForTimeout(remaining + 1500);

    await demo.goto();
    await expect(demo.signedOut).toBeVisible();
    // Portvakt's session ended too: signing in again shows the login UI and the IdP again.
    const upstream = countUpstreamVisits(page);
    await demo.startSignIn();
    await login.chooseMethod(displayName);
    await new MockIdp(page).choosePersona("bankid", "samuel-samordning");
    await demo.expectSignedIn();
    expect(upstream.count()).toBeGreaterThan(0);
  } finally {
    // People signed in with it, so it cannot be deleted: disable it (the demo tenant's chooser
    // stays as seeded for the other scenarios).
    await api.send("PATCH", `/tenants/${demoTenant.id}/login-methods/${created.id}`, {
      body: { enabled: false },
      etag: policy.etag,
    });
  }
});
