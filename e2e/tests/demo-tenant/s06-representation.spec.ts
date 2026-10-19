import { expect, organisationNumber, tenantAdmin, test } from "../../src/fixtures";
import { ACCESS_TOKEN_DUE_MS, JAVA, METHODS, RUN_DIGITS, RUN_ID } from "../../src/env";
import { DemoPage, type DemoName } from "../../src/pages/demo";
import { LoginUi } from "../../src/pages/login-ui";
import { MockIdp } from "../../src/pages/mock-idp";

/**
 * Scenario 6: an agent with a representation grant (mock BankID persona Sven, by personal
 * identity number) chooses an organisation; the demo shows that it acts for the organisation and
 * who the agent is. The tenant administrator revokes the grant in the portal; the next token
 * refresh fails and the demo's session ends. The SDKs refresh a token once half its lifetime
 * has passed, so the test waits for that (ACCESS_TOKEN_DUE_MS) before the call that must
 * refresh. Each variant has its own organisation and grant, made through the admin API.
 */
const SVEN_PIN = "191212121212";

const cases: readonly { demo: DemoName; title: string; digits: string }[] = [
  { demo: "A", title: "Service A", digits: "559901" },
  { demo: "C", title: "Tjänst C (Java)", digits: "559902" },
];

for (const { demo: which, title, digits } of cases) {
  test(`Scenario 6: an agent acts for an organisation in ${title} until the grant is revoked in the portal`, async ({
    page,
    browser,
    platformAdmin,
    demoTenant,
  }) => {
    test.skip(which === "C" && !JAVA, "the Java demo is not running (--no-java)");
    const organisation = {
      identifier: organisationNumber(`${digits.slice(0, 6)}${RUN_DIGITS}`),
      displayName: `Ombudstest ${which} ${RUN_ID} AB`,
    };
    const { partyId, grantId } = await platformAdmin.api.createOrganisationGrant(
      demoTenant.id,
      organisation,
      SVEN_PIN,
    );

    const demo = new DemoPage(page, which);
    const login = new LoginUi(page);
    await demo.startSignIn();
    await login.chooseMethod(METHODS.bankidOidc);
    await new MockIdp(page).choosePersona("bankid", "sven-medborgare");
    await login.chooseRepresentation({ partyId });
    await demo.expectSignedIn();

    await expect(demo.field("user-name")).toHaveText("Sven Medborgare");
    await expect(demo.field("representation")).toHaveText(
      `Agerar för ${organisation.displayName} (organisation)`,
    );
    const answer = await demo.callApi();
    expect(answer).not.toBe("session_ended");
    if (answer !== "session_ended") {
      expect(answer.status).toBe(200);
      expect(answer.body).toMatchObject({
        principal: { rep: { sub: partyId, type: "organisation" } },
      });
    }

    // The tenant administrator revokes the grant in the portal.
    const admin = await tenantAdmin(browser);
    try {
      await admin.portal.open("representation");
      await admin.portal.tab("Behörigheter");
      await admin.page.getByTestId(`revoke-grant-${grantId}`).click();
      await admin.page.getByTestId("revoke-grant-dialog-confirm").click();
      await expect(admin.page.getByTestId("revoke-grant-dialog")).toHaveCount(0);
      await expect(admin.page.getByTestId(`revoke-grant-${grantId}`)).toHaveCount(0);
    } finally {
      await admin.context.close();
    }

    // The next refresh (once the access token is due) is refused (invalid_grant): the demo's
    // session has ended.
    await page.waitForTimeout(ACCESS_TOKEN_DUE_MS);
    expect(await demo.callApi()).toBe("session_ended");
    await demo.goto();
    await expect(demo.signedOut).toBeVisible();
  });
}
