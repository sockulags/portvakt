import { expect, test } from "../../src/fixtures";
import { JAVA, LOA4, METHODS, URLS } from "../../src/env";
import { DemoPage, type DemoName } from "../../src/pages/demo";
import { LoginUi } from "../../src/pages/login-ui";
import { MockIdp } from "../../src/pages/mock-idp";

/**
 * Scenario 7: step-up. Maja signs in with mock BankID (loa3); "Kräv högre säkerhetsnivå" asks for
 * loa4, which only "Mock BankID hög (OIDC)" provides, so Portvakt sends her straight there (no
 * chooser), naming her by personal identity number (`pinLoginHint`); the demo then shows loa4.
 */
const MAJA_PIN = "197811234561";

const cases: readonly { demo: DemoName; title: string }[] = [
  { demo: "A", title: "Service A" },
  { demo: "C", title: "Tjänst C (Java)" },
];

for (const { demo: which, title } of cases) {
  test(`Scenario 7: ${title} asks for a higher acr and the user is sent to the method that provides it`, async ({
    page,
  }) => {
    test.skip(which === "C" && !JAVA, "the Java demo is not running (--no-java)");
    const demo = new DemoPage(page, which);
    const login = new LoginUi(page);
    await demo.startSignIn();
    await login.chooseMethod(METHODS.bankidOidc);
    await new MockIdp(page).choosePersona("bankid", "maja-loa4");
    await demo.expectSignedIn();
    await expect(demo.field("user-acr")).toHaveText("Tillitsnivå 3");

    // The upstream authorization request of the step-up: the loa4 method, for Maja.
    const upstream = page.waitForRequest(
      (request) =>
        request.isNavigationRequest() &&
        request.url().startsWith(`${URLS.mockIdp}/bankid/`) &&
        new URL(request.url()).searchParams.get("login_hint") === MAJA_PIN,
    );
    await demo.stepUp();
    const request = await upstream;
    expect(new URL(request.url()).searchParams.get("acr_values")).toBe(LOA4);
    await demo.expectSignedIn();
    await expect(login.view).toHaveCount(0);
    await expect(demo.field("user-acr")).toHaveText("Tillitsnivå 4");
    await expect(demo.field("user-name")).toHaveText("Maja Högnivå");

    const answer = await demo.callApi();
    expect(answer).not.toBe("session_ended");
    if (answer !== "session_ended") {
      expect(answer.status).toBe(200);
      expect(answer.body).toMatchObject({ principal: { acr: LOA4 } });
    }
  });
}
