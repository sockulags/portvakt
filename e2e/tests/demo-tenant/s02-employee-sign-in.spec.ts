import { expect, test } from "../../src/fixtures";
import { JAVA, METHODS } from "../../src/env";
import { DemoPage, type DemoName } from "../../src/pages/demo";
import { LoginUi } from "../../src/pages/login-ui";
import { MockIdp } from "../../src/pages/mock-idp";

/**
 * Scenario 2: an employee (mock Entra over OIDC) signs in to Service A without existing
 * beforehand; a group rule (grp-handlaggare -> handlaggare, seeded) gives the role, which Service
 * A displays. The same against the Java demo (Tjänst C) with another employee, who also did not
 * exist before.
 */
const cases: readonly { demo: DemoName; persona: string; name: string; title: string }[] = [
  { demo: "A", persona: "e2e-emma", name: "Emma Ek", title: "Service A" },
  { demo: "C", persona: "e2e-jonas", name: "Jonas Berg", title: "Tjänst C (Java)" },
];

for (const { demo: which, persona, name, title } of cases) {
  test(`Scenario 2: a new employee signs in to ${title} with mock Entra and gets handlaggare from a group rule`, async ({
    page,
    platformAdmin,
    demoTenant,
  }) => {
    test.skip(which === "C" && !JAVA, "the Java demo is not running (--no-java)");
    const search = () =>
      platformAdmin.api.send<{ items: unknown[] }>(
        "POST",
        `/tenants/${demoTenant.id}/persons/search`,
        { body: { query: name } },
      );
    expect((await search()).items, `${name} must not exist before the first login`).toEqual([]);

    const demo = new DemoPage(page, which);
    await demo.startSignIn();
    await new LoginUi(page).chooseMethod(METHODS.entra);
    await new MockIdp(page).choosePersona("entra", persona);
    await demo.expectSignedIn();

    await expect(demo.field("user-name")).toHaveText(name);
    await demo.expectRoles(["handlaggare"]);
    await expect(demo.field("user-idp-kind")).toHaveText("Anställd");

    // The access token carries the role too: the demo's own API answers with it.
    const answer = await demo.callApi();
    expect(answer).not.toBe("session_ended");
    if (answer === "session_ended") return;
    expect(answer.status).toBe(200);
    expect(answer.body).toMatchObject({
      principal: { roles: ["handlaggare"], idpKind: "employee" },
    });

    // Created just in time by this login.
    expect((await search()).items).toHaveLength(1);
  });
}
