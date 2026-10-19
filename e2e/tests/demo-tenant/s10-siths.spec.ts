import { expect, test } from "../../src/fixtures";
import { METHODS } from "../../src/env";
import { DemoPage } from "../../src/pages/demo";
import { LoginUi } from "../../src/pages/login-ui";
import { MockIdp } from "../../src/pages/mock-idp";

/**
 * Scenario 10: a SITHS-style employee login over SAML. The seeded "Mock SITHS (SAML)" method
 * keys identities by employeeHsaId; Service A may request the scope `hsa` (seeded) and does, so
 * the ID token carries `hsa_id`, which the demo shows. The organisation affiliation
 * `sara@2321000016` matches the seeded rule that gives the role `lakare`.
 */
test("Scenario 10: a SITHS employee over SAML gets her HSA-id mapped and a role from a rule", async ({
  page,
}) => {
  const demo = new DemoPage(page, "A");
  await demo.startSignIn();
  await new LoginUi(page).chooseMethod(METHODS.siths);
  await new MockIdp(page).choosePersona("saml/siths", "siths-sara");
  await demo.expectSignedIn();

  await expect(demo.field("user-name")).toHaveText("Sara Sjuksköterska");
  await expect(demo.field("user-hsa-id")).toHaveText("SE2321000016-1003");
  await expect(demo.field("user-idp-kind")).toHaveText("Anställd");
  await demo.expectRoles(["lakare"]);

  const session = await demo.session();
  expect(session.principal).toMatchObject({ hsaId: "SE2321000016-1003", roles: ["lakare"] });
});
