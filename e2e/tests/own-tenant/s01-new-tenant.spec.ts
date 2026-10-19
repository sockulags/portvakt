import { expect, test } from "../../src/fixtures";
import { LOA3, RUN_ID, SECRETS, URLS } from "../../src/env";
import { LoginUi } from "../../src/pages/login-ui";
import { MockIdp } from "../../src/pages/mock-idp";
import { startAuthorization } from "../../src/rp";

/**
 * Scenario 1: the platform administrator signs in to the admin portal, creates a tenant, enables
 * Service A there, and adds an employee login method (mock Entra over OIDC) and a citizen login
 * method (mock BankID over SAML, with the metadata URL of the mock), all through the portal's UI.
 * The new tenant then works: an employee and a citizen each sign in to Service A at the new
 * tenant's issuer (the test redeems the code as Service A, whose demo instance belongs to the
 * demo tenant).
 */
test("Scenario 1: a platform admin creates a tenant with Service A and two login methods in the portal, and it works", async ({
  browser,
  platformAdmin,
}) => {
  const { page, portal } = platformAdmin;
  const slug = `e2e-ny-${RUN_ID}`;
  const name = `Ny kommun ${RUN_ID}`;
  const employeeMethod = `Ny Entra ${RUN_ID}`;
  const citizenMethod = `Ny BankID SAML ${RUN_ID}`;

  // The tenant.
  await portal.open("overview");
  await portal.nav("tenants");
  await page.getByTestId("create-tenant").click();
  const dialog = page.getByTestId("tenant-dialog");
  await dialog.getByTestId("tenant-slug").fill(slug);
  await dialog.getByTestId("tenant-name-input").fill(name);
  await dialog.getByTestId("tenant-save").click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByTestId(`tenant-row-${slug}`)).toBeVisible();

  // Administer it: the switcher lists it now.
  await portal.switchTenant(name, slug);
  await expect(
    page.getByTestId("page-tenants").or(page.getByTestId("page-overview")),
  ).toBeVisible();

  // Service A, enabled in the new tenant.
  await portal.nav("applications");
  await page.getByTestId("attach-select").selectOption({ label: "Tjänst A (service-a)" });
  await page.getByTestId("attach-application").click();
  await expect(page.getByTestId("application-row-service-a")).toBeVisible();
  await expect(page.getByTestId("application-toggle-service-a")).toBeChecked();

  // The employee login method: mock Entra over OIDC.
  await portal.nav("login-methods");
  await page.getByTestId("create-oidc").click();
  const form = page.getByTestId("login-method-form");
  await form.getByTestId("field-displayName").fill(employeeMethod);
  await form.getByTestId("field-kind").selectOption("employee");
  await form.getByTestId("field-issuer").fill(`${URLS.mockIdp}/entra`);
  await form.getByTestId("field-clientId").fill("portvakt-dev");
  await form.getByTestId("field-clientSecret").fill("dev-only-entra-client-secret");
  await form.getByTestId("field-scopes").fill("openid profile email");
  await form.getByTestId("field-subjectClaim").fill("oid");
  await form.getByTestId("field-groupsClaim").fill("groups");
  await form.getByTestId("save-login-method").click();
  await expect(page.getByTestId("redirect-uri-value")).toContainText(`/t/${slug}/federation/`);

  // The citizen login method: mock BankID over SAML, metadata from the mock's URL.
  await portal.nav("login-methods");
  await page.getByTestId("create-saml").click();
  await form.getByTestId("field-displayName").fill(citizenMethod);
  await form.getByTestId("field-kind").selectOption("citizen");
  await form.getByTestId("field-idpEntityId").fill(`${URLS.mockIdp}/saml/bankid`);
  await form.getByTestId("field-metadataUrl").fill(`${URLS.mockIdp}/saml/bankid/metadata`);
  // The mock signs its metadata with a key made at start-up: development only.
  const unsigned = form.getByLabel("Använd metadata utan signaturkontroll (bara utveckling)");
  // The design system's checkbox: its visible box covers the input, so click the label text.
  await form.getByText("Använd metadata utan signaturkontroll (bara utveckling)").click();
  await expect(unsigned).toBeChecked();
  await form.getByTestId("save-login-method").click();
  await expect(page.getByTestId("sp-metadata-value")).toContainText(`/t/${slug}/saml/`);
  await expect(page.getByTestId("sp-keys")).toBeVisible();

  await portal.nav("login-methods");
  await expect(page.getByRole("button", { name: employeeMethod, exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: citizenMethod, exact: true })).toBeVisible();

  // The new tenant works: an employee signs in to Service A at its issuer...
  const issuer = `${URLS.portvakt}/t/${slug}`;
  for (const person of [
    { method: employeeMethod, issuer: "entra", persona: "anna-handlaggare", kind: "employee" },
    { method: citizenMethod, issuer: "saml/bankid", persona: "saml-sven", kind: "citizen" },
  ]) {
    // ...and a citizen, each in a browser of their own.
    const context = await browser.newContext({ locale: "sv-SE" });
    try {
      const user = await context.newPage();
      const flow = await startAuthorization(user, {
        tenant: slug,
        clientId: "service-a",
        clientSecret: SECRETS.serviceA,
        redirectUri: `${URLS.serviceA}/auth/callback`,
      });
      const login = new LoginUi(user);
      await login.expectChooser(slug);
      await login.chooseMethod(person.method);
      await new MockIdp(user).choosePersona(person.issuer, person.persona);
      const tokens = await flow.finish();
      expect(tokens.idClaims).toMatchObject({
        iss: issuer,
        aud: "service-a",
        tid: slug,
        idp_kind: person.kind,
      });
      expect(tokens.accessClaims).toMatchObject({ iss: issuer, aud: "service-a", tid: slug });
      if (person.kind === "citizen") expect(tokens.idClaims.acr).toBe(LOA3);
    } finally {
      await context.close();
    }
  }
});
