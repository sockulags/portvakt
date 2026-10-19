import pg from "pg";
import { expect, test } from "../../src/fixtures";
import { DATABASE_URL, LOA3, RUN_ID, URLS } from "../../src/env";

/**
 * Scenario 11: login methods with credentials that expire within 30 days are flagged on the
 * portal's Översikt and in the login method list. In a tenant of its own:
 * - an OIDC method whose client secret expires in 10 days, entered in the portal's form;
 * - a SAML method whose SP certificate expires in 10 days. Portvakt generates SP certificates
 *   valid for years and offers no way to shorten one, so the test moves the stored expiry
 *   (`saml_sp_keys.not_after`, what the warning reads) in the database.
 */
const inDays = (days: number): Date => new Date(Date.now() + days * 86_400_000);
const dateInput = (date: Date): string => date.toISOString().slice(0, 10);

test("Scenario 11: an expiring client secret and an expiring SP certificate are flagged in the portal", async ({
  platformAdmin,
}) => {
  const { page, portal, api } = platformAdmin;
  const tenant = await api.createTenant(`e2e-varning-${RUN_ID}`, `Varningar ${RUN_ID}`);
  const secretMethod = `Utgående hemlighet ${RUN_ID}`;
  const certificateMethod = `Utgående certifikat ${RUN_ID}`;

  // The OIDC method, with its secret's expiry date, through the portal.
  await portal.open("login-methods", { id: "new-oidc", tenantId: tenant.id });
  const form = page.getByTestId("login-method-form");
  await form.getByTestId("field-displayName").fill(secretMethod);
  await form.getByTestId("field-issuer").fill(`${URLS.mockIdp}/entra`);
  await form.getByTestId("field-clientId").fill("portvakt-dev");
  await form.getByTestId("field-clientSecret").fill("dev-only-entra-client-secret");
  await form.getByTestId("field-secretExpiresAt").fill(dateInput(inDays(10)));
  await form.getByTestId("field-subjectClaim").fill("oid");
  await form.getByTestId("save-login-method").click();
  await expect(page.getByTestId("method-warnings")).toContainText("Klienthemligheten går ut");

  // The SAML method (admin API), then its signing certificate's stored expiry, 10 days ahead.
  const saml = await api.createLoginMethod(tenant.id, {
    protocol: "saml",
    kind: "citizen",
    displayName: certificateMethod,
    assertedAcr: LOA3,
    sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 900, allowSso: true },
    saml: {
      idpEntityId: `${URLS.mockIdp}/saml/bankid`,
      metadataUrl: `${URLS.mockIdp}/saml/bankid/metadata`,
      allowUnsignedMetadata: true,
      requestedLoa: [LOA3],
      subjectSource: "personalIdentityNumber",
    },
  });
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  try {
    const updated = await client.query(
      "UPDATE saml_sp_keys SET not_after = $2 WHERE login_method_id = $1 AND purpose = 'signing' AND state = 'active'",
      [saml.id, inDays(10)],
    );
    expect(updated.rowCount).toBe(1);
  } finally {
    await client.end();
  }

  // Översikt: both methods are listed under warnings.
  await portal.open("overview", { tenantId: tenant.id });
  // (The SAML method has further warnings of its own: unsigned metadata, no logo.)
  const warnings = page.getByTestId("warning-item");
  await expect(warnings.filter({ hasText: secretMethod })).toHaveCount(1);
  await expect(warnings.filter({ hasText: secretMethod })).toContainText(
    "Klienthemligheten går ut",
  );
  await expect(
    warnings
      .filter({ hasText: certificateMethod })
      .filter({ hasText: "SP-certifikatet (signering) går ut" }),
  ).toHaveCount(1);

  // The login method list flags both rows.
  await portal.open("login-methods", { tenantId: tenant.id });
  for (const method of [secretMethod, certificateMethod]) {
    const row = page
      .getByRole("row")
      .filter({ has: page.getByRole("button", { name: method, exact: true }) });
    await expect(row.getByText(/varning/)).toBeVisible();
  }
  // The SAML method's own page names the certificate.
  await page.getByRole("button", { name: certificateMethod, exact: true }).click();
  await expect(page.getByTestId("method-warnings")).toContainText(
    "SP-certifikatet (signering) går ut",
  );
});
