import { expect, type Page } from "@playwright/test";
import { URLS } from "../env";

/** The mock IdP's persona pages (apps/mock-idp: OIDC `/entra`, `/bankid`; SAML `/saml/*`). */
export class MockIdp {
  constructor(readonly page: Page) {}

  /** Waits for the persona page of an issuer (`entra`, `bankid`, `saml/bankid`, `saml/siths`). */
  async expectPage(issuer: string): Promise<void> {
    await this.page.waitForURL((url) => url.href.startsWith(`${URLS.mockIdp}/${issuer}/`));
    await expect(this.page.getByRole("heading", { name: "Choose a persona" })).toBeVisible();
  }

  /** Signs a persona in by clicking its button (the real UI path). */
  async choosePersona(issuer: string, persona: string): Promise<void> {
    await this.expectPage(issuer);
    await this.page.getByTestId(`persona-${persona}`).click();
    await this.page.waitForURL((url) => !url.href.startsWith(`${URLS.mockIdp}/`));
  }

  async cancel(issuer: string): Promise<void> {
    await this.expectPage(issuer);
    await this.page.getByTestId("cancel").click();
  }
}

/**
 * Counts the browser's page navigations to the mock IdP, to tell an SSO (no upstream page) from
 * a new upstream login.
 */
export function countUpstreamVisits(page: Page): { readonly count: () => number } {
  let visits = 0;
  page.on("request", (request) => {
    if (request.isNavigationRequest() && request.url().startsWith(`${URLS.mockIdp}/`)) visits += 1;
  });
  return { count: () => visits };
}
