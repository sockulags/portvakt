import { expect, type Locator, type Page } from "@playwright/test";
import { AdminApi } from "../admin-api";
import { URLS } from "../env";
import { LoginUi } from "./login-ui";
import { MockIdp } from "./mock-idp";

export type AdminPage =
  | "overview"
  | "tenants"
  | "applications"
  | "login-methods"
  | "roles"
  | "persons"
  | "representation"
  | "keys"
  | "audit";

/** Swedish navigation labels (apps/admin/web/src/i18n.ts). */
export const NAV_LABELS: Record<AdminPage, string> = {
  overview: "Översikt",
  tenants: "Organisationer",
  applications: "Applikationer",
  "login-methods": "Inloggningsmetoder",
  roles: "Roller och regler",
  persons: "Personer",
  representation: "Ombud",
  keys: "Nycklar",
  audit: "Granskningslogg",
};

/** The admin portal (apps/admin) below `/t/{slug}/`, the tenant whose issuer signs admins in. */
export class AdminPortal {
  readonly api: AdminApi;

  constructor(
    readonly page: Page,
    readonly slug: string,
  ) {
    this.api = new AdminApi(page.context().request, slug);
  }

  get portal(): Locator {
    return this.page.getByTestId("portal");
  }

  /**
   * Signs a Mock Entra persona in through the portal's own start page: "Logga in", Portvakt (the
   * login method chooser when the tenant has several methods), the mock's persona page.
   */
  async signIn(persona: string, method?: string): Promise<void> {
    await this.page.goto(`${URLS.admin}/t/${this.slug}/`);
    await expect(this.page.getByTestId("sign-in-page")).toBeVisible();
    await this.page.getByTestId("sign-in").click();
    if (method !== undefined) await new LoginUi(this.page).chooseMethod(method);
    await new MockIdp(this.page).choosePersona("entra", persona);
    await expect(this.portal).toBeVisible();
  }

  /** Signs an employee in by email (home realm discovery: no chooser, no persona page). */
  async signInWithHint(email: string): Promise<void> {
    const returnTo = `/t/${this.slug}/`;
    await this.page.goto(
      `${URLS.admin}/t/${this.slug}/auth/login?${new URLSearchParams({ returnTo, loginHint: email }).toString()}`,
    );
    await expect(this.portal).toBeVisible();
  }

  /** Opens a page by URL (`?tenant=` for platform administrators working in another tenant). */
  async open(page: AdminPage, options: { id?: string; tenantId?: string } = {}): Promise<void> {
    const path = [
      `/t/${this.slug}`,
      page === "overview" ? "" : `/${page}`,
      options.id === undefined ? "" : `/${options.id}`,
    ].join("");
    const query = options.tenantId === undefined ? "" : `?tenant=${options.tenantId}`;
    await this.page.goto(
      `${URLS.admin}${path}${page === "overview" && options.id === undefined ? "/" : ""}${query}`,
    );
    await expect(this.page.getByTestId(`page-${page}`)).toBeVisible();
    await expect(this.page.getByTestId("loading")).toHaveCount(0);
  }

  /** Follows the sidebar navigation. */
  async nav(page: AdminPage): Promise<void> {
    await this.page
      .getByRole("navigation", { name: "Administration" })
      .getByRole("button", { name: NAV_LABELS[page], exact: true })
      .click();
    await expect(this.page.getByTestId(`page-${page}`)).toBeVisible();
  }

  /** Platform administrators: switch the administered tenant. */
  async switchTenant(name: string, slug: string): Promise<void> {
    await this.page.getByTestId("tenant-switcher").selectOption({ label: `${name} (${slug})` });
  }

  /** A design-system Switch: the visible control is its label (the input is covered). */
  async toggle(testId: string): Promise<void> {
    await this.page.getByTestId(testId).locator("xpath=ancestor::label[1]").click();
  }

  async tab(name: string): Promise<void> {
    await this.page.getByRole("tab", { name, exact: true }).click();
  }
}
