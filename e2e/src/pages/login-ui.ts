import { expect, type Locator, type Page } from "@playwright/test";
import { URLS } from "../env";

/** Portvakt's login UI (apps/login): the method chooser, the representation chooser, errors. */
export class LoginUi {
  constructor(readonly page: Page) {}

  get view(): Locator {
    return this.page.getByTestId("login-view");
  }

  get representationView(): Locator {
    return this.page.getByTestId("representation-view");
  }

  get errorView(): Locator {
    return this.page.getByTestId("error-view");
  }

  /** The button of a login method, by its display name ("Logga in med {name}"). */
  method(displayName: string): Locator {
    return this.view.getByRole("button", { name: `Logga in med ${displayName}`, exact: true });
  }

  async expectChooser(tenant?: string): Promise<void> {
    await expect(this.view).toBeVisible();
    await expect(this.page.getByTestId("method-list")).toBeVisible();
    if (tenant !== undefined) {
      expect(this.page.url()).toContain(`${URLS.portvakt}/t/${tenant}/interaction/`);
    }
  }

  async chooseMethod(displayName: string): Promise<void> {
    await this.expectChooser();
    await this.method(displayName).click();
  }

  /** The interaction uid of the shown login page (`/t/{slug}/interaction/{uid}`). */
  interactionUid(): string {
    const match = /\/interaction\/([^/?#]+)/.exec(new URL(this.page.url()).pathname);
    if (match === null) throw new Error(`not an interaction page: ${this.page.url()}`);
    return match[1]!;
  }

  async expectRepresentationChooser(): Promise<void> {
    await expect(this.representationView).toBeVisible();
    await expect(this.page.getByTestId("party-list")).toBeVisible();
  }

  /** Chooses "myself" or a party (by party id) in the representation chooser. */
  async chooseRepresentation(party: "self" | { readonly partyId: string }): Promise<void> {
    await this.expectRepresentationChooser();
    await this.page
      .getByTestId(
        party === "self" ? "representation-option-self" : `representation-option-${party.partyId}`,
      )
      .click();
  }

  /** An error view with this error code (`data-error`). */
  async expectError(code: string): Promise<void> {
    await expect(this.errorView).toBeVisible();
    await expect(this.page.getByTestId("error-code")).toHaveAttribute("data-error", code);
  }
}
