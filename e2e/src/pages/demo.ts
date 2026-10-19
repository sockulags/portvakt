import { expect, type Locator, type Page } from "@playwright/test";
import { URLS } from "../env";

export type DemoName = "A" | "B" | "C";

const ORIGINS: Record<DemoName, string> = {
  A: URLS.serviceA,
  B: URLS.serviceB,
  C: URLS.serviceC,
};

/**
 * A demo service: Tjänst A and B (examples/demo-service, React SPA) or Tjänst C (the Java demo,
 * Thymeleaf). Both render the same `data-testid`s, so one page object drives all three.
 */
export class DemoPage {
  readonly origin: string;

  constructor(
    readonly page: Page,
    readonly name: DemoName,
  ) {
    this.origin = ORIGINS[name];
  }

  get isJava(): boolean {
    return this.name === "C";
  }

  get signedIn(): Locator {
    return this.page.getByTestId("signed-in-view");
  }

  get signedOut(): Locator {
    return this.page.getByTestId("signed-out-view");
  }

  field(
    testId:
      "user-name" | "user-roles" | "user-acr" | "user-idp-kind" | "representation" | "user-hsa-id",
  ): Locator {
    return this.page.getByTestId(testId);
  }

  async goto(): Promise<void> {
    await this.page.goto(`${this.origin}/`);
    await expect(this.signedIn.or(this.signedOut)).toBeVisible();
  }

  /** From the signed-out start page: "Logga in" (to Portvakt). */
  async startSignIn(): Promise<void> {
    await this.goto();
    await expect(this.signedOut).toBeVisible();
    // The authorization request to Portvakt (with SSO the browser may be back here at once).
    const authorize = this.page.waitForRequest(
      (request) => request.isNavigationRequest() && request.url().startsWith(`${URLS.portvakt}/t/`),
    );
    await this.page.getByTestId("sign-in").click();
    await authorize;
  }

  /** A login hint for Portvakt (an employee's email: home realm discovery, straight upstream). */
  async startSignInWithHint(loginHint: string): Promise<void> {
    await this.page.goto(
      `${this.origin}/auth/login?${new URLSearchParams({ returnTo: "/", loginHint }).toString()}`,
    );
  }

  async expectSignedIn(): Promise<void> {
    await this.page.waitForURL((url) => url.href.startsWith(`${this.origin}/`));
    await expect(this.signedIn).toBeVisible();
  }

  async expectSignedOut(): Promise<void> {
    await this.page.waitForURL((url) => url.href.startsWith(`${this.origin}/`));
    await expect(this.signedOut).toBeVisible();
  }

  async expectRoles(roles: readonly string[]): Promise<void> {
    for (const role of roles) await expect(this.field("user-roles")).toContainText(role);
  }

  /** "Kräv högre säkerhetsnivå": a step-up to the demo's STEP_UP_ACR (loa4). */
  async stepUp(): Promise<void> {
    await this.page.getByTestId("step-up").click();
  }

  /**
   * "Anropa API": the demo's BFF calls its own API with the session's access token (refreshed
   * first: the e2e stack's tokens are always due for a refresh). Returns the API's HTTP status
   * and body, or `"session_ended"` when the demo answered by ending the session.
   */
  async callApi(): Promise<{ status: number; body: unknown } | "session_ended"> {
    const status = this.page.getByTestId("api-status");
    // The SPA fetches /app/api-call; the Java page submits a GET form to /call-api.
    const path = this.isJava ? "/call-api" : "/app/api-call";
    const answered = this.page.waitForResponse(
      (response) => new URL(response.url()).pathname === path,
    );
    await this.page.getByTestId("call-api").click();
    await answered;
    await this.page.waitForLoadState();
    // An ended session: the SPA shows its signed-out view; the Java demo sends the browser to
    // sign in again (Portvakt).
    const away = () => !this.page.url().startsWith(`${this.origin}/`);
    await expect
      .poll(
        async () =>
          away() ||
          (await status.or(this.signedOut).or(this.page.getByTestId("api-error")).isVisible()),
      )
      .toBe(true);
    if (away() || (await this.signedOut.isVisible())) return "session_ended";
    if (!(await status.isVisible())) throw new Error("the API call failed (api-error)");
    const text = (await status.textContent()) ?? "";
    const code = Number(/HTTP (\d{3})/.exec(text)?.[1]);
    const body: unknown = JSON.parse(
      (await this.page.getByTestId("api-result").textContent()) ?? "null",
    );
    return { status: code, body };
  }

  /** The session as the BFF reports it (`/auth/session`; TypeScript demo only). */
  async session(): Promise<{
    authenticated: boolean;
    principal?: Record<string, unknown>;
    sessionEndsAt?: string;
  }> {
    if (this.isJava) throw new Error("the Java demo has no /auth/session");
    const response = await this.page.request.get(`${this.origin}/auth/session`, {
      headers: { accept: "application/json" },
    });
    return (await response.json()) as {
      authenticated: boolean;
      principal?: Record<string, unknown>;
      sessionEndsAt?: string;
    };
  }
}
