import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { ActionResult, Bootstrap, InteractionDetails, LoginApi } from "./api";
import { App } from "./App";

const noHints = { uiLocales: [], acceptLanguage: [] };

const details: InteractionDetails = {
  tenant: { name: "Kommunen" },
  application: { name: "Ärendetjänsten" },
  methods: [
    { id: "entra", displayName: "Kommunens konto", kind: "employee" },
    { id: "bankid", displayName: "BankID", kind: "citizen" },
  ],
  homeRealmDiscovery: true,
  loginHint: null,
  csrfToken: "csrf-token",
};

const login = vi.fn((): Promise<ActionResult> =>
  Promise.resolve({ ok: true, redirectTo: "https://idp.example/auth" }),
);
const abort = vi.fn((): Promise<ActionResult> =>
  Promise.resolve({ ok: true, redirectTo: "https://app.example/cb" }),
);

function fakeApi(overrides: Partial<LoginApi> = {}): LoginApi {
  login.mockClear();
  abort.mockClear();
  return {
    details: () => Promise.resolve({ ok: true, details }),
    login,
    abort,
    ...overrides,
  };
}

const loginBootstrap = (extra: Partial<Extract<Bootstrap, { view: "login" }>> = {}): Bootstrap => ({
  view: "login",
  tenant: "kommunen",
  uid: "abc",
  locale: noHints,
  ...extra,
});

describe("login view", () => {
  it("shows the tenant, the application and the methods, and leaves for the chosen one", async () => {
    const api = fakeApi();
    const navigate = vi.fn();
    const user = userEvent.setup();
    render(<App bootstrap={loginBootstrap()} api={api} navigate={navigate} />);
    expect(
      await screen.findByText("Logga in för att fortsätta till Ärendetjänsten."),
    ).toBeDefined();
    expect(screen.getByText("Kommunen")).toBeDefined();
    expect(document.documentElement.lang).toBe("sv");
    // The heading has focus, for screen readers.
    expect(document.activeElement).toBe(screen.getByRole("heading", { level: 1 }));

    await user.click(screen.getByTestId("method-bankid"));
    expect(login).toHaveBeenCalledWith({ loginMethodId: "bankid" }, "csrf-token");
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("https://idp.example/auth"));
    expect(screen.getByTestId("redirecting")).toBeDefined();
  });

  it("shows a failed upstream login with the methods as the retry", async () => {
    render(<App bootstrap={loginBootstrap({ error: "upstream_denied" })} api={fakeApi()} />);
    const alert = await screen.findByTestId("login-error");
    expect(alert.getAttribute("data-error")).toBe("upstream_denied");
    expect(alert.textContent).toContain("Inloggningen avbröts");
    expect(screen.getByTestId("method-entra")).toBeDefined();
  });

  it("offers no methods when none meets the requirements, only the way back", async () => {
    const api = fakeApi({
      details: () =>
        Promise.resolve({
          ok: true,
          details: { ...details, methods: [], homeRealmDiscovery: false },
        }),
    });
    const navigate = vi.fn();
    const user = userEvent.setup();
    render(
      <App
        bootstrap={loginBootstrap({ error: "no_acceptable_method" })}
        api={api}
        navigate={navigate}
      />,
    );
    expect((await screen.findByTestId("login-error")).textContent).toContain(
      "Ingen inloggning uppfyller kraven",
    );
    expect(screen.queryByTestId("method-list")).toBeNull();
    await user.click(screen.getByTestId("cancel-login"));
    expect(abort).toHaveBeenCalledWith("csrf-token");
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("https://app.example/cb"));
  });

  it("shows the expired view when the interaction is gone", async () => {
    render(
      <App
        bootstrap={loginBootstrap()}
        api={fakeApi({
          details: () => Promise.resolve({ ok: false, error: "interaction_expired" }),
        })}
      />,
    );
    expect((await screen.findByTestId("error-code")).getAttribute("data-error")).toBe(
      "interaction_expired",
    );
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Inloggningen har gått ut");
  });

  it("switches to English, and starts in English with ui_locales=en", async () => {
    const user = userEvent.setup();
    const { unmount } = render(<App bootstrap={loginBootstrap()} api={fakeApi()} />);
    await screen.findByTestId("method-list");
    await user.click(screen.getByTestId("language-toggle"));
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Sign in");
    expect(document.documentElement.lang).toBe("en");
    expect(screen.getByTestId("language-toggle").textContent).toBe("Svenska");
    unmount();

    render(
      <App
        bootstrap={loginBootstrap({ locale: { uiLocales: ["en"], acceptLanguage: ["sv"] } })}
        api={fakeApi()}
      />,
    );
    expect(await screen.findByText("Sign in as an employee")).toBeDefined();
  });

  it("looks the home realm up from the email field", async () => {
    const api = fakeApi();
    const navigate = vi.fn();
    const user = userEvent.setup();
    render(<App bootstrap={loginBootstrap()} api={api} navigate={navigate} />);
    await user.type(await screen.findByTestId("hrd-email"), "anna@kommun.example{Enter}");
    expect(login).toHaveBeenCalledWith({ email: "anna@kommun.example" }, "csrf-token");
    await waitFor(() => expect(navigate).toHaveBeenCalled());
  });
});

describe("other views", () => {
  it("renders an error view with the OAuth code for unknown failures", () => {
    render(
      <App
        bootstrap={{
          view: "error",
          code: "request_failed",
          oauthError: "invalid_request",
          locale: noHints,
        }}
      />,
    );
    expect(screen.getByText("Felkod: invalid_request")).toBeDefined();
  });

  it("renders the logout confirmation with buttons for the server's form", () => {
    render(
      <App bootstrap={{ view: "logout", locale: { uiLocales: [], acceptLanguage: ["en"] } }} />,
    );
    const confirm = screen.getByTestId("logout-confirm");
    expect(confirm.getAttribute("form")).toBe("op.logoutForm");
    expect(confirm.getAttribute("name")).toBe("logout");
    expect(confirm.getAttribute("value")).toBe("yes");
    expect(confirm.textContent).toBe("Sign out");
    expect(screen.getByTestId("logout-cancel").getAttribute("name")).toBeNull();
  });

  it("renders the signed-out page and a generic error without a bootstrap", () => {
    const { unmount } = render(<App bootstrap={{ view: "logged_out", locale: noHints }} />);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Du är utloggad");
    unmount();
    render(<App bootstrap={null} />);
    expect(screen.getByTestId("error-code").getAttribute("data-error")).toBe("request_failed");
  });
});
