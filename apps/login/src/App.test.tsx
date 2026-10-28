import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type {
  ActionResult,
  Bootstrap,
  InteractionDetails,
  LoginApi,
  RepresentationApi,
  RepresentationDetails,
} from "./api";
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

  it("asks to wait when the interaction API is rate limited, keeping the methods", async () => {
    const limited = vi.fn((): Promise<ActionResult> =>
      Promise.resolve({ ok: false, error: "rate_limited" }),
    );
    const user = userEvent.setup();
    render(<App bootstrap={loginBootstrap()} api={fakeApi({ login: limited })} />);
    await user.click(await screen.findByTestId("method-bankid"));
    const alert = await screen.findByTestId("login-error");
    expect(alert.getAttribute("data-error")).toBe("rate_limited");
    expect(alert.textContent).toContain("För många försök");
    expect(screen.getByTestId("method-bankid")).toBeDefined();
  });

  it("shows the rate limit page of an authorization request", () => {
    render(
      <App bootstrap={{ view: "error", code: "rate_limited", locale: noHints }} api={fakeApi()} />,
    );
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("För många försök");
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

  it("announces loading in the page's language only (no English spinner label)", async () => {
    let answer: (result: { ok: true; details: InteractionDetails }) => void = () => undefined;
    const api = fakeApi({
      details: () =>
        new Promise((resolve) => {
          answer = resolve;
        }),
    });
    render(<App bootstrap={loginBootstrap()} api={api} />);
    const statuses = screen.getAllByRole("status");
    expect(statuses).toHaveLength(1);
    expect(statuses[0]!.textContent).toBe("Laddar …");
    // The design system's spinner (an English "Loading" status) is hidden from screen readers.
    expect(screen.getByLabelText("Loading").closest('[aria-hidden="true"]')).not.toBeNull();
    answer({ ok: true, details });
    await screen.findByTestId("method-list");
  });

  it("sends one login request at a time and keeps focus on the chosen button", async () => {
    let answer: (result: ActionResult) => void = () => undefined;
    const slow = vi.fn(
      () =>
        new Promise<ActionResult>((resolve) => {
          answer = resolve;
        }),
    );
    const user = userEvent.setup();
    render(<App bootstrap={loginBootstrap()} api={fakeApi({ login: slow })} />);
    const bankid = await screen.findByTestId("method-bankid");
    await user.click(bankid);
    await user.click(bankid);
    await user.click(screen.getByTestId("method-entra"));
    await user.click(screen.getByTestId("cancel-login"));
    await user.type(screen.getByTestId("hrd-email"), "anna@kommun.example{Enter}");
    expect(slow).toHaveBeenCalledTimes(1);
    expect(abort).not.toHaveBeenCalled();
    // The email form was not answered with an error: nothing was sent for it.
    expect(screen.getByTestId("hrd-error").textContent).toBe("");

    answer({ ok: false, error: "upstream_unavailable" });
    expect((await screen.findByTestId("login-error")).getAttribute("data-error")).toBe(
      "upstream_unavailable",
    );
    await user.click(screen.getByTestId("method-bankid"));
    expect(slow).toHaveBeenCalledTimes(2);
    expect(document.activeElement).toBe(screen.getByTestId("method-bankid"));
  });

  it("shows the current methods after the chosen one became unavailable", async () => {
    const detailsCalls = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, details })
      .mockResolvedValueOnce({
        ok: true,
        details: { ...details, methods: details.methods.filter((m) => m.id !== "bankid") },
      });
    const refused = vi.fn((): Promise<ActionResult> =>
      Promise.resolve({ ok: false, error: "login_method_unavailable" }),
    );
    const user = userEvent.setup();
    render(
      <App bootstrap={loginBootstrap()} api={fakeApi({ details: detailsCalls, login: refused })} />,
    );
    await user.click(await screen.findByTestId("method-bankid"));
    expect((await screen.findByTestId("login-error")).getAttribute("data-error")).toBe(
      "login_method_unavailable",
    );
    await waitFor(() => expect(screen.queryByTestId("method-bankid")).toBeNull());
    expect(detailsCalls).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId("method-entra")).toBeDefined();
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
    // The title names the page, not "Logga in".
    expect(document.title).toBe("Du är utloggad – Portvakt");
    unmount();
    render(<App bootstrap={null} />);
    expect(screen.getByTestId("error-code").getAttribute("data-error")).toBe("request_failed");
  });
});

describe("representation view", () => {
  const chooserDetails: RepresentationDetails = {
    tenant: { name: "Kommunen" },
    application: { name: "Bygglov" },
    allowSelf: true,
    parties: [
      {
        id: "11111111-1111-4111-8111-111111111111",
        type: "organisation",
        name: "Bygg AB",
        identifier: { kind: "organisation_number", value: "5566778899" },
      },
    ],
    csrfToken: "csrf-rep",
  };
  const bootstrap = (error?: "no_representation_available"): Bootstrap => ({
    view: "representation",
    tenant: "kommunen",
    uid: "abc",
    ...(error === undefined ? {} : { error }),
    locale: noHints,
  });
  const choose = vi.fn((): Promise<ActionResult> =>
    Promise.resolve({ ok: true, redirectTo: "https://app/cb" }),
  );
  const abortChooser = vi.fn((): Promise<ActionResult> =>
    Promise.resolve({ ok: true, redirectTo: "https://app/den" }),
  );
  const chooserApi = (overrides: Partial<RepresentationApi> = {}): RepresentationApi => {
    choose.mockClear();
    abortChooser.mockClear();
    return {
      details: () => Promise.resolve({ ok: true, details: chooserDetails }),
      choose,
      abort: abortChooser,
      ...overrides,
    };
  };

  it("lists the choices and leaves with the chosen party", async () => {
    const api = chooserApi();
    const navigate = vi.fn();
    const user = userEvent.setup();
    render(<App bootstrap={bootstrap()} representationApi={api} navigate={navigate} />);
    await screen.findByTestId("party-list");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Välj vem du företräder");
    expect(document.activeElement).toBe(screen.getByRole("heading", { level: 1 }));
    expect(screen.getByText(/Bygglov/)).toBeDefined();
    await user.click(screen.getByRole("button", { name: "Företräd Bygg AB" }));
    expect(choose).toHaveBeenCalledWith(
      { partyId: "11111111-1111-4111-8111-111111111111" },
      "csrf-rep",
    );
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("https://app/cb"));
  });

  it("shows a refused choice above the list, which stays as the retry", async () => {
    const api = chooserApi({
      choose: () => Promise.resolve({ ok: false, error: "representation_not_allowed" }),
    });
    const user = userEvent.setup();
    render(<App bootstrap={bootstrap()} representationApi={api} />);
    await user.click(await screen.findByTestId("representation-option-self"));
    const alert = await screen.findByTestId("representation-error");
    expect(alert.getAttribute("data-error")).toBe("representation_not_allowed");
    expect(screen.getByTestId("party-list")).toBeDefined();
  });

  it("lists the current parties after a refused one and moves focus to the alert", async () => {
    const party = chooserDetails.parties[0]!;
    const detailsCalls = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, details: chooserDetails })
      .mockResolvedValueOnce({ ok: true, details: { ...chooserDetails, parties: [] } });
    const api = chooserApi({
      details: detailsCalls,
      choose: () => Promise.resolve({ ok: false, error: "representation_not_allowed" }),
    });
    const user = userEvent.setup();
    render(<App bootstrap={bootstrap()} representationApi={api} />);
    await user.click(await screen.findByTestId(`representation-option-${party.id}`));
    const alert = await screen.findByTestId("representation-error");
    await waitFor(() =>
      expect(screen.queryByTestId(`representation-option-${party.id}`)).toBeNull(),
    );
    expect(detailsCalls).toHaveBeenCalledTimes(2);
    expect(document.activeElement).toBe(alert);
    expect(screen.getByTestId("representation-option-self")).toBeDefined();
    expect(screen.getByTestId<HTMLButtonElement>("representation-option-self").disabled).toBe(
      false,
    );
  });

  it("offers only the way back when there is nobody to represent", async () => {
    const api = chooserApi({
      details: () =>
        Promise.resolve({
          ok: true,
          details: { ...chooserDetails, allowSelf: false, parties: [] },
        }),
    });
    const navigate = vi.fn();
    const user = userEvent.setup();
    render(
      <App
        bootstrap={{
          ...bootstrap("no_representation_available"),
          locale: { uiLocales: ["en"], acceptLanguage: [] },
        }}
        representationApi={api}
        navigate={navigate}
      />,
    );
    expect(await screen.findByRole("heading", { level: 1 })).toBeDefined();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(
      "You cannot represent anyone here",
    );
    expect(screen.queryByTestId("party-list")).toBeNull();
    await user.click(screen.getByTestId("cancel-representation"));
    expect(abortChooser).toHaveBeenCalledWith("csrf-rep");
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("https://app/den"));
  });
});
