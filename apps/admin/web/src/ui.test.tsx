// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, type ApiClient } from "./api";
import { I18nContext, MESSAGES } from "./i18n";
import { ApplicationEditor } from "./pages/ApplicationEditor";
import { ApplicationsPage } from "./pages/Applications";
import { LoginMethodsPage } from "./pages/LoginMethods";
import { PersonsPage } from "./pages/Persons";
import { TenantsPage } from "./pages/Tenants";
import type { Location } from "./router";
import type { Application, LoginMethod, Me, Person, Tenant, TenantApplication } from "./types";
import { AdminContext, CopyValue, Modal, type Admin } from "./ui";

afterEach(() => {
  cleanup();
});

// jsdom has no ResizeObserver (the design system's tabs observe their size).
globalThis.ResizeObserver ??= class {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
};

const TENANT: Tenant = {
  id: "8a41c2d0-5e3b-4f7a-9c18-6b2e0d4f3a91",
  slug: "demo",
  name: "Demo kommun",
  status: "active",
  representationSources: ["internal"],
  createdAt: "2026-10-01T00:00:00.000Z",
  updatedAt: "2026-10-01T00:00:00.000Z",
  etag: '"t1"',
};
const METHOD_ID = "0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7";

const method = (etag: string, displayName = "Entra"): LoginMethod => ({
  id: METHOD_ID,
  tenantId: TENANT.id,
  protocol: "oidc",
  kind: "employee",
  displayName,
  assertedAcr: "urn:portvakt:acr:employee",
  homeRealmDomains: [],
  secretExpiresAt: null,
  sessionPolicy: { maxAgeSeconds: 3600, idleSeconds: 600, allowSso: true },
  linkByPin: false,
  trustPinForRepresentation: false,
  enabled: true,
  oidc: {
    issuer: "https://login.example.org",
    clientId: "portvakt",
    hasClientSecret: true,
    clientAuthMethod: "client_secret_basic",
    useUserinfo: false,
    clientAssertionAudience: "token_endpoint",
    allowedUpstreamTenants: [],
    trustUpstreamEmail: false,
    pinLoginHint: false,
    scopes: ["openid"],
    claimMapping: { subject: "sub" },
    redirectUri: "https://login.example.org/t/demo/federation/x/callback",
    jwksUri: "https://login.example.org/t/demo/federation/x/jwks",
  },
  warnings: [],
  etag,
});

const PAGES_UNDER_TEST = {
  "login-methods": () => <LoginMethodsPage />,
  tenants: () => <TenantsPage />,
  applications: () => <ApplicationsPage />,
  persons: () => <PersonsPage />,
} as const;

function renderPage(
  page: keyof typeof PAGES_UNDER_TEST,
  id: string | undefined,
  api: Partial<ApiClient>,
  locale: "sv" | "en" = "sv",
) {
  const location: Location = { slug: "system", page, id, tenant: undefined };
  const me: Me = { personId: "p", tenant: TENANT, platform: true, roles: ["platform-admin"] };
  const admin: Admin = {
    api: {
      slug: "system",
      session: vi.fn(),
      logout: vi.fn(),
      get: vi.fn(),
      send: vi.fn(),
      ...api,
    },
    me,
    tenant: TENANT,
    tenants: [TENANT],
    location,
    go: vi.fn(),
    reloadTenants: vi.fn(() => Promise.resolve()),
  };
  render(
    <I18nContext.Provider value={{ locale, t: MESSAGES[locale], setLocale: () => undefined }}>
      <AdminContext.Provider value={admin}>{PAGES_UNDER_TEST[page]()}</AdminContext.Provider>
    </I18nContext.Provider>,
  );
  return admin;
}

describe("optimistic concurrency in the UI", () => {
  it("shows a conflict when someone else changed the login method, and reloads it", async () => {
    const get = vi
      .fn()
      .mockResolvedValueOnce(method('"v1"'))
      .mockResolvedValueOnce(method('"v2"', "Entra (ändrad)"));
    const send = vi.fn().mockRejectedValue(new ApiError(412, "precondition_failed"));
    renderPage("login-methods", METHOD_ID, { get, send });
    const name = await screen.findByTestId("field-displayName");
    await userEvent.clear(name);
    await userEvent.type(name, "Mitt namn");
    await userEvent.click(screen.getByTestId("save-login-method"));

    expect(send).toHaveBeenCalledWith(
      "PATCH",
      `/tenants/${TENANT.id}/login-methods/${METHOD_ID}`,
      expect.objectContaining({
        etag: '"v1"',
        body: expect.objectContaining({ displayName: "Mitt namn" }) as unknown,
      }),
    );
    const notice = await screen.findByTestId("conflict-notice");
    expect(notice.textContent).toContain(MESSAGES.sv.errors.conflictTitle);

    await userEvent.click(screen.getByTestId("conflict-reload"));
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.getByTestId<HTMLInputElement>("field-displayName").value).toBe(
        "Entra (ändrad)",
      ),
    );
    expect(screen.queryByTestId("conflict-notice")).toBeNull();
  });

  it("validates before sending and maps server field errors to the form", async () => {
    const get = vi.fn().mockResolvedValue(method('"v1"'));
    const send = vi
      .fn()
      .mockRejectedValue(
        new ApiError(400, "validation_failed", [
          { field: "issuer", message: "refused by the outbound policy" },
        ]),
      );
    renderPage("login-methods", METHOD_ID, { get, send }, "en");
    const idle = await screen.findByTestId("field-idleMinutes");
    await userEvent.clear(idle);
    await userEvent.type(idle, "999");
    await userEvent.click(screen.getByTestId("save-login-method"));
    expect(send).not.toHaveBeenCalled();
    expect(await screen.findByText(MESSAGES.en.validation.idle_exceeds_max)).toBeTruthy();

    await userEvent.clear(idle);
    await userEvent.type(idle, "10");
    await userEvent.click(screen.getByTestId("save-login-method"));
    expect(await screen.findByText(/refused by the outbound policy/)).toBeTruthy();
  });

  it("shows the conflict notice in the tenant dialog", async () => {
    const get = vi.fn().mockResolvedValue({ items: [TENANT] });
    const send = vi.fn().mockRejectedValue(new ApiError(412, "precondition_failed"));
    renderPage("tenants", undefined, { get, send });
    await userEvent.click(await screen.findByTestId("tenant-edit-demo"));
    const input = screen.getByTestId("tenant-name-input");
    await userEvent.clear(input);
    await userEvent.type(input, "Nytt namn");
    await userEvent.click(screen.getByTestId("tenant-save"));
    expect(send).toHaveBeenCalledWith("PATCH", `/tenants/${TENANT.id}`, {
      body: { name: "Nytt namn" },
      etag: '"t1"',
    });
    expect(await screen.findByTestId("conflict-notice")).toBeTruthy();
  });
});

describe("Modal", () => {
  function Harness() {
    const [open, setOpen] = useState(false);
    return (
      <>
        <button type="button" onClick={() => setOpen(true)}>
          Open
        </button>
        {open ? (
          <Modal
            title="Edit thing"
            testId="harness"
            onClose={() => setOpen(false)}
            footer={
              <button type="button" onClick={() => setOpen(false)}>
                Done
              </button>
            }
          >
            <input aria-label="Name" />
          </Modal>
        ) : null}
      </>
    );
  }

  it("is a labelled modal dialog that traps focus and returns it on close", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const opener = screen.getByRole("button", { name: "Open" });
    await user.click(opener);
    const dialog = screen.getByRole("dialog", { name: "Edit thing" });
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    const heading = document.getElementById(dialog.getAttribute("aria-labelledby")!);
    expect(heading?.textContent).toBe("Edit thing");
    expect(dialog.contains(document.activeElement)).toBe(true);
    for (let index = 0; index < 6; index += 1) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
    await user.tab({ shift: true });
    expect(dialog.contains(document.activeElement)).toBe(true);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(opener);
  });
});

describe("CopyValue", () => {
  it("labels the value's group, not the code element (ARIA prohibits naming code)", () => {
    render(
      <I18nContext.Provider value={{ locale: "sv", t: MESSAGES.sv, setLocale: () => undefined }}>
        <CopyValue label="SP-metadata" value="https://example.test/metadata" testId="sp" />
      </I18nContext.Provider>,
    );
    const group = screen.getByRole("group", { name: "SP-metadata" });
    const code = screen.getByTestId("sp-value");
    expect(group.contains(code)).toBe(true);
    expect(code.hasAttribute("aria-labelledby")).toBe(false);
    expect(code.textContent).toBe("https://example.test/metadata");
  });
});

describe("removing things", () => {
  const APP_ID = "5b0f3c8e-2d6a-4f1b-9e7c-3a8d1f2e4b60";
  const attached: TenantApplication = {
    applicationId: APP_ID,
    clientId: "bygglov",
    name: "Bygglov",
    enabled: true,
    applicationEnabled: true,
    representationMode: "none",
    roles: [{ role: "handlaggare", description: null }],
    attributeKeys: [],
    attachedAt: "2026-10-01T00:00:00.000Z",
    etag: '"ta1"',
  };
  const usage = {
    roleAssignments: 3,
    pendingRoleAssignments: 0,
    roleRules: 1,
    attributeAssignments: 0,
    pendingAttributeAssignments: 0,
    grantLimits: 0,
  };

  it("detaches an application only after the client ID is typed, listing what goes with it", async () => {
    const get = vi.fn((path: string) =>
      Promise.resolve(
        path.endsWith("/usage")
          ? usage
          : path === "/applications"
            ? { items: [] }
            : { items: [attached] },
      ),
    );
    const send = vi.fn().mockResolvedValue(usage);
    renderPage("applications", undefined, { get: get as ApiClient["get"], send });
    await userEvent.click(await screen.findByTestId("application-detach-bygglov"));
    const list = await screen.findByTestId("application-detach-usage");
    expect(list.textContent).toContain("3 rolltilldelningar");
    expect(list.textContent).toContain("1 regel");
    expect(list.textContent).not.toContain("attribut");
    const confirm = screen.getByTestId<HTMLButtonElement>("application-detach-dialog-confirm");
    expect(confirm.disabled).toBe(true);
    await userEvent.type(screen.getByTestId("application-detach-confirm-input"), "bygglo");
    expect(confirm.disabled).toBe(true);
    await userEvent.type(screen.getByTestId("application-detach-confirm-input"), "v");
    expect(confirm.disabled).toBe(false);
    await userEvent.click(confirm);
    expect(send).toHaveBeenCalledWith(
      "POST",
      `/tenants/${TENANT.id}/applications/${APP_ID}/detach`,
      { body: { confirmClientId: "bygglov" }, etag: '"ta1"' },
    );
  });

  it("offers disabling a login method that is still in use instead of deleting it", async () => {
    const get = vi.fn().mockResolvedValue(method('"v1"'));
    const send = vi
      .fn()
      .mockRejectedValueOnce(new ApiError(409, "in_use"))
      .mockResolvedValueOnce({ ...method('"v2"'), enabled: false });
    renderPage("login-methods", METHOD_ID, { get, send });
    await userEvent.click(await screen.findByTestId("delete-login-method"));
    await userEvent.click(screen.getByTestId("login-method-delete-dialog-confirm"));
    expect(send).toHaveBeenCalledWith(
      "DELETE",
      `/tenants/${TENANT.id}/login-methods/${METHOD_ID}`,
      { etag: '"v1"' },
    );
    expect((await screen.findByTestId("login-method-in-use")).textContent).toContain(
      MESSAGES.sv.errors.inUse,
    );
    await userEvent.click(screen.getByTestId("login-method-disable-instead"));
    expect(send).toHaveBeenLastCalledWith(
      "PATCH",
      `/tenants/${TENANT.id}/login-methods/${METHOD_ID}`,
      { body: { enabled: false }, etag: '"v1"' },
    );
    await waitFor(() => expect(screen.queryByTestId("login-method-delete-dialog")).toBeNull());
  });

  it("refuses unlinking a person's only identity and offers deleting the person", async () => {
    const PERSON_ID = "9c2e4a1b-7d3f-4e5a-8b6c-1f0e2d3c4b5a";
    const person: Person = {
      id: PERSON_ID,
      displayName: "Anna Andersson",
      email: null,
      protectedIdentity: false,
      createdAt: "2026-10-01T00:00:00.000Z",
      lastLoginAt: null,
      identities: [
        {
          id: "1d2c3b4a-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
          loginMethodId: METHOD_ID,
          loginMethodName: "Entra",
          kind: "employee",
          subject: "anna",
          hasPin: false,
          lastLoginAt: "2026-10-01T00:00:00.000Z",
        },
      ],
      roleAssignments: [],
      attributeAssignments: [],
      grants: [],
      etag: '"p1"',
    };
    const get = vi.fn().mockResolvedValue(person);
    const send = vi.fn().mockResolvedValue(undefined);
    const admin = renderPage("persons", PERSON_ID, { get, send });
    await userEvent.click(await screen.findByTestId(`unlink-identity-${person.identities[0]!.id}`));
    expect(screen.getByTestId("unlink-identity-dialog").textContent).toContain(
      MESSAGES.sv.persons.unlinkOnlyBody,
    );
    await userEvent.click(screen.getByTestId("unlink-identity-dialog-confirm"));
    expect(send).not.toHaveBeenCalled();
    expect(screen.getByTestId("delete-person-impact").textContent).toContain("1");
    await userEvent.click(screen.getByTestId("delete-person-dialog-confirm"));
    expect(send).toHaveBeenCalledWith("DELETE", `/tenants/${TENANT.id}/persons/${PERSON_ID}`, {
      etag: '"p1"',
    });
    await waitFor(() => expect(admin.go).toHaveBeenCalledWith("persons"));
  });

  it("signs a person out everywhere only after the confirmation, and reports the counts", async () => {
    const PERSON_ID = "4b3a2c1d-6e5f-4a7b-9c8d-2e1f0a3b4c5d";
    const person: Person = {
      id: PERSON_ID,
      displayName: "Bo Berg",
      email: null,
      protectedIdentity: false,
      createdAt: "2026-10-01T00:00:00.000Z",
      lastLoginAt: null,
      identities: [],
      roleAssignments: [],
      attributeAssignments: [],
      grants: [],
      etag: '"p2"',
    };
    const get = vi.fn().mockResolvedValue(person);
    const send = vi.fn().mockResolvedValue({ sessions: 2, grants: 3 });
    renderPage("persons", PERSON_ID, { get, send });
    await userEvent.click(await screen.findByTestId("end-sessions"));
    expect(screen.getByTestId("end-sessions-dialog").textContent).toContain(
      MESSAGES.sv.persons.endSessionsBody,
    );
    expect(send).not.toHaveBeenCalled();
    await userEvent.click(screen.getByTestId("end-sessions-dialog-confirm"));
    expect(send).toHaveBeenCalledWith(
      "POST",
      `/tenants/${TENANT.id}/persons/${PERSON_ID}/end-sessions`,
    );
    expect((await screen.findByTestId("end-sessions-done")).textContent).toBe(
      "Utloggad: 2 sessioner och 3 tjänstebehörigheter avslutades.",
    );
    expect(screen.queryByTestId("end-sessions-dialog")).toBeNull();
  });
});

describe("application editor", () => {
  it("edits serviceAudiences as one client ID per line and sends only what changed", async () => {
    const application: Application = {
      id: "6c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f",
      clientId: "service-c",
      name: "Tjänst C",
      enabled: true,
      clientAuth: { method: "client_secret_basic" },
      redirectUris: ["https://c.example.test/auth/callback"],
      postLogoutRedirectUris: [],
      roles: [],
      attributeKeys: [],
      allowedExtraScopes: [],
      serviceAudiences: ["service-a"],
      representationMode: "none",
      etag: '"a1"',
    };
    const send = vi.fn().mockResolvedValue({ application });
    const onSaved = vi.fn();
    const admin = {
      api: { slug: "system", session: vi.fn(), logout: vi.fn(), get: vi.fn(), send },
      me: { personId: "p", tenant: TENANT, platform: true, roles: ["platform-admin"] },
      tenant: TENANT,
      tenants: [TENANT],
      location: { slug: "system", page: "applications", id: undefined, tenant: undefined },
      go: vi.fn(),
      reloadTenants: vi.fn(() => Promise.resolve()),
    } as unknown as Admin;
    render(
      <I18nContext.Provider value={{ locale: "sv", t: MESSAGES.sv, setLocale: () => undefined }}>
        <AdminContext.Provider value={admin}>
          <ApplicationEditor application={application} onClose={vi.fn()} onSaved={onSaved} />
        </AdminContext.Provider>
      </I18nContext.Provider>,
    );
    const field = screen.getByTestId<HTMLTextAreaElement>("application-edit-service-audiences");
    expect(field.value).toBe("service-a");
    await userEvent.type(field, "{enter}archive-service");
    await userEvent.click(screen.getByTestId("application-edit-save"));
    expect(send).toHaveBeenCalledWith("PATCH", `/applications/${application.id}`, {
      body: { serviceAudiences: ["service-a", "archive-service"] },
      etag: '"a1"',
    });
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
  });
});
