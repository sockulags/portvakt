// @vitest-environment jsdom
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { MESSAGES } from "./i18n";
import type { Me, SessionInfo, Tenant } from "./types";

const t = MESSAGES.sv;

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
const ME: Me = { personId: "p-1", tenant: TENANT, platform: false, roles: ["tenant-admin"] };
const SIGNED_IN: SessionInfo = {
  authenticated: true,
  principal: { name: "Anna Admin", sub: "p-1", tenant: "demo" },
  csrfToken: "csrf",
};

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

/** The BFF: the session and `/me`; every other API call stays pending (pages show loading). */
function stubBff(session: SessionInfo = SIGNED_IN, me: Me | number = ME) {
  vi.stubGlobal(
    "fetch",
    vi.fn((input: string) => {
      const url = input;
      if (url.endsWith("/auth/session")) return Promise.resolve(json(session));
      if (url.endsWith("/api/me")) {
        return Promise.resolve(typeof me === "number" ? json({ code: "forbidden" }, me) : json(me));
      }
      return new Promise<Response>(() => undefined);
    }),
  );
}

function narrowScreen(narrow: boolean) {
  vi.stubGlobal(
    "matchMedia",
    vi.fn((query: string) => ({
      matches: narrow,
      media: query,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    })),
  );
}

beforeEach(() => {
  window.history.replaceState(null, "", "/t/demo/");
  narrowScreen(false);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("portal navigation", () => {
  it("moves focus to the new page's heading after navigating, and names the document", async () => {
    stubBff();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByTestId("portal");
    expect(document.title).toBe(`${t.nav.pages.overview} – ${t.brand}`);

    const nav = screen.getByRole("navigation", { name: t.nav.label });
    await user.click(within(nav).getByRole("button", { name: t.nav.pages.persons }));
    const heading = await screen.findByRole("heading", { level: 1, name: t.persons.title });
    expect(document.activeElement).toBe(heading);
    expect(document.title).toBe(`${t.nav.pages.persons} – ${t.brand}`);
  });

  it("keeps focus on the tenant switcher when it leaves a detail page", async () => {
    const system: Tenant = {
      ...TENANT,
      id: "0b1c2d3e-4f50-4617-8a9b-0c1d2e3f4a5b",
      slug: "system",
    };
    const other: Tenant = { ...TENANT, id: "1c2d3e4f-5061-4728-9b0c-1d2e3f4a5b6c", slug: "other" };
    const me: Me = { personId: "p-1", tenant: system, platform: true, roles: ["platform-admin"] };
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/auth/session")) return Promise.resolve(json(SIGNED_IN));
        if (url.endsWith("/api/me")) return Promise.resolve(json(me));
        if (url.endsWith("/api/tenants")) {
          return Promise.resolve(json({ items: [system, TENANT, other] }));
        }
        return new Promise<Response>(() => undefined);
      }),
    );
    window.history.replaceState(
      null,
      "",
      `/t/system/persons/2d3e4f50-6172-4839-8c1d-2e3f4a5b6c7d?tenant=${TENANT.id}`,
    );
    const user = userEvent.setup();
    render(<App />);
    const switcher = await screen.findByTestId<HTMLSelectElement>("tenant-switcher");
    await user.selectOptions(switcher, other.id);
    await waitFor(() => expect(window.location.search).toBe(`?tenant=${other.id}`));
    expect(window.location.pathname).toBe("/t/system/persons");
    expect(document.activeElement).toBe(screen.getByTestId("tenant-switcher"));
  });

  it("offers a skip link to the content as the first stop", async () => {
    stubBff();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByTestId("portal");
    await user.tab();
    const skip = screen.getByTestId("skip-to-content");
    expect(document.activeElement).toBe(skip);
    expect(skip.textContent).toBe(t.nav.skipToContent);
    await user.keyboard("{Enter}");
    expect(document.activeElement).toBe(screen.getByTestId("page-overview"));
  });

  it("translates the design system's fixed English labels", async () => {
    stubBff();
    render(<App />);
    await screen.findByTestId("portal");
    // The navbar's empty link navigation ("Main") is not a landmark of its own.
    expect(screen.queryByRole("navigation", { name: "Main" })).toBeNull();
    expect(screen.getAllByRole("navigation").map((nav) => nav.getAttribute("aria-label"))).toEqual([
      t.nav.label,
    ]);
  });
});

describe("narrow screens", () => {
  it("labels the menu button in Swedish, moves focus into the drawer and closes it with Escape", async () => {
    narrowScreen(true);
    stubBff();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByTestId("portal");
    const menu = screen.getByRole("button", { name: t.nav.openMenu });
    expect(screen.queryByRole("button", { name: "Open menu" })).toBeNull();

    await user.click(menu);
    const drawer = await screen.findByTestId("nav-drawer");
    await waitFor(() => expect(menu.getAttribute("aria-label")).toBe(t.nav.closeMenu));
    expect(menu.getAttribute("aria-controls")).toBe(drawer.id);
    expect(drawer.contains(document.activeElement)).toBe(true);

    await user.keyboard("{Escape}");
    expect(screen.queryByTestId("nav-drawer")).toBeNull();
    expect(document.activeElement).toBe(menu);
    await waitFor(() => expect(menu.getAttribute("aria-label")).toBe(t.nav.openMenu));
  });
});

describe("pages before the portal", () => {
  it("names the sign-in page", async () => {
    stubBff({ authenticated: false });
    render(<App />);
    await screen.findByTestId("sign-in-page");
    expect(document.title).toBe(`${t.auth.signInTitle} – ${t.brand}`);
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
  });

  it("gives the no-access page a heading and a title", async () => {
    stubBff(SIGNED_IN, 403);
    render(<App />);
    await screen.findByTestId("no-access-page");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(t.auth.noAccessTitle);
    expect(document.title).toBe(`${t.auth.noAccessTitle} – ${t.brand}`);
  });

  it("announces loading in Swedish only (the design system's spinner is hidden)", () => {
    stubBff();
    render(<App />);
    const statuses = screen.getAllByRole("status");
    expect(statuses.map((status) => status.textContent)).toEqual([t.common.loading]);
  });
});
