import { describe, expect, it, vi } from "vitest";
import { createLoginApi, createRepresentationApi, parseBootstrap } from "./api";

const locale = { uiLocales: ["en"], acceptLanguage: ["sv-SE"] };

describe("parseBootstrap", () => {
  it("reads every view", () => {
    expect(
      parseBootstrap(
        JSON.stringify({ view: "login", tenant: "t", uid: "u", error: "upstream_denied", locale }),
      ),
    ).toEqual({ view: "login", tenant: "t", uid: "u", error: "upstream_denied", locale });
    expect(
      parseBootstrap(JSON.stringify({ view: "error", code: "state_invalid", locale })),
    ).toEqual({
      view: "error",
      code: "state_invalid",
      locale,
    });
    expect(
      parseBootstrap(
        JSON.stringify({
          view: "representation",
          tenant: "t",
          uid: "u",
          error: "no_representation_available",
          locale,
        }),
      ),
    ).toEqual({
      view: "representation",
      tenant: "t",
      uid: "u",
      error: "no_representation_available",
      locale,
    });
    expect(parseBootstrap(JSON.stringify({ view: "logout" }))).toEqual({
      view: "logout",
      locale: { uiLocales: [], acceptLanguage: [] },
    });
  });

  it("refuses malformed blocks and unknown codes", () => {
    expect(parseBootstrap(null)).toBeNull();
    expect(parseBootstrap("{")).toBeNull();
    expect(parseBootstrap(JSON.stringify({ view: "login", tenant: "t" }))).toBeNull();
    expect(parseBootstrap(JSON.stringify({ view: "error", code: "<script>" }))).toMatchObject({
      code: "request_failed",
    });
    expect(
      parseBootstrap(JSON.stringify({ view: "login", tenant: "t", uid: "u", error: "nope" })),
    ).not.toHaveProperty("error");
  });
});

describe("createLoginApi", () => {
  it("posts choices with the CSRF token to the interaction", async () => {
    const fetchImpl = vi.fn<typeof fetch>(() =>
      Promise.resolve(Response.json({ redirectTo: "https://idp.example/auth" })),
    );
    const api = createLoginApi("tenant-a", "uid 1", fetchImpl);
    expect(await api.login({ loginMethodId: "m1" }, "tok")).toEqual({
      ok: true,
      redirectTo: "https://idp.example/auth",
    });
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("/t/tenant-a/interaction/uid%201/login");
    expect(init).toMatchObject({ method: "POST", body: JSON.stringify({ loginMethodId: "m1" }) });
    expect((init!.headers as Record<string, string>)["x-csrf-token"]).toBe("tok");
  });

  it("maps failures to error codes", async () => {
    const api = createLoginApi("t", "u", () =>
      Promise.resolve(Response.json({ error: "no_home_realm" }, { status: 404 })),
    );
    expect(await api.login({ email: "a@b.example" }, "tok")).toEqual({
      ok: false,
      error: "no_home_realm",
    });
    expect(await api.details()).toEqual({ ok: false, error: "interaction_expired" });
    const offline = createLoginApi("t", "u", () => Promise.reject(new TypeError("offline")));
    expect(await offline.details()).toEqual({ ok: false, error: "request_failed" });
  });
});

describe("createRepresentationApi", () => {
  it("reads the parties, keeps only masked identifiers, and posts the choice", async () => {
    let calls = 0;
    const fetchImpl = vi.fn<typeof fetch>(() =>
      Promise.resolve(
        (calls += 1) === 1
          ? Response.json({
              tenant: { name: "Kommunen" },
              application: { name: "Bygglov" },
              allowSelf: true,
              parties: [
                {
                  id: "p1",
                  type: "person",
                  name: "Sven",
                  identifier: { kind: "birth_date", value: "19121212" },
                },
                // A full number is not a date part: dropped, nothing is shown.
                {
                  id: "p2",
                  type: "person",
                  name: "Other",
                  identifier: { kind: "birth_date", value: "191212121212" },
                },
                { id: "p3", type: "robot", name: "Nope", identifier: null },
              ],
              csrfToken: "tok",
            })
          : Response.json({ redirectTo: "https://app.example/cb" }),
      ),
    );
    const api = createRepresentationApi("t", "u", fetchImpl);
    const details = await api.details();
    expect(details).toMatchObject({ ok: true });
    if (!details.ok) return;
    expect(details.details.parties).toEqual([
      {
        id: "p1",
        type: "person",
        name: "Sven",
        identifier: { kind: "birth_date", value: "19121212" },
      },
      { id: "p2", type: "person", name: "Other", identifier: null },
    ]);
    expect(await api.choose({ partyId: "p1" }, "tok")).toEqual({
      ok: true,
      redirectTo: "https://app.example/cb",
    });
    const [url, init] = fetchImpl.mock.calls[1]!;
    expect(url).toBe("/t/t/interaction/u/representation");
    expect(init).toMatchObject({ method: "POST", body: JSON.stringify({ partyId: "p1" }) });
  });
});
