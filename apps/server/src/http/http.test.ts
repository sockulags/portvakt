import { HSTS } from "@portvakt/http-kit";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../app.js";
import { createLogger } from "../logging/logger.js";
import { basicClientId, bodyClientId } from "./client-id.js";
import { routeTemplate } from "./route-template.js";

describe("route templates", () => {
  it.each([
    ["/healthz", "/healthz"],
    ["/metrics", "/metrics"],
    ["/ui/login/assets/index-abc123.js", "/ui/login/{asset}"],
    ["/admin/api/v1/tenants/5f1c/applications", "/admin/api/v1/{other}"],
    ["/t/acme", "/t/{slug}"],
    ["/t/acme/.well-known/openid-configuration", "/t/{slug}/.well-known/openid-configuration"],
    ["/t/acme/auth", "/t/{slug}/auth"],
    ["/t/acme/auth/abc", "/t/{slug}/auth/{uid}"],
    ["/t/acme/token", "/t/{slug}/token"],
    ["/t/acme/token/revocation", "/t/{slug}/token/revocation"],
    ["/t/acme/interaction/u1", "/t/{slug}/interaction/{uid}"],
    ["/t/acme/interaction/u1/login", "/t/{slug}/interaction/{uid}/login"],
    [
      "/t/acme/interaction/u1/federation/complete",
      "/t/{slug}/interaction/{uid}/federation/complete",
    ],
    ["/t/acme/federation/5f1c/callback", "/t/{slug}/federation/{loginMethodId}/callback"],
    ["/t/acme/saml/5f1c/acs", "/t/{slug}/saml/{loginMethodId}/acs"],
    ["/t/acme/made-up/path", "/t/{slug}/{other}"],
    ["/wp-login.php", "other"],
  ])("maps %s to %s", (path, template) => {
    expect(routeTemplate(path)).toBe(template);
  });
});

describe("client ids for the token endpoint limit", () => {
  it("reads HTTP Basic (form-encoded) client ids", () => {
    const header = `Basic ${Buffer.from("my%3Aapp:secret").toString("base64")}`;
    expect(basicClientId(header)).toBe("my:app");
    expect(basicClientId(`Basic ${Buffer.from("app-1:s").toString("base64")}`)).toBe("app-1");
    expect(basicClientId("Bearer x")).toBeUndefined();
    expect(basicClientId(`Basic ${Buffer.from("no-colon").toString("base64")}`)).toBeUndefined();
    expect(basicClientId(undefined)).toBeUndefined();
  });

  it("reads client_id or the client assertion's sub from the body, without verifying", () => {
    expect(bodyClientId(new URLSearchParams({ client_id: "app-2" }))).toBe("app-2");
    const payload = Buffer.from(JSON.stringify({ iss: "app-3", sub: "app-3" })).toString(
      "base64url",
    );
    expect(bodyClientId(new URLSearchParams({ client_assertion: `e30.${payload}.sig` }))).toBe(
      "app-3",
    );
    expect(bodyClientId(new URLSearchParams({ client_assertion: "garbage" }))).toBeUndefined();
    expect(bodyClientId(new URLSearchParams({ client_id: "x".repeat(300) }))).toBeUndefined();
    expect(bodyClientId(new URLSearchParams())).toBeUndefined();
  });
});

describe("createApp hardening", () => {
  it("sends HSTS when the public URL is https", async () => {
    const app = createApp({
      logger: createLogger({ level: "silent" }),
      trustProxy: false,
      readiness: () => Promise.resolve({ ready: true, checks: {} }),
      hsts: true,
    });
    const res = await request(app).get("/healthz");
    expect(res.headers["strict-transport-security"]).toBe(HSTS);
  });
});
