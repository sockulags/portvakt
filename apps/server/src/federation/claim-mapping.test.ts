import { describe, expect, it } from "vitest";
import { claimMappingSchema } from "../domain/login-method.js";
import { mapUpstreamClaims, readClaim } from "./claim-mapping.js";

const PIN_CLAIM = "https://id.oidc.se/claim/personalIdentityNumber";

describe("upstream claim mapping", () => {
  const entra = claimMappingSchema.parse({
    subject: "oid",
    name: "name",
    email: "email",
    groups: "groups",
  });
  const bankid = claimMappingSchema.parse({
    subject: "sub",
    name: "name",
    pin: PIN_CLAIM,
    acr: "acr",
    protectedIdentity: "protected_identity",
  });

  it("maps an employee with groups and keeps the upstream amr", () => {
    const mapped = mapUpstreamClaims(entra, {
      sub: "pairwise",
      oid: "0b8f1c2e-7d1a-4a43-9a4e-2f7f7c1d9a01",
      name: " Anna Andersson ",
      email: "anna@kommun.example",
      groups: ["g1", "g1", "g2", 7],
      amr: ["pwd", "mfa", "not valid!"],
      email_verified: true,
    });
    expect(mapped).toEqual({
      subject: "0b8f1c2e-7d1a-4a43-9a4e-2f7f7c1d9a01",
      attributes: {
        name: "Anna Andersson",
        email: "anna@kommun.example",
        groups: ["g1", "g2", "7"],
        protectedIdentity: false,
      },
      pin: undefined,
      upstreamAcr: undefined,
      groupsOverage: false,
      amr: ["pwd", "mfa"],
    });
  });

  it("maps email only when verified upstream or the upstream is trusted for email", () => {
    const claims = { oid: "x", email: "anna@kommun.example" };
    const emailOf = (mapped: ReturnType<typeof mapUpstreamClaims>) =>
      typeof mapped === "string" ? undefined : mapped.attributes.email;
    expect(emailOf(mapUpstreamClaims(entra, claims))).toBeUndefined();
    expect(emailOf(mapUpstreamClaims(entra, { ...claims, email_verified: false }))).toBeUndefined();
    expect(emailOf(mapUpstreamClaims(entra, { ...claims, email_verified: "true" }))).toBe(
      "anna@kommun.example",
    );
    expect(emailOf(mapUpstreamClaims(entra, claims, { trustEmail: true }))).toBe(
      "anna@kommun.example",
    );
  });

  it('flags protected identity for true, "true", 1 and "1" only', () => {
    const flagged = (value: unknown) => {
      const mapped = mapUpstreamClaims(bankid, { sub: "c", protected_identity: value });
      return typeof mapped === "string" ? undefined : mapped.attributes.protectedIdentity;
    };
    for (const value of [true, "true", 1, "1"]) expect(flagged(value)).toBe(true);
    for (const value of [false, "false", 0, "0", "yes", 2, null, undefined, {}]) {
      expect(flagged(value)).toBe(false);
    }
  });

  it("treats a groups overage as no groups", () => {
    const mapped = mapUpstreamClaims(entra, {
      oid: "x",
      _claim_names: { groups: "src1" },
      _claim_sources: {
        src1: { endpoint: "https://graph.microsoft.com/v1.0/me/getMemberObjects" },
      },
    });
    expect(mapped).toMatchObject({ groupsOverage: true, attributes: { groups: [] } });
  });

  it("normalises the personal identity number and reads URI claim names", () => {
    const mapped = mapUpstreamClaims(bankid, {
      sub: "citizen-1",
      [PIN_CLAIM]: "191212121212",
      acr: "http://id.elegnamnden.se/loa/1.0/loa3",
      protected_identity: true,
    });
    expect(mapped).toMatchObject({
      subject: "citizen-1",
      pin: "191212121212",
      upstreamAcr: "http://id.elegnamnden.se/loa/1.0/loa3",
      attributes: { protectedIdentity: true },
      amr: ["fed"],
    });
    expect(mapUpstreamClaims(bankid, { sub: "c", [PIN_CLAIM]: "191212121213" })).toBe(
      "invalid_pin",
    );
  });

  it("requires a subject", () => {
    expect(mapUpstreamClaims(entra, { sub: "only-sub" })).toBe("missing_subject");
  });

  it("reads dotted paths into nested claims", () => {
    expect(readClaim({ realm_access: { roles: ["a"] } }, "realm_access.roles")).toEqual(["a"]);
    expect(readClaim({ a: "x" }, "a.b")).toBeUndefined();
  });
});
