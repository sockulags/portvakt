import { describe, expect, it } from "vitest";
import { parseChangeEvent } from "./change-events.js";

describe("parseChangeEvent", () => {
  const tenantId = "5f1c4b8e-0000-4000-8000-000000000001";

  it("accepts the known events", () => {
    expect(parseChangeEvent(JSON.stringify({ type: "tenant", tenantId }))).toEqual({
      type: "tenant",
      tenantId,
    });
    expect(parseChangeEvent('{"type":"signing_keys"}')).toEqual({ type: "signing_keys" });
  });

  it.each([
    undefined,
    "",
    "not json",
    "{}",
    '{"type":"tenant"}',
    '{"type":"tenant","tenantId":"x"}',
  ])("rejects %j", (payload) => {
    expect(parseChangeEvent(payload)).toBeNull();
  });
});
