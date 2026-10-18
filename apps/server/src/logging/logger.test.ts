import { describe, expect, it } from "vitest";
import { createLogger, serializeError } from "./logger.js";

function capture() {
  const lines: Record<string, unknown>[] = [];
  const logger = createLogger({
    level: "info",
    destination: { write: (line: string) => void lines.push(JSON.parse(line) as never) },
  });
  return { logger, lines };
}

describe("logger", () => {
  it("writes one JSON object per line with level, time and service", () => {
    const { logger, lines } = capture();
    logger.info({ tenant: "acme" }, "hello");
    expect(lines[0]).toMatchObject({
      level: "info",
      service: "portvakt",
      tenant: "acme",
      msg: "hello",
    });
    expect(typeof lines[0]?.time).toBe("string");
  });

  it("redacts credentials, tokens and personal data that slip into a log call", () => {
    const { logger, lines } = capture();
    logger.info(
      {
        req: { headers: { authorization: "Bearer abc", cookie: "_pv_session=x" } },
        body: { client_secret: "s3cret", refresh_token: "rt", code: "c", email: "a@b.se" },
      },
      "request",
    );
    const output = JSON.stringify(lines[0]);
    for (const value of ["Bearer abc", "_pv_session=x", "s3cret", '"rt"', '"c"', "a@b.se"]) {
      expect(output).not.toContain(value);
    }
    expect(output).toContain("[redacted]");
  });

  it("serializes errors without database row details", () => {
    const error = Object.assign(new Error("duplicate key value violates unique constraint"), {
      code: "23505",
      detail: "Key (email)=(someone@example.org) already exists.",
      where: "SQL statement",
    });
    const serialized = serializeError(new Error("wrapped", { cause: error }));
    expect(serialized).toMatchObject({
      type: "Error",
      message: "wrapped",
      cause: { code: "23505", message: "duplicate key value violates unique constraint" },
    });
    expect(JSON.stringify(serialized)).not.toContain("someone@example.org");
    expect(serializeError("text")).toEqual({ type: "string", message: "non-error thrown" });
  });
});

describe("key redaction at any depth", () => {
  it("censors listed keys at the top level and deep inside objects and arrays", () => {
    const { logger, lines } = capture();
    logger.info(
      {
        email: "top@example.org",
        token: "top-token",
        outer: { middle: { inner: { Password: "deep-secret", client_secret: "cs" } } },
        list: [{ refresh_token: "in-array" }],
        kept: { event: "grant.error", count: 3 },
      },
      "deep",
    );
    const line = lines[0]!;
    const output = JSON.stringify(line);
    for (const value of ["top@example.org", "top-token", "deep-secret", '"cs"', "in-array"]) {
      expect(output).not.toContain(value);
    }
    expect(line.email).toBe("[redacted]");
    expect(line.outer).toEqual({
      middle: { inner: { Password: "[redacted]", client_secret: "[redacted]" } },
    });
    expect(line.kept).toEqual({ event: "grant.error", count: 3 });
  });

  it("keeps OAuth error codes and the code of serialized errors", () => {
    const { logger, lines } = capture();
    logger.info({ error: "invalid_grant" }, "refused");
    logger.error({ err: Object.assign(new Error("boom"), { code: "23505" }) }, "failed");
    expect(lines[0]?.error).toBe("invalid_grant");
    expect(lines[1]?.err).toMatchObject({ code: "23505", message: "boom" });
  });
});
