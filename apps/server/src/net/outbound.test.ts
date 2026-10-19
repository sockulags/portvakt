import { execFile } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig } from "../config/index.js";
import { isSpecialUseAddress, OutboundGuard, OutboundRefusedError } from "./outbound.js";

let server: Server;
let port: number;

beforeAll(async () => {
  server = createServer((req, res) => {
    if (req.url === "/to-metadata") {
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" }).end();
    } else if (req.url === "/to-loopback") {
      res.writeHead(302, { location: `http://127.0.0.1:${port}/ok` }).end();
    } else if (req.url === "/loop") {
      res.writeHead(302, { location: "/loop" }).end();
    } else if (req.url === "/big") {
      res.writeHead(200).end("x".repeat(2048));
    } else {
      res.writeHead(200, { "content-type": "text/plain" }).end("ok");
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

const guard = (allowPrivateHosts: readonly string[] = [], production = false) =>
  new OutboundGuard({ production, allowPrivateHosts, timeoutSeconds: 5 });

const reasonOf = async (promise: Promise<unknown>): Promise<string | undefined> => {
  const error = await promise.catch((caught: unknown) => caught);
  return error instanceof OutboundRefusedError ? error.reason : `not refused: ${String(error)}`;
};

describe("outbound guard", () => {
  it("classifies special-use addresses", () => {
    for (const address of [
      "127.0.0.1",
      "10.1.2.3",
      "172.16.0.1",
      "192.168.1.1",
      "169.254.169.254",
      "100.64.0.1",
      "0.0.0.0",
      "224.0.0.1",
      "::1",
      "::",
      "fc00::1",
      "fd12:3456::1",
      "fe80::1",
      "ff02::1",
      "::ffff:127.0.0.1",
      "64:ff9b::7f00:1",
      "64:ff9b:1::1",
      "2002::1",
      "2002:7f00:1::1",
      "::127.0.0.1",
      "::7f00:1",
      "::a9fe:a9fe",
      "::8.8.8.8",
      "not-an-ip",
    ]) {
      expect(isSpecialUseAddress(address), address).toBe(true);
    }
    for (const address of ["8.8.8.8", "193.180.0.1", "2001:4860:4860::8888"]) {
      expect(isSpecialUseAddress(address), address).toBe(false);
    }
  });

  it("refuses loopback, private, link-local and metadata addresses, by literal or by name", async () => {
    const strict = guard();
    expect(await reasonOf(strict.fetch(`http://127.0.0.1:${port}/ok`))).toBe("special_use_address");
    expect(await reasonOf(strict.fetch("http://169.254.169.254/latest/meta-data/"))).toBe(
      "special_use_address",
    );
    expect(await reasonOf(strict.fetch("http://[::1]/"))).toBe("special_use_address");
    expect(await reasonOf(strict.fetch("http://10.0.0.1/"))).toBe("special_use_address");
    // A name resolving to loopback is refused where the connection is made.
    expect(await reasonOf(strict.fetch(`http://localhost:${port}/ok`))).toBe("special_use_address");
    expect(await reasonOf(strict.fetch("file:///etc/passwd"))).toBe("scheme");
  });

  it("allows listed hosts, checks every redirect hop again and caps hops and size", async () => {
    const local = guard(["localhost"]);
    expect(await (await local.fetch(`http://localhost:${port}/ok`)).text()).toBe("ok");
    expect(await reasonOf(local.fetch(`http://localhost:${port}/to-metadata`))).toBe(
      "special_use_address",
    );
    // 127.0.0.1 is not listed, only localhost: the redirect to it is refused.
    expect(await reasonOf(local.fetch(`http://localhost:${port}/to-loopback`))).toBe(
      "special_use_address",
    );
    expect(await reasonOf(local.fetch(`http://localhost:${port}/loop`))).toBe("too_many_redirects");
    expect(await reasonOf(local.fetch(`http://localhost:${port}/big`, { maxBytes: 1024 }))).toBe(
      "too_large",
    );
    // With redirect: "manual" the caller gets the redirect itself.
    const manual = await local.fetch(`http://localhost:${port}/to-metadata`, {
      redirect: "manual",
    });
    expect(manual.status).toBe(302);
  });

  it("requires https and no private allowlist in production", async () => {
    expect(() => guard(["localhost"], true)).toThrow(/refused in production/);
    expect(await reasonOf(guard([], true).fetch("http://example.org/"))).toBe("insecure_scheme");
    expect(() =>
      loadConfig({
        NODE_ENV: "production",
        PUBLIC_URL: "https://login.example.org",
        DATABASE_URL: "postgres://app:secret-value-1@db.example.org/portvakt",
        MIGRATION_DATABASE_URL: "postgres://owner:secret-value-2@db.example.org/portvakt",
        MASTER_KEY: Buffer.alloc(32, 7).toString("base64"),
        COOKIE_KEYS: "a-production-cookie-key-with-enough-length-0001",
        ALLOW_PRIVATE_UPSTREAM_HOSTS: "localhost",
      }),
    ).toThrow(/ALLOW_PRIVATE_UPSTREAM_HOSTS: refused in production/);
  });

  it("works constructed in isolation, in a fresh process (undici imported directly)", async () => {
    // Only this module is loaded in the child: nothing else of the server sets up undici first.
    const module = pathToFileURL(fileURLToPath(new URL("./outbound.ts", import.meta.url))).href;
    const script = [
      `const { OutboundGuard } = await import(${JSON.stringify(module)});`,
      'const guard = new OutboundGuard({ production: false, allowPrivateHosts: ["localhost"], timeoutSeconds: 5 });',
      `const ok = await (await guard.fetch("http://localhost:${port}/ok")).text();`,
      `const refused = await guard.fetch("http://127.0.0.1:${port}/ok").then(() => "accepted", (e) => e.reason);`,
      "console.log(JSON.stringify({ ok, refused }));",
    ].join("\n");
    const { stdout } = await promisify(execFile)(
      process.execPath,
      ["--conditions=portvakt-source", "--import", "tsx", "--input-type=module", "-e", script],
      { timeout: 30_000 },
    );
    expect(JSON.parse(stdout.trim())).toEqual({ ok: "ok", refused: "special_use_address" });
  });
});
