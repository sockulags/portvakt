import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DestinationStream } from "pino";
import type { AddressInfo } from "node:net";
import { afterAll } from "vitest";
import { loadConfig, type Config } from "../config/index.js";
import { createLogger } from "../logging/logger.js";
import { createPortvakt, type Portvakt } from "../server.js";
import { setupTestDatabase, testMasterKeys, type TestDatabase } from "./test-database.js";

/**
 * A running Portvakt for integration tests: a private test schema (see `setupTestDatabase`),
 * the real app on an ephemeral port of 127.0.0.1, `PUBLIC_URL` pointing at it, and NODE_ENV=test
 * (so the test-only login route is mounted). Shut down and cleaned up after the file.
 */
export interface TestServer {
  readonly db: TestDatabase;
  readonly config: Config;
  readonly portvakt: Portvakt;
  readonly server: Server;
  /** `http://127.0.0.1:{port}` */
  readonly baseUrl: string;
  issuerOf(slug: string): string;
}

export const TEST_COOKIE_KEYS = [
  "test-cookie-key-0123456789abcdef0123456789",
  "test-cookie-key-previous-0123456789abcdef",
];

let loginUiFixture: string | undefined;

/**
 * A minimal login UI build (an `index.html` shell) for integration tests, so they do not depend
 * on whether apps/login was built (CI tests before it builds). Removed after the test file.
 */
export function testLoginUiDir(): string {
  if (loginUiFixture === undefined) {
    const dir = mkdtempSync(join(tmpdir(), "portvakt-login-ui-"));
    writeFileSync(
      join(dir, "index.html"),
      [
        "<!doctype html>",
        '<html lang="sv">',
        '<head><meta charset="utf-8"><title>Logga in</title></head>',
        '<body><div id="root"></div></body>',
        "</html>",
      ].join("\n"),
    );
    loginUiFixture = dir;
    afterAll(() => {
      rmSync(dir, { recursive: true, force: true });
      loginUiFixture = undefined;
    });
  }
  return loginUiFixture;
}

export interface TestServerOptions {
  /** Extra environment for `loadConfig`. */
  readonly env?: Readonly<Record<string, string>>;
  /** Captures the server's log output (level from TEST_LOG_LEVEL, else trace when given). */
  readonly logDestination?: DestinationStream;
}

export async function startTestServer(
  options: TestServerOptions = {},
): Promise<TestServer | undefined> {
  const db = await setupTestDatabase();
  if (db === undefined) return undefined;

  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  const config = loadConfig({
    NODE_ENV: "test",
    PORT: String(port),
    PUBLIC_URL: baseUrl,
    DATABASE_URL: db.url,
    MIGRATION_DATABASE_URL: db.migrationUrl,
    MASTER_KEY: testMasterKeys.current.toString("base64"),
    MASTER_KEY_PREVIOUS: testMasterKeys.previous.map((key) => key.toString("base64")).join(","),
    COOKIE_KEYS: TEST_COOKIE_KEYS.join(","),
    SHUTDOWN_DRAIN_DELAY: "0",
    // The mock IdP and the test server itself are on loopback.
    ALLOW_PRIVATE_UPSTREAM_HOSTS: "127.0.0.1,localhost",
    LOGIN_UI_DIR: testLoginUiDir(),
    LOG_LEVEL:
      process.env.TEST_LOG_LEVEL ?? (options.logDestination === undefined ? "silent" : "trace"),
    ...options.env,
  });
  const logger = createLogger({
    level: config.logLevel,
    ...(options.logDestination === undefined ? {} : { destination: options.logDestination }),
  });
  const portvakt = createPortvakt({
    config,
    pool: db.pool,
    logger,
    keys: db.keys,
  });
  portvakt.serve(server);
  // Registered after the database cleanup hook, so it runs before it (hooks run as a stack).
  afterAll(async () => {
    await portvakt.shutdown();
  });
  await portvakt.start();
  return {
    db,
    config,
    portvakt,
    server,
    baseUrl,
    issuerOf: (slug) => `${baseUrl}/t/${slug}`,
  };
}

interface StoredCookie {
  readonly host: string;
  readonly name: string;
  readonly value: string;
  readonly path: string;
}

/**
 * A minimal browser for the front-channel part of the code flow: follows nothing by itself,
 * keeps host-only cookies per host (with port, so Portvakt and the mock IdP on two ports of
 * 127.0.0.1 stay apart), name and path, and sends the ones whose host and path match.
 */
export class TestBrowser {
  readonly #cookies = new Map<string, StoredCookie>();

  /**
   * Sends a request without following redirects and records the cookies it sets.
   * `sendCookies: false` models a cross-site POST, where browsers send no SameSite=Lax cookie.
   */
  async request(
    url: string,
    init: RequestInit = {},
    options: { readonly sendCookies?: boolean } = {},
  ): Promise<Response> {
    const target = new URL(url);
    const headers = new Headers(init.headers);
    const cookie = this.#cookieHeader(target.host, target.pathname);
    if (cookie !== "" && options.sendCookies !== false) headers.set("cookie", cookie);
    const response = await fetch(target, { ...init, headers, redirect: "manual" });
    for (const header of response.headers.getSetCookie()) {
      this.#store(header, target.host, target.pathname);
    }
    return response;
  }

  /** The redirect target of a 3xx response, resolved against the request URL. */
  static location(response: Response, base: string): string {
    const location = response.headers.get("location");
    if (location === null || response.status < 300 || response.status >= 400) {
      throw new Error(`Expected a redirect, got ${response.status}`);
    }
    return new URL(location, base).href;
  }

  /** Drops every cookie of a host (`host:port`), as if that site's data were cleared. */
  forgetHost(host: string): void {
    for (const [key, cookie] of this.#cookies) {
      if (cookie.host === host) this.#cookies.delete(key);
    }
  }

  cookieNames(): string[] {
    return [...this.#cookies.values()].map((cookie) => `${cookie.name}@${cookie.path}`);
  }

  #cookieHeader(host: string, path: string): string {
    return [...this.#cookies.values()]
      .filter((cookie) => cookie.host === host && pathMatches(path, cookie.path))
      .map((cookie) => `${cookie.name}=${cookie.value}`)
      .join("; ");
  }

  #store(header: string, host: string, requestPath: string): void {
    const [pair = "", ...attributes] = header.split(";").map((part) => part.trim());
    const separator = pair.indexOf("=");
    if (separator <= 0) return;
    const name = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    let path = requestPath.slice(0, requestPath.lastIndexOf("/")) || "/";
    let expired = value === "";
    for (const attribute of attributes) {
      const [key = "", attributeValue = ""] = attribute.split("=");
      const lower = key.toLowerCase();
      if (lower === "path") path = attributeValue;
      if (lower === "max-age" && Number(attributeValue) <= 0) expired = true;
      if (lower === "expires" && new Date(attributeValue).getTime() <= Date.now()) expired = true;
    }
    const key = `${host}|${name}@${path}`;
    if (expired) this.#cookies.delete(key);
    else this.#cookies.set(key, { host, name, value, path });
  }
}

function pathMatches(requestPath: string, cookiePath: string): boolean {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith("/") || requestPath[cookiePath.length] === "/";
}
