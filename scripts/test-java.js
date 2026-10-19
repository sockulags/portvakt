// @ts-check
/**
 * `npm run test:java`: the Java SDK's build and tests (sdk-java, examples/demo-service-java)
 * against a real Portvakt, on Windows, macOS and Linux. No local JDK: Maven runs in Docker.
 *
 * 1. Postgres (`npm run db:up`), a fresh database `portvakt_java_test`, migrations;
 * 2. the login UI build when missing (`--build` forces it);
 * 3. the mock IdP on :4900 and the dev seed (tenant `demo` with service-c, the Java demo, plus
 *    the isolation tenant `demo-isolation`, and service-d with private_key_jwt and a key made for
 *    this run), then Portvakt on :3900;
 * 4. `mvn -C verify` (strict checksums) in the `maven` container of deploy/images.Dockerfile
 *    (maven:3.9-eclipse-temurin-21, pinned by digest; dependencies cached in the
 *    named volume `portvakt-m2`, or in the host directory PORTVAKT_M2_DIR when set, as in CI),
 *    with the URLs as system properties;
 * 5. everything it started is stopped again (the database keeps running: `npm run db:down`).
 *
 * Networking: Portvakt, the mock IdP and Postgres (:5433, the JDBC token store tests) run on the host and are reached at the same URL from
 * the host and from the container: http://localhost:3900 and http://localhost:4900. Inside the
 * container `scripts/java-test/PortForward.java` listens on those localhost ports and forwards
 * to the Docker host (`host.docker.internal`, built into Docker Desktop and mapped with
 * `--add-host=host.docker.internal:host-gateway` on Linux). This avoids depending on
 * host.docker.internal resolving on the host itself (Docker Desktop writes a LAN address into
 * the hosts file that goes stale when the network changes) and on Docker Desktop's optional host
 * networking. The Java demo runs inside the container on localhost:3300, the redirect URI the
 * seed registers for service-c.
 *
 * Options: `--build` (rebuild the login UI) and `--keep` (leave Portvakt and the mock IdP
 * running after the tests); every other argument goes to Maven, for example
 * `npm run test:java -- -pl portvakt-sdk-core`.
 */
import { spawn, spawnSync } from "node:child_process";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import { image } from "./images.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const isWindows = process.platform === "win32";
const isLinux = process.platform === "linux";
const npmCli = process.env.npm_execpath;
const npmDirect = npmCli !== undefined && /.c?js$/.test(npmCli) && existsSync(npmCli);
const OWN_OPTIONS = ["--build", "--keep"];
const args = process.argv.slice(2).filter((arg) => arg !== "--");
const mavenArgs = args.filter((arg) => !OWN_OPTIONS.includes(arg));
const forceBuild = args.includes("--build");
const keep = args.includes("--keep");

/** maven:3.9-eclipse-temurin-21, pinned by digest in deploy/images.Dockerfile. */
const IMAGE = image("maven");
const M2_VOLUME = "portvakt-m2";
/** A host directory for the Maven repository instead of the named volume (CI caches it). */
const M2_DIR = process.env.PORTVAKT_M2_DIR;
const CONTAINER = "portvakt-java-test-maven";
const PORTS = { portvakt: 3900, mockIdp: 4900 };
const PORTVAKT_URL = `http://localhost:${PORTS.portvakt}`;
const MOCK_IDP_URL = `http://localhost:${PORTS.mockIdp}`;
const DATABASE = "portvakt_java_test";
const DB_HOST = "localhost:5433";
const SERVICE_C_SECRET = "dev-only-service-c-client-secret-0123456789";
const ISOLATION_TENANT = "demo-isolation";
const DB_PORT = 5433;

/** service-d's key (private_key_jwt): new for every run; the seed registers its public part. */
const serviceDKey = (() => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const kid = `service-d-${randomUUID()}`;
  const jwk = { ...privateKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" };
  const { d: _d, ...publicJwk } = jwk;
  void _d;
  return { privateJwk: JSON.stringify(jwk), publicJwk: JSON.stringify(publicJwk) };
})();

/**
 * The development values of .env.example, overridden for the test stack.
 * @returns {NodeJS.ProcessEnv}
 */
function environment() {
  const example = parseEnv(readFileSync(join(root, ".env.example"), "utf8"));
  /** @type {NodeJS.ProcessEnv} */
  const env = { ...process.env };
  for (const [key, value] of Object.entries(example)) {
    if (value !== "") env[key] = value;
  }
  return {
    ...env,
    NODE_ENV: "development",
    LOG_LEVEL: "warn",
    PORT: String(PORTS.portvakt),
    PUBLIC_URL: PORTVAKT_URL,
    DATABASE_URL: `postgres://portvakt_app:portvakt_app@${DB_HOST}/${DATABASE}`,
    MIGRATION_DATABASE_URL: `postgres://portvakt:portvakt@${DB_HOST}/${DATABASE}`,
    ALLOW_PRIVATE_UPSTREAM_HOSTS: "localhost,127.0.0.1",
    MIGRATE_ON_START: "false",
    SHUTDOWN_DRAIN_DELAY: "0s",
    // The integration tests sign in from 127.0.0.1 many times a minute: raised per-IP limits.
    RATE_LIMIT_AUTHORIZE_IP: "10000/1m",
    RATE_LIMIT_INTERACTION_IP: "10000/1m",
    RATE_LIMIT_FEDERATION_IP: "10000/1m",
    RATE_LIMIT_TOKEN_IP: "10000/1m",
    RATE_LIMIT_TOKEN_CLIENT: "10000/1m",
  };
}

const env = environment();

/** @type {Map<string, import("node:child_process").ChildProcess>} */
const children = new Map();
let stopping = false;

/**
 * @param {string} name
 * @param {string[]} args
 * @param {NodeJS.ProcessEnv} childEnv
 * @param {boolean} detached
 */
function spawnNpm(name, args, childEnv, detached) {
  const [command, commandArgs] = npmDirect
    ? [process.execPath, [/** @type {string} */ (npmCli), ...args]]
    : [isWindows ? "npm.cmd" : "npm", args];
  const child = spawn(command, commandArgs, {
    cwd: root,
    env: childEnv,
    shell: !npmDirect && isWindows,
    detached: detached && !isWindows,
    stdio: ["ignore", "pipe", "pipe"],
  });
  pipeOutput(name, child);
  return child;
}

/** @param {string} name @param {import("node:child_process").ChildProcess} child */
function pipeOutput(name, child) {
  const prefix = (/** @type {Buffer} */ chunk) =>
    chunk
      .toString()
      .split(/\r?\n/)
      .filter((line) => line.trim() !== "")
      .map((line) => `[${name}] ${line}`)
      .join("\n");
  child.stdout?.on("data", (chunk) => console.log(prefix(chunk)));
  child.stderr?.on("data", (chunk) => console.error(prefix(chunk)));
}

/** Runs a one-off npm step to completion; stops everything when it fails. */
async function step(/** @type {string} */ name, /** @type {string[]} */ args, childEnv = env) {
  console.log(`[test-java] ${name}: npm ${args.join(" ")}`);
  const child = spawnNpm(name, args, childEnv, false);
  const code = await new Promise((resolve) => child.on("exit", resolve));
  if (code !== 0) {
    console.error(`[test-java] ${name} failed (exit code ${String(code)})`);
    await stopAll(1);
  }
}

/** Starts a long-running npm process; the run fails when it exits early. */
function service(/** @type {string} */ name, /** @type {string[]} */ args, childEnv = env) {
  console.log(`[test-java] starting ${name}: npm ${args.join(" ")}`);
  const child = spawnNpm(name, args, childEnv, true);
  children.set(name, child);
  child.on("exit", (code) => {
    children.delete(name);
    if (!stopping) {
      console.error(`[test-java] ${name} exited (code ${String(code)}); stopping`);
      void stopAll(1);
    }
  });
}

/** Polls a URL until it answers 2xx. */
async function waitFor(/** @type {string} */ name, /** @type {string} */ url, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (stopping) return;
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2000) });
      if (response.ok) {
        console.log(`[test-java] ${name} is up (${url})`);
        return;
      }
    } catch {
      // Not listening yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  console.error(`[test-java] ${name} did not answer ${url} within ${timeoutMs / 1000} s`);
  await stopAll(1);
}

/** A fresh, empty test database (dropped and created again by the owner role, with psql). */
async function recreateDatabase() {
  console.log(`[test-java] database ${DATABASE}: recreating`);
  const result = spawnSync(
    "docker",
    [
      "compose",
      "-f",
      "deploy/docker-compose.dev.yml",
      "exec",
      "-T",
      "postgres",
      "psql",
      "-v",
      "ON_ERROR_STOP=1",
      "-U",
      "portvakt",
      "-d",
      "portvakt",
      "-c",
      `DROP DATABASE IF EXISTS ${DATABASE} WITH (FORCE)`,
      "-c",
      `CREATE DATABASE ${DATABASE} OWNER portvakt`,
    ],
    { cwd: root, encoding: "utf8" },
  );
  if (result.status !== 0) {
    console.error(
      `[test-java] creating ${DATABASE} failed: ${result.stderr || result.error?.message}`,
    );
    await stopAll(1);
  }
}

function kill(/** @type {import("node:child_process").ChildProcess} */ child) {
  if (child.pid === undefined || child.exitCode !== null) return;
  if (isWindows) {
    spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
  } else {
    try {
      process.kill(-child.pid, "SIGTERM");
    } catch {
      child.kill("SIGTERM");
    }
  }
}

async function stopAll(code = 0) {
  if (stopping) return;
  stopping = true;
  spawnSync("docker", ["rm", "-f", CONTAINER], { stdio: "ignore" });
  const running = [...children.values()];
  const exited = running.map(
    (child) =>
      new Promise((resolve) =>
        child.exitCode === null ? child.on("exit", resolve) : resolve(undefined),
      ),
  );
  for (const child of running) kill(child);
  await Promise.race([Promise.all(exited), new Promise((resolve) => setTimeout(resolve, 10_000))]);
  process.exit(code);
}

process.on("SIGINT", () => void stopAll(130));
process.on("SIGTERM", () => void stopAll(143));
if (!isWindows) process.on("SIGHUP", () => void stopAll(129));

/** `mvn verify` in the Maven container; resolves with its exit code. */
function runMaven() {
  const uid = typeof process.getuid === "function" ? process.getuid() : 0;
  const gid = typeof process.getgid === "function" ? process.getgid() : 0;
  const properties = [
    "-Dportvakt.it.required=true",
    `-Dportvakt.it.issuer=${PORTVAKT_URL}/t/demo`,
    `-Dportvakt.it.isolation-issuer=${PORTVAKT_URL}/t/${ISOLATION_TENANT}`,
    `-Dportvakt.it.client-secret=${SERVICE_C_SECRET}`,
    `-Dportvakt.it.mock-idp=${MOCK_IDP_URL}`,
    `-Dportvakt.it.private-jwk=${serviceDKey.privateJwk}`,
    `-Dportvakt.it.jdbc-url=jdbc:postgresql://localhost:${DB_PORT}/${DATABASE}`,
  ];
  const quote = (/** @type {string} */ value) => `'${value.replace(/'/g, "'\\''")}'`;
  // -C: a download whose checksum does not match fails the build instead of a warning.
  const mvn = ["mvn", "-B", "-ntp", "-C", "verify", ...properties, ...mavenArgs]
    .map(quote)
    .join(" ");
  const script = [
    "set -u",
    `java /workspace/scripts/java-test/PortForward.java host.docker.internal ${PORTS.portvakt} ${PORTS.mockIdp} ${DB_PORT} > /tmp/forward.log 2>&1 &`,
    "for i in $(seq 1 150); do grep -q ready /tmp/forward.log && break; sleep 0.2; done",
    "grep -q ready /tmp/forward.log || { cat /tmp/forward.log; exit 1; }",
    `curl -sf ${PORTVAKT_URL}/readyz > /dev/null || { echo 'Portvakt is not reachable from the container'; exit 1; }`,
    `${mvn}; status=$?`,
    // Linux: the build output belongs to the user who ran the tests, not to root.
    ...(isLinux
      ? [
          `chown -R ${uid}:${gid} /workspace/sdk-java /workspace/examples/demo-service-java${M2_DIR === undefined ? "" : " /root/.m2"} 2>/dev/null || true`,
        ]
      : []),
    "exit $status",
  ].join("\n");
  const args = [
    "run",
    "--rm",
    "--name",
    CONTAINER,
    ...(isLinux ? ["--add-host=host.docker.internal:host-gateway"] : []),
    "-v",
    `${root.replace(/[\\/]$/, "")}:/workspace`,
    "-v",
    `${M2_DIR ?? M2_VOLUME}:/root/.m2`,
    "-w",
    "/workspace/sdk-java",
    IMAGE,
    "sh",
    "-c",
    script,
  ];
  console.log(`[test-java] maven: docker run ${IMAGE} mvn verify ${mavenArgs.join(" ")}`);
  // Git Bash on Windows would rewrite the /workspace paths: no path conversion.
  const child = spawn("docker", args, {
    cwd: root,
    env: { ...process.env, MSYS_NO_PATHCONV: "1" },
    stdio: ["ignore", "inherit", "inherit"],
  });
  return new Promise((resolve) => child.on("exit", (code) => resolve(code ?? 1)));
}

async function main() {
  await step("db", ["run", "db:up"]);
  await recreateDatabase();
  if (forceBuild || !existsSync(join(root, "apps/login/dist/index.html"))) {
    await step("login-ui", ["run", "build", "-w", "apps/login"]);
  }
  await step("migrate", ["run", "migrate", "-w", "apps/server"]);

  const mockClients = ["entra", "bankid"].map((issuer) => ({
    issuer,
    client_id: "portvakt-dev",
    client_secret:
      env[`MOCK_IDP_${issuer.toUpperCase()}_CLIENT_SECRET`] ?? `dev-only-${issuer}-client-secret`,
    redirect_uri_prefixes: [`${PORTVAKT_URL}/t/`],
  }));
  service("mock-idp", ["run", "start", "-w", "apps/mock-idp"], {
    ...env,
    MOCK_IDP_PORT: String(PORTS.mockIdp),
    MOCK_IDP_PUBLIC_URL: MOCK_IDP_URL,
    MOCK_IDP_CLIENTS: JSON.stringify(mockClients),
  });
  await waitFor("mock-idp", `${MOCK_IDP_URL}/healthz`);

  await step("seed", ["run", "seed:dev", "-w", "apps/server"], {
    ...env,
    MOCK_IDP_PUBLIC_URL: MOCK_IDP_URL,
    DEMO_SERVICE_C_URL: "http://localhost:3300",
    DEMO_SERVICE_C_CLIENT_SECRET: SERVICE_C_SECRET,
    DEMO_SERVICE_D_URL: "http://localhost:3301",
    DEMO_SERVICE_D_PUBLIC_JWK: serviceDKey.publicJwk,
    SEED_ISOLATION_TENANT: ISOLATION_TENANT,
  });

  service("portvakt", ["run", "start", "-w", "apps/server"], env);
  await waitFor("portvakt", `${PORTVAKT_URL}/readyz`);

  const code = await runMaven();
  console.log(`[test-java] maven finished (exit code ${code})`);
  if (keep) {
    console.log(
      `[test-java] --keep: Portvakt ${PORTVAKT_URL}, mock IdP ${MOCK_IDP_URL}; Ctrl+C stops them`,
    );
    return;
  }
  await stopAll(code);
}

main().catch((error) => {
  console.error("[test-java] failed:", error instanceof Error ? error.message : error);
  void stopAll(1);
});
