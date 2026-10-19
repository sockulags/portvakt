// @ts-check
/**
 * `npm run test:e2e`: the Playwright end-to-end suite (e2e/) over the whole stack, on Windows,
 * macOS and Linux. Plain Node, no shell syntax.
 *
 * 1. Postgres (`npm run db:up`), a fresh database `portvakt_e2e`, migrations;
 * 2. the login UI, demo SPA and admin SPA builds (skipped with `--no-build`, as in CI after
 *    `npm run build`), and the Java demo's build in the Maven container, started at once
 *    because it takes longest (dependencies cached in the named volume `portvakt-m2`, or the host
 *    directory PORTVAKT_M2_DIR as in CI);
 * 3. the mock IdP (:4800, the default personas plus e2e/personas.e2e.json), the dev seed, Portvakt
 *    (:3800), the demo as Tjänst A (:3810) and Tjänst B (:3820), the admin portal (:3840) and the
 *    Java demo Tjänst C (:3830, in the container; networking as in scripts/test-java.js);
 * 4. Chromium (`playwright install chromium`, a no-op when present), then `playwright test`
 *    with the URLs in E2E_* variables; every other argument goes to Playwright
 *    (`npm run test:e2e -- --grep "Scenario 4"`, `-- --headed`, `-- --debug`);
 * 5. everything it started is stopped again, also on failure and Ctrl+C (the database keeps
 *    running: `npm run db:down`).
 *
 * The ports differ from `npm run dev:stack` (3000...) and `npm run test:java` (3900, 4900), so
 * the suite runs next to both. Process logs go to e2e/.artifacts/logs/<process>.log; the
 * Playwright report and failure traces to e2e/.artifacts.
 *
 * Options: `--no-build` (use the existing SPA builds), `--no-java` (skip the Java demo and its
 * scenario variants; local iteration only, the release gate runs them), `--keep` (leave the
 * stack running after the tests; Ctrl+C stops it).
 *
 * `--compose` (`npm run test:e2e:compose`) runs the same suite against the production images
 * instead: it builds them (deploy/Dockerfile; `--no-build` uses the existing ones), starts
 * deploy/docker-compose.yml with the local and e2e overrides (a fresh database volume, the
 * migration jobs, the dev seed, Portvakt, the admin portal, the mock IdP and Tjänst A and B in
 * containers, on the same ports), joins the Java demo to the stack's network namespace, streams
 * every container's log to e2e/.artifacts/logs, and removes the stack (and its volume) at the end.
 */
import { spawn, spawnSync } from "node:child_process";
import {
  createWriteStream,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { connect } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import { image } from "./images.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const isWindows = process.platform === "win32";
const isLinux = process.platform === "linux";
const npmCli = process.env.npm_execpath;
const npmDirect = npmCli !== undefined && /.c?js$/.test(npmCli) && existsSync(npmCli);
const OWN_OPTIONS = ["--no-build", "--no-java", "--keep", "--compose"];
const args = process.argv.slice(2).filter((arg) => arg !== "--");
const playwrightArgs = args.filter((arg) => !OWN_OPTIONS.includes(arg));
const skipBuild = args.includes("--no-build");
const withJava = !args.includes("--no-java");
const keep = args.includes("--keep");
const composeMode = args.includes("--compose");

const PORTS = {
  portvakt: 3800,
  mockIdp: 4800,
  serviceA: 3810,
  serviceB: 3820,
  serviceC: 3830,
  admin: 3840,
};
const url = (/** @type {number} */ port) => `http://localhost:${port}`;
const PORTVAKT_URL = url(PORTS.portvakt);
const MOCK_IDP_URL = url(PORTS.mockIdp);
const ADMIN_URL = url(PORTS.admin);
const DATABASE = "portvakt_e2e";
const DB_HOST = "localhost:5433";
const SECRETS = {
  a: "e2e-only-service-a-client-secret-0123456789",
  b: "e2e-only-service-b-client-secret-0123456789",
  c: "e2e-only-service-c-client-secret-0123456789",
  admin: "e2e-only-admin-client-secret-0123456789abcdef",
};
/** maven:3.9-eclipse-temurin-21, pinned by digest in deploy/images.Dockerfile. */
const JAVA_IMAGE = image("maven");
const JAVA_CONTAINER = "portvakt-e2e-java";
const M2 = process.env.PORTVAKT_M2_DIR ?? "portvakt-m2";

/** `--compose`: the production images on Docker Compose (deploy/docker-compose.e2e.yml). */
const COMPOSE_PROJECT = "portvakt-e2e";
const COMPOSE = [
  "compose",
  "--env-file",
  "deploy/compose/local.env",
  "--env-file",
  "deploy/compose/e2e.env",
  "-f",
  "deploy/docker-compose.yml",
  "-f",
  "deploy/docker-compose.local.yml",
  "-f",
  "deploy/docker-compose.e2e.yml",
  "--profile",
  "demo",
];
/** The container whose network namespace every service of the compose stack shares. */
const COMPOSE_NETWORK_CONTAINER = `${COMPOSE_PROJECT}-postgres-1`;
/** Long-running compose services and the log file each one writes (e2e/.artifacts/logs). */
const COMPOSE_SERVICES = {
  server: "portvakt",
  "mock-idp": "mock-idp",
  "demo-a": "service-a",
  "demo-b": "service-b",
  admin: "admin",
};
/** One-off compose jobs; their output is saved once they have finished. */
const COMPOSE_JOBS = ["migrate", "admin-migrate", "seed"];

const artifacts = join(root, "e2e", ".artifacts");
const logDir = join(artifacts, "logs");
/** The process ids of a running stack, so a later run can stop what a killed run left behind. */
const pidFile = join(artifacts, "stack-pids.json");

/** @type {Map<string, import("node:child_process").ChildProcess>} */
const children = new Map();
let stopping = false;
let javaStarted = false;

const log = (/** @type {string} */ message) => console.log(`[e2e] ${message}`);

/**
 * The development values of .env.example, overridden for the e2e stack.
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
    LOG_LEVEL: "info",
    PORT: String(PORTS.portvakt),
    PUBLIC_URL: PORTVAKT_URL,
    DATABASE_URL: `postgres://portvakt_app:portvakt_app@${DB_HOST}/${DATABASE}`,
    MIGRATION_DATABASE_URL: `postgres://portvakt:portvakt@${DB_HOST}/${DATABASE}`,
    ALLOW_PRIVATE_UPSTREAM_HOSTS: "localhost,127.0.0.1",
    MIGRATE_ON_START: "false",
    SHUTDOWN_DRAIN_DELAY: "0s",
    // Short access tokens: the SDKs refresh a token once half its lifetime has passed (or less
    // than their default minimum is left), so "the next refresh" (scenarios 6 and 9) comes after
    // waiting E2E_ACCESS_TOKEN_DUE seconds (e2e/src/env.ts), not after minutes.
    ACCESS_TOKEN_TTL: "10s",
    // A manual rotation in the portal publishes the new key and activates it this much later
    // (scenario 9 waits for it). Production refuses less than the SDKs' JWKS caching.
    KEY_MANUAL_PUBLISH_AHEAD: "15s",
    // Every browser of the suite signs in from 127.0.0.1, in parallel: the per-IP limits are
    // raised (they stay on, so their code runs on every request).
    RATE_LIMIT_AUTHORIZE_IP: "10000/1m",
    RATE_LIMIT_AUTHORIZE_CLIENT: "10000/1m",
    RATE_LIMIT_INTERACTION_IP: "10000/1m",
    RATE_LIMIT_FEDERATION_IP: "10000/1m",
    RATE_LIMIT_TOKEN_IP: "10000/1m",
    RATE_LIMIT_TOKEN_CLIENT: "10000/1m",
    RATE_LIMIT_ADMIN_API: "10000/1m",
    ADMIN_RATE_LIMIT_LOGIN: "10000/1m",
    ADMIN_PUBLIC_URL: ADMIN_URL,
    ADMIN_CLIENT_SECRET: SECRETS.admin,
  };
}

const env = environment();

/** A child process whose output goes to e2e/.artifacts/logs/<name>.log. */
function spawnLogged(
  /** @type {string} */ name,
  /** @type {string} */ command,
  /** @type {string[]} */ commandArgs,
  /** @type {{ env?: NodeJS.ProcessEnv; shell?: boolean; detached?: boolean; cwd?: string }} */ options,
) {
  const file = createWriteStream(join(logDir, `${name}.log`), { flags: "a" });
  const child = spawn(command, commandArgs, {
    cwd: options.cwd ?? root,
    env: options.env ?? env,
    shell: options.shell ?? false,
    detached: (options.detached ?? false) && !isWindows,
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout?.pipe(file, { end: false });
  child.stderr?.pipe(file, { end: false });
  child.on("exit", () => file.end());
  return child;
}

function spawnNpm(
  /** @type {string} */ name,
  /** @type {string[]} */ npmArgs,
  /** @type {NodeJS.ProcessEnv} */ childEnv,
  detached = false,
) {
  const [command, commandArgs] = npmDirect
    ? [process.execPath, [/** @type {string} */ (npmCli), ...npmArgs]]
    : [isWindows ? "npm.cmd" : "npm", npmArgs];
  return spawnLogged(name, command, commandArgs, {
    env: childEnv,
    shell: !npmDirect && isWindows,
    detached,
  });
}

/** Runs a one-off npm step to completion; stops everything when it fails. */
async function step(/** @type {string} */ name, /** @type {string[]} */ npmArgs, childEnv = env) {
  log(`${name}: npm ${npmArgs.join(" ")}`);
  const child = spawnNpm(name, npmArgs, childEnv);
  const code = await new Promise((resolve) => child.on("exit", resolve));
  if (code !== 0) {
    console.error(`[e2e] ${name} failed (exit code ${String(code)}); see ${logFile(name)}`);
    printTail(name);
    await stopAll(1);
  }
}

/** Starts a long-running process; the run stops when it exits early. */
function service(
  /** @type {string} */ name,
  /** @type {import("node:child_process").ChildProcess} */ child,
) {
  children.set(name, child);
  writePids();
  child.on("exit", (code) => {
    children.delete(name);
    if (!stopping) {
      console.error(`[e2e] ${name} exited (code ${String(code)}); see ${logFile(name)}`);
      printTail(name);
      void stopAll(1);
    }
  });
}

function npmService(/** @type {string} */ name, /** @type {string[]} */ npmArgs, childEnv = env) {
  log(`starting ${name}: npm ${npmArgs.join(" ")}`);
  service(name, spawnNpm(name, npmArgs, childEnv, true));
}

const logFile = (/** @type {string} */ name) => join(logDir, `${name}.log`);

function printTail(/** @type {string} */ name, lines = 30) {
  try {
    const text = readFileSync(logFile(name), "utf8").trimEnd().split(/\r?\n/);
    console.error(
      text
        .slice(-lines)
        .map((line) => `  [${name}] ${line}`)
        .join("\n"),
    );
  } catch {
    // No log yet.
  }
}

/** Polls a URL until it answers 2xx. */
async function waitFor(
  /** @type {string} */ name,
  /** @type {string} */ target,
  timeoutMs = 90_000,
) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (stopping) return;
    try {
      const response = await fetch(target, { signal: AbortSignal.timeout(2000) });
      if (response.ok) {
        log(`${name} is up (${target})`);
        return;
      }
    } catch {
      // Not listening yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  console.error(`[e2e] ${name} did not answer ${target} within ${timeoutMs / 1000} s`);
  printTail(name);
  await stopAll(1);
}

/** Whether something already listens on localhost:port (a leftover run, another stack). */
function inUse(/** @type {number} */ port) {
  return new Promise((resolve) => {
    const socket = connect({ host: "localhost", port });
    socket.setTimeout(1000);
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => resolve(false));
  });
}

/** Ends a process and its children (on Unix its process group: services start detached). */
function killTree(/** @type {number} */ pid) {
  if (isWindows) {
    // The shell and npm in between: end the whole process tree.
    spawnSync("taskkill", ["/pid", String(pid), "/T", "/F"], { stdio: "ignore" });
  } else {
    try {
      process.kill(-pid, "SIGTERM");
    } catch {
      try {
        process.kill(pid, "SIGTERM");
      } catch {
        // Already gone.
      }
    }
  }
}

function kill(/** @type {import("node:child_process").ChildProcess} */ child) {
  if (child.pid === undefined || child.exitCode !== null) return;
  killTree(child.pid);
}

function writePids() {
  const pids = [...children.values()].map((child) => child.pid).filter((pid) => pid !== undefined);
  writeFileSync(
    pidFile,
    JSON.stringify({ pids, container: javaStarted ? JAVA_CONTAINER : null, compose: composeMode }),
  );
}

/**
 * A run that was killed without its cleanup (no Ctrl+C: a closed terminal on Windows, a killed
 * CI step) leaves its stack running: stop it before checking the ports.
 */
async function reapPrevious() {
  if (!existsSync(pidFile)) return;
  // Only while the stack's ports still answer: after a reboot the recorded ids may belong to
  // other processes.
  const running = await Promise.all(Object.values(PORTS).map((port) => inUse(port)));
  if (!running.some(Boolean)) {
    rmSync(pidFile, { force: true });
    return;
  }
  try {
    const previous = JSON.parse(readFileSync(pidFile, "utf8"));
    if (Array.isArray(previous.pids) && previous.pids.length > 0) {
      log(`stopping what a previous run left running (${previous.pids.length} processes)`);
      for (const pid of previous.pids) if (Number.isInteger(pid)) killTree(pid);
    }
    if (previous.compose === true) {
      log("removing the compose stack a previous run left running");
      spawnSync("docker", [...COMPOSE, "down", "-v", "--remove-orphans"], {
        cwd: root,
        stdio: "ignore",
      });
    }
  } catch {
    // An unreadable file: nothing to reap.
  }
  spawnSync("docker", ["rm", "-f", JAVA_CONTAINER], { stdio: "ignore" });
  rmSync(pidFile, { force: true });
  // Give the ports a moment to close.
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const still = await Promise.all(Object.values(PORTS).map((port) => inUse(port)));
    if (!still.some(Boolean)) return;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

async function stopAll(code = 0) {
  if (stopping) return;
  stopping = true;
  log("stopping the stack");
  if (javaStarted) spawnSync("docker", ["rm", "-f", JAVA_CONTAINER], { stdio: "ignore" });
  const running = [...children.values()];
  if (composeMode) {
    for (const child of running) kill(child);
    log("removing the compose stack and its database volume");
    spawnSync("docker", [...COMPOSE, "down", "-v", "--remove-orphans", "--timeout", "10"], {
      cwd: root,
      stdio: "ignore",
    });
  }
  const exited = running.map(
    (child) =>
      new Promise((resolve) =>
        child.exitCode === null ? child.on("exit", resolve) : resolve(undefined),
      ),
  );
  for (const child of running) kill(child);
  await Promise.race([Promise.all(exited), new Promise((resolve) => setTimeout(resolve, 10_000))]);
  rmSync(pidFile, { force: true });
  log(`process logs: ${logDir}`);
  log(
    `Playwright report: ${join(artifacts, "playwright-report")} (npx playwright show-report e2e/.artifacts/playwright-report)`,
  );
  process.exit(code);
}

process.on("SIGINT", () => void stopAll(130));
process.on("SIGTERM", () => void stopAll(143));
if (!isWindows) process.on("SIGHUP", () => void stopAll(129));

/** A fresh, empty database (dropped and created again by the owner role, with psql). */
async function recreateDatabase() {
  log(`database ${DATABASE}: recreating`);
  // The postgres image restarts the server once after its init scripts, so a container reported
  // healthy can still answer "the database system is starting up"; retry for a bounded time.
  const deadline = Date.now() + 30_000;
  let result = recreateOnce();
  while (result.status !== 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    result = recreateOnce();
  }
  if (result.status !== 0) {
    console.error(`[e2e] creating ${DATABASE} failed: ${result.stderr || result.error?.message}`);
    await stopAll(1);
  }
}

function recreateOnce() {
  return spawnSync(
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
}

/** The mock IdP's personas: its defaults plus the e2e personas (e2e/personas.e2e.json). */
function writePersonas() {
  const base = JSON.parse(readFileSync(join(root, "apps/mock-idp/personas.json"), "utf8"));
  const extra = JSON.parse(readFileSync(join(root, "e2e/personas.e2e.json"), "utf8"));
  const merged = {
    entra: [...base.entra, ...(extra.entra ?? [])],
    bankid: [...base.bankid, ...(extra.bankid ?? [])],
    saml: {
      bankid: [...(base.saml?.bankid ?? []), ...(extra.saml?.bankid ?? [])],
      freja: [...(base.saml?.freja ?? []), ...(extra.saml?.freja ?? [])],
      siths: [...(base.saml?.siths ?? []), ...(extra.saml?.siths ?? [])],
    },
  };
  const path = join(artifacts, "personas.json");
  writeFileSync(path, JSON.stringify(merged, null, 2));
  return path;
}

/**
 * Tjänst C in the Maven container: builds the demo (and the SDK it uses) once, waits for
 * Portvakt, then runs the jar on :3830 (published to the host). Inside the container
 * PortForward.java makes Portvakt and the mock IdP reachable at the host's URLs.
 */
function startJava(compose = false) {
  const uid = typeof process.getuid === "function" ? process.getuid() : 0;
  const gid = typeof process.getgid === "function" ? process.getgid() : 0;
  const jar = "../examples/demo-service-java/target/portvakt-demo-service-java-1.0.0.jar";
  // In the compose stack's network namespace, localhost is the stack itself: no forwarding.
  const forward = compose
    ? []
    : [
        `java /workspace/scripts/java-test/PortForward.java host.docker.internal ${PORTS.portvakt} ${PORTS.mockIdp} > /tmp/forward.log 2>&1 &`,
      ];
  const script = [
    "set -u",
    ...forward,
    "echo '[java] building the demo'",
    "mvn -B -ntp -C -q -DskipTests -pl :portvakt-demo-service-java -am package; status=$?",
    // Linux: the build output belongs to the user who ran the suite, not to root.
    ...(isLinux
      ? [
          `chown -R ${uid}:${gid} /workspace/sdk-java /workspace/examples/demo-service-java${process.env.PORTVAKT_M2_DIR === undefined ? "" : " /root/.m2"} 2>/dev/null || true`,
        ]
      : []),
    "[ $status -eq 0 ] || exit $status",
    ...(compose
      ? []
      : [
          "grep -q ready /tmp/forward.log || { sleep 2; grep -q ready /tmp/forward.log; } || { cat /tmp/forward.log; exit 1; }",
        ]),
    "echo '[java] waiting for Portvakt'",
    `for i in $(seq 1 600); do curl -sf ${PORTVAKT_URL}/readyz > /dev/null && break; sleep 0.5; done`,
    `exec java -jar ${jar}`,
  ].join("\n");
  const dockerArgs = [
    "run",
    "--rm",
    "--name",
    JAVA_CONTAINER,
    ...(compose
      ? ["--network", `container:${COMPOSE_NETWORK_CONTAINER}`]
      : [
          ...(isLinux ? ["--add-host=host.docker.internal:host-gateway"] : []),
          "-p",
          `${PORTS.serviceC}:${PORTS.serviceC}`,
        ]),
    "-v",
    `${root.replace(/[\\/]$/, "")}:/workspace`,
    "-v",
    `${M2}:/root/.m2`,
    "-w",
    "/workspace/sdk-java",
    "-e",
    `PORT=${PORTS.serviceC}`,
    "-e",
    `PUBLIC_URL=${url(PORTS.serviceC)}`,
    "-e",
    `ISSUER=${PORTVAKT_URL}/t/demo`,
    "-e",
    "CLIENT_ID=service-c",
    "-e",
    `CLIENT_SECRET=${SECRETS.c}`,
    "-e",
    "COOKIE_NAME=demo_c_e2e_session",
    // http on localhost: the demo's local profile (insecure cookie, http issuer).
    "-e",
    "SPRING_PROFILES_ACTIVE=local",
    JAVA_IMAGE,
    "sh",
    "-c",
    script,
  ];
  spawnSync("docker", ["rm", "-f", JAVA_CONTAINER], { stdio: "ignore" });
  log(`starting service-c: docker run ${JAVA_IMAGE} (build, then the jar on :${PORTS.serviceC})`);
  javaStarted = true;
  // Git Bash on Windows would rewrite the /workspace paths: no path conversion.
  service(
    "service-c",
    spawnLogged("service-c", "docker", dockerArgs, {
      env: { ...process.env, MSYS_NO_PATHCONV: "1" },
    }),
  );
}

/** @param {"A" | "B"} which */
function demoEnvironment(which) {
  const port = which === "A" ? PORTS.serviceA : PORTS.serviceB;
  return {
    ...env,
    APP_NAME: `Tjänst ${which}`,
    PORT: String(port),
    PUBLIC_URL: url(port),
    ISSUER: `${PORTVAKT_URL}/t/demo`,
    CLIENT_ID: which === "A" ? "service-a" : "service-b",
    CLIENT_SECRET: which === "A" ? SECRETS.a : SECRETS.b,
    COOKIE_NAME: which === "A" ? "demo_a_e2e_session" : "demo_b_e2e_session",
    // Service A may ask for the SITHS claims (scenario 10; the seed allows it `hsa`).
    ...(which === "A" ? { SCOPES: "openid profile email hsa" } : {}),
  };
}

/** Runs the Playwright CLI of the e2e workspace with this Node; resolves with its exit code. */
function playwright(/** @type {string[]} */ cliArgs, /** @type {NodeJS.ProcessEnv} */ childEnv) {
  const require = createRequire(join(root, "e2e", "package.json"));
  const cli = require.resolve("@playwright/test/cli");
  const child = spawn(process.execPath, [cli, ...cliArgs], {
    cwd: join(root, "e2e"),
    env: childEnv,
    stdio: "inherit",
  });
  children.set(`playwright ${cliArgs[0]}`, child);
  return new Promise((resolve) =>
    child.on("exit", (code) => {
      children.delete(`playwright ${cliArgs[0]}`);
      resolve(code ?? 1);
    }),
  );
}

/** Fresh log directory, leftovers of a killed run stopped, the stack's ports free. */
async function prepare() {
  mkdirSync(artifacts, { recursive: true });
  await reapPrevious();
  rmSync(logDir, { recursive: true, force: true });
  mkdirSync(logDir, { recursive: true });

  const busy = [];
  for (const [name, port] of Object.entries(PORTS)) {
    if (!withJava && name === "serviceC") continue;
    if (await inUse(port)) busy.push(`${name} :${port}`);
  }
  if (busy.length > 0) {
    console.error(
      `[e2e] ports already in use: ${busy.join(", ")}. A previous run may still be running.`,
    );
    process.exit(1);
  }
}

async function main() {
  const started = Date.now();
  await prepare();

  if (withJava) startJava();
  await step("db", ["run", "db:up"]);
  await recreateDatabase();
  await step("migrate", ["run", "migrate", "-w", "apps/server"]);
  if (!skipBuild) {
    log("building the login UI, the demo SPA and the admin SPA");
    await Promise.all([
      step("build-login", ["run", "build", "-w", "apps/login"]),
      step("build-demo", ["run", "build:web", "-w", "examples/demo-service"]),
      step("build-admin", ["run", "build:web", "-w", "apps/admin"]),
    ]);
  } else {
    for (const built of [
      "apps/login/dist/index.html",
      "examples/demo-service/dist/web/index.html",
      "apps/admin/dist/web/index.html",
    ]) {
      if (!existsSync(join(root, built))) {
        console.error(`[e2e] --no-build: ${built} is missing; run npm run build first`);
        await stopAll(1);
      }
    }
  }

  const mockClients = ["entra", "bankid"].map((issuer) => ({
    issuer,
    client_id: "portvakt-dev",
    client_secret: `dev-only-${issuer}-client-secret`,
    redirect_uri_prefixes: [`${PORTVAKT_URL}/t/`],
  }));
  npmService("mock-idp", ["run", "start", "-w", "apps/mock-idp"], {
    ...env,
    MOCK_IDP_PORT: String(PORTS.mockIdp),
    MOCK_IDP_PUBLIC_URL: MOCK_IDP_URL,
    MOCK_IDP_CLIENTS: JSON.stringify(mockClients),
    MOCK_IDP_PERSONAS: writePersonas(),
  });
  await waitFor("mock-idp", `${MOCK_IDP_URL}/healthz`);

  await step("seed", ["run", "seed:dev", "-w", "apps/server"], {
    ...env,
    MOCK_IDP_PUBLIC_URL: MOCK_IDP_URL,
    MOCK_IDP_ENTRA_CLIENT_SECRET: "dev-only-entra-client-secret",
    MOCK_IDP_BANKID_CLIENT_SECRET: "dev-only-bankid-client-secret",
    DEMO_SERVICE_A_URL: url(PORTS.serviceA),
    DEMO_SERVICE_B_URL: url(PORTS.serviceB),
    DEMO_SERVICE_C_URL: url(PORTS.serviceC),
    DEMO_SERVICE_A_CLIENT_SECRET: SECRETS.a,
    DEMO_SERVICE_B_CLIENT_SECRET: SECRETS.b,
    DEMO_SERVICE_C_CLIENT_SECRET: SECRETS.c,
  });

  npmService("portvakt", ["run", "start", "-w", "apps/server"]);
  await waitFor("portvakt", `${PORTVAKT_URL}/readyz`);

  npmService("service-a", ["run", "start", "-w", "examples/demo-service"], demoEnvironment("A"));
  npmService("service-b", ["run", "start", "-w", "examples/demo-service"], demoEnvironment("B"));
  npmService("admin", ["run", "start", "-w", "apps/admin"], {
    ...env,
    ADMIN_PORT: String(PORTS.admin),
    PORTVAKT_PUBLIC_URL: PORTVAKT_URL,
  });
  await Promise.all([
    waitFor("service-a", `${url(PORTS.serviceA)}/healthz`),
    waitFor("service-b", `${url(PORTS.serviceB)}/healthz`),
    waitFor("admin", `${ADMIN_URL}/healthz`),
    // The first run downloads the Maven dependencies into the cache.
    ...(withJava ? [waitFor("service-c", `${url(PORTS.serviceC)}/healthz`, 15 * 60_000)] : []),
  ]);
  if (stopping) return;
  await runSuite(started, env.MIGRATION_DATABASE_URL ?? "");
}

/** Chromium, then the Playwright suite against the running stack; stops it unless --keep. */
async function runSuite(/** @type {number} */ started, /** @type {string} */ databaseUrl) {
  log(`stack ready after ${Math.round((Date.now() - started) / 1000)} s`);

  const install = await playwright(["install", "chromium"], process.env);
  if (install !== 0) {
    console.error("[e2e] playwright install chromium failed");
    await stopAll(1);
  }

  const testEnv = {
    ...process.env,
    E2E_PORTVAKT_URL: PORTVAKT_URL,
    E2E_MOCK_IDP_URL: MOCK_IDP_URL,
    E2E_SERVICE_A_URL: url(PORTS.serviceA),
    E2E_SERVICE_B_URL: url(PORTS.serviceB),
    E2E_SERVICE_C_URL: url(PORTS.serviceC),
    E2E_ADMIN_URL: ADMIN_URL,
    E2E_SERVICE_A_SECRET: SECRETS.a,
    E2E_SERVICE_B_SECRET: SECRETS.b,
    E2E_DATABASE_URL: databaseUrl,
    E2E_LOG_DIR: logDir,
    E2E_JAVA: withJava ? "1" : "0",
  };
  const testsStarted = Date.now();
  const code = await playwright(["test", ...playwrightArgs], testEnv);
  log(
    `playwright finished (exit code ${code}) in ${Math.round((Date.now() - testsStarted) / 1000)} s; ` +
      `total ${Math.round((Date.now() - started) / 1000)} s`,
  );
  if (keep) {
    log(
      `--keep: Portvakt ${PORTVAKT_URL}, admin ${ADMIN_URL}, A ${url(PORTS.serviceA)}, ` +
        `B ${url(PORTS.serviceB)}, C ${url(PORTS.serviceC)}; Ctrl+C stops them`,
    );
    return;
  }
  await stopAll(code);
}

/** Runs `docker compose <args>` for the e2e stack to completion; stops everything on failure. */
async function compose(/** @type {string} */ name, /** @type {string[]} */ composeArgs) {
  log(`${name}: docker compose ${composeArgs.join(" ")}`);
  const child = spawnLogged(name, "docker", [...COMPOSE, ...composeArgs], {
    env: { ...process.env, MSYS_NO_PATHCONV: "1" },
  });
  const code = await new Promise((resolve) => child.on("exit", resolve));
  if (code !== 0) {
    console.error(`[e2e] ${name} failed (exit code ${String(code)}); see ${logFile(name)}`);
    printTail(name);
    await stopAll(1);
  }
}

/**
 * `--compose`: the production images (deploy/Dockerfile) on Docker Compose with the local and
 * e2e overrides. Services share the network namespace of the `postgres` container, which
 * publishes the suite's ports, so browsers and containers use the same URLs.
 */
async function mainCompose() {
  const started = Date.now();
  await prepare();
  writePids();
  writePersonas();
  // A run killed before its cleanup may have left the stack or its volume behind.
  spawnSync("docker", [...COMPOSE, "down", "-v", "--remove-orphans"], {
    cwd: root,
    stdio: "ignore",
  });
  if (!skipBuild) {
    log("building the images (deploy/Dockerfile: server, admin, mock-idp, demo)");
    await compose("images", ["build"]);
  }
  await compose("postgres", ["up", "-d", "--wait", "postgres"]);
  if (withJava) startJava(true);
  await compose("stack", ["up", "-d", "--wait", "--wait-timeout", "300"]);
  if (stopping) return;
  for (const job of COMPOSE_JOBS) {
    writeFileSync(
      logFile(job),
      spawnSync("docker", [...COMPOSE, "logs", "--no-color", "--no-log-prefix", job], {
        cwd: root,
        encoding: "utf8",
      }).stdout,
    );
  }
  // One follower per service: its output is the service's log, and its end (the container
  // stopped) ends the run, as a process of the local stack would.
  for (const [serviceName, logName] of Object.entries(COMPOSE_SERVICES)) {
    service(
      logName,
      spawnLogged(
        logName,
        "docker",
        [...COMPOSE, "logs", "-f", "--no-color", "--no-log-prefix", serviceName],
        { env: { ...process.env, MSYS_NO_PATHCONV: "1" } },
      ),
    );
  }
  await Promise.all([
    waitFor("portvakt", `${PORTVAKT_URL}/readyz`),
    waitFor("admin", `${ADMIN_URL}/healthz`),
    ...(withJava ? [waitFor("service-c", `${url(PORTS.serviceC)}/healthz`, 15 * 60_000)] : []),
  ]);
  if (stopping) return;
  // The compose database: the owner role of deploy/compose/local.env, published on :5434.
  await runSuite(started, "postgres://portvakt:portvakt@localhost:5434/portvakt");
}

(composeMode ? mainCompose() : main()).catch((error) => {
  console.error("[e2e] failed:", error instanceof Error ? error.message : error);
  void stopAll(1);
});
