// @ts-check
/**
 * `npm run dev:stack`: the whole local stack in one terminal, on Windows, macOS and Linux.
 *
 * 1. Postgres (`npm run db:up`) and migrations;
 * 2. the login UI and the demo SPA builds (when missing, or always with `--build`);
 * 3. the mock IdP on :4500, then the dev seed (it fetches SAML metadata from the mock);
 * 4. Portvakt on :3000, then the demo service as Service A on :3100 and Service B on :3200, and
 *    the admin portal on :3400 (/t/system/: erik-admin, platform admin; /t/demo/: anna-handlaggare).
 *
 * Ctrl+C stops every process it started (the database keeps running: `npm run db:down`).
 * Without a root .env the values of .env.example are used.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";

const root = fileURLToPath(new URL("..", import.meta.url));
const isWindows = process.platform === "win32";
/**
 * npm itself: `npm run` sets npm_execpath to npm-cli.js, which runs with this Node directly (no
 * shell, so no DEP0190 warning on Windows). Otherwise the npm command, through a shell on Windows
 * where it is a .cmd script.
 */
const npmCli = process.env.npm_execpath;
const npmDirect = npmCli !== undefined && /.c?js$/.test(npmCli) && existsSync(npmCli);
const forceBuild = process.argv.includes("--build");

const PORTS = { server: 3000, mockIdp: 4500, serviceA: 3100, serviceB: 3200, admin: 3400 };
const PORTVAKT_URL = `http://localhost:${PORTS.server}`;
const MOCK_IDP_URL = `http://localhost:${PORTS.mockIdp}`;
const ADMIN_URL = `http://localhost:${PORTS.admin}`;

/** The environment every child starts from: ours, plus .env.example when there is no .env. */
function baseEnvironment() {
  const env = { ...process.env };
  if (!existsSync(join(root, ".env"))) {
    console.log("[dev-stack] no .env found: using the development values of .env.example");
    const example = parseEnv(readFileSync(join(root, ".env.example"), "utf8"));
    for (const [key, value] of Object.entries(example)) {
      if (env[key] === undefined && value !== "") env[key] = value;
    }
  } else {
    // The server scripts read .env themselves; the demos need their secrets from it.
    const local = parseEnv(readFileSync(join(root, ".env"), "utf8"));
    for (const key of [
      "DEMO_SERVICE_A_CLIENT_SECRET",
      "DEMO_SERVICE_B_CLIENT_SECRET",
      "DEMO_SERVICE_C_CLIENT_SECRET",
      "ADMIN_CLIENT_SECRET",
    ]) {
      const value = local[key];
      if (env[key] === undefined && value !== undefined && value !== "") env[key] = value;
    }
  }
  return env;
}

const env = baseEnvironment();
const secrets = {
  a: env.DEMO_SERVICE_A_CLIENT_SECRET ?? "dev-only-service-a-client-secret-0123456789",
  b: env.DEMO_SERVICE_B_CLIENT_SECRET ?? "dev-only-service-b-client-secret-0123456789",
  // The Java demo (examples/demo-service-java, Tjänst C on :3300) is not started here; the seed
  // registers service-c with this secret, its development default.
  c: env.DEMO_SERVICE_C_CLIENT_SECRET ?? "dev-only-service-c-client-secret-0123456789",
  admin: env.ADMIN_CLIENT_SECRET ?? "dev-only-admin-client-secret-0123456789abcdef",
};

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
  const prefix = (/** @type {Buffer} */ chunk) =>
    chunk
      .toString()
      .split(/\r?\n/)
      .filter((line) => line.trim() !== "")
      .map((line) => `[${name}] ${line}`)
      .join("\n");
  child.stdout?.on("data", (chunk) => console.log(prefix(chunk)));
  child.stderr?.on("data", (chunk) => console.error(prefix(chunk)));
  return child;
}

/** Runs a one-off step to completion; exits the stack when it fails. */
async function step(/** @type {string} */ name, /** @type {string[]} */ args, childEnv = env) {
  console.log(`[dev-stack] ${name}: npm ${args.join(" ")}`);
  const child = spawnNpm(name, args, childEnv, false);
  const code = await new Promise((resolve) => child.on("exit", resolve));
  if (code !== 0) {
    console.error(`[dev-stack] ${name} failed (exit code ${String(code)})`);
    await stopAll(1);
  }
}

/** Starts a long-running process; the stack stops when it exits. */
function service(/** @type {string} */ name, /** @type {string[]} */ args, childEnv = env) {
  console.log(`[dev-stack] starting ${name}: npm ${args.join(" ")}`);
  const child = spawnNpm(name, args, childEnv, true);
  children.set(name, child);
  child.on("exit", (code) => {
    children.delete(name);
    if (!stopping) {
      console.error(`[dev-stack] ${name} exited (code ${String(code)}); stopping the stack`);
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
        console.log(`[dev-stack] ${name} is up (${url})`);
        return;
      }
    } catch {
      // Not listening yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  console.error(`[dev-stack] ${name} did not answer ${url} within ${timeoutMs / 1000} s`);
  await stopAll(1);
}

function kill(/** @type {import("node:child_process").ChildProcess} */ child) {
  if (child.pid === undefined || child.exitCode !== null) return;
  if (isWindows) {
    // The shell and npm in between: end the whole process tree.
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
  console.log("[dev-stack] stopping");
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

process.on("SIGINT", () => void stopAll(0));
process.on("SIGTERM", () => void stopAll(0));
// A closed terminal on macOS and Linux: stop the children instead of leaving them running.
if (!isWindows) process.on("SIGHUP", () => void stopAll(0));

/** @param {"A" | "B"} which */
function demoEnvironment(which) {
  const port = which === "A" ? PORTS.serviceA : PORTS.serviceB;
  return {
    ...env,
    NODE_ENV: "development",
    APP_NAME: `Tjänst ${which}`,
    PORT: String(port),
    PUBLIC_URL: `http://localhost:${port}`,
    ISSUER: `${PORTVAKT_URL}/t/demo`,
    CLIENT_ID: which === "A" ? "service-a" : "service-b",
    CLIENT_SECRET: which === "A" ? secrets.a : secrets.b,
    // Cookies on localhost are shared across ports: each instance needs its own name.
    COOKIE_NAME: which === "A" ? "demo_a_session" : "demo_b_session",
  };
}

async function main() {
  await step("db", ["run", "db:up"]);
  await step("migrate", ["run", "migrate", "-w", "apps/server"]);
  if (forceBuild || !existsSync(join(root, "apps/login/dist/index.html"))) {
    await step("login-ui", ["run", "build", "-w", "apps/login"]);
  }
  if (forceBuild || !existsSync(join(root, "examples/demo-service/dist/web/index.html"))) {
    await step("demo-web", ["run", "build", "-w", "examples/demo-service"]);
  }
  if (forceBuild || !existsSync(join(root, "apps/admin/dist/web/index.html"))) {
    await step("admin-web", ["run", "build", "-w", "apps/admin"]);
  }

  service("mock-idp", ["run", "start", "-w", "apps/mock-idp"], {
    ...env,
    MOCK_IDP_PORT: String(PORTS.mockIdp),
    MOCK_IDP_PUBLIC_URL: MOCK_IDP_URL,
  });
  await waitFor("mock-idp", `${MOCK_IDP_URL}/healthz`);

  await step("seed", ["run", "seed:dev", "-w", "apps/server"], {
    ...env,
    MOCK_IDP_PUBLIC_URL: MOCK_IDP_URL,
    DEMO_SERVICE_A_URL: `http://localhost:${PORTS.serviceA}`,
    DEMO_SERVICE_B_URL: `http://localhost:${PORTS.serviceB}`,
    DEMO_SERVICE_A_CLIENT_SECRET: secrets.a,
    DEMO_SERVICE_B_CLIENT_SECRET: secrets.b,
    DEMO_SERVICE_C_CLIENT_SECRET: secrets.c,
    ADMIN_PUBLIC_URL: ADMIN_URL,
    ADMIN_CLIENT_SECRET: secrets.admin,
  });

  service("portvakt", ["run", "start", "-w", "apps/server"], {
    ...env,
    PORT: String(PORTS.server),
    PUBLIC_URL: PORTVAKT_URL,
  });
  await waitFor("portvakt", `${PORTVAKT_URL}/readyz`);

  service("service-a", ["run", "start", "-w", "examples/demo-service"], demoEnvironment("A"));
  service("service-b", ["run", "start", "-w", "examples/demo-service"], demoEnvironment("B"));
  await waitFor("service-a", `http://localhost:${PORTS.serviceA}/healthz`);
  await waitFor("service-b", `http://localhost:${PORTS.serviceB}/healthz`);
  service("admin", ["run", "start", "-w", "apps/admin"], {
    ...env,
    NODE_ENV: "development",
    ADMIN_PORT: String(PORTS.admin),
    ADMIN_PUBLIC_URL: ADMIN_URL,
    PORTVAKT_PUBLIC_URL: PORTVAKT_URL,
    ADMIN_CLIENT_SECRET: secrets.admin,
  });
  await waitFor("admin", `${ADMIN_URL}/healthz`);

  console.log(
    [
      "",
      "[dev-stack] ready:",
      `  Portvakt     ${PORTVAKT_URL}/t/demo (issuer of the demo tenant)`,
      `  Mock IdP     ${MOCK_IDP_URL}`,
      `  Tjänst A     http://localhost:${PORTS.serviceA}`,
      `  Tjänst B     http://localhost:${PORTS.serviceB} (disabled in the tenant until enabled)`,
      `  Admin        ${ADMIN_URL}/t/system/ (erik-admin) and ${ADMIN_URL}/t/demo/ (anna-handlaggare)`,
      "  Ctrl+C stops everything (the database keeps running).",
      "",
    ].join("\n"),
  );
}

main().catch((error) => {
  console.error("[dev-stack] failed:", error instanceof Error ? error.message : error);
  void stopAll(1);
});
