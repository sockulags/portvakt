// @ts-check
/**
 * `npm run license:check`: the licenses of every production dependency (what the server, the
 * admin portal, the SDK and the demo ship; devDependencies excluded) must be permissive. The
 * production set comes from package-lock.json (entries without `dev`), the license from each
 * installed package's package.json. SPDX expressions are evaluated: `A OR B` passes when one
 * side does, `A AND B` when both do. Copyleft (GPL, AGPL, LGPL, SSPL, EUPL, ...) and unknown or
 * missing licenses fail; exceptions need an entry in EXCEPTIONS with a reason.
 *
 * `--all` checks devDependencies too (informational: they are never shipped).
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const includeDev = process.argv.includes("--all");

/** Permissive licenses (SPDX ids). */
export const ALLOWED = new Set([
  "MIT",
  "MIT-0",
  "ISC",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "0BSD",
  "Apache-2.0",
  "BlueOak-1.0.0",
  "CC0-1.0",
  "Unlicense",
  "Python-2.0",
  "Zlib",
  "CC-BY-4.0",
]);

/** Licenses refused outright (also inside an OR without a permissive alternative). */
const COPYLEFT = /^(A?GPL|LGPL|SSPL|EUPL|OSL|CPAL|MPL|EPL|CDDL)/i;

/**
 * Licenses allowed for some packages only. OFL-1.1 (SIL Open Font License): the design system's
 * fonts (@fontsource, self-hosted by the login UI and the admin portal). It allows bundling and
 * redistributing the fonts with any software; only modified fonts must stay under the OFL.
 * @type {Readonly<Record<string, RegExp>>}
 */
const SCOPED = { "OFL-1.1": /^@fontsource\// };

/**
 * Packages whose package.json names no SPDX license although the package is permissively
 * licensed, by name: the license and where that was checked.
 * @type {Readonly<Record<string, { license: string; reason: string }>>}
 */
const EXCEPTIONS = {};

/**
 * Whether an SPDX expression is allowed.
 * @param {string} expression
 * @returns {boolean}
 */
export function allowed(expression) {
  const text = expression.trim().replace(/^\((.*)\)$/, "$1");
  const or = splitTop(text, "OR");
  if (or.length > 1) return or.some(allowed);
  const and = splitTop(text, "AND");
  if (and.length > 1) return and.every(allowed);
  const id = text.replace(/\+$/, "").replace(/ WITH .*$/, "");
  if (COPYLEFT.test(id)) return false;
  return ALLOWED.has(id);
}

/**
 * Splits at top-level (unparenthesised) `operator`s.
 * @param {string} text
 * @param {"OR" | "AND"} operator
 */
function splitTop(text, operator) {
  const parts = [];
  let depth = 0;
  let current = "";
  const tokens = text.split(/(\(|\)|\s+)/).filter((token) => token !== "");
  for (const token of tokens) {
    if (token === "(") depth += 1;
    if (token === ")") depth -= 1;
    if (depth === 0 && token === operator) {
      parts.push(current.trim());
      current = "";
    } else current += token;
  }
  parts.push(current.trim());
  return parts.filter((part) => part !== "");
}

/**
 * The declared license of an installed package (`license`, or the old `licenses` array).
 * @param {Record<string, unknown>} manifest
 * @returns {string | undefined}
 */
function licenseOf(manifest) {
  const license = manifest.license;
  if (typeof license === "string") return license;
  if (license !== null && typeof license === "object" && "type" in license) {
    return String(/** @type {{ type: unknown }} */ (license).type);
  }
  const licenses = manifest.licenses;
  if (Array.isArray(licenses)) {
    const types = licenses.map((entry) =>
      typeof entry === "string" ? entry : String(/** @type {{ type?: unknown }} */ (entry).type),
    );
    return types.length === 1 ? types[0] : `(${types.join(" OR ")})`;
  }
  return undefined;
}

function main() {
  /** @type {{ packages: Record<string, { dev?: boolean; devOptional?: boolean; link?: boolean; license?: string; name?: string }> }} */
  const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
  /** @type {Map<string, Set<string>>} */
  const byLicense = new Map();
  /** @type {string[]} */
  const problems = [];
  let count = 0;
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (path === "" || entry.link === true) continue;
    if (!includeDev && (entry.dev === true || entry.devOptional === true)) continue;
    const manifestPath = join(root, path, "package.json");
    const name = path.replace(/^.*node_modules\//, "");
    let license = entry.license;
    if (existsSync(manifestPath)) {
      license = licenseOf(JSON.parse(readFileSync(manifestPath, "utf8"))) ?? license;
    }
    const exception = EXCEPTIONS[name];
    if (license === undefined && exception !== undefined) license = exception.license;
    count += 1;
    const key = license ?? "(none)";
    byLicense.set(key, (byLicense.get(key) ?? new Set()).add(name));
    if (license === undefined) problems.push(`${name}: no license declared`);
    else if (!allowed(license) && !(SCOPED[license]?.test(name) ?? false)) {
      problems.push(`${name}: ${license} is not on the allowlist`);
    }
  }
  const scope = includeDev ? "all dependencies" : "production dependencies";
  console.log(`License check of ${count} ${scope}:`);
  for (const [license, names] of [...byLicense].sort((a, b) => b[1].size - a[1].size)) {
    console.log(`  ${license}: ${names.size}`);
  }
  if (problems.length > 0) {
    console.error(`\n${problems.length} package(s) need attention:`);
    for (const problem of problems) console.error(`  - ${problem}`);
    process.exitCode = 1;
    return;
  }
  console.log("Every license is on the allowlist.");
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) main();
