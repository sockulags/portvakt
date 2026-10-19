#!/usr/bin/env node
// The container images of the development and test tooling, from deploy/images.Dockerfile (the
// one tracked list, pinned by digest; Dependabot updates it). `node scripts/images.js --check`
// (npm run images:check) verifies that the files that cannot read it name the same images.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST = join(root, "deploy", "images.Dockerfile");
const PINNED = /^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$/;

/** The images of the manifest by stage name: `FROM <image>:<tag>@sha256:<digest> AS <name>`. */
export function images() {
  /** @type {Map<string, string>} */
  const found = new Map();
  for (const line of readFileSync(MANIFEST, "utf8").split(/\r?\n/)) {
    const match = /^FROM\s+(\S+)\s+AS\s+([a-z0-9-]+)\s*$/i.exec(line.trim());
    if (match === null) continue;
    const reference = match[1] ?? "";
    const name = match[2] ?? "";
    if (!PINNED.test(reference)) {
      throw new Error(
        `deploy/images.Dockerfile: ${name} is not pinned as <image>:<tag>@sha256:<digest>`,
      );
    }
    found.set(name.toLowerCase(), reference);
  }
  return found;
}

/**
 * One image of the manifest; throws when it is missing.
 * @param {string} name
 */
export function image(name) {
  const reference = images().get(name);
  if (reference === undefined) throw new Error(`deploy/images.Dockerfile: no image ${name}`);
  return reference;
}

function check() {
  const postgres = image("postgres");
  const problems = [];
  for (const file of ["deploy/docker-compose.dev.yml", ".github/workflows/ci.yml"]) {
    const text = readFileSync(join(root, file), "utf8");
    const named = [...text.matchAll(/^\s*image:\s*(\S+)\s*$/gm)].map((match) => match[1] ?? "");
    const postgresImages = named.filter((reference) => reference.startsWith("postgres:"));
    if (postgresImages.length === 0) problems.push(`${file}: names no postgres image`);
    for (const reference of postgresImages) {
      if (reference !== postgres) {
        problems.push(`${file}: ${reference} differs from deploy/images.Dockerfile (${postgres})`);
      }
    }
  }
  for (const [name, reference] of images()) console.log(`${name}: ${reference}`);
  if (problems.length > 0) {
    for (const problem of problems) console.error(`images:check: ${problem}`);
    process.exit(1);
  }
  console.log("images:check: every file names the pinned images");
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.includes("--check")) check();
  else for (const [name, reference] of images()) console.log(`${name}: ${reference}`);
}
