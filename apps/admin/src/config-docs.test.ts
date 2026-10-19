import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ADMIN_CONFIG_VARIABLES } from "./config.js";

/**
 * docs/operations.md is the configuration reference: its "Admin portal" table lists every
 * variable the admin portal reads, and nothing else.
 */
const operations = readFileSync(new URL("../../../docs/operations.md", import.meta.url), "utf8");

function documentedVariables(markdown: string, heading: string): Set<string> {
  const start = markdown.indexOf(`\n${heading}\n`);
  if (start < 0) throw new Error(`docs/operations.md: no section "${heading}"`);
  const rest = markdown.slice(start + heading.length + 2);
  const end = rest.search(/\n#{2,3} /);
  const section = end < 0 ? rest : rest.slice(0, end);
  const names = new Set<string>();
  for (const line of section.split("\n")) {
    const match = /^\|\s*`([A-Z][A-Z0-9_]*)`/.exec(line);
    if (match?.[1] !== undefined) names.add(match[1]);
  }
  return names;
}

describe("configuration reference (docs/operations.md)", () => {
  const documented = documentedVariables(operations, "### Admin portal variables");

  it("documents every variable of the admin portal", () => {
    expect(ADMIN_CONFIG_VARIABLES.filter((name) => !documented.has(name))).toEqual([]);
  });

  it("documents no variable the admin portal does not read", () => {
    expect([...documented].filter((name) => !ADMIN_CONFIG_VARIABLES.includes(name))).toEqual([]);
  });
});
