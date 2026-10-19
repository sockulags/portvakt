import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CONFIG_VARIABLES } from "./index.js";

/**
 * docs/operations.md is the configuration reference: its "Server" table lists every variable
 * the configuration schema reads, and nothing else.
 */
const operations = readFileSync(new URL("../../../../docs/operations.md", import.meta.url), "utf8");

/** The variables named in the first column of the tables of one reference section. */
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
  const documented = documentedVariables(operations, "### Server variables");

  it("documents every variable of the server's configuration schema", () => {
    const missing = CONFIG_VARIABLES.filter((name) => !documented.has(name));
    expect(missing).toEqual([]);
  });

  it("documents no variable the server does not read", () => {
    const unknown = [...documented].filter((name) => !CONFIG_VARIABLES.includes(name));
    expect(unknown).toEqual([]);
  });
});
