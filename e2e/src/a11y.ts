import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, type TestInfo } from "@playwright/test";

/** WCAG 2.0 and 2.1, levels A and AA (axe's tags). */
const WCAG_21_AA = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

/**
 * The accessibility gate: axe-core's WCAG 2.1 AA rules on the page as it is now. Every finding
 * is attached to the report; serious and critical ones fail the test. No rule is disabled.
 */
export async function expectAccessible(
  page: Page,
  testInfo: TestInfo,
  name: string,
): Promise<void> {
  const blocking = await blockingViolations(page, testInfo, name);
  expect(blocking, `${name}: serious or critical WCAG 2.1 AA violations`).toEqual([]);
}

/** The serious and critical WCAG 2.1 AA violations on the page (all findings are attached). */
export async function blockingViolations(
  page: Page,
  testInfo: TestInfo,
  name: string,
): Promise<{ rule: string; impact: string | null | undefined; help: string; nodes: string[] }[]> {
  const results = await new AxeBuilder({ page }).withTags(WCAG_21_AA).analyze();
  await testInfo.attach(`axe: ${name}`, {
    body: JSON.stringify(
      {
        url: results.url,
        passed: results.passes.length,
        // Rules axe could not decide alone, reviewed by hand (M7): color-contrast on the design
        // system's buttons, whose fill has a sheen gradient (measured: the lightest edge still
        // gives at least 4.79:1, the danger button in light mode; primary 12.3:1), and on admin
        // form labels "partially obscured" by the sticky form actions while axe scrolls.
        incomplete: results.incomplete.map((rule) => ({
          rule: rule.id,
          nodes: rule.nodes.map((node) => ({
            target: node.target.join(" "),
            reason: [...node.any, ...node.all, ...node.none].map((check) => check.message),
          })),
        })),
        violations: results.violations,
      },
      null,
      2,
    ),
    contentType: "application/json",
  });
  return results.violations
    .filter((violation) => violation.impact === "serious" || violation.impact === "critical")
    .map((violation) => ({
      rule: violation.id,
      impact: violation.impact,
      help: violation.help,
      nodes: violation.nodes.map(
        (node) => `${node.target.join(" ")}: ${node.failureSummary ?? ""}`,
      ),
    }));
}
