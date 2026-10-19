import { blockingViolations } from "../../src/a11y";
import { expect, test } from "../../src/fixtures";

/**
 * The accessibility gate itself: on a page with known serious violations it reports them, so a
 * green gate on the product pages means something.
 */
test("Accessibility: the gate reports serious violations", async ({ page }, testInfo) => {
  await page.setContent(
    '<!doctype html><html lang="sv"><head><title>Gate</title></head><body><main>' +
      '<h1>Kontroll</h1><img src="data:image/gif;base64,R0lGODlhAQABAAAAACw=">' +
      '<button></button><p style="color:#ccc;background:#fff">Låg kontrast</p></main></body></html>',
  );
  const rules = (await blockingViolations(page, testInfo, "gate self-check")).map(
    (item) => item.rule,
  );
  expect(rules).toEqual(expect.arrayContaining(["image-alt", "button-name", "color-contrast"]));
});
