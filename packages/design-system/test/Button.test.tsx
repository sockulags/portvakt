import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Button } from "../src/components/index";

describe("Button", () => {
  it("renders its label as a button", () => {
    const html = renderToStaticMarkup(<Button variant="primary">Continue</Button>);
    expect(html).toContain("<button");
    expect(html).toContain("Continue");
    expect(html).toContain('data-variant="primary"');
  });
});
