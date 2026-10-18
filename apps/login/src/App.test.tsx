import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { App } from "./App";

describe("App", () => {
  it("renders the page with a design system button", () => {
    const html = renderToStaticMarkup(<App />);
    expect(html).toContain("Sign in");
    expect(html).toContain('data-ds="button"');
  });
});
