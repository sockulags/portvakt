import { describe, expect, it } from "vitest";
import { LOGIN_ERROR_CODES } from "./api";
import { format, MESSAGES, pickLocale } from "./i18n";

describe("pickLocale", () => {
  it("defaults to Swedish", () => {
    expect(pickLocale({ uiLocales: [], acceptLanguage: [] })).toBe("sv");
    expect(pickLocale({ uiLocales: [], acceptLanguage: ["de-DE", "fr"] })).toBe("sv");
  });

  it("follows Accept-Language in preference order, by primary subtag", () => {
    expect(pickLocale({ uiLocales: [], acceptLanguage: ["en-GB", "sv"] })).toBe("en");
    expect(pickLocale({ uiLocales: [], acceptLanguage: ["de", "sv-SE", "en"] })).toBe("sv");
  });

  it("lets ui_locales override Accept-Language", () => {
    expect(pickLocale({ uiLocales: ["en"], acceptLanguage: ["sv-SE"] })).toBe("en");
    expect(pickLocale({ uiLocales: ["fi", "sv"], acceptLanguage: ["en"] })).toBe("sv");
  });
});

describe("messages", () => {
  it("has a title and text for every error code in both languages", () => {
    for (const locale of ["sv", "en"] as const) {
      for (const code of LOGIN_ERROR_CODES) {
        expect(MESSAGES[locale].errors[code].title.length).toBeGreaterThan(0);
        expect(MESSAGES[locale].errors[code].body.length).toBeGreaterThan(0);
      }
    }
  });

  it("formats placeholders and leaves unknown ones", () => {
    expect(format("Logga in med {name}", { name: "BankID" })).toBe("Logga in med BankID");
    expect(format("{a} {b}", { a: "x" })).toBe("x {b}");
  });
});
