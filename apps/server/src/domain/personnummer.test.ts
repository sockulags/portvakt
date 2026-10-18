import { describe, expect, it } from "vitest";
import {
  luhnValid,
  organisationsnummerSchema,
  parseOrganisationsnummer,
  parsePersonnummer,
  personnummerSchema,
} from "./personnummer.js";

const now = new Date(Date.UTC(2026, 9, 18));

describe("parsePersonnummer", () => {
  it.each([
    ["19121212-1212", "191212121212"],
    ["191212121212", "191212121212"],
    ["121212+1212", "191212121212"],
    ["199001012385", "199001012385"],
    ["900101-2385", "199001012385"],
    ["20000101-0008", "200001010008"],
    ["000101-0008", "200001010008"],
    ["000101+0008", "190001010008"],
    [" 19121212-1212 ", "191212121212"],
  ])("parses %s as %s", (input, canonical) => {
    expect(parsePersonnummer(input, now)?.canonical).toBe(canonical);
  });

  it("picks the century so that a short form with '-' is under 100 years old", () => {
    // 2026-10-19 is tomorrow, so 261019 means 1926; 2026-10-17 was yesterday, so 2026.
    expect(parsePersonnummer("261019-0007", now)?.canonical).toBe("192610190007");
    expect(parsePersonnummer("261017-0009", now)?.canonical).toBe("202610170009");
    // '+' adds another century.
    expect(parsePersonnummer("261017+0009", now)?.canonical).toBe("192610170009");
    expect(parsePersonnummer("990101-0000", now)?.canonical).toBe("199901010000");
  });

  it("recognises a samordningsnummer (day + 60)", () => {
    const parsed = parsePersonnummer("701063-2391", now);
    expect(parsed).toMatchObject({ canonical: "197010632391", kind: "samordningsnummer" });
    expect(parsed?.birthDate.toISOString().slice(0, 10)).toBe("1970-10-03");
    expect(parsePersonnummer("19121212-1212", now)?.kind).toBe("personnummer");
  });

  it.each([
    ["19121212-1213", "wrong check digit"],
    ["19121312-1212", "month 13"],
    ["19120230-1212", "30 February"],
    ["19121292-1212", "samordning day out of range"],
    ["1212121212", "ten digits without separator"],
    ["121212_1212", "bad separator"],
    ["2027-01-01-0000", "garbage"],
    ["20990101-0005", "date of birth in the future"],
    ["", "empty"],
  ])("rejects %s (%s)", (input) => {
    expect(parsePersonnummer(input, now)).toBeNull();
  });

  it("is exposed as a zod schema producing the canonical form", () => {
    expect(personnummerSchema.parse("121212-1212")).toBe("201212121212");
    expect(personnummerSchema.safeParse("121212-1213").success).toBe(false);
  });
});

describe("parseOrganisationsnummer", () => {
  it("accepts 10 digits with or without hyphen and returns the canonical form", () => {
    expect(parseOrganisationsnummer("556677-8899")).toBe("5566778899");
    expect(parseOrganisationsnummer("5566778899")).toBe("5566778899");
    expect(organisationsnummerSchema.parse(" 556677-8899 ")).toBe("5566778899");
  });

  it("rejects a bad check digit, a personnummer and other shapes", () => {
    expect(parseOrganisationsnummer("556677-8898")).toBeNull();
    expect(parseOrganisationsnummer("121212-1212")).toBeNull(); // third digit < 2
    expect(parseOrganisationsnummer("16556677-8899")).toBeNull();
    expect(parseOrganisationsnummer("55667-78899")).toBeNull();
  });
});

describe("luhnValid", () => {
  it("validates mod 10", () => {
    expect(luhnValid("8112189876")).toBe(true);
    expect(luhnValid("8112189875")).toBe(false);
    expect(luhnValid("abc")).toBe(false);
  });
});
