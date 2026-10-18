import { describe, expect, it } from "vitest";
import { DEFAULT_ACR_RANKING } from "../config/index.js";
import { AcrRanking, parseAcrValues } from "./acr.js";

const [loa2, loa3, loa4] = DEFAULT_ACR_RANKING as [string, string, string];

describe("AcrRanking", () => {
  const ranking = new AcrRanking(DEFAULT_ACR_RANKING);

  it("lets a higher ranked level satisfy a lower one, never the other way", () => {
    expect(ranking.satisfies(loa4, loa3)).toBe(true);
    expect(ranking.satisfies(loa3, loa3)).toBe(true);
    expect(ranking.satisfies(loa2, loa3)).toBe(false);
  });

  it("matches unranked values only exactly", () => {
    expect(ranking.satisfies("urn:x:employee", "urn:x:employee")).toBe(true);
    expect(ranking.satisfies("urn:x:employee", loa2)).toBe(false);
    expect(ranking.satisfies(loa4, "urn:x:employee")).toBe(false);
  });

  it("accepts any of the requested values, and everything without a request", () => {
    expect(ranking.satisfiesAny(loa3, [loa4, loa3])).toBe(true);
    expect(ranking.satisfiesAny(loa2, [loa4, loa3])).toBe(false);
    expect(ranking.satisfiesAny(loa2, [])).toBe(true);
  });

  it("parses acr_values", () => {
    expect(parseAcrValues(`${loa3}  ${loa4} ${loa3}`)).toEqual([loa3, loa4]);
    expect(parseAcrValues(undefined)).toEqual([]);
  });
});
