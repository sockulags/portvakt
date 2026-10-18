/**
 * Assurance level ordering (ACR_RANKING, lowest first). `acr_values` is a list of acceptable
 * levels: a login satisfies it when its acr equals one of them or ranks at least as high as a
 * ranked one. Values outside the ranking only ever satisfy themselves.
 */
export class AcrRanking {
  readonly #rank: ReadonlyMap<string, number>;
  readonly values: readonly string[];

  constructor(order: readonly string[]) {
    this.values = [...order];
    this.#rank = new Map(order.map((value, index) => [value, index]));
  }

  rank(acr: string): number | undefined {
    return this.#rank.get(acr);
  }

  /** Whether a login asserting `asserted` meets the level `required`. */
  satisfies(asserted: string, required: string): boolean {
    if (asserted === required) return true;
    const have = this.#rank.get(asserted);
    const need = this.#rank.get(required);
    return have !== undefined && need !== undefined && have >= need;
  }

  /** Whether `asserted` meets at least one requested value; an empty request is always met. */
  satisfiesAny(asserted: string, requested: readonly string[]): boolean {
    return requested.length === 0 || requested.some((value) => this.satisfies(asserted, value));
  }
}

/** Splits an `acr_values` parameter (space-separated) into its values. */
export function parseAcrValues(value: unknown): string[] {
  if (typeof value !== "string") return [];
  return [...new Set(value.split(" ").filter((item) => item.length > 0 && item.length <= 255))];
}
