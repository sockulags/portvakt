/** Returns the single row a statement must produce (INSERT ... RETURNING and friends). */
export function requireRow<R>(rows: readonly R[]): R {
  const [row] = rows;
  if (row === undefined) throw new Error("Statement returned no row");
  return row;
}

/** Collects positional parameters for dynamically built (but always parameterised) SQL. */
export class SqlParams {
  readonly values: unknown[] = [];

  /** Adds a value and returns its placeholder (`$n`). */
  add(value: unknown): string {
    this.values.push(value);
    return `$${this.values.length}`;
  }
}
