const UNIT_SECONDS = {
  s: 1,
  m: 60,
  h: 60 * 60,
  d: 24 * 60 * 60,
  w: 7 * 24 * 60 * 60,
} as const;

const SEGMENT = /(\d+)([smhdw])/g;
const WHOLE = /^(?:\d+[smhdw])+$/;

/**
 * Parses a duration such as `90d`, `36h`, `1h30m` or `45s` into whole seconds.
 * Units: s, m, h, d, w. Returns `undefined` for anything else (including zero).
 */
export function parseDurationSeconds(input: string): number | undefined {
  const value = input.trim().toLowerCase();
  if (!WHOLE.test(value)) return undefined;
  let total = 0;
  for (const match of value.matchAll(SEGMENT)) {
    const amount = Number(match[1]);
    const unit = match[2] as keyof typeof UNIT_SECONDS;
    total += amount * UNIT_SECONDS[unit];
  }
  if (!Number.isSafeInteger(total) || total <= 0) return undefined;
  return total;
}
