import { z } from "zod";

/**
 * Swedish personal identity numbers (personnummer, samordningsnummer) and organisation numbers
 * (organisationsnummer). Parsing never throws; it returns `null` for anything invalid. Values are
 * personal data: never log them.
 */

export type PersonnummerKind = "personnummer" | "samordningsnummer";

export interface Personnummer {
  /** Canonical 12-digit form `YYYYMMDDNNNC` (a samordningsnummer keeps its day + 60). */
  readonly canonical: string;
  readonly kind: PersonnummerKind;
  /** Date of birth (UTC midnight). */
  readonly birthDate: Date;
}

/** Luhn (mod 10) check over a string of digits, weights 2,1,2,1,... from the left. */
export function luhnValid(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i += 1) {
    const weight = (digits.length - i) % 2 === 0 ? 2 : 1;
    const product = Number(digits[i]) * weight;
    sum += product > 9 ? product - 9 : product;
  }
  return sum % 10 === 0;
}

function utcDate(year: number, month: number, day: number): Date | undefined {
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return undefined;
  }
  return date;
}

const SHORT = /^(\d{2})(\d{2})(\d{2})([-+])(\d{4})$/;
const LONG = /^(\d{4})(\d{2})(\d{2})-?(\d{4})$/;

/**
 * Parses `YYMMDD-NNNC`, `YYMMDD+NNNC` (`+`: the person is 100 years or older), `YYYYMMDDNNNC` and
 * `YYYYMMDD-NNNC`. Validates the date (day + 60 for a samordningsnummer), the Luhn check digit,
 * and that the date of birth is not in the future relative to `now`.
 */
export function parsePersonnummer(input: string, now: Date = new Date()): Personnummer | null {
  const value = input.trim();
  let year: number;
  let month: string;
  let day: string;
  let serial: string;

  const short = SHORT.exec(value);
  const long = short === null ? LONG.exec(value) : null;
  if (short !== null) {
    const [, yy, mm, dd, separator, nnnc] = short as unknown as [
      string,
      string,
      string,
      string,
      string,
      string,
    ];
    month = mm;
    day = dd;
    serial = nnnc;
    const nowYear = now.getUTCFullYear();
    year = nowYear - ((((nowYear - Number(yy)) % 100) + 100) % 100);
    const birth = birthDateOf(year, month, day);
    if (birth !== undefined && birth.getTime() > now.getTime()) year -= 100;
    if (separator === "+") year -= 100;
  } else if (long !== null) {
    const [, yyyy, mm, dd, nnnc] = long as unknown as [string, string, string, string, string];
    year = Number(yyyy);
    month = mm;
    day = dd;
    serial = nnnc;
  } else {
    return null;
  }

  const birthDate = birthDateOf(year, month, day);
  if (birthDate === undefined || birthDate.getTime() > now.getTime()) return null;
  const tenDigits = `${String(year % 100).padStart(2, "0")}${month}${day}${serial}`;
  if (!luhnValid(tenDigits)) return null;
  return {
    canonical: `${String(year).padStart(4, "0")}${month}${day}${serial}`,
    kind: Number(day) > 60 ? "samordningsnummer" : "personnummer",
    birthDate,
  };
}

function birthDateOf(year: number, month: string, day: string): Date | undefined {
  const dayNumber = Number(day);
  const realDay = dayNumber > 60 ? dayNumber - 60 : dayNumber;
  if (realDay < 1) return undefined;
  return utcDate(year, Number(month), realDay);
}

/**
 * Parses an organisationsnummer: 10 digits, optionally `NNNNNN-NNNN`. The third digit is at least
 * 2 (which tells it apart from a personnummer) and the last digit is a Luhn check digit.
 * Returns the canonical 10-digit form.
 */
export function parseOrganisationsnummer(input: string): string | null {
  const match = /^(\d{6})-?(\d{4})$/.exec(input.trim());
  if (match === null) return null;
  const digits = `${match[1]}${match[2]}`;
  if (Number(digits[2]) < 2 || !luhnValid(digits)) return null;
  return digits;
}

/** zod schema: any accepted personnummer format, output in canonical 12-digit form. */
export const personnummerSchema = z.string().transform((value, ctx) => {
  const parsed = parsePersonnummer(value);
  if (parsed === null) {
    ctx.addIssue({ code: "custom", message: "must be a valid personnummer or samordningsnummer" });
    return z.NEVER;
  }
  return parsed.canonical;
});

/** zod schema: organisationsnummer, output in canonical 10-digit form. */
export const organisationsnummerSchema = z.string().transform((value, ctx) => {
  const parsed = parseOrganisationsnummer(value);
  if (parsed === null) {
    ctx.addIssue({ code: "custom", message: "must be a valid organisationsnummer" });
    return z.NEVER;
  }
  return parsed;
});
