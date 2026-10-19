import { canonicalJson } from "./etag.js";

/** One changed field in an admin audit event (see `changesOf` in the audit catalogue). */
export type DiffEntry =
  { readonly from?: DiffValue; readonly to?: DiffValue } | { readonly changed: true };
type DiffScalar = string | number | boolean | null;
type DiffValue = DiffScalar | DiffScalar[];

const MAX_STRING = 2048;
const MAX_ITEMS = 100;
const IDENTIFIER = /^[a-z][A-Za-z0-9]*$/;

/** A value as an audit diff may hold it, or `undefined` when it must be reduced to `changed`. */
function auditable(value: unknown): DiffValue | undefined {
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") return value.length <= MAX_STRING ? value : undefined;
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) {
    if (value.length > MAX_ITEMS) return undefined;
    const items: DiffScalar[] = [];
    for (const item of value) {
      if (item === null || ["string", "number", "boolean"].includes(typeof item)) {
        if (typeof item === "string" && item.length > MAX_STRING) return undefined;
        items.push(item as DiffScalar);
      } else {
        // Lists of objects (roles, logos) are recorded as compact JSON strings.
        const json = canonicalJson(item);
        if (json.length > MAX_STRING) return undefined;
        items.push(json);
      }
    }
    return items;
  }
  return undefined;
}

/** Flattens nested plain objects into dotted paths; arrays and scalars are leaves. */
function flatten(value: unknown, prefix: string, out: Map<string, unknown>): void {
  if (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof Date)
  ) {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (item === undefined || !IDENTIFIER.test(key)) continue;
      flatten(item, prefix === "" ? key : `${prefix}.${key}`, out);
    }
    return;
  }
  out.set(prefix, value);
}

/**
 * The changes between two views of a resource, for an `admin.*` audit event. Fields listed in
 * `redacted` (and below them) are reported as `{ changed: true }` without values, and so is any
 * value too large for the log. `before` is `{}` for a creation.
 */
export function diff(
  before: Readonly<Record<string, unknown>>,
  after: Readonly<Record<string, unknown>>,
  redacted: readonly string[] = [],
): Record<string, DiffEntry> {
  const old = new Map<string, unknown>();
  const next = new Map<string, unknown>();
  flatten(before, "", old);
  flatten(after, "", next);
  const isRedacted = (path: string): boolean =>
    redacted.some((field) => path === field || path.startsWith(`${field}.`));
  const changes: Record<string, DiffEntry> = {};
  for (const path of new Set([...old.keys(), ...next.keys()])) {
    if (path === "") continue;
    const from = old.get(path);
    const to = next.get(path);
    if (canonicalJson(from ?? null) === canonicalJson(to ?? null)) continue;
    if (isRedacted(path)) {
      changes[path] = { changed: true };
      continue;
    }
    const fromValue = from === undefined ? undefined : auditable(from);
    const toValue = to === undefined ? undefined : auditable(to);
    if (
      (from !== undefined && fromValue === undefined) ||
      (to !== undefined && toValue === undefined)
    ) {
      changes[path] = { changed: true };
      continue;
    }
    changes[path] = {
      ...(fromValue === undefined ? {} : { from: fromValue }),
      ...(toValue === undefined ? {} : { to: toValue }),
    };
  }
  return changes;
}
