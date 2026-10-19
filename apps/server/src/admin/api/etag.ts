import { createHash } from "node:crypto";
import { ApiError } from "./problem.js";

/** JSON with sorted keys, so equal representations always hash alike. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/**
 * The entity tag of a resource: a hash of its whole representation (without the tag itself),
 * so any change of a returned field, including `updatedAt`, gives a new tag.
 */
export function etagOf(representation: Readonly<Record<string, unknown>>): string {
  const { etag: _etag, ...rest } = representation;
  void _etag;
  const digest = createHash("sha256").update(canonicalJson(rest)).digest("base64url");
  return `"${digest.slice(0, 27)}"`;
}

/** Adds `etag` to a representation. */
export function withEtag<T extends Record<string, unknown>>(
  representation: T,
): T & { etag: string } {
  return { ...representation, etag: etagOf(representation) };
}

/**
 * Optimistic concurrency: the request's `If-Match` must name the current tag (428 without one,
 * 412 on a mismatch). `*` is not accepted: a client must have read the version it changes.
 */
export function requireMatch(ifMatch: string | undefined, current: string): void {
  if (ifMatch === undefined || ifMatch.trim() === "") throw new ApiError("precondition_required");
  const presented = ifMatch
    .split(",")
    .map((tag) => tag.trim().replace(/^W\//, ""))
    .filter((tag) => tag !== "");
  if (!presented.includes(current)) throw new ApiError("precondition_failed");
}
