import type { Request, Response } from "express";

/** The value of one cookie of the request (the first one with that name). */
export function readCookie(req: Request, name: string): string | undefined {
  const header = req.headers.cookie;
  if (typeof header !== "string" || header.length > 16_384) return undefined;
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() !== name) continue;
    let value = part.slice(separator + 1).trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2)
      value = value.slice(1, -1);
    try {
      return decodeURIComponent(value);
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export interface CookieAttributes {
  readonly path: string;
  readonly domain?: string | undefined;
  readonly secure: boolean;
  readonly sameSite: "lax" | "strict";
  /** Seconds; 0 deletes the cookie. Omitted: a browser-session cookie. */
  readonly maxAge?: number;
}

/** Appends a `Set-Cookie` header (always HttpOnly). */
export function setCookie(
  res: Response,
  name: string,
  value: string,
  attributes: CookieAttributes,
): void {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${attributes.path}`, "HttpOnly"];
  if (attributes.domain !== undefined) parts.push(`Domain=${attributes.domain}`);
  if (attributes.secure) parts.push("Secure");
  parts.push(`SameSite=${attributes.sameSite === "strict" ? "Strict" : "Lax"}`);
  if (attributes.maxAge !== undefined) {
    const maxAge = Math.max(0, Math.floor(attributes.maxAge));
    parts.push(`Max-Age=${maxAge}`);
    if (maxAge === 0) parts.push("Expires=Thu, 01 Jan 1970 00:00:00 GMT");
  }
  res.append("Set-Cookie", parts.join("; "));
}

/**
 * Whether the request is a top-level browser navigation (it can be redirected to Portvakt) as
 * opposed to an XHR/fetch call (it gets a JSON error). `Sec-Fetch-Mode` decides when the browser
 * sends it; otherwise a GET that accepts HTML and is not marked as XHR.
 */
export function isBrowserNavigation(req: Request): boolean {
  const mode = req.get("sec-fetch-mode");
  if (mode !== undefined && mode !== "") return mode === "navigate";
  if (req.method !== "GET" && req.method !== "HEAD") return false;
  if (req.get("x-requested-with") !== undefined) return false;
  return (req.get("accept") ?? "").includes("text/html");
}

/** Whether the caller asked for JSON (fetch from an SPA) rather than an HTML page. */
export function wantsJson(req: Request): boolean {
  if (req.get("sec-fetch-mode") === "navigate") return false;
  const accept = req.get("accept") ?? "";
  return accept.includes("application/json") && !accept.includes("text/html");
}

const MAX_RETURN_TO = 2048;

/**
 * A same-origin relative path to return to after a login, or `undefined`. Accepted: a path that
 * starts with a single `/`, without backslashes, control characters or a scheme-relative
 * (`//host`) start, which resolves to the same origin. Everything else (absolute URLs,
 * `//evil`, `/\evil`, `javascript:`) is refused.
 */
export function safeReturnTo(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_RETURN_TO) {
    return undefined;
  }
  if (!value.startsWith("/") || value.startsWith("//")) return undefined;
  if (value.includes("\\")) return undefined;
  // Control characters (and the tab or newlines browsers strip from URLs) and spaces.
  if (hasControlCharacters(value, true)) return undefined;
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return undefined;
  }
  if (decoded.startsWith("//") || decoded.includes("\\")) return undefined;
  const base = "http://portvakt-return-to.invalid";
  let resolved: URL;
  try {
    resolved = new URL(value, base);
  } catch {
    return undefined;
  }
  if (resolved.origin !== base) return undefined;
  // Dot segments are resolved only now: `/.//evil`, `/a/..//evil` and `/%2e//evil` all become
  // `//evil`, which a browser reads as another host. The result itself must be a safe path.
  const path = resolved.pathname;
  if (path.startsWith("//") || path.startsWith("/\\") || path.includes("\\")) return undefined;
  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(path);
  } catch {
    return undefined;
  }
  if (decodedPath.startsWith("//") || decodedPath.includes("\\")) return undefined;
  const result = `${path}${resolved.search}${resolved.hash}`;
  // And it must still resolve to the same origin, read on its own.
  if (new URL(result, base).origin !== base || result.startsWith("//")) return undefined;
  return result;
}

/** Whether a string has C0 control characters or DEL (and, with `space`, a space). */
export function hasControlCharacters(value: string, space = false): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code === 0x7f || (space && code === 0x20)) return true;
  }
  return false;
}

/** Escapes text for an HTML page. */
export const escapeHtml = (value: string): string =>
  value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
