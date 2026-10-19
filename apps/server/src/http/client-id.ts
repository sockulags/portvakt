import { Readable } from "node:stream";
import type { Request } from "express";

/**
 * oidc-provider's own body limit for its form and JSON endpoints (`shared/selective_body.js`):
 * bodies read here for the rate limit are capped the same way.
 */
export const PROVIDER_BODY_LIMIT = 56 * 1024;

const CLIENT_ID = /^[\x21-\x7e]{1,255}$/;

/** The client_id of HTTP Basic client authentication (`client_secret_basic`), if any. */
export function basicClientId(authorization: string | undefined): string | undefined {
  if (authorization === undefined || !/^basic /i.test(authorization)) return undefined;
  const decoded = Buffer.from(authorization.slice(6).trim(), "base64").toString("utf8");
  const separator = decoded.indexOf(":");
  if (separator <= 0) return undefined;
  try {
    // RFC 6749 2.3.1: the client_id is form-urlencoded before it is base64 encoded.
    const id = decodeURIComponent(decoded.slice(0, separator).replace(/\+/g, " "));
    return CLIENT_ID.test(id) ? id : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The client a form body names: `client_id`, or the `sub` of a `client_assertion`
 * (private_key_jwt), read without verifying it. Only ever used as a rate-limit key: a forged
 * value charges that client's bucket, which the per-IP limit checked first bounds.
 */
export function bodyClientId(body: URLSearchParams): string | undefined {
  const direct = body.get("client_id");
  if (direct !== null) return CLIENT_ID.test(direct) ? direct : undefined;
  const assertion = body.get("client_assertion");
  const payload = assertion?.split(".")[1];
  if (payload === undefined || payload.length > 8192) return undefined;
  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as unknown;
    const sub = (claims as { sub?: unknown } | null)?.sub;
    return typeof sub === "string" && CLIENT_ID.test(sub) ? sub : undefined;
  } catch {
    return undefined;
  }
}

export class BodyTooLargeError extends Error {
  constructor() {
    super("request body too large");
    this.name = "BodyTooLargeError";
  }
}

/**
 * Reads a form body (at most {@link PROVIDER_BODY_LIMIT}) so the rate limit can see its
 * client_id, then makes the request readable again for oidc-provider, which reads the body
 * itself (`req.readable` and `req.iterator()` in `selective_body.js`): the same bytes are
 * replayed, so the provider parses exactly what it would have read. Requests of another content
 * type are left alone (`undefined`).
 */
export async function readReplayableForm(req: Request): Promise<URLSearchParams | undefined> {
  if (!req.is("application/x-www-form-urlencoded") || !req.readable) return undefined;
  const declared = Number(req.get("content-length") ?? "0");
  if (declared > PROVIDER_BODY_LIMIT) throw new BodyTooLargeError();
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req.iterator({ destroyOnReturn: false })) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    size += buffer.length;
    if (size > PROVIDER_BODY_LIMIT) throw new BodyTooLargeError();
    chunks.push(buffer);
  }
  const body = Buffer.concat(chunks, size);
  Object.defineProperty(req, "readable", { value: true, configurable: true });
  Object.defineProperty(req, "iterator", {
    configurable: true,
    value: () => Readable.from([body]),
  });
  return new URLSearchParams(body.toString("utf8"));
}
