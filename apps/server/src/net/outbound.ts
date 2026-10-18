import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { BlockList, isIP, type LookupFunction } from "node:net";
import { Agent, fetch as undiciFetch, type RequestInit as UndiciRequestInit } from "undici";

/**
 * Every outbound request Portvakt makes to a URL an administrator or an application configured
 * (SAML metadata, upstream OIDC discovery, JWKS, token and userinfo, downstream client
 * `jwks_uri`) goes through this guard:
 *
 * - only http(s), and https only in production;
 * - addresses are checked where the connection is made (the DNS lookup of the socket), so a
 *   host that resolves to a loopback, private (RFC 1918, CGNAT), link-local (169.254.0.0/16, the
 *   cloud metadata address), unique-local, unspecified, multicast or reserved address is refused,
 *   also after DNS rebinding; literal IP hosts are checked before connecting;
 * - redirects are followed by hand (at most {@link MAX_REDIRECTS}), each hop checked again;
 * - response bodies are capped.
 *
 * Development and tests may allow named hosts (ALLOW_PRIVATE_UPSTREAM_HOSTS, refused in
 * production). Failures are {@link OutboundRefusedError} with a fixed reason for the logs; callers
 * report a generic code.
 */

export const MAX_REDIRECTS = 3;
const DEFAULT_MAX_BYTES = 5 * 1024 * 1024;

export class OutboundRefusedError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(`outbound request refused: ${reason}`);
    this.name = "OutboundRefusedError";
    this.reason = reason;
  }
}

const blocked = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  blocked.addSubnet(network, prefix, "ipv4");
}
for (const [network, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["64:ff9b::", 96],
  ["64:ff9b:1::", 48],
  ["2002::", 16],
  ["100::", 64],
  ["2001:db8::", 32],
  ["fc00::", 7],
  ["fe80::", 10],
  ["fec0::", 10],
  ["ff00::", 8],
] as const) {
  blocked.addSubnet(network, prefix, "ipv6");
}

/** Whether an address is one outbound requests must not reach. */
export function isSpecialUseAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return blocked.check(address, "ipv4");
  if (family !== 6) return true;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped?.[1] !== undefined) return blocked.check(mapped[1], "ipv4");
  return blocked.check(address, "ipv6");
}

export interface OutboundOptions {
  readonly production: boolean;
  /** Hostnames (or literal IPs) allowed to resolve to special-use addresses (dev and tests). */
  readonly allowPrivateHosts: readonly string[];
  readonly timeoutSeconds: number;
}

export interface OutboundRequestInit extends RequestInit {
  /** Cap of the response body (default 5 MB). */
  readonly maxBytes?: number;
}

export class OutboundGuard {
  readonly #options: OutboundOptions;
  readonly #allowed: ReadonlySet<string>;
  readonly #dispatcher: Agent;

  constructor(options: OutboundOptions) {
    if (options.production && options.allowPrivateHosts.length > 0) {
      throw new Error("ALLOW_PRIVATE_UPSTREAM_HOSTS is refused in production");
    }
    this.#options = options;
    this.#allowed = new Set(options.allowPrivateHosts.map((host) => host.toLowerCase()));
    const lookup: LookupFunction = (hostname, lookupOptions, callback) => {
      dnsLookup(hostname, { ...lookupOptions, all: true }, (error, addresses: LookupAddress[]) => {
        if (error !== null) {
          callback(error, "", 0);
          return;
        }
        if (!this.#allowed.has(hostname.toLowerCase())) {
          if (
            addresses.length === 0 ||
            addresses.some((entry) => isSpecialUseAddress(entry.address))
          ) {
            callback(new OutboundRefusedError("special_use_address"), "", 0);
            return;
          }
        }
        if (lookupOptions.all === true) {
          (callback as unknown as (err: null, list: LookupAddress[]) => void)(null, addresses);
          return;
        }
        const first = addresses[0];
        callback(null, first?.address ?? "", first?.family ?? 4);
      });
    };
    this.#dispatcher = new Agent({ connect: { lookup } });
  }

  /** Checks a URL before any connection: scheme, and a literal IP host. */
  check(url: URL): void {
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      throw new OutboundRefusedError("scheme");
    }
    if (this.#options.production && url.protocol !== "https:") {
      throw new OutboundRefusedError("insecure_scheme");
    }
    if (url.username !== "" || url.password !== "") throw new OutboundRefusedError("credentials");
    const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (isIP(host) !== 0 && !this.#allowed.has(host) && isSpecialUseAddress(host)) {
      throw new OutboundRefusedError("special_use_address");
    }
  }

  /**
   * `fetch` with the guard: manual redirects (each hop checked; with `redirect: "manual"` the
   * caller gets the 3xx), a timeout unless the caller passes a signal, and a capped body.
   */
  async fetch(input: string | URL, init: OutboundRequestInit = {}): Promise<Response> {
    const { maxBytes = DEFAULT_MAX_BYTES, redirect, ...rest } = init;
    let url = new URL(input);
    let request: RequestInit = rest;
    for (let hop = 0; ; hop += 1) {
      this.check(url);
      let response: Response;
      try {
        // undici's own fetch with its Agent: no dependence on the runtime's bundled version.
        response = await undiciFetch(url, {
          ...(request as UndiciRequestInit),
          redirect: "manual",
          signal: request.signal ?? AbortSignal.timeout(this.#options.timeoutSeconds * 1000),
          dispatcher: this.#dispatcher,
        });
      } catch (error) {
        // fetch wraps a refusal of the connection's lookup in its own TypeError.
        for (let cause: unknown = error; cause instanceof Error; cause = cause.cause) {
          if (cause instanceof OutboundRefusedError) throw cause;
        }
        throw error;
      }
      const location = response.headers.get("location");
      if (
        response.status >= 300 &&
        response.status < 400 &&
        location !== null &&
        redirect !== "manual"
      ) {
        await response.body?.cancel();
        if (hop >= MAX_REDIRECTS) throw new OutboundRefusedError("too_many_redirects");
        url = new URL(location, url);
        // A redirect turns the request into a GET without a body (as fetch does for 301-303).
        if (response.status !== 307 && response.status !== 308) {
          const { body: _body, method: _method, ...withoutBody } = request;
          void _body;
          void _method;
          request = { ...withoutBody, method: "GET" };
        }
        continue;
      }
      return capped(response, maxBytes);
    }
  }
}

async function capped(response: Response, maxBytes: number): Promise<Response> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > maxBytes) {
    await response.body?.cancel();
    throw new OutboundRefusedError("too_large");
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  const reader: ReadableStreamDefaultReader<Uint8Array> | undefined = response.body?.getReader();
  if (reader !== undefined) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new OutboundRefusedError("too_large");
      }
      chunks.push(value);
    }
  }
  const headers = new Headers(response.headers);
  headers.delete("content-encoding");
  headers.delete("content-length");
  const body = response.status === 204 || response.status === 304 ? null : Buffer.concat(chunks);
  const result = new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
  Object.defineProperty(result, "url", { value: response.url });
  return result;
}
