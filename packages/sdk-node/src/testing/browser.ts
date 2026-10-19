import { request as httpRequest } from "node:http";

/**
 * A cookie-keeping fetch for the SDK's unit tests: host-only cookies per `host:port`, path
 * matching, no redirects followed unless asked.
 */
export class MiniBrowser {
  readonly #cookies = new Map<
    string,
    { host: string; name: string; value: string; path: string }
  >();

  async request(url: string, init: RequestInit = {}): Promise<Response> {
    const target = new URL(url);
    const headers = new Headers(init.headers);
    const cookie = this.#cookieHeader(target);
    if (cookie !== "") headers.set("cookie", cookie);
    const response = await fetch(target, { ...init, headers, redirect: "manual" });
    for (const header of response.headers.getSetCookie()) this.#store(header, target);
    return response;
  }

  /**
   * A top-level GET navigation (`Sec-Fetch-Mode: navigate`, which fetch cannot send: it always
   * sends `cors`), with extra headers such as `Sec-Fetch-Site` (default `same-origin`) or
   * `Referer`. Returns the status, the Location header, the other headers and the body.
   */
  navigate(
    url: string,
    headers: Readonly<Record<string, string>> = { "sec-fetch-site": "same-origin" },
  ): Promise<{
    readonly status: number;
    readonly location: string | null;
    readonly headers: Readonly<Record<string, string | string[] | undefined>>;
    readonly body: string;
  }> {
    const target = new URL(url);
    const cookie = this.#cookieHeader(target);
    return new Promise((resolve, reject) => {
      const req = httpRequest(
        target,
        {
          method: "GET",
          headers: {
            accept: "text/html",
            "sec-fetch-mode": "navigate",
            ...headers,
            ...(cookie === "" ? {} : { cookie }),
          },
        },
        (res) => {
          for (const header of res.headers["set-cookie"] ?? []) this.#store(header, target);
          const chunks: Buffer[] = [];
          res.on("data", (chunk: Buffer) => chunks.push(chunk));
          res.on("end", () => {
            resolve({
              status: res.statusCode ?? 0,
              location: res.headers.location ?? null,
              headers: res.headers,
              body: Buffer.concat(chunks).toString("utf8"),
            });
          });
        },
      );
      req.on("error", reject);
      req.end();
    });
  }

  #cookieHeader(target: URL): string {
    return [...this.#cookies.values()]
      .filter((entry) => entry.host === target.host && pathMatches(target.pathname, entry.path))
      .map((entry) => `${entry.name}=${entry.value}`)
      .join("; ");
  }

  /** Follows redirects (GET) until a non-redirect response; returns it and the final URL. */
  async follow(url: string, init: RequestInit = {}): Promise<{ response: Response; url: string }> {
    let current = url;
    let response = await this.request(current, init);
    for (let hops = 0; response.status >= 300 && response.status < 400; hops += 1) {
      if (hops > 10) throw new Error("too many redirects");
      current = new URL(response.headers.get("location")!, current).href;
      response = await this.request(current);
    }
    return { response, url: current };
  }

  cookie(name: string): string | undefined {
    return [...this.#cookies.values()].find((entry) => entry.name === name)?.value;
  }

  setCookie(host: string, name: string, value: string, path = "/"): void {
    this.#cookies.set(`${host}|${name}|${path}`, { host, name, value, path });
  }

  #store(header: string, target: URL): void {
    const [pair = "", ...attributes] = header.split(";").map((part) => part.trim());
    const separator = pair.indexOf("=");
    if (separator <= 0) return;
    const name = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    let path = "/";
    let expired = false;
    for (const attribute of attributes) {
      const [key = "", attributeValue = ""] = attribute.split("=");
      if (key.toLowerCase() === "path") path = attributeValue;
      if (key.toLowerCase() === "max-age" && Number(attributeValue) <= 0) expired = true;
    }
    const key = `${target.host}|${name}|${path}`;
    if (expired) this.#cookies.delete(key);
    else this.#cookies.set(key, { host: target.host, name, value, path });
  }
}

function pathMatches(requestPath: string, cookiePath: string): boolean {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith("/") || requestPath[cookiePath.length] === "/";
}
