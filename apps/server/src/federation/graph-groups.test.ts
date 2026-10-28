import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { OutboundGuard } from "../net/outbound.js";
import {
  fetchOverageGroups,
  GraphGroupsError,
  MAX_OVERAGE_GROUPS,
  MAX_OVERAGE_PAGES,
} from "./graph-groups.js";

type Handler = (req: IncomingMessage, res: ServerResponse, base: string) => void;

describe("groups overage through Microsoft Graph", () => {
  const server = createServer((req, res) => handler(req, res, base));
  let handler: Handler = (_req, res) => res.end();
  let base = "";
  const seen: { url: string; authorization: string | undefined }[] = [];
  const outbound = new OutboundGuard({
    production: false,
    allowPrivateHosts: ["127.0.0.1"],
    timeoutSeconds: 5,
  });
  const lookup = () => fetchOverageGroups({ outbound, graphApiUrl: `${base}/graph` }, "token-1");
  const json = (res: ServerResponse, body: unknown, status = 200) => {
    res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  };
  const failure = async (): Promise<string> => {
    const error = await lookup().then(
      () => undefined,
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(GraphGroupsError);
    return (error as GraphGroupsError).reason;
  };

  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  beforeEach(() => {
    seen.length = 0;
  });

  const record =
    (inner: Handler): Handler =>
    (req, res, url) => {
      seen.push({ url: req.url ?? "", authorization: req.headers.authorization });
      inner(req, res, url);
    };

  it("reads every page and keeps group ids only", async () => {
    handler = record((req, res, url) => {
      if (req.url?.includes("skiptoken=2") === true) {
        json(res, { value: [{ "@odata.type": "#microsoft.graph.group", id: "grp-b" }] });
        return;
      }
      json(res, {
        value: [
          { "@odata.type": "#microsoft.graph.group", id: "grp-a" },
          { "@odata.type": "#microsoft.graph.directoryRole", id: "role-1" },
          { "@odata.type": "#microsoft.graph.group", id: "grp-a" },
        ],
        "@odata.nextLink": `${url}/graph/v1.0/me/transitiveMemberOf?$skiptoken=2`,
      });
    });
    expect(await lookup()).toEqual(["grp-a", "grp-b"]);
    expect(seen).toEqual([
      {
        url: "/graph/v1.0/me/transitiveMemberOf?$select=id&$top=999",
        authorization: "Bearer token-1",
      },
      { url: "/graph/v1.0/me/transitiveMemberOf?$skiptoken=2", authorization: "Bearer token-1" },
    ]);
  });

  it("never sends the access token to a paging link outside the Graph base", async () => {
    handler = record((_req, res) => {
      json(res, { value: [], "@odata.nextLink": "https://evil.example/v1.0/me?$skiptoken=1" });
    });
    expect(await failure()).toBe("invalid_response");
    expect(seen).toHaveLength(1);
  });

  it("does not follow redirects", async () => {
    handler = record((_req, res, url) => {
      res.writeHead(302, { location: `${url}/elsewhere` }).end();
    });
    expect(await failure()).toBe("invalid_response");
    expect(seen).toHaveLength(1);
  });

  it("fails closed on refusals, server errors and malformed answers", async () => {
    handler = (_req, res) => json(res, { error: { code: "InvalidAuthenticationToken" } }, 401);
    expect(await failure()).toBe("refused");
    handler = (_req, res) => json(res, { error: {} }, 503);
    expect(await failure()).toBe("unavailable");
    handler = (_req, res) => json(res, {}, 429);
    expect(await failure()).toBe("unavailable");
    handler = (_req, res) => res.writeHead(200).end("not json");
    expect(await failure()).toBe("invalid_response");
    handler = (_req, res) => json(res, { value: "nope" });
    expect(await failure()).toBe("invalid_response");
  });

  it("is bounded in pages and groups", async () => {
    handler = (_req, res, url) => {
      json(res, {
        value: [],
        "@odata.nextLink": `${url}/graph/v1.0/me/transitiveMemberOf?$skiptoken=x`,
      });
    };
    expect(await failure()).toBe("too_many_groups");

    let page = 0;
    handler = (_req, res, url) => {
      page += 1;
      json(res, {
        value: Array.from({ length: 999 }, (_, index) => ({
          "@odata.type": "#microsoft.graph.group",
          id: `grp-${page}-${index}`,
        })),
        "@odata.nextLink": `${url}/graph/v1.0/me/transitiveMemberOf?$skiptoken=${page}`,
      });
    };
    expect(await failure()).toBe("too_many_groups");
    expect(page).toBeLessThan(MAX_OVERAGE_PAGES);
    expect(MAX_OVERAGE_GROUPS).toBeLessThan(2 * 999);
  });

  it("fails as unavailable when Graph cannot be reached", async () => {
    const unreachable = fetchOverageGroups(
      { outbound, graphApiUrl: "http://127.0.0.1:9/graph" },
      "token-1",
    );
    await expect(unreachable).rejects.toMatchObject({ reason: "unavailable" });
  });
});
