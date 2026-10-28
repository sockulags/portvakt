import { z } from "zod";
import { OutboundRefusedError, type OutboundGuard } from "../net/outbound.js";

/**
 * Entra ID groups overage through Microsoft Graph: when an ID token names a source for the
 * groups claim instead of carrying it (`_claim_names`), the groups of the signed-in user are read
 * with the upstream access token from `{GRAPH_API_URL}/v1.0/me/transitiveMemberOf` (group ids
 * only). Every request goes through the outbound guard, redirects are refused (the access token
 * never follows one), paging follows `@odata.nextLink` only below the configured base URL, and
 * the result is bounded: more than {@link MAX_OVERAGE_GROUPS} groups or
 * {@link MAX_OVERAGE_PAGES} pages fail the lookup (the login fails closed rather than evaluating
 * rules on a partial list).
 */

/** At most this many groups (as the groups claim mapping keeps). */
export const MAX_OVERAGE_GROUPS = 1000;
/** At most this many pages of `transitiveMemberOf`. */
export const MAX_OVERAGE_PAGES = 10;
/** Page size asked for (`$top`; Graph's maximum for directory objects). */
const PAGE_SIZE = 999;
/** Largest response page (999 ids with their types fit in well under 1 MB). */
const MAX_PAGE_BYTES = 1024 * 1024;

const GROUP_TYPE = "#microsoft.graph.group";

/** Why a groups lookup failed: fixed reasons for logs; the login reports a generic code. */
export type GraphGroupsFailure =
  /** Graph could not be reached, timed out, or answered 5xx / 429. */
  | "unavailable"
  /** Graph refused the request (401/403: the access token is not valid for Graph). */
  | "refused"
  /** The answer was not what Graph sends (status, JSON, paging link outside the base). */
  | "invalid_response"
  /** More groups or pages than the bounds allow. */
  | "too_many_groups";

export class GraphGroupsError extends Error {
  readonly reason: GraphGroupsFailure;

  constructor(reason: GraphGroupsFailure) {
    super(`groups overage lookup failed: ${reason}`);
    this.name = "GraphGroupsError";
    this.reason = reason;
  }
}

const pageSchema = z.object({
  value: z
    .array(
      z
        .object({
          "@odata.type": z.string().max(200).optional(),
          id: z.string().max(512).optional(),
        })
        .loose(),
    )
    .max(PAGE_SIZE + 1),
  "@odata.nextLink": z.string().max(4096).optional(),
});

export interface GraphGroupsOptions {
  readonly outbound: OutboundGuard;
  /** GRAPH_API_URL without a trailing slash, e.g. `https://graph.microsoft.com`. */
  readonly graphApiUrl: string;
}

/**
 * The ids of every group the access token's user is a transitive member of. Throws
 * {@link GraphGroupsError}; never logs or returns anything else about the user.
 */
export async function fetchOverageGroups(
  options: GraphGroupsOptions,
  accessToken: string,
): Promise<string[]> {
  const base = `${options.graphApiUrl}/v1.0/`;
  let next: string | undefined =
    `${base}me/transitiveMemberOf?$select=id&$top=${String(PAGE_SIZE)}`;
  const groups = new Set<string>();
  for (let page = 0; next !== undefined; page += 1) {
    if (page >= MAX_OVERAGE_PAGES) throw new GraphGroupsError("too_many_groups");
    // The access token goes only to the configured Graph base (paging links included).
    if (!next.startsWith(base)) throw new GraphGroupsError("invalid_response");
    const body = await fetchPage(options.outbound, next, accessToken);
    for (const item of body.value) {
      if (item["@odata.type"] !== GROUP_TYPE) continue;
      const id = item.id?.trim();
      if (id === undefined || id.length === 0) continue;
      groups.add(id);
      if (groups.size > MAX_OVERAGE_GROUPS) throw new GraphGroupsError("too_many_groups");
    }
    next = body["@odata.nextLink"];
  }
  return [...groups];
}

async function fetchPage(
  outbound: OutboundGuard,
  url: string,
  accessToken: string,
): Promise<z.infer<typeof pageSchema>> {
  let response: Response;
  try {
    response = await outbound.fetch(url, {
      headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
      // A redirect would carry the access token elsewhere: it is an error instead.
      redirect: "manual",
      maxBytes: MAX_PAGE_BYTES,
    });
  } catch (error) {
    if (error instanceof OutboundRefusedError) {
      throw new GraphGroupsError(
        error.reason === "too_large" ? "too_many_groups" : "invalid_response",
      );
    }
    throw new GraphGroupsError("unavailable");
  }
  if (response.status >= 500 || response.status === 429) throw new GraphGroupsError("unavailable");
  if (response.status === 401 || response.status === 403) throw new GraphGroupsError("refused");
  if (response.status !== 200) throw new GraphGroupsError("invalid_response");
  let json: unknown;
  try {
    json = await response.json();
  } catch {
    throw new GraphGroupsError("invalid_response");
  }
  const parsed = pageSchema.safeParse(json);
  if (!parsed.success) throw new GraphGroupsError("invalid_response");
  return parsed.data;
}
