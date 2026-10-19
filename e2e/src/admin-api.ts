import { expect, type APIRequestContext } from "@playwright/test";
import { URLS } from "./env";

/** An admin API problem (RFC 9457) or another unexpected answer. */
export class AdminApiError extends Error {
  constructor(
    readonly status: number,
    readonly body: unknown,
  ) {
    super(`admin API answered ${status}: ${JSON.stringify(body)}`);
  }
}

export interface Tenant {
  readonly id: string;
  readonly slug: string;
  readonly name: string;
  readonly etag: string;
}

/**
 * The admin API through the admin portal's BFF (`/t/{slug}/api/*`), with the cookies of a browser
 * context signed in to the portal: the same path the SPA takes (session token, CSRF header), for
 * test setup and for checks the scenarios make besides the UI.
 */
export class AdminApi {
  #csrf: string | undefined;

  constructor(
    readonly request: APIRequestContext,
    readonly slug: string,
  ) {}

  get base(): string {
    return `${URLS.admin}/t/${this.slug}`;
  }

  async #csrfToken(): Promise<string> {
    if (this.#csrf !== undefined) return this.#csrf;
    const response = await this.request.get(`${this.base}/auth/session`, {
      headers: { accept: "application/json" },
    });
    const session = (await response.json()) as { authenticated: boolean; csrfToken?: string };
    if (!session.authenticated || session.csrfToken === undefined) {
      throw new Error(`not signed in to the admin portal of ${this.slug}`);
    }
    this.#csrf = session.csrfToken;
    return this.#csrf;
  }

  /** The raw answer (status and JSON body), for checks of refusals. */
  async raw(
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    options: { body?: unknown; etag?: string } = {},
  ): Promise<{ status: number; body: unknown; etag: string | undefined }> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (method !== "GET") headers["x-csrf-token"] = await this.#csrfToken();
    if (options.etag !== undefined) headers["if-match"] = options.etag;
    const response = await this.request.fetch(`${this.base}/api${path}`, {
      method,
      headers,
      ...(options.body === undefined ? {} : { data: options.body }),
    });
    const text = await response.text();
    return {
      status: response.status(),
      body: text === "" ? undefined : (JSON.parse(text) as unknown),
      etag: response.headers().etag,
    };
  }

  async send<T>(
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    options: { body?: unknown; etag?: string } = {},
  ): Promise<T> {
    const answer = await this.raw(method, path, options);
    if (answer.status >= 400) throw new AdminApiError(answer.status, answer.body);
    return answer.body as T;
  }

  get<T>(path: string): Promise<T> {
    return this.send<T>("GET", path);
  }

  async tenant(slug: string): Promise<Tenant> {
    const { items } = await this.get<{ items: Tenant[] }>("/tenants");
    const tenant = items.find((item) => item.slug === slug);
    if (tenant === undefined) throw new Error(`no tenant ${slug}`);
    return tenant;
  }

  async createTenant(slug: string, name: string): Promise<Tenant> {
    return this.send<Tenant>("POST", "/tenants", { body: { slug, name } });
  }

  async applicationId(clientId: string): Promise<string> {
    const { items } = await this.get<{ items: { id: string; clientId: string }[] }>(
      "/applications",
    );
    const application = items.find((item) => item.clientId === clientId);
    if (application === undefined) throw new Error(`no application ${clientId}`);
    return application.id;
  }

  /** Enables (or disables) an application in a tenant, attaching it first when needed. */
  async setApplicationEnabled(tenantId: string, clientId: string, enabled: boolean): Promise<void> {
    const applicationId = await this.applicationId(clientId);
    const { items } = await this.get<{
      items: { applicationId: string; enabled: boolean; etag: string }[];
    }>(`/tenants/${tenantId}/applications`);
    let entry = items.find((item) => item.applicationId === applicationId);
    if (entry === undefined) {
      if (!enabled) return;
      entry = await this.send<{ applicationId: string; enabled: boolean; etag: string }>(
        "PUT",
        `/tenants/${tenantId}/applications/${applicationId}`,
      );
    }
    if (entry.enabled === enabled) return;
    await this.send("PATCH", `/tenants/${tenantId}/applications/${applicationId}`, {
      body: { enabled },
      etag: entry.etag,
    });
  }

  async loginMethods(
    tenantId: string,
  ): Promise<{ id: string; displayName: string; etag: string; warnings: { code: string }[] }[]> {
    return (
      await this.get<{
        items: { id: string; displayName: string; etag: string; warnings: { code: string }[] }[];
      }>(`/tenants/${tenantId}/login-methods`)
    ).items;
  }

  async loginMethodId(tenantId: string, displayName: string): Promise<string> {
    const method = (await this.loginMethods(tenantId)).find(
      (item) => item.displayName === displayName,
    );
    if (method === undefined) throw new Error(`no login method ${displayName}`);
    return method.id;
  }

  async createLoginMethod(
    tenantId: string,
    body: Record<string, unknown>,
  ): Promise<{ id: string; etag: string }> {
    return this.send<{ id: string; etag: string }>("POST", `/tenants/${tenantId}/login-methods`, {
      body,
    });
  }

  /** An organisation party and a grant for a personal identity number (all applications). */
  async createOrganisationGrant(
    tenantId: string,
    organisation: { identifier: string; displayName: string },
    agentPin: string,
  ): Promise<{ partyId: string; grantId: string }> {
    const party = await this.send<{ id: string }>("POST", `/tenants/${tenantId}/parties`, {
      body: { type: "organisation", ...organisation },
    });
    const grant = await this.send<{ id: string }>("POST", `/tenants/${tenantId}/grants`, {
      body: { partyId: party.id, agent: { pin: agentPin }, allApplications: true },
    });
    return { partyId: party.id, grantId: grant.id };
  }
}

/** Polls an admin API read until it satisfies a check (asynchronous effects in Portvakt). */
export async function eventually<T>(
  read: () => Promise<T>,
  check: (value: T) => boolean,
): Promise<T> {
  let last: T | undefined;
  await expect
    .poll(async () => {
      last = await read();
      return check(last);
    })
    .toBe(true);
  return last as T;
}
