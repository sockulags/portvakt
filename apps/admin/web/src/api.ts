import type { FieldError, SessionInfo } from "./types";

/** An admin API error (RFC 9457 problem), or a transport failure (`network`). */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly errors: readonly FieldError[];

  constructor(status: number, code: string, errors: readonly FieldError[] = []) {
    super(code);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.errors = errors;
  }

  /** Someone else changed the resource since it was read (optimistic concurrency). */
  get isConflict(): boolean {
    return this.status === 412 || this.code === "precondition_failed";
  }

  /** The field errors as a map, for forms. */
  fieldErrors(): Record<string, string> {
    const map: Record<string, string> = {};
    for (const error of this.errors) map[error.field] ??= error.message;
    return map;
  }
}

export interface ApiClient {
  readonly slug: string;
  readonly get: <T>(path: string) => Promise<T>;
  readonly send: <T>(
    method: "POST" | "PUT" | "PATCH" | "DELETE",
    path: string,
    options?: { body?: unknown; etag?: string },
  ) => Promise<T>;
  readonly session: () => Promise<SessionInfo>;
  readonly logout: () => Promise<void>;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

async function problemOf(response: Response): Promise<ApiError> {
  let code = `http_${response.status}`;
  let errors: FieldError[] = [];
  try {
    const body: unknown = await response.json();
    if (isObject(body)) {
      if (typeof body.code === "string") code = body.code;
      if (Array.isArray(body.errors)) {
        errors = body.errors.filter(
          (item): item is FieldError =>
            isObject(item) && typeof item.field === "string" && typeof item.message === "string",
        );
      }
    }
  } catch {
    // Not JSON: the status code tells enough.
  }
  return new ApiError(response.status, code, errors);
}

/**
 * The portal's view of the admin API: everything goes through the BFF below `/t/{slug}/api`
 * with the session cookie; mutations carry the session's CSRF token. The SPA never holds an
 * access token.
 */
export function createApi(
  slug: string,
  fetcher: typeof fetch = (...args) => fetch(...args),
): ApiClient {
  const base = `/t/${slug}`;
  let csrf: string | undefined;

  const session = async (): Promise<SessionInfo> => {
    const response = await fetcher(`${base}/auth/session`, {
      headers: { accept: "application/json" },
      credentials: "same-origin",
    });
    if (!response.ok) throw await problemOf(response);
    const info = (await response.json()) as SessionInfo;
    csrf = info.csrfToken;
    return info;
  };

  const request = async <T>(
    method: string,
    path: string,
    body: unknown,
    etag: string | undefined,
    retry: boolean,
  ): Promise<T> => {
    const headers: Record<string, string> = { accept: "application/json" };
    if (method !== "GET") {
      if (csrf === undefined) await session();
      if (csrf !== undefined) headers["x-csrf-token"] = csrf;
    }
    if (body !== undefined) headers["content-type"] = "application/json";
    if (etag !== undefined) headers["if-match"] = etag;
    let response: Response;
    try {
      response = await fetcher(`${base}/api${path}`, {
        method,
        headers,
        credentials: "same-origin",
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch {
      throw new ApiError(0, "network");
    }
    if (response.status === 403 && retry && method !== "GET") {
      const problem = await problemOf(response.clone());
      if (problem.code === "csrf_failed") {
        await session();
        return request<T>(method, path, body, etag, false);
      }
    }
    if (!response.ok) throw await problemOf(response);
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  };

  return {
    slug,
    get: (path) => request("GET", path, undefined, undefined, false),
    send: (method, path, options = {}) => request(method, path, options.body, options.etag, true),
    session,
    async logout() {
      if (csrf === undefined) await session();
      const response = await fetcher(`${base}/auth/logout`, {
        method: "POST",
        headers: { accept: "application/json", "x-csrf-token": csrf ?? "" },
        credentials: "same-origin",
      });
      const target = response.ok
        ? ((await response.json()) as { redirectTo?: string }).redirectTo
        : undefined;
      window.location.assign(target ?? `${base}/`);
    },
  };
}
