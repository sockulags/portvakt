import express, { Router, type NextFunction, type Request, type Response } from "express";
import { z } from "zod";
import { ROUTE_TEMPLATE } from "../../app.js";
import { ADMIN_API_BASE } from "../constants.js";
import { clientIpKey, type RequestLimits } from "../../http/rate-limits.js";
import type { Logger } from "../../logging/logger.js";
import { SYSTEM_TENANT_SLUG } from "../../domain/tenant.js";
import type { AdminAuthenticator, Caller } from "./auth.js";
import {
  ApiError,
  PROBLEM_CODES,
  problemSchema,
  sendProblem,
  toApiError,
  zodFieldErrors,
  type ProblemCode,
} from "./problem.js";

export type HttpMethod = "get" | "post" | "put" | "patch" | "delete";

export interface RouteInput<P, Q, B> {
  readonly caller: Caller;
  readonly params: P;
  readonly query: Q;
  readonly body: B;
  /** The `If-Match` header, for routes that change a resource. */
  readonly ifMatch: string | undefined;
}

export interface RouteResult<R> {
  readonly status?: number;
  readonly body?: R;
  /** Sent as `ETag` (the representation's `etag` is used when this is absent). */
  readonly etag?: string;
}

/** One operation of the admin API: the Express route and its OpenAPI description at once. */
export interface AdminRoute {
  readonly method: HttpMethod;
  /** OpenAPI path below the API base, with `{param}` placeholders. */
  readonly path: string;
  readonly operationId: string;
  readonly summary: string;
  readonly description?: string;
  readonly tag: string;
  /** Only platform administrators (platform-admin in the system tenant). */
  readonly platformOnly: boolean;
  /** Requires `If-Match` (optimistic concurrency); 412 on a stale tag, 428 without one. */
  readonly ifMatch: boolean;
  readonly status: number;
  readonly params: z.ZodObject | undefined;
  readonly query: z.ZodObject | undefined;
  readonly body: z.ZodType | undefined;
  /** `undefined` for 204 responses. */
  readonly response: z.ZodType | undefined;
  /** Problem codes the operation documents besides the common ones. */
  readonly errors: readonly ProblemCode[];
  readonly handler: (input: RouteInput<unknown, unknown, unknown>) => Promise<RouteResult<unknown>>;
}

interface RouteSpec<
  PS extends z.ZodObject | undefined,
  QS extends z.ZodObject | undefined,
  BS extends z.ZodType | undefined,
  RS extends z.ZodType | undefined,
> {
  readonly method: HttpMethod;
  readonly path: string;
  readonly operationId: string;
  readonly summary: string;
  readonly description?: string;
  readonly tag: string;
  readonly platformOnly?: boolean;
  readonly ifMatch?: boolean;
  readonly status?: 200 | 201 | 204;
  readonly params?: PS;
  readonly query?: QS;
  readonly body?: BS;
  readonly response?: RS;
  readonly errors?: readonly ProblemCode[];
  readonly handler: (
    input: RouteInput<
      PS extends z.ZodObject ? z.output<PS> : Record<string, never>,
      QS extends z.ZodObject ? z.output<QS> : Record<string, never>,
      BS extends z.ZodType ? z.output<BS> : undefined
    >,
  ) => Promise<RouteResult<RS extends z.ZodType ? z.input<RS> : never>>;
}

/** Declares an operation with its schemas; the handler's input and output are typed by them. */
export function route<
  PS extends z.ZodObject | undefined = undefined,
  QS extends z.ZodObject | undefined = undefined,
  BS extends z.ZodType | undefined = undefined,
  RS extends z.ZodType | undefined = undefined,
>(spec: RouteSpec<PS, QS, BS, RS>): AdminRoute {
  return {
    method: spec.method,
    path: spec.path,
    operationId: spec.operationId,
    summary: spec.summary,
    ...(spec.description === undefined ? {} : { description: spec.description }),
    tag: spec.tag,
    platformOnly: spec.platformOnly ?? false,
    ifMatch: spec.ifMatch ?? false,
    status: spec.status ?? (spec.response === undefined ? 204 : 200),
    params: spec.params,
    query: spec.query,
    body: spec.body,
    response: spec.response,
    errors: spec.errors ?? [],
    handler: spec.handler as AdminRoute["handler"],
  };
}

const expressPath = (path: string): string => path.replace(/\{(\w+)\}/g, ":$1");

const BODY_METHODS = new Set<HttpMethod>(["post", "put", "patch"]);

/** Largest request body (inline SAML metadata may be up to 10 MB). */
export const MAX_BODY = "11mb";

export interface MountOptions {
  readonly routes: readonly AdminRoute[];
  readonly authenticator: AdminAuthenticator;
  readonly logger: Logger;
  /** RATE_LIMIT_ADMIN_API per caller (failed authentications: per client IP). */
  readonly limits?: RequestLimits | undefined;
}

/** The Express router of the admin API (mounted below the API base). */
export function mountRoutes(options: MountOptions): Router {
  const router = Router();
  const json = express.json({ limit: MAX_BODY, type: () => true, strict: true });
  const log = options.logger.child({ component: "admin-api" });

  for (const spec of options.routes) {
    const template = `${ADMIN_API_BASE}${spec.path}`;
    const handler = (req: Request, res: Response, next: NextFunction): void => {
      res.set("Cache-Control", "no-store");
      (res.locals as Record<string, unknown>)[ROUTE_TEMPLATE] = template;
      /** Takes a token of the admin API limit for `key`; refused: 429 with Retry-After. */
      const limit = (key: string): void => {
        const outcome = options.limits?.check([["adminApi", key]]);
        if (outcome === undefined || outcome.allowed) return;
        res.set("Retry-After", String(outcome.retryAfterSeconds));
        throw new ApiError("rate_limited");
      };
      void (async () => {
        let caller: Caller;
        try {
          caller = await options.authenticator.authenticate(req.get("authorization"));
        } catch (error) {
          // Failed authentications count against the client IP (token guessing, broken clients).
          limit(`ip:${clientIpKey(req)}`);
          throw error;
        }
        limit(`caller:${caller.tenant.id}:${caller.personId}`);
        // Only platform administrators administer the system tenant: anyone else signed in
        // there sees nothing but who they are.
        if (!caller.platform && caller.tenant.slug === SYSTEM_TENANT_SLUG && spec.path !== "/me") {
          throw new ApiError("not_found");
        }
        if (spec.platformOnly && !caller.platform) throw new ApiError("forbidden");

        const params = spec.params === undefined ? {} : spec.params.safeParse(req.params);
        if (spec.params !== undefined && !(params as z.ZodSafeParseResult<unknown>).success) {
          // A malformed id names nothing that exists.
          throw new ApiError("not_found");
        }
        // A tenant administrator addressing another tenant learns nothing, not even whether the
        // request would have been valid: 404 before the body is read.
        const tenantId = (params as { data?: { tenantId?: unknown } }).data?.tenantId;
        if (typeof tenantId === "string" && !caller.platform && tenantId !== caller.tenant.id) {
          throw new ApiError("not_found");
        }
        const query =
          spec.query === undefined
            ? ({ success: true, data: {} } as const)
            : spec.query.safeParse(req.query);
        if (!query.success) {
          throw new ApiError("validation_failed", { errors: zodFieldErrors(query.error, "query") });
        }

        let body: unknown = undefined;
        if (spec.body !== undefined) {
          if (!req.is("application/json")) throw new ApiError("unsupported_media_type");
          await new Promise<void>((resolve, reject) => {
            json(req, res, (error?: unknown) =>
              error === undefined
                ? resolve()
                : reject(error instanceof Error ? error : new Error("invalid body")),
            );
          }).catch((error: unknown) => {
            const type = (error as { type?: unknown }).type;
            if (type === "entity.too.large") throw new ApiError("payload_too_large");
            throw new ApiError("invalid_json");
          });
          const parsed = spec.body.safeParse(req.body);
          if (!parsed.success) {
            throw new ApiError("validation_failed", { errors: zodFieldErrors(parsed.error) });
          }
          body = parsed.data;
        } else if (BODY_METHODS.has(spec.method) && (req.get("content-length") ?? "0") !== "0") {
          // An operation without a body accepts an empty one only.
          if (!req.is("application/json")) throw new ApiError("unsupported_media_type");
        }

        const result = await spec.handler({
          caller,
          params: (params as { data?: unknown }).data ?? {},
          query: query.data,
          body,
          ifMatch: req.get("if-match"),
        });
        const status = result.status ?? spec.status;
        const representation = result.body as { etag?: unknown } | undefined;
        const etag =
          result.etag ??
          (typeof representation?.etag === "string" ? representation.etag : undefined);
        if (etag !== undefined) res.set("ETag", etag);
        if (status === 204 || result.body === undefined) {
          res.status(status === 200 ? 204 : status).end();
          return;
        }
        res.status(status).json(result.body);
      })().catch((error: unknown) => {
        const apiError = toApiError(error);
        if (apiError.code === "internal_error") {
          log.error({ err: error, operation: spec.operationId }, "admin API error");
        }
        if (res.headersSent) {
          next(error);
          return;
        }
        sendProblem(res, apiError);
      });
    };
    router[spec.method](expressPath(spec.path), handler);
  }
  return router;
}

// OpenAPI ------------------------------------------------------------------------------------------

type JsonObject = Record<string, unknown>;

/** Hoists `$defs` of a converted schema into `defs` and points its refs at the components. */
function hoist(schema: JsonObject, defs: Record<string, unknown>): JsonObject {
  const local = (schema.$defs ?? {}) as Record<string, JsonObject>;
  const rewrite = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(rewrite);
    if (value !== null && typeof value === "object") {
      const out: JsonObject = {};
      for (const [key, item] of Object.entries(value as JsonObject)) {
        if (key === "$schema" || key === "$defs") continue;
        if (key === "$ref" && typeof item === "string" && item.startsWith("#/$defs/")) {
          out.$ref = `#/components/schemas/${item.slice("#/$defs/".length)}`;
        } else {
          out[key] = rewrite(item);
        }
      }
      return out;
    }
    return value;
  };
  for (const [id, def] of Object.entries(local)) defs[id] ??= rewrite(def);
  return rewrite(schema) as JsonObject;
}

function jsonSchema(schema: z.ZodType, io: "input" | "output", defs: Record<string, unknown>) {
  return hoist(
    z.toJSONSchema(schema, { target: "draft-2020-12", io, unrepresentable: "any" }),
    defs,
  );
}

const COMMON_ERRORS: readonly ProblemCode[] = [
  "unauthorized",
  "invalid_token",
  "forbidden",
  "validation_failed",
];

export interface OpenApiInfo {
  readonly title: string;
  readonly version: string;
  readonly description: string;
  readonly serverUrl: string;
}

/** The OpenAPI 3.1 document of the routes, generated from their zod schemas. */
export function openApiDocument(routes: readonly AdminRoute[], info: OpenApiInfo): JsonObject {
  const defs: Record<string, unknown> = {};
  const problem = jsonSchema(problemSchema, "output", defs);
  defs.Problem ??= problem;
  const problemRef = { $ref: "#/components/schemas/Problem" };
  const paths: Record<string, Record<string, unknown>> = {};
  const tags = new Set<string>();

  for (const spec of routes) {
    tags.add(spec.tag);
    const parameters: JsonObject[] = [];
    for (const [location, object] of [
      ["path", spec.params],
      ["query", spec.query],
    ] as const) {
      if (object === undefined) continue;
      const converted = jsonSchema(object, "input", defs);
      const properties = (converted.properties ?? {}) as Record<string, JsonObject>;
      const required = new Set((converted.required ?? []) as string[]);
      for (const [name, schema] of Object.entries(properties)) {
        const { description, ...rest } = schema;
        parameters.push({
          name,
          in: location,
          required: location === "path" ? true : required.has(name),
          schema: rest,
          ...(typeof description === "string" ? { description } : {}),
        });
      }
    }
    if (spec.ifMatch) {
      parameters.push({
        name: "If-Match",
        in: "header",
        required: true,
        description: "The `etag` of the version being changed (optimistic concurrency).",
        schema: { type: "string" },
      });
    }

    const responses: JsonObject = {};
    responses[String(spec.status)] =
      spec.response === undefined
        ? { description: "Done." }
        : {
            description: "Success.",
            ...(spec.ifMatch || spec.method === "get"
              ? { headers: { ETag: { schema: { type: "string" } } } }
              : {}),
            content: { "application/json": { schema: jsonSchema(spec.response, "output", defs) } },
          };
    const codes = new Set<ProblemCode>([
      ...COMMON_ERRORS,
      ...(spec.params === undefined ? [] : (["not_found"] as const)),
      ...(spec.ifMatch ? (["precondition_failed", "precondition_required"] as const) : []),
      ...(spec.body === undefined ? [] : (["unsupported_media_type", "invalid_json"] as const)),
      ...spec.errors,
    ]);
    const byStatus = new Map<number, ProblemCode[]>();
    for (const code of codes) {
      const status = PROBLEM_CODES[code].status;
      byStatus.set(status, [...(byStatus.get(status) ?? []), code]);
    }
    for (const [status, list] of [...byStatus].sort(([a], [b]) => a - b)) {
      responses[String(status)] = {
        description: `Problem: ${list.join(", ")}.`,
        content: { "application/problem+json": { schema: problemRef } },
      };
    }

    const operation: JsonObject = {
      operationId: spec.operationId,
      summary: spec.summary,
      ...(spec.description === undefined ? {} : { description: spec.description }),
      tags: [spec.tag],
      ...(spec.platformOnly ? { "x-portvakt-access": "platform-admin" } : {}),
      ...(parameters.length > 0 ? { parameters } : {}),
      ...(spec.body === undefined
        ? {}
        : {
            requestBody: {
              required: true,
              content: { "application/json": { schema: jsonSchema(spec.body, "input", defs) } },
            },
          }),
      responses,
    };
    paths[spec.path] ??= {};
    paths[spec.path]![spec.method] = operation;
  }

  return {
    openapi: "3.1.1",
    info: { title: info.title, version: info.version, description: info.description },
    servers: [{ url: info.serverUrl }],
    security: [{ bearerAuth: [] }],
    tags: [...tags].map((name) => ({ name })),
    paths,
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description:
            "An access token of application `portvakt-admin` from any active tenant's issuer.",
        },
      },
      schemas: defs,
    },
  };
}
