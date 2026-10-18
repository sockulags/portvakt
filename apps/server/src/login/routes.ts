import express, { Router, type NextFunction, type Request, type Response } from "express";
import { z } from "zod";
import type { Config } from "../config/index.js";
import type { LoginMethod } from "../domain/login-method.js";
import { FederationError, type FederationService } from "../federation/service.js";
import type { Logger } from "../logging/logger.js";
import { parseAcrValues } from "../oidc/acr.js";
import {
  InteractionError,
  loadInteraction,
  type InteractionContext,
  type InteractionDetails,
  type InteractionService,
} from "../oidc/interactions.js";
import type { TenantProvider } from "../oidc/provider.js";
import type { Repositories } from "../repositories/index.js";
import { csrfGuard, csrfToken } from "./csrf.js";
import { samlRoutes } from "./saml-routes.js";
import {
  isLoginErrorCode,
  LOGIN_UI_HEADERS,
  localeHints,
  type LoginErrorCode,
  type LoginUiShell,
  type UiBootstrap,
} from "./ui-shell.js";

export interface LoginRoutesOptions {
  readonly config: Config;
  readonly repos: Repositories;
  readonly federation: FederationService;
  readonly interactions: InteractionService;
  readonly shell: LoginUiShell;
  readonly logger: Logger;
  /** The tenant provider `tenantRoutes` resolved for the request. */
  readonly tenantOf: (res: Response) => TenantProvider;
}

/** A login method as the login UI shows it (no configuration, no secrets). */
export interface LoginMethodView {
  readonly id: string;
  readonly displayName: string;
  readonly kind: LoginMethod["kind"];
}

/** `GET /t/{slug}/interaction/{uid}/details`: what the login UI's chooser needs. */
export interface InteractionDetailsResponse {
  readonly tenant: { readonly name: string };
  readonly application: { readonly name: string } | null;
  readonly methods: readonly LoginMethodView[];
  /** Some offered method has home realm domains: the email field is shown. */
  readonly homeRealmDiscovery: boolean;
  /** `login_hint` when it is an email address (prefills the email field). */
  readonly loginHint: string | null;
  readonly csrfToken: string;
}

const loginRequestSchema = z.union([
  z.object({ loginMethodId: z.uuid() }).strict(),
  z.object({ email: z.string().trim().min(3).max(320) }).strict(),
]);

const STATUS_BY_ERROR: Partial<Record<LoginErrorCode, number>> = {
  interaction_expired: 404,
  app_unavailable: 403,
  login_method_unavailable: 403,
  no_acceptable_method: 403,
  upstream_unavailable: 502,
};
const statusOf = (code: LoginErrorCode): number => STATUS_BY_ERROR[code] ?? 400;

const looksLikeEmail = (value: string | undefined): value is string =>
  value !== undefined && /^[^\s@]+@[^\s@]+$/.test(value);

/**
 * The login flow below `/t/{slug}` (mounted by `tenantRoutes`, after the tenant is resolved):
 *
 * - `GET  /interaction/{uid}`: the login UI, or straight upstream when no choice is needed
 *   (exactly one acceptable login method, or `login_hint` with an email of a home realm);
 * - `GET  /interaction/{uid}/details`: JSON for the login UI (methods filtered by `acr_values`);
 * - `POST /interaction/{uid}/login`: `{ loginMethodId }` or `{ email }` (home realm discovery);
 * - `POST /interaction/{uid}/abort`: back to the application with `access_denied`;
 * - `GET  /interaction/{uid}/federation/complete`: finishes an upstream login;
 * - `GET  /federation/{loginMethodId}/callback`: the upstream redirect URI;
 * - `GET  /federation/{loginMethodId}/jwks`: the login method's public client key;
 * - `GET  /login/error`: error view outside an interaction;
 * - `/saml/{loginMethodId}/...`: the SP endpoints of SAML login methods (`saml-routes.ts`).
 *
 * The POSTs are CSRF-protected (`csrf.ts`); the interaction is bound to the browser by the
 * interaction cookie, which is scoped to `/t/{slug}/interaction/{uid}`.
 */
export function loginRoutes(options: LoginRoutesOptions): Router {
  const { config, repos, federation, interactions, shell, tenantOf } = options;
  const router = Router();
  const origin = new URL(config.publicUrl).origin;

  const sendPage = (res: Response, status: number, bootstrap: UiBootstrap): void => {
    res.status(status).set(LOGIN_UI_HEADERS).send(shell.render(bootstrap));
  };
  const contextOf = (req: Request, res: Response): InteractionContext => {
    const uid = req.params.uid;
    if (typeof uid !== "string") throw new InteractionError("interaction_not_found", "No uid");
    return { tenantProvider: tenantOf(res), uid, req, res };
  };
  const interactionUrl = (tp: TenantProvider, uid: string, error?: LoginErrorCode): string =>
    `${config.publicUrl}${tp.basePath}/interaction/${encodeURIComponent(uid)}${
      error === undefined ? "" : `?error=${error}`
    }`;

  /** Enabled login methods that can satisfy the request's `acr_values`. */
  async function acceptableMethods(
    tp: TenantProvider,
    details: InteractionDetails,
  ): Promise<LoginMethod[]> {
    const requested = parseAcrValues(details.params.acrValues);
    const enabled = await repos.loginMethods.listEnabled(tp.tenant.id);
    return enabled.filter((method) => federation.satisfies(method, requested));
  }

  /** Home realm discovery: the acceptable method owning the email's domain. */
  async function homeRealmMethod(
    tp: TenantProvider,
    methods: readonly LoginMethod[],
    email: string,
  ): Promise<LoginMethod | undefined> {
    const found = await repos.loginMethods.findEnabledByHomeRealm(tp.tenant.id, email);
    return found === null ? undefined : methods.find((method) => method.id === found.id);
  }

  const noStore = (_req: Request, res: Response, next: NextFunction): void => {
    res.setHeader("Cache-Control", "no-store");
    next();
  };
  const json = express.json({ limit: "4kb", strict: true });
  const guard = csrfGuard({
    keys: config.cookieKeys,
    origin,
    tenantIdOf: (res) => tenantOf(res).tenant.id,
  });
  type Handler = (req: Request, res: Response) => Promise<void>;
  const run =
    (fn: Handler) =>
    (req: Request, res: Response, next: NextFunction): void => {
      fn(req, res).catch(next);
    };

  /** JSON endpoints: interaction and federation errors become `{ error }` responses. */
  const api =
    (fn: Handler) =>
    (req: Request, res: Response, next: NextFunction): void => {
      fn(req, res).catch((error: unknown) => {
        if (error instanceof InteractionError) {
          const status =
            error.code === "interaction_not_found"
              ? 404
              : error.code === "invalid_input"
                ? 400
                : 403;
          res.status(status).json({ error: error.code });
          return;
        }
        if (error instanceof FederationError) {
          res.status(statusOf(error.code)).json({ error: error.code });
          return;
        }
        next(error);
      });
    };

  router.get(
    "/interaction/:uid",
    noStore,
    run(async (req, res) => {
      const ctx = contextOf(req, res);
      const acceptLanguage = req.get("accept-language");
      let details: InteractionDetails;
      try {
        details = await loadInteraction(ctx);
      } catch (error) {
        if (error instanceof InteractionError) {
          sendPage(res, 404, {
            view: "error",
            code: "interaction_expired",
            locale: localeHints(undefined, acceptLanguage),
          });
          return;
        }
        throw error;
      }
      const locale = localeHints(details.params.uiLocales, acceptLanguage);
      const queryError = req.query.error;
      let error = isLoginErrorCode(queryError) ? queryError : undefined;
      if (error === undefined) {
        const methods = await acceptableMethods(ctx.tenantProvider, details);
        if (methods.length === 0) {
          await federation.recordFailure("no_acceptable_method", {
            tenantId: ctx.tenantProvider.tenant.id,
            clientId: details.clientId,
          });
          error = "no_acceptable_method";
        } else {
          const hint = details.params.loginHint;
          const direct =
            (looksLikeEmail(hint)
              ? await homeRealmMethod(ctx.tenantProvider, methods, hint)
              : undefined) ?? (methods.length === 1 ? methods[0] : undefined);
          if (direct !== undefined) {
            try {
              res.redirect(303, await federation.begin(ctx.tenantProvider, details, direct));
              return;
            } catch (failure) {
              if (!(failure instanceof FederationError)) throw failure;
              error = failure.code;
            }
          }
        }
      }
      sendPage(res, 200, {
        view: "login",
        tenant: ctx.tenantProvider.tenant.slug,
        uid: details.uid,
        ...(error === undefined ? {} : { error }),
        locale,
      });
    }),
  );

  router.get(
    "/interaction/:uid/details",
    noStore,
    api(async (req, res) => {
      const ctx = contextOf(req, res);
      const details = await loadInteraction(ctx);
      const tp = ctx.tenantProvider;
      const [methods, application] = await Promise.all([
        acceptableMethods(tp, details),
        details.clientId === undefined
          ? Promise.resolve(null)
          : repos.applications.findEnabledByClientId(tp.tenant.id, details.clientId),
      ]);
      const body: InteractionDetailsResponse = {
        tenant: { name: tp.tenant.name },
        application: application === null ? null : { name: application.name },
        methods: methods.map((method) => ({
          id: method.id,
          displayName: method.displayName,
          kind: method.kind,
        })),
        homeRealmDiscovery: methods.some((method) => method.homeRealmDomains.length > 0),
        loginHint: looksLikeEmail(details.params.loginHint) ? details.params.loginHint : null,
        csrfToken: csrfToken(config.cookieKeys, tp.tenant.id, details.uid),
      };
      res.json(body);
    }),
  );

  router.post(
    "/interaction/:uid/login",
    noStore,
    guard,
    json,
    api(async (req, res) => {
      const ctx = contextOf(req, res);
      const parsed = loginRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: "invalid_request" });
        return;
      }
      const details = await loadInteraction(ctx);
      const tp = ctx.tenantProvider;
      const methods = await acceptableMethods(tp, details);
      const choice = parsed.data;
      if ("email" in choice) {
        const method = await homeRealmMethod(tp, methods, choice.email);
        if (method === undefined) {
          res.status(404).json({ error: "no_home_realm" });
          return;
        }
        res.json({ redirectTo: await federation.begin(tp, details, method) });
        return;
      }
      const method = methods.find((candidate) => candidate.id === choice.loginMethodId);
      if (method === undefined) {
        res.status(403).json({ error: "login_method_unavailable" });
        return;
      }
      res.json({ redirectTo: await federation.begin(tp, details, method) });
    }),
  );

  router.post(
    "/interaction/:uid/abort",
    noStore,
    guard,
    json,
    api(async (req, res) => {
      const { returnTo } = await interactions.abort(contextOf(req, res));
      res.json({ redirectTo: returnTo });
    }),
  );

  router.get(
    "/interaction/:uid/federation/complete",
    noStore,
    run(async (req, res) => {
      const ctx = contextOf(req, res);
      const ref = typeof req.query.ref === "string" ? req.query.ref : "";
      try {
        res.redirect(303, await federation.finish(ctx, ref));
      } catch (error) {
        if (error instanceof InteractionError && error.code === "interaction_not_found") {
          sendPage(res, 404, {
            view: "error",
            code: "interaction_expired",
            locale: localeHints(undefined, req.get("accept-language")),
          });
          return;
        }
        let code: LoginErrorCode;
        if (error instanceof FederationError) code = error.code;
        else if (error instanceof InteractionError) {
          code = "login_method_unavailable";
          await federation.recordFailure(code, { tenantId: ctx.tenantProvider.tenant.id });
        } else throw error;
        res.redirect(303, interactionUrl(ctx.tenantProvider, ctx.uid, code));
      }
    }),
  );

  router.get(
    "/federation/:loginMethodId/callback",
    noStore,
    run(async (req, res) => {
      const tp = tenantOf(res);
      const currentUrl = new URL(req.originalUrl, config.publicUrl);
      const loginMethodId = req.params.loginMethodId;
      res.redirect(
        303,
        await federation.callback(
          tp,
          typeof loginMethodId === "string" ? loginMethodId : "",
          currentUrl,
        ),
      );
    }),
  );

  router.get(
    "/federation/:loginMethodId/jwks",
    run(async (req, res) => {
      const tp = tenantOf(res);
      const id = req.params.loginMethodId;
      const jwk =
        typeof id === "string" && z.uuid().safeParse(id).success
          ? await repos.loginMethods.ensureClientPublicJwk(tp.tenant.id, id)
          : null;
      if (jwk === null) {
        res.status(404).json({ error: "not_found" });
        return;
      }
      res.set("Cache-Control", "public, max-age=300").json({ keys: [jwk] });
    }),
  );

  router.get(
    "/login/error",
    noStore,
    run((req, res) => {
      const code = isLoginErrorCode(req.query.code) ? req.query.code : "request_failed";
      sendPage(res, statusOf(code), {
        view: "error",
        code,
        locale: localeHints(undefined, req.get("accept-language")),
      });
      return Promise.resolve();
    }),
  );

  router.use(samlRoutes({ federation, shell, tenantOf }));

  return router;
}
