import { z } from "zod";
import { targetTenant, type AdminDeps } from "../context.js";
import { route, type AdminRoute } from "../registry.js";
import { isoDateTime, isoOrNull, tenantParams } from "../schemas.js";
import { keySet } from "./keys.js";
import { loginMethodView, warningSchema } from "./login-methods.js";

const dashboardSchema = z
  .object({
    logins: z.object({
      last24h: z.number().int(),
      last7d: z.number().int(),
      failedLast24h: z.number().int(),
    }),
    activeSessions: z.number().int().describe("Broker sessions of the tenant that have not ended."),
    loginMethods: z.object({ total: z.number().int(), enabled: z.number().int() }),
    applications: z.object({ attached: z.number().int(), enabled: z.number().int() }),
    warnings: z
      .array(
        warningSchema.extend({
          loginMethodId: z.uuid(),
          loginMethodName: z.string(),
        }),
      )
      .describe("Expiring secrets and SP certificates (30 days) and SAML settings to review."),
    keys: z.object({
      activeKid: z.string().nullable(),
      activatedAt: isoDateTime.nullable(),
      nextKid: z.string().nullable(),
      retiringKids: z.array(z.string()),
      nextScheduledRotationAt: isoDateTime.nullable(),
    }),
  })
  .meta({ id: "Dashboard" });

export function dashboardRoutes(deps: AdminDeps): AdminRoute[] {
  return [
    route({
      method: "get",
      path: "/tenants/{tenantId}/dashboard",
      operationId: "getDashboard",
      summary: "Overview: logins, sessions, warnings and key rotation status",
      tag: "Dashboard",
      params: tenantParams,
      response: dashboardSchema,
      handler: async ({ caller, params }) => {
        const tenant = await targetTenant(deps, caller, params.tenantId);
        const { repos } = deps;
        const [logins, activeSessions, methods, applications, keys] = await Promise.all([
          repos.stats.loginCounts(tenant.id),
          repos.stats.activeSessions(tenant.id),
          repos.loginMethods.list(tenant.id),
          repos.applications.listForTenant(tenant.id),
          keySet(deps),
        ]);
        const warnings = [];
        for (const method of methods) {
          const view = await loginMethodView(deps, deps, tenant, method);
          for (const warning of view.warnings) {
            warnings.push({
              ...warning,
              loginMethodId: method.id,
              loginMethodName: method.displayName,
            });
          }
        }
        const live = keys.keys;
        const active = live.find((key) => key.state === "active");
        return {
          body: {
            logins: {
              last24h: logins.successLast24h,
              last7d: logins.successLast7d,
              failedLast24h: logins.failureLast24h,
            },
            activeSessions,
            loginMethods: {
              total: methods.length,
              enabled: methods.filter((method) => method.enabled).length,
            },
            applications: {
              attached: applications.length,
              enabled: applications.filter((entry) => entry.enabled && entry.application.enabled)
                .length,
            },
            warnings,
            keys: {
              activeKid: active?.kid ?? null,
              activatedAt: active?.activatedAt ?? null,
              nextKid: live.find((key) => key.state === "next")?.kid ?? null,
              retiringKids: live.filter((key) => key.state === "retiring").map((key) => key.kid),
              nextScheduledRotationAt: isoOrNull(
                keys.nextScheduledRotationAt === null
                  ? null
                  : new Date(keys.nextScheduledRotationAt),
              ),
            },
          },
        };
      },
    }),
  ];
}
