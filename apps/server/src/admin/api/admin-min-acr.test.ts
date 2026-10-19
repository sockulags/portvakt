import { describe, expect, it } from "vitest";
import { DEFAULT_ACR_RANKING } from "../../config/index.js";
import { createLoginMethod, EMPLOYEE_ACR } from "../../testing/fixtures.js";
import {
  adminCall,
  adminToken,
  createAdmin,
  createAdminTenant,
  setupAdminWorld,
  TENANT_ADMIN_ROLE,
} from "../../testing/admin.js";
import { startTestServer } from "../../testing/test-server.js";

const [LOA2, LOA3, LOA4] = DEFAULT_ACR_RANKING as [string, string, string];

const ts = await startTestServer({ env: { ADMIN_MIN_ACR: LOA3 } });

describe.skipIf(ts === undefined)("admin API with ADMIN_MIN_ACR", () => {
  it("refuses tokens whose acr ranks below ADMIN_MIN_ACR, unranked ones included", async () => {
    const world = await setupAdminWorld(ts!);
    const { tenant } = await createAdminTenant(world, "minacr");
    const { repos } = ts!.db;
    const tokenAt = async (assertedAcr: string) => {
      const method = await createLoginMethod(repos, tenant.id, {
        displayName: `Sign-in ${assertedAcr}`,
        kind: "citizen",
        assertedAcr,
        claimMapping: { subject: "sub", acr: "acr" },
      });
      const person = await createAdmin(world, tenant, method, [TENANT_ADMIN_ROLE]);
      return adminToken(world, tenant, method, person);
    };

    for (const acr of [EMPLOYEE_ACR, LOA2]) {
      const response = await adminCall(ts!, await tokenAt(acr), "GET", "/me");
      expect(response.status).toBe(403);
      expect(response.body).toMatchObject({ code: "acr_too_low" });
    }
    for (const acr of [LOA3, LOA4]) {
      const response = await adminCall(ts!, await tokenAt(acr), "GET", "/me");
      expect(response.status).toBe(200);
    }
  });
});
