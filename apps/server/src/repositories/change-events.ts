import { z } from "zod";
import type { Db } from "../db/database.js";

/**
 * Change notifications for state that running replicas cache (per-tenant OIDC providers and the
 * signing key set). Repository write paths emit them with `pg_notify` on {@link CHANGE_CHANNEL};
 * every replica LISTENs and invalidates what changed (`oidc/change-listener.ts`). Inside a
 * transaction the notification is delivered on commit and dropped on rollback, so listeners never
 * see a change that did not happen.
 *
 * Rule: a repository method emits an event when it changes a row a cached provider or the key
 * cache is built from: a tenant (slug, status), an application's client configuration, an
 * application's attachment to a tenant, a tenant's login methods (acr values), or a signing key's
 * state. Roles, rules, attributes and persons are read live and emit nothing.
 *
 * Payloads carry ids only, never personal data.
 */
export const CHANGE_CHANNEL = "portvakt_changes";

export const changeEventSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("tenant"), tenantId: z.uuid() }),
  z.object({ type: z.literal("tenant_applications"), tenantId: z.uuid() }),
  z.object({ type: z.literal("login_methods"), tenantId: z.uuid() }),
  z.object({ type: z.literal("application"), applicationId: z.uuid() }),
  z.object({ type: z.literal("signing_keys") }),
]);
export type ChangeEvent = z.infer<typeof changeEventSchema>;

export async function emitChange(db: Db, event: ChangeEvent): Promise<void> {
  await db.query("SELECT pg_notify($1, $2)", [CHANGE_CHANNEL, JSON.stringify(event)]);
}

/** Parses a notification payload; `null` for anything that is not a valid event. */
export function parseChangeEvent(payload: string | undefined): ChangeEvent | null {
  if (payload === undefined) return null;
  try {
    const result = changeEventSchema.safeParse(JSON.parse(payload));
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}
