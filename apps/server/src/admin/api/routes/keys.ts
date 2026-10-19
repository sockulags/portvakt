import { z } from "zod";
import { SIGNING_KEY_STATES, type SigningKey } from "../../../domain/signing-key.js";
import { auditEvent } from "../../../audit/catalogue.js";
import type { RotationResult } from "../../../keys/rotation.js";
import { actorOf, type AdminDeps } from "../context.js";
import { etagOf, requireMatch } from "../etag.js";
import { route, type AdminRoute } from "../registry.js";
import { auditReasonSchema, etag, iso, isoDateTime, isoOrNull, strictBody } from "../schemas.js";

/** At most this many retired keys are listed (newest first); every live key always is. */
const RETIRED_SHOWN = 20;

const signingKeySchema = z.object({
  kid: z.string(),
  alg: z.string(),
  state: z.enum(SIGNING_KEY_STATES),
  createdAt: isoDateTime,
  activatedAt: isoDateTime.nullable(),
  retiringAt: isoDateTime.nullable(),
  retiredAt: isoDateTime.nullable(),
  /** A `next` key of a manual rotation: when it becomes active. */
  activateAt: isoDateTime.nullable(),
});

const keySetSchema = z
  .object({
    keys: z.array(signingKeySchema),
    policy: z.object({
      intervalSeconds: z.number().int(),
      publishAheadSeconds: z.number().int(),
      retireAfterSeconds: z.number().int(),
      manualPublishAheadSeconds: z.number().int(),
    }),
    /** When the scheduled rotation introduces the next key (active key + interval - publish ahead). */
    nextScheduledRotationAt: isoDateTime.nullable(),
    etag,
  })
  .meta({ id: "SigningKeys" });
type KeySetView = z.input<typeof keySetSchema>;

const rotationSchema = z
  .object({
    /**
     * `scheduled`: the new key is published and becomes active at `activatesAt`
     * (KEY_MANUAL_PUBLISH_AHEAD); `activated`: a new key signs now (emergency, or a published
     * key that was already due).
     */
    status: z.enum(["activated", "scheduled"]),
    activatedKid: z.string().nullable(),
    nextKid: z.string().nullable(),
    activatesAt: isoDateTime.nullable(),
    retiringKid: z.string().nullable(),
    retiredKids: z.array(z.string()),
    keys: keySetSchema,
  })
  .meta({ id: "KeyRotation" });

const keyView = (key: SigningKey) => ({
  kid: key.kid,
  alg: key.alg,
  state: key.state,
  createdAt: iso(key.createdAt),
  activatedAt: isoOrNull(key.activatedAt),
  retiringAt: isoOrNull(key.retiringAt),
  retiredAt: isoOrNull(key.retiredAt),
  activateAt: isoOrNull(key.activateAt),
});

export async function keySet(deps: AdminDeps): Promise<KeySetView> {
  return keySetOf(await deps.repos.signingKeys.list(), deps);
}

/** The key set view of the given keys (the tag covers the live keys and their states). */
function keySetOf(all: readonly SigningKey[], deps: Pick<AdminDeps, "config">): KeySetView {
  const live = all.filter((key) => key.state !== "retired");
  const retired = all
    .filter((key) => key.state === "retired")
    .sort((a, b) => (b.retiredAt?.getTime() ?? 0) - (a.retiredAt?.getTime() ?? 0))
    .slice(0, RETIRED_SHOWN);
  const order = { active: 0, next: 1, retiring: 2, retired: 3 } as const;
  const keys = [...live, ...retired].sort((a, b) => order[a.state] - order[b.state]);
  const policy = deps.config.keyRotation;
  const active = live.find((key) => key.state === "active");
  const next = live.find((key) => key.state === "next");
  const due =
    active?.activatedAt === undefined || active.activatedAt === null || next !== undefined
      ? null
      : new Date(
          active.activatedAt.getTime() +
            (policy.intervalSeconds - policy.publishAheadSeconds) * 1000,
        );
  const views = keys.map(keyView);
  return {
    keys: views,
    policy: { ...policy },
    nextScheduledRotationAt: isoOrNull(due),
    // The tag follows the live keys, their states and a scheduled activation: what a rotation
    // changes.
    etag: etagOf({
      keys: live.map((key) => `${key.kid}:${key.state}:${key.activateAt?.toISOString() ?? ""}`),
    }),
  };
}

const kidsOf = (result: RotationResult) =>
  result.status === "activated"
    ? {
        activatedKid: result.activatedKid,
        retiringKid: result.retiringKid,
        retiredKids: [...result.retiredKids],
      }
    : { activatedKid: null, retiringKid: null, retiredKids: [] };

export function keyRoutes(deps: AdminDeps): AdminRoute[] {
  return [
    route({
      method: "get",
      path: "/signing-keys",
      operationId: "listSigningKeys",
      summary: "The signing keys (shared by every tenant) and the rotation policy",
      tag: "Signing keys",
      response: keySetSchema,
      handler: async () => ({ body: await keySet(deps) }),
    }),
    route({
      method: "post",
      path: "/signing-keys/rotate",
      operationId: "rotateSigningKeys",
      summary: "Rotate the signing keys (platform administrators)",
      description:
        "Without `emergency` a new key is published in JWKS at once and becomes active " +
        "`policy.manualPublishAheadSeconds` later (status `scheduled`, `nextKid`, `activatesAt`), " +
        "so every verifier has fetched it before it signs; the previous key then stays published " +
        "(retiring) so issued tokens remain verifiable. `emergency` (key compromise) generates a " +
        "fresh key, activates it at once and retires every other key (next, active, retiring) in " +
        "the same transaction (status `activated`, `retiredKids`): JWKS publishes only the new " +
        "key, so every outstanding token stops verifying and every session must refresh or sign " +
        "in again. When the cause is a database or key leak, rotate MASTER_KEY too " +
        "(MASTER_KEY_PREVIOUS and `rewrap-secrets`). The reason is audited and must not contain personal data. " +
        "If-Match takes the key set's etag; it is checked under the rotation's lock, so of " +
        "concurrent rotations with the same tag exactly one succeeds.",
      tag: "Signing keys",
      platformOnly: true,
      ifMatch: true,
      body: strictBody({ reason: auditReasonSchema, emergency: z.boolean().default(false) }),
      response: rotationSchema,
      handler: async ({ caller, body, ifMatch }) => {
        const result = await deps.rotation.rotateNow(
          { actor: actorOf(caller), reason: body.reason, emergency: body.emergency },
          {
            check: async (repos) => {
              requireMatch(ifMatch, keySetOf(await repos.signingKeys.list(), deps).etag);
            },
            // A platform event (no tenant), committed with the rotation.
            audit: (rotated) => [
              auditEvent({
                action: "admin.signing_key.rotate",
                tenantId: null,
                actor: actorOf(caller),
                subject: {
                  type: "signing_key",
                  id: rotated.status === "activated" ? rotated.activatedKid : rotated.nextKid,
                },
                details: {
                  actorTenantId: caller.tenant.id,
                  emergency: body.emergency,
                  ...kidsOf(rotated),
                  ...(rotated.status === "scheduled"
                    ? {
                        scheduledKid: rotated.nextKid,
                        activatesAt: rotated.activatesAt.toISOString(),
                      }
                    : {}),
                },
              }),
            ],
          },
        );
        return {
          body: {
            status: result.status,
            ...kidsOf(result),
            nextKid: result.status === "scheduled" ? result.nextKid : null,
            activatesAt: result.status === "scheduled" ? iso(result.activatesAt) : null,
            keys: await keySet(deps),
          },
        };
      },
    }),
  ];
}
