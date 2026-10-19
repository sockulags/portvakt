import { z } from "zod";
import { SIGNING_KEY_STATES, type SigningKey } from "../../../domain/signing-key.js";
import { auditEvent } from "../../../audit/catalogue.js";
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
});

const keySetSchema = z
  .object({
    keys: z.array(signingKeySchema),
    policy: z.object({
      intervalSeconds: z.number().int(),
      publishAheadSeconds: z.number().int(),
      retireAfterSeconds: z.number().int(),
    }),
    /** When the scheduled rotation introduces the next key (active key + interval - publish ahead). */
    nextScheduledRotationAt: isoDateTime.nullable(),
    etag,
  })
  .meta({ id: "SigningKeys" });
type KeySetView = z.input<typeof keySetSchema>;

const rotationSchema = z
  .object({
    activatedKid: z.string(),
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
    // The tag follows the live keys and their states: what a rotation changes.
    etag: etagOf({ keys: live.map((key) => `${key.kid}:${key.state}`) }),
  };
}

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
      summary: "Rotate the signing keys now (platform administrators)",
      description:
        "A new key signs from now on; the previous one stays published (retiring) so issued " +
        "tokens remain verifiable. `emergency` (key compromise) retires the previous key at once: " +
        "tokens it signed stop verifying. The reason is audited and must not contain personal " +
        "data. If-Match takes the key set's etag; it is checked under the rotation's lock, so of " +
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
                subject: { type: "signing_key", id: rotated.activatedKid },
                details: {
                  actorTenantId: caller.tenant.id,
                  emergency: body.emergency,
                  activatedKid: rotated.activatedKid,
                  retiringKid: rotated.retiringKid,
                  retiredKids: [...rotated.retiredKids],
                },
              }),
            ],
          },
        );
        return {
          body: {
            activatedKid: result.activatedKid,
            retiringKid: result.retiringKid,
            retiredKids: [...result.retiredKids],
            keys: await keySet(deps),
          },
        };
      },
    }),
  ];
}
