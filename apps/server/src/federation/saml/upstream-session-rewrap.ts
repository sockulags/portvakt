import { z } from "zod";
import type { KeyRing } from "../../crypto/keyring.js";
import type { Db } from "../../db/database.js";
import {
  SESSION_RECORD_KIND,
  sessionUpstreamSchema,
  UPSTREAM_INDEX_KIND,
  upstreamSessionKey,
  type SessionUpstream,
} from "../../oidc/login-context.js";
import { reindexUpstreamSession } from "./upstream-session.js";

const upstreamsSchema = z.array(sessionUpstreamSchema);

/**
 * Master key rotation for the upstream SAML sessions of live broker sessions (session records,
 * `PortvaktSession`): every upstream whose sealed NameID/SessionIndex is not under the current
 * master key is re-wrapped, its blind indexes are computed again with the current index key, and
 * its index row (`PortvaktUpstreamSession`, keyed by the NameID's index) is replaced, keeping the
 * record's expiry. Afterwards the previous master key is no longer needed for single logout.
 *
 * A record that changed its upstreams meanwhile (a new login) is left alone: its new upstreams
 * are under the current key anyway, and a later run picks up any old ones. An upstream that no
 * configured key can open stays as it is (it is useless either way) and is not counted.
 * Returns the number of upstream sessions re-wrapped.
 */
export async function rewrapUpstreamSessions(db: Db, keys: KeyRing): Promise<number> {
  const rows = await db.query<{
    tenant_id: string;
    id: string;
    upstreams: unknown;
    expires_at: Date | null;
  }>(
    `SELECT tenant_id, id, payload->'upstreams' AS upstreams, expires_at FROM oidc_payloads
      WHERE kind = $1 AND jsonb_typeof(payload->'upstreams') = 'array'
        AND (expires_at IS NULL OR expires_at > now())`,
    [SESSION_RECORD_KIND],
  );
  let count = 0;
  for (const row of rows) {
    const parsed = upstreamsSchema.safeParse(row.upstreams);
    if (!parsed.success) continue;
    const changes: { readonly before: SessionUpstream; readonly after: SessionUpstream }[] = [];
    const upstreams = parsed.data.map((upstream) => {
      if (!keys.secrets.needsRewrap(upstream.sealed)) return upstream;
      let after: SessionUpstream;
      try {
        after = {
          ...reindexUpstreamSession(keys, upstream.loginMethodId, upstream),
          loginMethodId: upstream.loginMethodId,
        };
      } catch {
        return upstream;
      }
      changes.push({ before: upstream, after });
      return after;
    });
    if (changes.length === 0) continue;
    const updated = await db.query(
      `UPDATE oidc_payloads SET payload = jsonb_set(payload, '{upstreams}', $4::jsonb)
        WHERE tenant_id = $1 AND kind = $2 AND id = $3 AND payload->'upstreams' = $5::jsonb
        RETURNING id`,
      [
        row.tenant_id,
        SESSION_RECORD_KIND,
        row.id,
        JSON.stringify(upstreams),
        JSON.stringify(row.upstreams),
      ],
    );
    if (updated.length === 0) continue;
    for (const { before, after } of changes) {
      const oldKey = upstreamSessionKey(before.loginMethodId, before.nameIdIndex);
      const newKey = upstreamSessionKey(after.loginMethodId, after.nameIdIndex);
      await db.query("DELETE FROM oidc_payloads WHERE tenant_id = $1 AND kind = $2 AND id = $3", [
        row.tenant_id,
        UPSTREAM_INDEX_KIND,
        `${row.id}|${oldKey}`,
      ]);
      await db.query(
        `INSERT INTO oidc_payloads (tenant_id, kind, id, payload, uid, expires_at)
         VALUES ($1, $2, $3, $4::jsonb, $5, $6)
         ON CONFLICT (tenant_id, kind, id) DO UPDATE SET
           payload = EXCLUDED.payload, uid = EXCLUDED.uid, expires_at = EXCLUDED.expires_at`,
        [
          row.tenant_id,
          UPSTREAM_INDEX_KIND,
          `${row.id}|${newKey}`,
          JSON.stringify({ sessionUid: row.id }),
          newKey,
          row.expires_at,
        ],
      );
    }
    count += changes.length;
  }
  return count;
}
