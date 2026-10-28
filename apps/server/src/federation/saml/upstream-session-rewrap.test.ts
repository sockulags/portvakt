import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createKeyRing } from "../../crypto/keyring.js";
import {
  LoginStateStore,
  SESSION_RECORD_KIND,
  UPSTREAM_INDEX_KIND,
  type SessionRecord,
} from "../../oidc/login-context.js";
import { rewrapAllSecrets } from "../../repositories/rewrap.js";
import { createTenant } from "../../testing/fixtures.js";
import { setupTestDatabase, testMasterKeys } from "../../testing/test-database.js";
import type { LogoutSubject } from "./protocol.js";
import {
  nameIdIndexCandidates,
  sealUpstreamSession,
  sessionIndexCandidates,
  unsealUpstreamSession,
} from "./upstream-session.js";
import { rewrapUpstreamSessions } from "./upstream-session-rewrap.js";

const testDb = await setupTestDatabase();

const subject = (nameId: string, sessionIndex?: string): LogoutSubject => ({
  nameId,
  nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  nameQualifier: undefined,
  spNameQualifier: undefined,
  sessionIndex,
});

describe.skipIf(testDb === undefined)("master key rotation of upstream SAML sessions", () => {
  const { repos, db } = testDb!;
  const oldKeys = createKeyRing({ current: testMasterKeys.current, previous: [] });
  const newKey = Buffer.from("test-master-key-upstream-32bytes", "utf8");
  const rotating = createKeyRing({ current: newKey, previous: [testMasterKeys.current] });
  const newOnly = createKeyRing({ current: newKey, previous: [] });

  function record(upstreams: SessionRecord["upstreams"]): SessionRecord {
    const now = Math.floor(Date.now() / 1000);
    return {
      personId: randomUUID(),
      loginMethodId: randomUUID(),
      loginMethodKind: "citizen",
      acr: "http://id.elegnamnden.se/loa/1.0/loa3",
      amr: ["fed"],
      authTime: now,
      sessionExpiresAt: now + 3600,
      retainUntil: now + 7200,
      idleSeconds: 900,
      allowSso: true,
      clientId: "app",
      lastActivityAt: now,
      ...(upstreams === undefined ? {} : { upstreams }),
    };
  }

  const indexRows = async (tenantId: string, sessionUid: string) =>
    db.query<{ id: string; uid: string; expires_at: Date }>(
      `SELECT id, uid, expires_at FROM oidc_payloads
        WHERE tenant_id = $1 AND kind = $2 AND payload->>'sessionUid' = $3 ORDER BY id`,
      [tenantId, UPSTREAM_INDEX_KIND, sessionUid],
    );

  it("re-wraps the sealed upstreams, re-indexes them and replaces their index rows", async () => {
    const tenant = await createTenant(repos, "slo-rewrap");
    const store = new LoginStateStore(tenant.id, db);
    const bankid = randomUUID();
    const freja = randomUUID();
    const sessionUid = `session-${randomUUID()}`;
    await store.saveSession(
      sessionUid,
      record([
        {
          ...sealUpstreamSession(oldKeys, bankid, subject("nameid-1", "idx-1")),
          loginMethodId: bankid,
        },
        { ...sealUpstreamSession(oldKeys, freja, subject("nameid-2")), loginMethodId: freja },
      ]),
    );
    // A session without upstreams is not touched.
    const plainUid = `session-${randomUUID()}`;
    await store.saveSession(plainUid, record(undefined));
    const [before] = await db.query<{ expires_at: Date }>(
      "SELECT expires_at FROM oidc_payloads WHERE tenant_id = $1 AND kind = $2 AND id = $3",
      [tenant.id, SESSION_RECORD_KIND, sessionUid],
    );

    const result = await rewrapAllSecrets(db, rotating);
    expect(result.upstreamSessions).toBe(2);
    expect(await rewrapUpstreamSessions(db, rotating)).toBe(0);

    // Only the new master key is needed from now on: unsealing (SP-initiated logout) ...
    const after = await new LoginStateStore(tenant.id, db).findSession(sessionUid);
    const [first, second] = after?.upstreams ?? [];
    expect(unsealUpstreamSession(newOnly, bankid, first!)).toMatchObject({
      nameId: "nameid-1",
      sessionIndex: "idx-1",
    });
    expect(unsealUpstreamSession(newOnly, freja, second!).nameId).toBe("nameid-2");
    expect(first!.nameIdIndex).toBe(nameIdIndexCandidates(newOnly, bankid, "nameid-1")[0]);
    expect(first!.sessionIndexIndex).toBe(sessionIndexCandidates(newOnly, bankid, "idx-1")[0]);
    // ... and the index rows the IdP-initiated logout looks up, with the record's expiry.
    const rows = await indexRows(tenant.id, sessionUid);
    expect(rows.map((row) => row.uid).sort()).toEqual(
      [
        `saml:${bankid}:${nameIdIndexCandidates(newOnly, bankid, "nameid-1")[0]!}`,
        `saml:${freja}:${nameIdIndexCandidates(newOnly, freja, "nameid-2")[0]!}`,
      ].sort(),
    );
    for (const row of rows) expect(row.expires_at.getTime()).toBe(before!.expires_at.getTime());

    // IdP-initiated logout with the new key alone ends the session.
    expect(
      await new LoginStateStore(tenant.id, db).endSessionsOfUpstream(
        bankid,
        nameIdIndexCandidates(newOnly, bankid, "nameid-1"),
        sessionIndexCandidates(newOnly, bankid, "idx-1"),
      ),
    ).toBe(1);
    expect(await store.findSession(sessionUid)).toBeUndefined();
    expect(await indexRows(tenant.id, sessionUid)).toEqual([]);
    expect(await store.findSession(plainUid)).toBeDefined();

    // Back to the test master key for the rest of the file.
    await rewrapAllSecrets(
      db,
      createKeyRing({ current: testMasterKeys.current, previous: [newKey] }),
    );
  });

  it("leaves an upstream session no configured key opens as it is", async () => {
    const tenant = await createTenant(repos, "slo-rewrap-skip");
    const store = new LoginStateStore(tenant.id, db);
    const method = randomUUID();
    const foreign = createKeyRing({
      current: Buffer.from("test-master-key-foreign-32-bytes", "utf8"),
      previous: [],
    });
    const sessionUid = `session-${randomUUID()}`;
    const unreadable = {
      ...sealUpstreamSession(foreign, method, subject("lost")),
      loginMethodId: method,
    };
    await store.saveSession(sessionUid, record([unreadable]));
    expect(await rewrapUpstreamSessions(db, rotating)).toBe(0);
    expect((await store.findSession(sessionUid))?.upstreams).toEqual([unreadable]);
  });
});
