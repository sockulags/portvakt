import { createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JSONWebKeySet } from "jose";
import * as client from "openid-client";
import { describe, expect, it } from "vitest";
import {
  codeFlow,
  createPerson,
  createTenantWorld,
  discoverWithSecret,
} from "../testing/oidc-flow.js";
import { uniqueSuffix } from "../testing/fixtures.js";
import { startTestServer } from "../testing/test-server.js";
import { createLogger } from "../logging/logger.js";
import { createPortvakt } from "../server.js";
import { generateSigningKey } from "../crypto/jwk.js";
import { JOB_LOCKS, runExclusive } from "../jobs/exclusive.js";

const ts = await startTestServer();

const DAY = 86_400;

// Signing keys are global: the cases in this file build on each other, in order.
describe.skipIf(ts === undefined)("signing keys and rotation", () => {
  const { db, portvakt, config } = ts!;
  const { repos } = db;
  const policy = config.keyRotation;
  /** Signed by the first key; checked again once that key is retired. */
  let tokenOfRetiringKey = { issuer: "", token: "" };

  async function world() {
    const w = await createTenantWorld(repos, "rot");
    const rp = await discoverWithSecret(ts!, w.tenant.slug, w.app);
    return { ...w, rp, issuer: ts!.issuerOf(w.tenant.slug) };
  }

  async function jwksOf(issuer: string): Promise<JSONWebKeySet> {
    return (await (await fetch(`${issuer}/jwks`)).json()) as JSONWebKeySet;
  }

  async function verify(issuer: string, token: string) {
    return jwtVerify(token, createLocalJWKSet(await jwksOf(issuer)), { issuer });
  }

  async function newToken(rp: client.Configuration): Promise<string> {
    return (await client.clientCredentialsGrant(rp)).access_token;
  }

  /** Moves a key's timestamps into the past, as if `seconds` had passed. */
  async function age(kid: string, seconds: number): Promise<void> {
    await db.ownerDb.query(
      `UPDATE signing_keys
          SET created_at = created_at - make_interval(secs => $2),
              activated_at = activated_at - make_interval(secs => $2),
              retiring_at = retiring_at - make_interval(secs => $2)
        WHERE kid = $1`,
      [kid, seconds],
    );
  }

  it("creates and activates a key on first start, with an audit event", async () => {
    const [active, ...others] = await repos.signingKeys.list(["next", "active", "retiring"]);
    expect(others).toEqual([]);
    expect(active?.state).toBe("active");
    expect(portvakt.keyCache.current?.activeKid).toBe(active?.kid);
    const audit = await repos.audit.query(
      { allTenants: true, tenantId: null },
      { actions: ["key.create", "key.activate"] },
    );
    expect(audit.events.map((event) => event.action).sort()).toEqual([
      "key.activate",
      "key.create",
    ]);
    // Starting again (another replica) does not add a key.
    await portvakt.rotation.ensureActiveKey();
    expect(await repos.signingKeys.list(["next", "active", "retiring"])).toHaveLength(1);
  });

  it("publishes a scheduled next key ahead of use while the active key keeps signing", async () => {
    const { rp, issuer } = await world();
    const activeKid = portvakt.keyCache.current!.activeKid;
    expect((await portvakt.jobs.rotateKeys()).createdKid).toBeNull();

    await age(activeKid, policy.intervalSeconds - policy.publishAheadSeconds + 60);
    const step = await portvakt.jobs.rotateKeys();
    expect(step).toMatchObject({ ran: true, activatedKid: null, retiredKids: [] });
    expect(step.createdKid).toBeTypeOf("string");
    expect((await jwksOf(issuer)).keys.map((key) => key.kid)).toEqual([activeKid, step.createdKid]);
    // The next key is published but never used to sign: not for access tokens, not for ID tokens.
    expect(decodeProtectedHeader(await newToken(rp)).kid).toBe(activeKid);
    expect(portvakt.keyCache.current!.kids.map((key) => key.state)).toEqual(["active", "next"]);
    const w = await world();
    const { person } = await createPerson(repos, w, `p-${uniqueSuffix()}`);
    const tokens = await codeFlow(ts!, w.rp, w.app.application.redirectUris[0]!, {
      personId: person.id,
      loginMethodId: w.loginMethod.id,
      acr: w.loginMethod.assertedAcr,
    });
    expect(decodeProtectedHeader(tokens.id_token!).kid).toBe(activeKid);

    // Not due yet: the next key waits KEY_PUBLISH_AHEAD.
    expect((await portvakt.jobs.rotateKeys()).activatedKid).toBeNull();
  });

  it("activates the next key after publish-ahead; tokens of the retiring key stay valid", async () => {
    const { rp, issuer } = await world();
    const oldKid = portvakt.keyCache.current!.activeKid;
    const [next] = await repos.signingKeys.list(["next"]);
    const oldToken = await newToken(rp);
    expect(decodeProtectedHeader(oldToken).kid).toBe(oldKid);
    tokenOfRetiringKey = { issuer, token: oldToken };

    await age(next!.kid, policy.publishAheadSeconds + 60);
    const step = await portvakt.jobs.rotateKeys();
    expect(step).toMatchObject({ ran: true, activatedKid: next!.kid, createdKid: null });
    expect(portvakt.keyCache.current!.activeKid).toBe(next!.kid);

    const newer = await newToken(rp);
    expect(decodeProtectedHeader(newer).kid).toBe(next!.kid);
    expect((await verify(issuer, newer)).protectedHeader.kid).toBe(next!.kid);
    expect((await verify(issuer, oldToken)).protectedHeader.kid).toBe(oldKid);
    expect((await repos.signingKeys.findByKid(oldKid))?.state).toBe("retiring");

    // ID tokens use the new key as well.
    expect(portvakt.keyCache.current!.jwks.keys[0]?.kid).toBe(next!.kid);
  });

  it("retires the retiring key after retire-after; its tokens stop verifying", async () => {
    const { rp, issuer } = await world();
    await expect(
      verify(tokenOfRetiringKey.issuer, tokenOfRetiringKey.token),
    ).resolves.toBeDefined();
    const [retiring] = await repos.signingKeys.list(["retiring"]);
    const stillValid = await newToken(rp);
    expect((await portvakt.jobs.rotateKeys()).retiredKids).toEqual([]);

    await age(retiring!.kid, policy.retireAfterSeconds + 60);
    expect((await portvakt.jobs.rotateKeys()).retiredKids).toEqual([retiring!.kid]);
    const published = (await jwksOf(issuer)).keys.map((key) => key.kid);
    expect(published).not.toContain(retiring!.kid);
    expect(published).toEqual([portvakt.keyCache.current!.activeKid]);
    await expect(verify(issuer, stillValid)).resolves.toBeDefined();
    await expect(verify(tokenOfRetiringKey.issuer, tokenOfRetiringKey.token)).rejects.toThrow();
  });

  /** Moves a scheduled activation into the past, as if KEY_MANUAL_PUBLISH_AHEAD had passed. */
  async function makeDue(kid: string): Promise<void> {
    await db.ownerDb.query(
      "UPDATE signing_keys SET activate_at = now() - interval '1 second' WHERE kid = $1",
      [kid],
    );
  }

  it("rotates on demand by publishing ahead: the new key is in JWKS first, signs after the wait", async () => {
    const { rp, issuer } = await world();
    const before = portvakt.keyCache.current!.activeKid;
    const oldToken = await newToken(rp);
    const started = Date.now();
    const result = await portvakt.rotation.rotateNow({
      actor: { type: "person", id: crypto.randomUUID() },
      reason: "scheduled maintenance",
      emergency: false,
    });
    if (result.status !== "scheduled") throw new Error(`expected scheduled, got ${result.status}`);
    const { nextKid, activatesAt } = result;
    // KEY_MANUAL_PUBLISH_AHEAD (10 minutes by default) from now.
    expect(activatesAt.getTime()).toBeGreaterThanOrEqual(
      started + policy.manualPublishAheadSeconds * 1000 - 2000,
    );
    expect(activatesAt.getTime()).toBeLessThanOrEqual(
      Date.now() + policy.manualPublishAheadSeconds * 1000 + 2000,
    );
    // Published at once, not signing yet: the job does nothing before the time.
    expect((await jwksOf(issuer)).keys.map((key) => key.kid)).toContain(nextKid);
    expect(decodeProtectedHeader(await newToken(rp)).kid).toBe(before);
    expect((await portvakt.jobs.rotateKeys()).activatedKid).toBeNull();
    expect((await repos.signingKeys.findByKid(nextKid))?.activateAt?.getTime()).toBe(
      activatesAt.getTime(),
    );

    // A second request while one is pending keeps the schedule (idempotent).
    const again = await portvakt.rotation.rotateNow({
      actor: { type: "system", id: null },
      reason: "clicked twice",
      emergency: false,
    });
    expect(again).toEqual({ status: "scheduled", nextKid, activatesAt });

    // Once due, the rotation job activates it (no forced transition).
    await makeDue(nextKid);
    expect(await portvakt.jobs.rotateKeys()).toMatchObject({ activatedKid: nextKid });
    expect(portvakt.keyCache.current!.activeKid).toBe(nextKid);
    expect(decodeProtectedHeader(await newToken(rp)).kid).toBe(nextKid);
    expect((await verify(issuer, oldToken)).protectedHeader.kid).toBe(before);
    expect((await repos.signingKeys.findByKid(nextKid))?.activateAt).toBeNull();
    const audit = await repos.audit.query(
      { allTenants: true, tenantId: null },
      { actions: ["key.rotate", "key.activate", "key.activate_forced"] },
    );
    const forKey = audit.events.filter((event) => event.subject?.id === nextKid);
    expect(forKey.map((event) => event.action).sort()).toEqual([
      "key.activate",
      "key.rotate",
      "key.rotate",
    ]);
    expect(forKey.find((event) => event.action === "key.rotate")?.details).toMatchObject({
      emergency: false,
      activatesAt: activatesAt.toISOString(),
    });
  });

  it("activates at once a next key that was published long enough ago", async () => {
    const before = portvakt.keyCache.current!.activeKid;
    const next = await repos.signingKeys.createNext(generateSigningKey());
    await age(next.kid, policy.manualPublishAheadSeconds + 60);
    const result = await portvakt.rotation.rotateNow({
      actor: { type: "system", id: null },
      reason: "published by the scheduled rotation",
      emergency: false,
    });
    expect(result).toEqual({
      status: "activated",
      activatedKid: next.kid,
      retiringKid: before,
      retiredKids: [],
    });
    expect(portvakt.keyCache.current!.activeKid).toBe(next.kid);
  });

  it("emergency rotation signs with a fresh key and retires every other key at once", async () => {
    const { rp, issuer } = await world();
    const compromised = portvakt.keyCache.current!.activeKid;
    const signedByIt = await newToken(rp);
    // The previous cases left retiring keys; a pending manual rotation adds a published next key.
    const retiring = (await repos.signingKeys.list(["retiring"])).map((key) => key.kid);
    expect(retiring.length).toBeGreaterThan(0);
    expect((await jwksOf(issuer)).keys.map((key) => key.kid)).toEqual(
      expect.arrayContaining(retiring),
    );
    const pending = await portvakt.rotation.rotateNow({
      actor: { type: "system", id: null },
      reason: "planned",
      emergency: false,
    });
    if (pending.status !== "scheduled") throw new Error("expected a scheduled rotation");
    const result = await portvakt.rotation.rotateNow({
      actor: { type: "system", id: null },
      reason: "key compromise",
      emergency: true,
    });
    if (result.status !== "activated") throw new Error("expected an activated rotation");
    // A fresh key: neither the pending next key (stored next to the compromised one) nor another.
    const others = [compromised, ...retiring, pending.nextKid];
    expect(others).not.toContain(result.activatedKid);
    expect(result.retiringKid).toBeNull();
    expect([...result.retiredKids].sort()).toEqual([...others].sort());
    for (const kid of others) {
      expect((await repos.signingKeys.findByKid(kid))?.state).toBe("retired");
    }
    // JWKS publishes the new key only, at once (this replica reloaded in the same call).
    expect((await jwksOf(issuer)).keys.map((key) => key.kid)).toEqual([result.activatedKid]);
    await expect(verify(issuer, signedByIt)).rejects.toThrow();
    expect(decodeProtectedHeader(await newToken(rp)).kid).toBe(result.activatedKid);
    const [rotateEvent] = (
      await repos.audit.query(
        { allTenants: true, tenantId: null },
        { actions: ["key.rotate"], subjectId: result.activatedKid },
      )
    ).events;
    expect(rotateEvent?.details).toMatchObject({ emergency: true, retiringKid: null });
    expect([...((rotateEvent?.details.retiredKids as string[] | undefined) ?? [])].sort()).toEqual(
      [...result.retiredKids].sort(),
    );
    await expect(
      portvakt.rotation.rotateNow({
        actor: { type: "system", id: null },
        reason: "",
        emergency: true,
      }),
    ).rejects.toThrow(/Invalid input/);
  });

  it("lets only one replica run the job, and replicas activate a scheduled key on time", async () => {
    // A replica with a one-second publish-ahead: its timer runs the job when the key is due.
    const replica = createPortvakt({
      config: { ...config, keyRotation: { ...config.keyRotation, manualPublishAheadSeconds: 1 } },
      pool: db.pool,
      logger: createLogger({ level: "silent" }),
      keys: db.keys,
    });
    try {
      await replica.start();
      expect(replica.keyCache.current?.version).toBe(portvakt.keyCache.current?.version);

      const skipped = await runExclusive(db.db, JOB_LOCKS.keyRotation, { wait: true }, () =>
        replica.jobs.rotateKeys(),
      );
      expect(skipped).toEqual({
        ran: true,
        value: { ran: false, createdKid: null, activatedKid: null, retiredKids: [] },
      });

      const result = await replica.rotation.rotateNow({
        actor: { type: "system", id: null },
        reason: "replica convergence",
        emergency: false,
      });
      if (result.status !== "scheduled") throw new Error("expected a scheduled rotation");
      // Both replicas see the published key at once (NOTIFY), and the active one after it is due.
      await expect
        .poll(() => portvakt.keyCache.current?.kids.map((key) => key.kid))
        .toContain(result.nextKid);
      await expect
        .poll(() => portvakt.keyCache.current?.activeKid, { timeout: 10_000 })
        .toBe(result.nextKid);
      await expect.poll(() => replica.keyCache.current?.activeKid).toBe(result.nextKid);
    } finally {
      await replica.shutdown();
    }
  });

  it("keeps the retire-after window at least as long as any signed token", () => {
    expect(policy.retireAfterSeconds).toBeGreaterThanOrEqual(
      Math.max(config.tokens.accessTokenSeconds, config.tokens.idTokenSeconds),
    );
    expect(policy.retireAfterSeconds).toBe(2 * DAY);
  });
});
