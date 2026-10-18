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

  it("rotates on demand: the next token uses a new kid, the previous kid stays verifiable", async () => {
    const { rp, issuer } = await world();
    const before = portvakt.keyCache.current!.activeKid;
    const oldToken = await newToken(rp);
    const result = await portvakt.rotation.rotateNow({
      actor: { type: "person", id: crypto.randomUUID() },
      reason: "scheduled maintenance",
      emergency: false,
    });
    expect(result).toMatchObject({ retiringKid: before, retiredKids: [] });
    expect(result.activatedKid).not.toBe(before);
    expect(portvakt.keyCache.current!.activeKid).toBe(result.activatedKid);
    expect(decodeProtectedHeader(await newToken(rp)).kid).toBe(result.activatedKid);
    expect((await verify(issuer, oldToken)).protectedHeader.kid).toBe(before);
    const audit = await repos.audit.query(
      { allTenants: true, tenantId: null },
      { actions: ["key.rotate", "key.activate_forced"] },
    );
    expect(audit.events.map((event) => event.action).sort()).toEqual([
      "key.activate_forced",
      "key.rotate",
    ]);
  });

  it("emergency rotation retires the compromised key at once", async () => {
    const { rp, issuer } = await world();
    const compromised = portvakt.keyCache.current!.activeKid;
    const signedByIt = await newToken(rp);
    const result = await portvakt.rotation.rotateNow({
      actor: { type: "system", id: null },
      reason: "key compromise",
      emergency: true,
    });
    expect(result.retiredKids).toEqual([compromised]);
    expect(result.retiringKid).toBeNull();
    expect((await jwksOf(issuer)).keys.map((key) => key.kid)).not.toContain(compromised);
    await expect(verify(issuer, signedByIt)).rejects.toThrow();
    await expect(
      portvakt.rotation.rotateNow({
        actor: { type: "system", id: null },
        reason: "",
        emergency: true,
      }),
    ).rejects.toThrow(/Invalid input/);
  });

  it("lets only one replica run the job, and other replicas follow on NOTIFY", async () => {
    const replica = createPortvakt({
      config,
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

      const result = await portvakt.rotation.rotateNow({
        actor: { type: "system", id: null },
        reason: "replica convergence",
        emergency: false,
      });
      await expect.poll(() => replica.keyCache.current?.activeKid).toBe(result.activatedKid);
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
