import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Express } from "express";
import type { Pool } from "pg";
import { createApp, type ReadinessReport } from "./app.js";
import type { Config } from "./config/index.js";
import { createKeyRing, type KeyRing } from "./crypto/keyring.js";
import { createDb } from "./db/database.js";
import { JOB_LOCKS, runExclusive } from "./jobs/exclusive.js";
import { PeriodicTask } from "./jobs/periodic.js";
import { SigningKeyCache } from "./keys/key-cache.js";
import { KeyRotationService, type ScheduledRotationResult } from "./keys/rotation.js";
import type { Logger } from "./logging/logger.js";
import { ChangeListener } from "./oidc/change-listener.js";
import { createInteractionService, type InteractionService } from "./oidc/interactions.js";
import { buildTenantProvider } from "./oidc/provider.js";
import { ProviderRegistry } from "./oidc/registry.js";
import { tenantRoutes } from "./oidc/routes.js";
import { defaultSessionPolicy, type SessionPolicy } from "./oidc/session-policy.js";
import type { ChangeEvent } from "./repositories/change-events.js";
import { createRepositories, type Repositories } from "./repositories/index.js";
import { OidcPayloadRepository } from "./repositories/oidc-payloads.js";

const READINESS_DB_TIMEOUT_MS = 2000;
const CLEANUP_BATCH_SIZE = 5000;
/** Upper bound per run; the next run continues where this one stopped. */
const CLEANUP_MAX_BATCHES = 200;

export interface PortvaktOptions {
  readonly config: Config;
  /** Runtime role pool. The caller owns it and ends it after {@link Portvakt.shutdown}. */
  readonly pool: Pool;
  readonly logger: Logger;
  /** Connection string of the LISTEN connection; defaults to `config.database.url`. */
  readonly listenUrl?: string;
  /** Defaults to the key ring of `config.masterKeys`. */
  readonly keys?: KeyRing;
  /** Session lifetimes; defaults to the configured lifetimes (M3 plugs in session policies). */
  readonly sessionPolicy?: SessionPolicy;
}

export interface Portvakt {
  readonly app: Express;
  readonly repos: Repositories;
  readonly registry: ProviderRegistry;
  readonly keyCache: SigningKeyCache;
  /** `rotateNow` is the entry point for the admin API (M6). */
  readonly rotation: KeyRotationService;
  /** `completeLogin` is the entry point for the login UI (M3). */
  readonly interactions: InteractionService;
  readonly readiness: () => Promise<ReadinessReport>;
  /** The scheduled jobs, runnable on demand (tests, operations). */
  readonly jobs: {
    readonly reload: () => Promise<void>;
    readonly cleanupExpired: () => Promise<number | null>;
    readonly rotateKeys: () => Promise<ScheduledRotationResult>;
  };
  /** Ensures a signing key exists, loads keys, subscribes to changes and starts the jobs. */
  start(): Promise<void>;
  /**
   * Serves the app (or `handler`, for embedding it) on an HTTP server that graceful shutdown
   * then closes.
   */
  serve(server: Server, handler?: RequestListener): void;
  listen(port: number, host?: string): Promise<Server>;
  /**
   * Graceful shutdown: readiness turns 503, requests are still served for
   * `shutdownDrainDelaySeconds` (so load balancers stop routing here first), then responses ask
   * clients to close the connection, listening stops, in-flight requests get `shutdownTimeoutSeconds` to finish (then connections
   * are closed), and the jobs and the change listener stop. The pool stays open for the caller.
   */
  shutdown(): Promise<void>;
}

export function createPortvakt(options: PortvaktOptions): Portvakt {
  const { config, pool, logger } = options;
  const db = createDb(pool);
  const keys = options.keys ?? createKeyRing(config.masterKeys);
  const repos = createRepositories(db, keys);
  const sessionPolicy = options.sessionPolicy ?? defaultSessionPolicy(config.tokens);
  const keyCache = new SigningKeyCache(repos.signingKeys);
  const servers = new Set<Server>();
  /** Shutdown began: readiness reports 503. */
  let draining = false;
  /** The listener is closing: responses ask clients to close their connection. */
  let closing = false;
  let started = false;

  const registry = new ProviderRegistry({
    repos,
    keys: keyCache,
    logger,
    build: (tenant, loaded, fingerprint) =>
      buildTenantProvider(tenant, loaded, fingerprint, { config, repos, logger, sessionPolicy }),
  });

  const reloadKeys = async (): Promise<void> => {
    if (await keyCache.reload())
      logger.info({ keys: keyCache.current?.kids }, "signing keys loaded");
  };

  const rotation = new KeyRotationService({
    db,
    keys,
    policy: config.keyRotation,
    logger,
    onChange: reloadKeys,
  });
  const interactions = createInteractionService(repos);

  const onEvent = async (event: ChangeEvent): Promise<void> => {
    switch (event.type) {
      case "tenant":
      case "tenant_applications":
        registry.invalidateTenant(event.tenantId);
        return;
      case "application":
        registry.invalidateAll();
        return;
      case "signing_keys":
        await reloadKeys();
        return;
    }
  };
  const listener = new ChangeListener({
    url: options.listenUrl ?? config.database.url,
    logger,
    onEvent,
    onResync: async () => {
      await reloadKeys();
      registry.invalidateAll();
    },
  });

  const jobs = {
    reload: async (): Promise<void> => {
      await reloadKeys();
      await registry.reconcile();
    },
    /**
     * One transaction (and lock acquisition) per batch, so each batch commits on its own and no
     * lock is held across the whole run. `null` when another replica is cleaning up.
     */
    cleanupExpired: async (): Promise<number | null> => {
      let total = 0;
      for (let batch = 0; batch < CLEANUP_MAX_BATCHES; batch += 1) {
        const result = await runExclusive(db, JOB_LOCKS.payloadCleanup, { wait: false }, (tx) =>
          new OidcPayloadRepository(tx).deleteExpiredBatch(CLEANUP_BATCH_SIZE),
        );
        if (!result.ran) return batch === 0 ? null : total;
        total += result.value;
        if (result.value < CLEANUP_BATCH_SIZE) break;
      }
      if (total > 0) logger.info({ deleted: total }, "deleted expired oidc payloads");
      return total;
    },
    rotateKeys: () => rotation.runScheduled(),
  };
  const tasks = [
    new PeriodicTask({
      name: "provider-reload",
      intervalSeconds: config.intervals.providerReloadSeconds,
      run: jobs.reload,
      logger,
    }),
    new PeriodicTask({
      name: "payload-cleanup",
      intervalSeconds: config.intervals.payloadCleanupSeconds,
      run: async () => {
        await jobs.cleanupExpired();
      },
      logger,
    }),
    new PeriodicTask({
      name: "key-rotation",
      intervalSeconds: config.intervals.keyRotationCheckSeconds,
      run: async () => {
        await jobs.rotateKeys();
      },
      logger,
      runImmediately: true,
    }),
  ];

  const readiness = async (): Promise<ReadinessReport> => {
    const database = await pingDatabase(pool);
    const signingKeys = keyCache.ready;
    return {
      ready: database && signingKeys && !draining,
      checks: { database, signingKeys, accepting: !draining },
    };
  };

  // loadConfig only allows test mode with a loopback or .test PUBLIC_URL.
  const testRoutes = config.nodeEnv === "test";
  if (testRoutes) {
    logger.warn(
      "NODE_ENV=test: the unauthenticated test login route is mounted; never expose this server",
    );
  }

  const app = createApp({
    logger,
    trustProxy: config.trustProxy,
    readiness,
    isDraining: () => closing,
    routes: [
      tenantRoutes({
        registry,
        interactions,
        logger,
        testRoutes,
        publicUrl: config.publicUrl,
      }),
    ],
  });

  const serve = (server: Server, handler: RequestListener = app): void => {
    server.on("request", handler);
    servers.add(server);
    server.once("close", () => servers.delete(server));
  };

  return {
    app,
    repos,
    registry,
    keyCache,
    rotation,
    interactions,
    readiness,
    jobs,
    async start() {
      if (started) return;
      await rotation.ensureActiveKey();
      await reloadKeys();
      await listener.start();
      for (const task of tasks) task.start();
      started = true;
    },
    serve,
    async listen(port, host) {
      const server = createServer();
      serve(server);
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.off("error", reject);
          resolve();
        });
      });
      const address = server.address() as AddressInfo;
      logger.info({ port: address.port }, "listening");
      return server;
    },
    async shutdown() {
      if (draining) return;
      draining = true;
      logger.info({ drainDelaySeconds: config.shutdownDrainDelaySeconds }, "shutting down");
      // Readiness is 503 from here on; keep serving until load balancers have noticed.
      if (config.shutdownDrainDelaySeconds > 0) {
        await new Promise((resolve) =>
          setTimeout(resolve, config.shutdownDrainDelaySeconds * 1000),
        );
      }
      closing = true;
      await Promise.all(
        [...servers].map((server) => closeServer(server, config.shutdownTimeoutSeconds * 1000)),
      );
      await Promise.all(tasks.map((task) => task.stop()));
      await listener.stop();
      logger.info("shut down");
    },
  };
}

async function pingDatabase(pool: Pool): Promise<boolean> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<boolean>((resolve) => {
    timer = setTimeout(() => resolve(false), READINESS_DB_TIMEOUT_MS);
  });
  try {
    return await Promise.race([
      pool.query("SELECT 1").then(
        () => true,
        () => false,
      ),
      timeout,
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** How often a draining server closes keep-alive connections that have gone idle. */
const DRAIN_POLL_MS = 50;

/**
 * Stops accepting, lets in-flight requests finish (closing each connection once it is idle, so a
 * keep-alive client cannot hold shutdown open), then forces whatever is left after the timeout.
 */
async function closeServer(server: Server, timeoutMs: number): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve) => {
    const drain = setInterval(() => server.closeIdleConnections(), DRAIN_POLL_MS);
    const force = setTimeout(() => server.closeAllConnections(), timeoutMs);
    drain.unref();
    force.unref();
    server.close(() => {
      clearInterval(drain);
      clearTimeout(force);
      resolve();
    });
    server.closeIdleConnections();
  });
}
