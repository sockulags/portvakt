import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express, { Router, type Express } from "express";
import type { Pool } from "pg";
import { createApp, type ReadinessReport } from "./app.js";
import { AuditLog, type AuditSink } from "./audit/audit-log.js";
import type { Config } from "./config/index.js";
import { createKeyRing, type KeyRing } from "./crypto/keyring.js";
import { createDb } from "./db/database.js";
import { JOB_LOCKS, runExclusive } from "./jobs/exclusive.js";
import { PeriodicTask } from "./jobs/periodic.js";
import { SigningKeyCache } from "./keys/key-cache.js";
import { SamlLoginMethodAdmin } from "./federation/saml/admin.js";
import { FederationService } from "./federation/service.js";
import { UpstreamClients } from "./federation/upstream.js";
import { KeyRotationService, type ScheduledRotationResult } from "./keys/rotation.js";
import type { Logger } from "./logging/logger.js";
import { loginRoutes } from "./login/routes.js";
import { samlAssetRoutes } from "./login/saml-routes.js";
import { MetricRegistry } from "./metrics/registry.js";
import { OutboundGuard } from "./net/outbound.js";
import { LOGIN_UI_BASE, LoginUiShell } from "./login/ui-shell.js";
import { AcrRanking } from "./oidc/acr.js";
import { ChangeListener } from "./oidc/change-listener.js";
import { createInteractionService, type InteractionService } from "./oidc/interactions.js";
import { createProviderPages } from "./oidc/pages.js";
import { buildTenantProvider } from "./oidc/provider.js";
import { ProviderRegistry } from "./oidc/registry.js";
import { tenantOf, tenantRoutes } from "./oidc/routes.js";
import { SessionPolicyService } from "./oidc/session-policy.js";
import type { ChangeEvent } from "./repositories/change-events.js";
import { FederationStateRepository } from "./repositories/federation-states.js";
import { createRepositories, type Repositories } from "./repositories/index.js";
import { OidcPayloadRepository } from "./repositories/oidc-payloads.js";
import { RepresentationRegistry } from "./representation/registry.js";
import { InternalRepresentationSource } from "./representation/source.js";
import { SamlRepository } from "./repositories/saml.js";

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
  /** Where committed audit events are forwarded besides the table (default: nowhere). */
  readonly auditSink?: AuditSink;
}

export interface Portvakt {
  readonly app: Express;
  readonly repos: Repositories;
  readonly registry: ProviderRegistry;
  readonly keyCache: SigningKeyCache;
  /** `rotateNow` is the entry point for the admin API (M6). */
  readonly rotation: KeyRotationService;
  /** `completeLogin` finishes a login (the federation calls it). */
  readonly interactions: InteractionService;
  /** The audit event catalogue writer (append-only table, then the audit sink). */
  readonly auditLog: AuditLog;
  /** Representation sources merged per tenant (the chooser, `rep`, re-checks at refresh). */
  readonly representation: RepresentationRegistry;
  /** Upstream federation (OIDC and SAML login methods). */
  readonly federation: FederationService;
  /** Admin-facing SAML login method operations (the admin API, M6, calls these). */
  readonly samlAdmin: SamlLoginMethodAdmin;
  /** In-process counters (M8 exposes them to Prometheus). */
  readonly metrics: MetricRegistry;
  readonly readiness: () => Promise<ReadinessReport>;
  /** The scheduled jobs, runnable on demand (tests, operations). */
  readonly jobs: {
    readonly reload: () => Promise<void>;
    readonly cleanupExpired: () => Promise<number | null>;
    readonly rotateKeys: () => Promise<ScheduledRotationResult>;
    /** Refreshes due SAML IdP metadata; `null` when another replica is running it. */
    readonly refreshSamlMetadata: () => Promise<number | null>;
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
  const repos = createRepositories(db, keys, {
    maxSessionSeconds: config.tokens.sessionSeconds,
    acrRanking: config.acrRanking,
  });
  const sessionPolicy = new SessionPolicyService(config.tokens, repos.loginMethods);
  const auditLog = new AuditLog({
    audit: repos.audit,
    logger,
    ...(options.auditSink === undefined ? {} : { sink: options.auditSink }),
  });
  // v1: the internal register. Bolagsverket or Mina ombud are added here as further sources and
  // enabled per tenant (tenants.representation_sources).
  const representation = new RepresentationRegistry({
    sources: [new InternalRepresentationSource(repos.grants)],
    persons: repos.persons,
    loginMethods: repos.loginMethods,
    logger,
  });
  const acrRanking = new AcrRanking(config.acrRanking);
  const shell = new LoginUiShell({
    dir: config.loginUiDir,
    production: config.isProduction,
    logger,
  });
  const pages = createProviderPages(shell);
  const metrics = new MetricRegistry();
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
    build: (input) =>
      buildTenantProvider(input, {
        config,
        db,
        repos,
        auditLog,
        representation,
        logger,
        sessionPolicy,
        acrRanking,
        pages,
        upstreamLogout: (logout) => federation.saml.startLogout(logout),
        outbound,
      }),
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
    auditLog,
  });
  const interactions = createInteractionService(repos, auditLog);
  const outbound = new OutboundGuard({
    production: config.isProduction,
    allowPrivateHosts: config.federation.allowPrivateUpstreamHosts,
    timeoutSeconds: config.federation.upstreamTimeoutSeconds,
  });
  const upstream = new UpstreamClients({
    outbound,
    loginMethods: repos.loginMethods,
    logger,
    production: config.isProduction,
    timeoutSeconds: config.federation.upstreamTimeoutSeconds,
    metadataTtlSeconds: config.federation.metadataTtlSeconds,
    failureCacheSeconds: config.federation.failureCacheSeconds,
  });
  const federation = new FederationService({
    config,
    db,
    repos,
    auditLog,
    logger,
    upstream,
    acrRanking,
    interactions,
    metrics,
    keys,
    outbound,
  });
  const samlAdmin = new SamlLoginMethodAdmin({
    repos,
    saml: federation.saml,
    production: config.isProduction,
  });

  const onEvent = async (event: ChangeEvent): Promise<void> => {
    switch (event.type) {
      case "tenant":
      case "tenant_applications":
      case "login_methods":
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
        const result = await runExclusive(
          db,
          JOB_LOCKS.payloadCleanup,
          { wait: false },
          async (tx) =>
            (await new OidcPayloadRepository(tx).deleteExpiredBatch(CLEANUP_BATCH_SIZE)) +
            (await new FederationStateRepository(tx, keys.secrets).deleteExpiredBatch(
              CLEANUP_BATCH_SIZE,
            )) +
            (await new SamlRepository(tx, keys.secrets).deleteExpiredReplayBatch(
              CLEANUP_BATCH_SIZE,
            )),
        );
        if (!result.ran) return batch === 0 ? null : total;
        total += result.value;
        if (result.value < CLEANUP_BATCH_SIZE) break;
      }
      if (total > 0) {
        logger.info({ deleted: total }, "deleted expired oidc payloads, states and replay entries");
      }
      return total;
    },
    rotateKeys: () => rotation.runScheduled(),
    refreshSamlMetadata: async (): Promise<number | null> => {
      // The lock only elects one replica; the refreshes run on the pool, outside its transaction.
      const result = await runExclusive(
        db,
        JOB_LOCKS.samlMetadataRefresh,
        { wait: false },
        async () => federation.saml.refreshDue(),
      );
      return result.ran ? result.value : null;
    },
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
      name: "saml-metadata-refresh",
      intervalSeconds: config.intervals.samlMetadataCheckSeconds,
      run: async () => {
        await jobs.refreshSamlMetadata();
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
      loginUiAssets(shell.dir, config.isProduction),
      samlAssetRoutes(),
      tenantRoutes({
        registry,
        interactions,
        logger,
        testRoutes,
        publicUrl: config.publicUrl,
        loginRoutes: loginRoutes({
          config,
          repos,
          auditLog,
          representation,
          federation,
          interactions,
          shell,
          logger,
          tenantOf,
        }),
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
    auditLog,
    representation,
    federation,
    samlAdmin,
    metrics,
    readiness,
    jobs,
    async start() {
      if (started) return;
      // Production serves the built login UI and refuses to start without it.
      if (config.isProduction) shell.assertBuilt();
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

/**
 * The login UI's built assets (`apps/login/dist`, Vite `base` ${LOGIN_UI_BASE}). File names are
 * content-hashed, so production lets browsers cache them for a year.
 */
function loginUiAssets(dir: string, production: boolean): Router {
  const router = Router();
  // The shell is only ever served with its bootstrap block (login/ui-shell.ts), never raw.
  router.all(`${LOGIN_UI_BASE}index.html`, (_req, res) => {
    res.status(404).json({ error: "not_found" });
  });
  router.use(
    LOGIN_UI_BASE,
    express.static(dir, {
      index: false,
      fallthrough: true,
      immutable: production,
      maxAge: production ? "365d" : 0,
      setHeaders: (res) => {
        res.setHeader("X-Content-Type-Options", "nosniff");
      },
    }),
  );
  return router;
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
