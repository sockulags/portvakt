import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { metricsHandler, outsideRequest } from "@portvakt/http-kit";
import express, { Router, type Express } from "express";
import type { Pool } from "pg";
import { adminApiRouter } from "./admin/api/index.js";
import { runBootstrap, type BootstrapResult } from "./admin/bootstrap.js";
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
import { RequestLimits } from "./http/rate-limits.js";
import { registerCollectors } from "./metrics/collectors.js";
import { MetricRegistry } from "./metrics/registry.js";
import { OutboundGuard } from "./net/outbound.js";
import { LOGIN_UI_BASE, LOGIN_UI_HEADERS, LoginUiShell, localeHints } from "./login/ui-shell.js";
import { AcrRanking } from "./oidc/acr.js";
import { ChangeListener } from "./oidc/change-listener.js";
import { createInteractionService, type InteractionService } from "./oidc/interactions.js";
import { createProviderPages } from "./oidc/pages.js";
import { buildTenantProvider } from "./oidc/provider.js";
import { ProviderRegistry } from "./oidc/registry.js";
import { tenantOf, tenantRoutes } from "./oidc/routes.js";
import { CHANGE_CHANNEL } from "./repositories/change-events.js";
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
  /** The metrics registry served at `/metrics` (Prometheus text format). */
  readonly metrics: MetricRegistry;
  /** The rate limits of this replica (RATE_LIMIT_*). */
  readonly limits: RequestLimits;
  /** First-start bootstrap (also run by `start()`); does nothing once a tenant exists. */
  readonly bootstrap: () => Promise<BootstrapResult>;
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
   * Serves `/metrics` alone on a port of its own (METRICS_PORT), closed by shutdown; behind
   * METRICS_TOKEN when set.
   */
  listenMetrics(port: number, host?: string): Promise<Server>;
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
  const metrics = new MetricRegistry({ prefix: "portvakt" });
  const limits = new RequestLimits(config.rateLimits, metrics);
  const keyCache = new SigningKeyCache(repos.signingKeys);
  const stopCollectors = registerCollectors(metrics, {
    pool,
    repos,
    saml: new SamlRepository(db, keys.secrets),
    keyCache,
  });
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
        metrics,
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
    onChange: async () => {
      await reloadKeys();
      await scheduleActivation();
    },
    auditLog,
  });
  const interactions = createInteractionService(repos, auditLog);
  const outbound = new OutboundGuard({
    production: config.isProduction,
    allowPrivateHosts: config.federation.allowPrivateUpstreamHosts,
    timeoutSeconds: config.federation.upstreamTimeoutSeconds,
    metrics,
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
    auditLog,
  });
  const repositoryOptions = {
    maxSessionSeconds: config.tokens.sessionSeconds,
    acrRanking: config.acrRanking,
  };
  const adminApi = adminApiRouter({
    config,
    db,
    keys,
    repos,
    repositoryOptions,
    keyCache,
    rotation,
    saml: federation.saml,
    samlAdmin,
    auditLog,
    outbound,
    logger,
    limits,
  });
  const bootstrap = (): Promise<BootstrapResult> =>
    runBootstrap({ config, db, keys, repositoryOptions, auditLog, outbound, logger });

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
        await scheduleActivation();
        return;
    }
  };
  /** Created at start, on the channel the pool's connections notify on (tests: per schema). */
  let listener: ChangeListener | undefined;
  const createListener = (channel: string): ChangeListener =>
    new ChangeListener({
      url: options.listenUrl ?? config.database.url,
      logger,
      onEvent,
      channel,
      onResync: async () => {
        await reloadKeys();
        await scheduleActivation();
        registry.invalidateAll();
      },
    });

  /**
   * A manual rotation schedules the next key's activation (KEY_MANUAL_PUBLISH_AHEAD): every
   * replica runs the rotation job at that time (the advisory lock lets one of them do it), so
   * activation does not wait for KEY_ROTATION_CHECK_INTERVAL. Re-armed whenever the keys change.
   */
  let activationTimer: NodeJS.Timeout | undefined;
  const scheduleActivation = async (): Promise<void> => {
    if (draining) return;
    const at = await rotation.scheduledActivation();
    if (activationTimer !== undefined) clearTimeout(activationTimer);
    activationTimer = undefined;
    if (at === null) return;
    // At most a day ahead (setTimeout's range); the periodic check covers anything later.
    // Overdue (another replica holds the lock, or the clocks differ): try again in a second.
    const delay = Math.min(Math.max(1000, at.getTime() - Date.now() + 250), 86_400_000);
    // Armed while handling the rotation request: the job's log lines are not that request's.
    activationTimer = outsideRequest(() =>
      setTimeout(() => {
        activationTimer = undefined;
        jobs
          .rotateKeys()
          .then(() => scheduleActivation())
          .catch((error: unknown) => {
            logger.error({ err: error }, "scheduled key activation failed");
          });
      }, delay),
    );
    activationTimer.unref();
  };

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
      // The lock only elects one replica; the refreshes run on the pool, outside its transaction,
      // which therefore stays idle for as long as the refreshes take (each request is bounded by
      // UPSTREAM_TIMEOUT): DATABASE_IDLE_IN_TRANSACTION_TIMEOUT must not end it.
      const result = await runExclusive(
        db,
        JOB_LOCKS.samlMetadataRefresh,
        { wait: false, idleInTransactionTimeoutSeconds: 0 },
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

  const scrape = metricsHandler(metrics, { token: config.metrics.token });
  const app = createApp({
    logger,
    trustProxy: config.trustProxy,
    readiness,
    isDraining: () => closing,
    hsts: config.publicUrl.startsWith("https://"),
    maxUrlLength: config.http.maxUrlLength,
    metrics,
    // On the main port only without a port of its own; production requires METRICS_TOKEN then.
    ...(config.metrics.enabled && config.metrics.port === undefined
      ? { metricsEndpoint: scrape }
      : {}),
    routes: [
      adminApi,
      loginUiAssets(shell.dir, config.isProduction),
      samlAssetRoutes(),
      tenantRoutes({
        registry,
        interactions,
        logger,
        testRoutes,
        publicUrl: config.publicUrl,
        limits,
        rateLimitedPage: (req, res) => {
          res.set(LOGIN_UI_HEADERS).send(
            shell.render({
              view: "error",
              code: "rate_limited",
              locale: localeHints(req.query.ui_locales, req.get("accept-language")),
            }),
          );
        },
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
          limits,
        }),
      }),
    ],
  });

  const serve = (server: Server, handler: RequestListener = app): void => {
    applyServerLimits(server, config.http);
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
    limits,
    bootstrap,
    readiness,
    jobs,
    async start() {
      if (started) return;
      // Production serves the built login UI and refuses to start without it.
      if (config.isProduction) shell.assertBuilt();
      await rotation.ensureActiveKey();
      await reloadKeys();
      await bootstrap();
      listener = createListener(await changeChannel(db));
      await listener.start();
      await scheduleActivation();
      for (const task of tasks) task.start();
      started = true;
    },
    serve,
    async listen(port, host) {
      const server = createServer({ maxHeaderSize: config.http.maxHeaderBytes });
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
    async listenMetrics(port, host) {
      const server = createServer((req, res) => {
        if ((req.url ?? "").split("?", 1)[0] === "/metrics") scrape(req, res);
        else {
          res.statusCode = 404;
          res.end();
        }
      });
      server.requestTimeout = 10_000;
      server.headersTimeout = 10_000;
      servers.add(server);
      server.once("close", () => servers.delete(server));
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.off("error", reject);
          resolve();
        });
      });
      logger.info({ port: (server.address() as AddressInfo).port }, "metrics listening");
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
      if (activationTimer !== undefined) clearTimeout(activationTimer);
      await listener?.stop();
      stopCollectors();
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

/**
 * Timeouts of every server Portvakt serves on (HTTP_REQUEST_TIMEOUT, HTTP_HEADERS_TIMEOUT,
 * HTTP_KEEP_ALIVE_TIMEOUT): slow clients cannot hold connections open, and idle keep-alive
 * connections outlive the load balancer's (so it never reuses one Node just closed).
 */
function applyServerLimits(server: Server, limits: Config["http"]): void {
  server.requestTimeout = limits.requestTimeoutSeconds * 1000;
  server.headersTimeout = limits.headersTimeoutSeconds * 1000;
  server.keepAliveTimeout = limits.keepAliveTimeoutSeconds * 1000;
}

/**
 * The channel change notifications go to: CHANGE_CHANNEL, unless the pool's connections name
 * another one (`portvakt.change_channel`, set per schema by the test database so parallel test
 * files never see each other's events).
 */
async function changeChannel(db: ReturnType<typeof createDb>): Promise<string> {
  const [row] = await db.query<{ channel: string }>(
    "SELECT coalesce(nullif(current_setting('portvakt.change_channel', true), ''), $1) AS channel",
    [CHANGE_CHANNEL],
  );
  return row?.channel ?? CHANGE_CHANNEL;
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
