import { registerProcessMetrics, type Sample } from "@portvakt/http-kit";
import type { Pool } from "pg";
import type { SigningKeyCache } from "../keys/key-cache.js";
import type { Repositories } from "../repositories/index.js";
import type { SamlRepository } from "../repositories/saml.js";
import type { MetricRegistry } from "./registry.js";

export interface CollectorSources {
  readonly pool: Pool;
  readonly repos: Repositories;
  readonly saml: SamlRepository;
  readonly keyCache: SigningKeyCache;
}

const seconds = (date: Date): number => Math.round(date.getTime() / 1000);

/**
 * Metrics read at scrape time: process figures, the runtime pool, signing keys (states, ages,
 * a scheduled activation) and SAML metadata freshness. Key ids and login method ids are
 * configuration ids, tenant slugs the tenant's own handle: no personal data. Returns a function
 * stopping the process metrics' event loop monitor.
 */
export function registerCollectors(metrics: MetricRegistry, sources: CollectorSources): () => void {
  const stop = registerProcessMetrics(metrics);
  const { pool, repos, saml, keyCache } = sources;

  metrics.collect(
    "portvakt_db_pool_connections",
    "Runtime pool connections by state",
    "gauge",
    () => [
      { labels: { state: "total" }, value: pool.totalCount },
      { labels: { state: "idle" }, value: pool.idleCount },
      { labels: { state: "waiting" }, value: pool.waitingCount },
    ],
  );

  // Published keys (next, active, retiring) from the database, which every replica converges to.
  const published = () => repos.signingKeys.listPublished();
  metrics.collect(
    "portvakt_signing_key_age_seconds",
    "Seconds since each published signing key was created, by kid and state",
    "gauge",
    async () => {
      const now = Date.now();
      return (await published()).map((key) => ({
        labels: { kid: key.kid, state: key.state },
        value: Math.round((now - key.createdAt.getTime()) / 1000),
      }));
    },
  );
  metrics.collect(
    "portvakt_signing_key_state_since_seconds",
    "When each published signing key entered its current state (Unix time)",
    "gauge",
    async () =>
      (await published()).map((key) => ({
        labels: { kid: key.kid, state: key.state },
        value: seconds(
          (key.state === "active"
            ? key.activatedAt
            : key.state === "retiring"
              ? key.retiringAt
              : null) ?? key.createdAt,
        ),
      })),
  );
  metrics.collect(
    "portvakt_signing_key_activation_scheduled_seconds",
    "When the pending next key becomes active (Unix time; manual rotation)",
    "gauge",
    async () =>
      (await published()).flatMap((key): Sample[] =>
        key.state === "next" && key.activateAt !== null
          ? [{ labels: { kid: key.kid }, value: seconds(key.activateAt) }]
          : [],
      ),
  );
  metrics.collect(
    "portvakt_signing_keys_loaded",
    "Keys this replica signs and verifies with, by state (0 before the first load)",
    "gauge",
    () => {
      const counts = { next: 0, active: 0, retiring: 0 };
      for (const key of keyCache.current?.kids ?? []) {
        if (key.state in counts) counts[key.state as keyof typeof counts] += 1;
      }
      return Object.entries(counts).map(([state, value]) => ({ labels: { state }, value }));
    },
  );

  const metadata = () => saml.metadataStatus();
  metrics.collect(
    "portvakt_saml_metadata_age_seconds",
    "Seconds since the cached IdP metadata of each enabled SAML login method was refreshed",
    "gauge",
    async () => {
      const now = Date.now();
      return (await metadata()).flatMap((entry): Sample[] =>
        entry.cachedAt === null
          ? []
          : [
              {
                labels: { login_method: entry.loginMethodId, tenant: entry.tenantSlug },
                value: Math.round((now - entry.cachedAt.getTime()) / 1000),
              },
            ],
      );
    },
  );
  metrics.collect(
    "portvakt_saml_metadata_valid_until_seconds",
    "validUntil of the cached IdP metadata (Unix time), when the metadata names one",
    "gauge",
    async () =>
      (await metadata()).flatMap((entry): Sample[] =>
        entry.validUntil === null
          ? []
          : [
              {
                labels: { login_method: entry.loginMethodId, tenant: entry.tenantSlug },
                value: seconds(entry.validUntil),
              },
            ],
      ),
  );
  metrics.collect(
    "portvakt_saml_metadata_refresh_failing",
    "1 while the last metadata refresh of a SAML login method failed",
    "gauge",
    async () =>
      (await metadata()).map((entry) => ({
        labels: { login_method: entry.loginMethodId, tenant: entry.tenantSlug },
        value: entry.failing ? 1 : 0,
      })),
  );
  return stop;
}
