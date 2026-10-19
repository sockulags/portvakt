/**
 * The server's metrics: the shared registry of `@portvakt/http-kit` (Prometheus text format),
 * served at `/metrics` (`metrics/endpoint.ts`). Label values never carry personal data or
 * tenant-controlled free text: reason codes, route templates, status codes, grant types and
 * configuration ids (login method ids, tenant slugs) only.
 */
export { Counter, Gauge, Histogram, MetricRegistry, type Labels } from "@portvakt/http-kit";

/** Metric names used across the server. */
export const METRICS = {
  /** Upstream callbacks refused before any interaction is known (unknown or foreign state). */
  federationCallbackRejected: "portvakt_federation_callback_rejected_total",
  /** SAML IdP metadata refreshes (`outcome` success or failure, `reason` of a failure). */
  samlMetadataRefresh: "portvakt_saml_metadata_refresh_total",
  /** SAML single logout messages (`direction`, `outcome`). */
  samlLogout: "portvakt_saml_logout_total",
  /** Finished logins (`outcome` success or failure, `reason`, `protocol` oidc, saml or none). */
  logins: "portvakt_logins_total",
  /** Token endpoint successes (`grant_type`, `tenant` slug). */
  tokensIssued: "portvakt_tokens_issued_total",
  /** Requests refused by a rate limit (`limit`). */
  rateLimited: "portvakt_rate_limited_total",
  /** Requests to upstream IdPs and configured URLs (`login_method`, `purpose`, `outcome`). */
  upstreamDuration: "portvakt_upstream_request_duration_seconds",
  /** Failed upstream requests (`login_method`, `purpose`, `reason`). */
  upstreamFailures: "portvakt_upstream_request_failures_total",
} as const;
