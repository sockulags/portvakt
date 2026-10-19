import { LOGIN_UI_BASE } from "../login/ui-shell.js";

/**
 * Route templates for metrics: the path with tenant slugs, ids and asset names replaced by
 * placeholders, so labels never carry ids, tenant-chosen text or anything a client made up.
 * Unknown paths are `other`.
 */
const SEGMENT = "[^/]+";

const TENANT_PATTERNS: readonly (readonly [string, string])[] = [
  ["/.well-known/openid-configuration", "/.well-known/openid-configuration"],
  ["/jwks", "/jwks"],
  ["/auth", "/auth"],
  [`/auth/${SEGMENT}`, "/auth/{uid}"],
  ["/request", "/request"],
  ["/token", "/token"],
  ["/token/introspection", "/token/introspection"],
  ["/token/revocation", "/token/revocation"],
  ["/session/end", "/session/end"],
  ["/session/end/confirm", "/session/end/confirm"],
  ["/session/end/success", "/session/end/success"],
  [`/interaction/${SEGMENT}`, "/interaction/{uid}"],
  [`/interaction/${SEGMENT}/(details|login|abort|representation)`, "/interaction/{uid}/$1"],
  [`/interaction/${SEGMENT}/federation/complete`, "/interaction/{uid}/federation/complete"],
  [`/interaction/${SEGMENT}/__test__/login`, "/interaction/{uid}/__test__/login"],
  [`/federation/${SEGMENT}/(callback|jwks)`, "/federation/{loginMethodId}/$1"],
  [`/saml/${SEGMENT}/(metadata|post|logout|acs|slo)`, "/saml/{loginMethodId}/$1"],
  ["/login/error", "/login/error"],
];

const TENANT_ROUTES = TENANT_PATTERNS.map(
  ([pattern, template]) => [new RegExp(`^${pattern}/?$`), template] as const,
);

const FIXED = new Set(["/healthz", "/readyz", "/metrics", "/ui/saml/autosubmit.js"]);

export function routeTemplate(path: string): string {
  if (FIXED.has(path)) return path;
  if (path.startsWith(LOGIN_UI_BASE)) return `${LOGIN_UI_BASE}{asset}`;
  if (path.startsWith("/admin/api/v1/")) return "/admin/api/v1/{other}";
  const tenant = /^\/t\/[^/]+(\/.*)?$/.exec(path);
  if (tenant === null) return "other";
  const rest = tenant[1] ?? "";
  if (rest === "" || rest === "/") return "/t/{slug}";
  for (const [pattern, template] of TENANT_ROUTES) {
    const match = pattern.exec(rest);
    if (match !== null) return `/t/{slug}${template.replace("$1", () => match[1] ?? "")}`;
  }
  return "/t/{slug}/{other}";
}
