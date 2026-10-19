import { useCallback, useEffect, useState } from "react";

/** The portal's pages (URL paths below `/t/{slug}/`). */
export const PAGES = [
  "overview",
  "tenants",
  "applications",
  "login-methods",
  "roles",
  "persons",
  "representation",
  "keys",
  "audit",
] as const;
export type Page = (typeof PAGES)[number];

export interface Location {
  /** The tenant whose issuer the administrator signed in through. */
  readonly slug: string;
  readonly page: Page;
  /** A sub-resource: `new-oidc` / `new-saml`, or an id (login method, person). */
  readonly id: string | undefined;
  /** Platform administrators: the tenant being administered (`?tenant=` id). */
  readonly tenant: string | undefined;
}

const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ID = /^(?:new-oidc|new-saml|[0-9a-f-]{36})$/;

/** Parses `/t/{slug}/{page}/{id}?tenant=`; `undefined` outside the portal's paths. */
export function parseLocation(pathname: string, search: string): Location | undefined {
  const parts = pathname.split("/").filter((part) => part !== "");
  if (parts[0] !== "t" || parts[1] === undefined || !SLUG.test(parts[1])) return undefined;
  const page = (PAGES as readonly string[]).includes(parts[2] ?? "")
    ? (parts[2] as Page)
    : "overview";
  const id = parts[3] !== undefined && ID.test(parts[3]) ? parts[3] : undefined;
  const tenant = new URLSearchParams(search).get("tenant") ?? undefined;
  return {
    slug: parts[1],
    page,
    id,
    tenant: tenant !== undefined && /^[0-9a-f-]{36}$/.test(tenant) ? tenant : undefined,
  };
}

/** The URL of a location. */
export function hrefOf(location: Location): string {
  const segments = [
    "t",
    location.slug,
    ...(location.page === "overview" ? [] : [location.page]),
    ...(location.id === undefined ? [] : [location.id]),
  ];
  const path = `/${segments.join("/")}${location.page === "overview" ? "/" : ""}`;
  return location.tenant === undefined ? path : `${path}?tenant=${location.tenant}`;
}

/** The current location, and navigation through the history API (no full reload). */
export function useLocation(): [Location | undefined, (next: Location) => void] {
  const read = () => parseLocation(window.location.pathname, window.location.search);
  const [location, setLocation] = useState(read);
  useEffect(() => {
    const onPop = () => setLocation(read());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);
  const navigate = useCallback((next: Location) => {
    window.history.pushState(null, "", hrefOf(next));
    setLocation(next);
    window.scrollTo?.(0, 0);
  }, []);
  return [location, navigate];
}
