import { Avatar, Button, Select } from "@portvakt/design-system/components";
import {
  AppShell,
  EmptyState,
  Navbar,
  SidebarNav,
  type IconName,
  type SidebarNavSection,
} from "@portvakt/design-system/patterns";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { ApiError, createApi, type ApiClient } from "./api";
import {
  format,
  I18nContext,
  LOCALES,
  MESSAGES,
  pickLocale,
  storedLocale,
  storeLocale,
  type I18n,
  type Locale,
} from "./i18n";
import { ApplicationsPage } from "./pages/Applications";
import { AuditPage } from "./pages/Audit";
import { KeysPage } from "./pages/Keys";
import { LoginMethodsPage } from "./pages/LoginMethods";
import { OverviewPage } from "./pages/Overview";
import { PersonsPage } from "./pages/Persons";
import { RepresentationPage } from "./pages/Representation";
import { RolesPage } from "./pages/Roles";
import { TenantsPage } from "./pages/Tenants";
import { useLocation, type Location, type Page } from "./router";
import type { List, Me, SessionInfo, Tenant } from "./types";
import { AdminContext, ErrorState, Loading, useAdmin, type Admin } from "./ui";

const ICONS: Record<Page, IconName> = {
  overview: "home",
  tenants: "folder",
  applications: "inbox",
  "login-methods": "settings",
  roles: "users",
  persons: "search",
  representation: "file",
  keys: "chart",
  audit: "bell",
};

const TENANT_PAGES: readonly Page[] = [
  "overview",
  "applications",
  "login-methods",
  "roles",
  "persons",
  "representation",
  "audit",
];

/** Narrow screens (phones): the navigation moves behind a menu button. */
function useNarrow(): boolean {
  const query = "(max-width: 767px)";
  const [narrow, setNarrow] = useState(() => window.matchMedia?.(query).matches ?? false);
  useEffect(() => {
    const media = window.matchMedia?.(query);
    if (media === undefined) return;
    const onChange = () => setNarrow(media.matches);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);
  return narrow;
}

function useI18nState(): I18n {
  const [locale, setLocaleState] = useState<Locale>(() => pickLocale(storedLocale()));
  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);
  return useMemo(
    () => ({
      locale,
      t: MESSAGES[locale],
      setLocale: (next: Locale) => {
        storeLocale(next);
        setLocaleState(next);
      },
    }),
    [locale],
  );
}

function LanguageToggle({ i18n }: { readonly i18n: I18n }) {
  const other = LOCALES.find((candidate) => candidate !== i18n.locale) ?? i18n.locale;
  return (
    <Button
      variant="ghost"
      size="sm"
      lang={other}
      aria-label={MESSAGES[other].switchLanguage}
      data-testid="language-toggle"
      onClick={() => i18n.setLocale(other)}
    >
      {MESSAGES[other].languageName}
    </Button>
  );
}

/** A centred page for the states before the portal itself (sign in, no access). */
function Gate({
  i18n,
  children,
  testId,
}: {
  readonly i18n: I18n;
  readonly children: ReactNode;
  readonly testId: string;
}) {
  return (
    <div className="pv-gate" data-testid={testId}>
      <div className="pv-gate-bar">
        <span className="pv-brand">{i18n.t.brand}</span>
        <LanguageToggle i18n={i18n} />
      </div>
      <main className="pv-gate-main">{children}</main>
    </div>
  );
}

type Boot =
  | { readonly state: "loading" }
  | { readonly state: "signed_out" }
  | { readonly state: "no_access" }
  | { readonly state: "error"; readonly error: unknown }
  | {
      readonly state: "ready";
      readonly session: SessionInfo;
      readonly me: Me;
      readonly tenants: readonly Tenant[];
    };

export function App() {
  const i18n = useI18nState();
  const [location, navigate] = useLocation();
  const slug = location?.slug;
  const api = useMemo(() => (slug === undefined ? undefined : createApi(slug)), [slug]);
  const [boot, setBoot] = useState<Boot>({ state: "loading" });

  const load = useCallback(async (client: ApiClient): Promise<Boot> => {
    try {
      const session = await client.session();
      if (!session.authenticated) return { state: "signed_out" };
      const me = await client.get<Me>("/me");
      // The system tenant is administered by platform administrators only.
      if (!me.platform && me.tenant.slug === "system") return { state: "no_access" };
      const tenants = me.platform
        ? (await client.get<List<Tenant>>("/tenants")).items
        : [me.tenant];
      return { state: "ready", session, me, tenants };
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) return { state: "signed_out" };
      if (error instanceof ApiError && error.status === 403) return { state: "no_access" };
      return { state: "error", error };
    }
  }, []);

  useEffect(() => {
    if (api === undefined) return;
    let current = true;
    void load(api).then((next) => {
      if (current) setBoot(next);
    });
    return () => {
      current = false;
    };
  }, [api, load]);

  const reloadTenants = useCallback(async () => {
    if (api === undefined || boot.state !== "ready") return;
    const tenants = boot.me.platform
      ? (await api.get<List<Tenant>>("/tenants")).items
      : [boot.me.tenant];
    setBoot({ ...boot, tenants });
  }, [api, boot]);

  const { t } = i18n;
  let content: ReactNode;
  if (location === undefined || api === undefined) {
    content = (
      <Gate i18n={i18n} testId="unknown-tenant">
        <EmptyState icon="alert" title={t.errors.notFound} description={t.auth.unknownTenant} />
      </Gate>
    );
  } else if (boot.state === "loading") {
    content = (
      <Gate i18n={i18n} testId="booting">
        <Loading />
      </Gate>
    );
  } else if (boot.state === "signed_out") {
    const returnTo = `${window.location.pathname}${window.location.search}`;
    content = (
      <Gate i18n={i18n} testId="sign-in-page">
        <h1 className="pv-gate-title">{t.auth.signInTitle}</h1>
        <p className="pv-gate-text">{format(t.auth.signInBody, { tenant: location.slug })}</p>
        <Button
          size="lg"
          data-testid="sign-in"
          onClick={() =>
            window.location.assign(
              `/t/${location.slug}/auth/login?${new URLSearchParams({ returnTo }).toString()}`,
            )
          }
        >
          {t.auth.signIn}
        </Button>
      </Gate>
    );
  } else if (boot.state === "no_access") {
    content = (
      <Gate i18n={i18n} testId="no-access-page">
        <EmptyState
          icon="alert"
          title={t.auth.noAccessTitle}
          description={t.auth.noAccessBody}
          actions={
            <Button variant="secondary" onClick={() => void api.logout()} data-testid="sign-out">
              {t.nav.signOut}
            </Button>
          }
        />
      </Gate>
    );
  } else if (boot.state === "error") {
    content = (
      <Gate i18n={i18n} testId="boot-error">
        <ErrorState error={boot.error} onRetry={() => void load(api).then(setBoot)} />
      </Gate>
    );
  } else {
    const targetId = boot.me.platform ? (location.tenant ?? boot.me.tenant.id) : boot.me.tenant.id;
    const tenant = boot.tenants.find((item) => item.id === targetId) ?? boot.me.tenant;
    const admin: Admin = {
      api,
      me: boot.me,
      tenant,
      tenants: boot.tenants,
      location,
      go: (page, id) => navigate({ ...location, page, id }),
      reloadTenants,
    };
    content = (
      <AdminContext.Provider value={admin}>
        <Portal i18n={i18n} session={boot.session} onNavigate={navigate} />
      </AdminContext.Provider>
    );
  }
  return <I18nContext.Provider value={i18n}>{content}</I18nContext.Provider>;
}

function initials(name: string | undefined): string {
  if (name === undefined || name.trim() === "") return "?";
  return name
    .trim()
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");
}

function Portal({
  i18n,
  session,
  onNavigate,
}: {
  readonly i18n: I18n;
  readonly session: SessionInfo;
  readonly onNavigate: (location: Location) => void;
}) {
  const admin = useAdmin();
  const { t } = i18n;
  const narrow = useNarrow();
  const [menuOpen, setMenuOpen] = useState(false);
  const { location, me } = admin;
  const page = location.page;

  useEffect(() => {
    document.title = `${t.nav.pages[page]} – ${t.brand}`;
  }, [page, t]);

  const sections: SidebarNavSection[] = [
    {
      title: t.nav.sectionTenant,
      items: TENANT_PAGES.map((id) => ({ id, label: t.nav.pages[id], icon: ICONS[id] })),
    },
    {
      title: t.nav.sectionPlatform,
      items: [
        ...(me.platform
          ? [{ id: "tenants", label: t.nav.pages.tenants, icon: ICONS.tenants }]
          : []),
        { id: "keys", label: t.nav.pages.keys, icon: ICONS.keys },
      ],
    },
  ];
  const go = (id: string) => {
    setMenuOpen(false);
    admin.go(id as Page);
  };
  const name = session.principal?.name;

  const switcher =
    me.platform && admin.tenants.length > 1 ? (
      <label className="pv-switcher">
        <span className="pv-visually-hidden">{t.nav.tenantSwitcher}</span>
        <Select
          data-testid="tenant-switcher"
          aria-label={t.nav.tenantSwitcher}
          value={admin.tenant.id}
          onChange={(event) => {
            setMenuOpen(false);
            onNavigate({ ...location, id: undefined, tenant: event.target.value });
          }}
        >
          {admin.tenants.map((item) => (
            <option key={item.id} value={item.id}>
              {item.name} ({item.slug})
            </option>
          ))}
        </Select>
      </label>
    ) : (
      <span className="pv-tenant-name" data-testid="tenant-name">
        {admin.tenant.name}
      </span>
    );

  const footer = (
    <div className="pv-user">
      <Avatar initials={initials(name)} />
      {/* A plain span cannot carry aria-label (ARIA prohibits naming the generic role): the
          full "Inloggad som ..." is visually hidden text, the short visible name is hidden from
          screen readers so it is not read twice. */}
      <span
        className="pv-user-name"
        title={format(t.nav.signedInAs, { name: name ?? me.personId })}
      >
        <span className="pv-visually-hidden">
          {format(t.nav.signedInAs, { name: name ?? me.personId })}
        </span>
        <span aria-hidden="true">{name ?? me.personId.slice(0, 8)}</span>
      </span>
      <Button
        variant="ghost"
        size="sm"
        data-testid="sign-out"
        onClick={() => void admin.api.logout()}
      >
        {t.nav.signOut}
      </Button>
    </div>
  );

  const sidebar = (
    <SidebarNav
      label={t.nav.label}
      sections={sections.map((section) => ({
        ...section,
        items: section.items.map((item) => ({ ...item })),
      }))}
      active={page}
      onNavigate={go}
      header={switcher}
      footer={footer}
    />
  );

  return (
    <div className="pv-portal" data-testid="portal" data-narrow={narrow || undefined}>
      <AppShell
        navbar={
          <Navbar
            brand={<span className="pv-brand">{t.brand}</span>}
            links={[]}
            compact={narrow}
            menuOpen={menuOpen}
            onMenuToggle={() => setMenuOpen((open) => !open)}
            actions={<LanguageToggle i18n={i18n} />}
          />
        }
        sidebar={narrow ? undefined : sidebar}
      >
        {narrow && menuOpen && (
          <div className="pv-drawer" data-testid="nav-drawer">
            {sidebar}
          </div>
        )}
        <div className="pv-content" data-testid={`page-${page}`}>
          <PageContent page={page} />
        </div>
      </AppShell>
    </div>
  );
}

function PageContent({ page }: { readonly page: Page }) {
  const admin = useAdmin();
  switch (page) {
    case "overview":
      return <OverviewPage />;
    case "tenants":
      return admin.me.platform ? <TenantsPage /> : <OverviewPage />;
    case "applications":
      return <ApplicationsPage />;
    case "login-methods":
      return <LoginMethodsPage />;
    case "roles":
      return <RolesPage />;
    case "persons":
      return <PersonsPage />;
    case "representation":
      return <RepresentationPage />;
    case "keys":
      return <KeysPage />;
    case "audit":
      return <AuditPage />;
  }
}
