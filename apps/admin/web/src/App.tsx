import { Avatar, Button, Select } from "@portvakt/design-system/components";
import {
  AppShell,
  EmptyState,
  Navbar,
  SidebarNav,
  type IconName,
  type SidebarNavSection,
} from "@portvakt/design-system/patterns";
import { useCallback, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
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

/**
 * A centred page for the states before the portal itself (sign in, no access). It names the
 * document after `title`; without a visible heading of its own (`hasHeading`), the title is
 * also the page's (visually hidden) h1, so every page has one.
 */
function Gate({
  i18n,
  title,
  hasHeading = false,
  children,
  testId,
}: {
  readonly i18n: I18n;
  readonly title: string;
  readonly hasHeading?: boolean;
  readonly children: ReactNode;
  readonly testId: string;
}) {
  useEffect(() => {
    document.title = `${title} – ${i18n.t.brand}`;
  }, [title, i18n.t.brand]);
  return (
    <div className="pv-gate" data-testid={testId}>
      <div className="pv-gate-bar">
        <span className="pv-brand">{i18n.t.brand}</span>
        <LanguageToggle i18n={i18n} />
      </div>
      <main className="pv-gate-main">
        {!hasHeading && <h1 className="pv-visually-hidden">{title}</h1>}
        {children}
      </main>
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
      <Gate i18n={i18n} title={t.errors.notFound} testId="unknown-tenant">
        <EmptyState icon="alert" title={t.errors.notFound} description={t.auth.unknownTenant} />
      </Gate>
    );
  } else if (boot.state === "loading") {
    content = (
      <Gate i18n={i18n} title={t.common.loading} testId="booting">
        <Loading />
      </Gate>
    );
  } else if (boot.state === "signed_out") {
    const returnTo = `${window.location.pathname}${window.location.search}`;
    content = (
      <Gate i18n={i18n} title={t.auth.signInTitle} hasHeading testId="sign-in-page">
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
      <Gate i18n={i18n} title={t.auth.noAccessTitle} testId="no-access-page">
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
      <Gate i18n={i18n} title={t.errors.title} testId="boot-error">
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
  const portalRef = useRef<HTMLDivElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);
  const drawerId = useId();

  useEffect(() => {
    document.title = `${t.nav.pages[page]} – ${t.brand}`;
  }, [page, t]);

  // Navigation without a page load says nothing to screen readers and leaves focus on the
  // clicked item: focus moves to the new page's heading (or the content). Not at the first
  // render, and not for the tenant switcher (a select that changes while it is operated).
  const view = `${page}/${location.id ?? ""}`;
  const shownView = useRef(view);
  useEffect(() => {
    if (shownView.current === view) return;
    shownView.current = view;
    const content = contentRef.current;
    if (content === null) return;
    const heading = content.querySelector<HTMLElement>("h1");
    if (heading === null) {
      content.focus();
      return;
    }
    if (!heading.hasAttribute("tabindex")) heading.setAttribute("tabindex", "-1");
    heading.focus();
  }, [view]);

  // The design system's navbar and breadcrumbs carry fixed English labels ("Open menu",
  // "Breadcrumb", an empty "Main" navigation since the portal's links live in the sidebar).
  // They are translated here, as `Modal` completes the dialog's semantics, and kept so when
  // React re-renders them.
  useEffect(() => {
    const root = portalRef.current;
    if (root === null) return;
    const set = (element: Element, name: string, value: string) => {
      if (element.getAttribute(name) !== value) element.setAttribute(name, value);
    };
    const apply = () => {
      for (const nav of root.querySelectorAll('nav[data-ds="breadcrumbs"]')) {
        set(nav, "aria-label", t.nav.breadcrumbs);
      }
      for (const nav of root.querySelectorAll('[data-ds="navbar"] nav')) {
        set(nav, "aria-hidden", "true");
      }
      const button = root.querySelector('[data-ds="navbar"] button[aria-expanded]');
      if (button !== null) {
        const open = button.getAttribute("aria-expanded") === "true";
        set(button, "aria-label", open ? t.nav.closeMenu : t.nav.openMenu);
        set(button, "aria-controls", drawerId);
      }
    };
    apply();
    const observer = new MutationObserver(apply);
    observer.observe(root, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["aria-label", "aria-expanded", "aria-controls"],
    });
    return () => observer.disconnect();
  }, [t, drawerId]);

  // The drawer (narrow screens): focus moves into it, Escape closes it and focus returns to
  // the menu button.
  useEffect(() => {
    if (!narrow || !menuOpen) return;
    drawerRef.current?.querySelector<HTMLElement>("select, button")?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setMenuOpen(false);
      portalRef.current
        ?.querySelector<HTMLElement>('[data-ds="navbar"] button[aria-expanded]')
        ?.focus();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [narrow, menuOpen]);

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
    <div
      className="pv-portal"
      data-testid="portal"
      data-narrow={narrow || undefined}
      ref={portalRef}
    >
      <a
        className="pv-skip-link"
        href="#main-content"
        data-testid="skip-to-content"
        onClick={(event) => {
          event.preventDefault();
          contentRef.current?.focus();
        }}
      >
        {t.nav.skipToContent}
      </a>
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
          <div className="pv-drawer" id={drawerId} data-testid="nav-drawer" ref={drawerRef}>
            {sidebar}
          </div>
        )}
        <div
          className="pv-content"
          id="main-content"
          tabIndex={-1}
          ref={contentRef}
          data-testid={`page-${page}`}
        >
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
