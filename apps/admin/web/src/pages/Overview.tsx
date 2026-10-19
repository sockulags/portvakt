import { Badge, Button, Card } from "@portvakt/design-system/components";
import { EmptyState, PageHeader, StatCard } from "@portvakt/design-system/patterns";
import { format, formatDate, plural, useI18n, type Messages, type Locale } from "../i18n";
import type { Dashboard, Warning } from "../types";
import { ErrorState, useAdmin, useResource } from "../ui";

/** The text of a login method warning, in the current language. */
export function warningText(warning: Warning, t: Messages, locale: Locale): string {
  return format(t.warnings[warning.code], {
    date: formatDate(warning.expiresAt, locale),
    purpose: warning.purpose === undefined ? "" : t.warnings.purposes[warning.purpose],
  });
}

/** `2027-01-14`: short enough for a stat card in any language. */
const shortDate = (iso: string | null | undefined): string =>
  iso === null || iso === undefined ? "–" : iso.slice(0, 10);

/** Whole days from now (`87 d`): fits a stat card at any width. */
const daysUntil = (iso: string | null | undefined): string => {
  if (iso === null || iso === undefined) return "–";
  return `${Math.max(0, Math.ceil((new Date(iso).getTime() - Date.now()) / 86_400_000))} d`;
};

const EXPIRY = new Set([
  "client_secret_expiring",
  "client_secret_expired",
  "sp_certificate_expiring",
]);

export function OverviewPage() {
  const { api, tenant, go } = useAdmin();
  const { t, locale } = useI18n();
  const dashboard = useResource(
    () => api.get<Dashboard>(`/tenants/${tenant.id}/dashboard`),
    tenant.id,
  );
  const data = dashboard.data;
  const loading = dashboard.loading && data === undefined;

  return (
    <>
      <PageHeader
        title={t.overview.title}
        description={t.overview.description}
        meta={<Badge>{tenant.name}</Badge>}
      />
      {dashboard.error !== undefined ? (
        <ErrorState error={dashboard.error} onRetry={dashboard.reload} />
      ) : (
        <>
          <div className="pv-stats" data-testid="stats">
            <div data-testid="stat-logins-24h">
              <StatCard
                loading={loading}
                label={t.overview.logins24h}
                value={String(data?.logins.last24h ?? 0)}
                hint={plural(t.overview.failed24h, data?.logins.failedLast24h ?? 0)}
              />
            </div>
            <div data-testid="stat-logins-7d">
              <StatCard
                loading={loading}
                label={t.overview.logins7d}
                value={String(data?.logins.last7d ?? 0)}
              />
            </div>
            <div data-testid="stat-sessions">
              <StatCard
                loading={loading}
                label={t.overview.sessions}
                value={String(data?.activeSessions ?? 0)}
              />
            </div>
            <div data-testid="stat-methods">
              <StatCard
                loading={loading}
                label={t.overview.methods}
                value={String(data?.loginMethods.total ?? 0)}
                hint={format(t.overview.methodsHint, {
                  enabled: data?.loginMethods.enabled ?? 0,
                  total: data?.loginMethods.total ?? 0,
                })}
              />
            </div>
            <div data-testid="stat-keys">
              <StatCard
                loading={loading}
                label={t.overview.keyRotation}
                value={
                  data?.keys.nextKid !== null && data?.keys.nextKid !== undefined
                    ? t.overview.rotationPending
                    : daysUntil(data?.keys.nextScheduledRotationAt)
                }
                hint={format(t.overview.activeKey, {
                  date: shortDate(data?.keys.nextScheduledRotationAt),
                  kid: data?.keys.activeKid?.slice(0, 8) ?? "–",
                })}
              />
            </div>
          </div>

          <section className="pv-section" aria-labelledby="warnings-title">
            <h2 className="pv-section-title" id="warnings-title">
              {t.overview.warningsTitle}
            </h2>
            {loading ? null : data === undefined || data.warnings.length === 0 ? (
              <Card className="pv-card">
                <EmptyState
                  icon="inbox"
                  compact
                  title={t.overview.noWarnings}
                  description={t.overview.noWarningsBody}
                />
              </Card>
            ) : (
              <ul className="pv-warnings" data-testid="warnings">
                {data.warnings.map((warning, index) => (
                  <li
                    key={`${warning.loginMethodId}-${warning.code}-${index}`}
                    data-testid="warning-item"
                  >
                    <Card className="pv-warning">
                      <div className="pv-warning-text">
                        <Badge color={EXPIRY.has(warning.code) ? "danger" : "warning"}>
                          {warning.loginMethodName}
                        </Badge>
                        <span>{warningText(warning, t, locale)}</span>
                      </div>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => go("login-methods", warning.loginMethodId)}
                      >
                        {t.overview.openMethod}
                      </Button>
                    </Card>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </>
  );
}
