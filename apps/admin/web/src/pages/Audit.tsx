import { Badge, Button, Field, Select, TextInput } from "@portvakt/design-system/components";
import { DataTable, EmptyState, PageHeader } from "@portvakt/design-system/patterns";
import { useState } from "react";
import { formatDate, useI18n } from "../i18n";
import type { AuditEvent, AuditPage as Page } from "../types";
import { ActionError, useAdmin, useResource } from "../ui";

interface Filters {
  actionPrefix: string;
  actorId: string;
  subjectId: string;
  from: string;
  to: string;
  scope: "tenant" | "platform";
}

const EMPTY: Filters = {
  actionPrefix: "",
  actorId: "",
  subjectId: "",
  from: "",
  to: "",
  scope: "tenant",
};

/** The query string of an audit request (dates as the start of the day, `to` exclusive). */
export function auditQuery(filters: Filters, cursor: string | undefined, limit = 50): string {
  const params = new URLSearchParams({ limit: String(limit) });
  if (filters.actionPrefix.trim() !== "")
    params.set("actionPrefix", filters.actionPrefix.trim().toLowerCase());
  if (filters.actorId.trim() !== "") params.set("actorId", filters.actorId.trim());
  if (filters.subjectId.trim() !== "") params.set("subjectId", filters.subjectId.trim());
  if (filters.from !== "") params.set("from", new Date(`${filters.from}T00:00:00`).toISOString());
  if (filters.to !== "") {
    const end = new Date(`${filters.to}T00:00:00`);
    end.setDate(end.getDate() + 1);
    params.set("to", end.toISOString());
  }
  if (cursor !== undefined) params.set("cursor", cursor);
  return params.toString();
}

export function AuditPage() {
  const { api, tenant, me } = useAdmin();
  const { t, locale } = useI18n();
  const [draft, setDraft] = useState<Filters>(EMPTY);
  const [filters, setFilters] = useState<Filters>(EMPTY);
  const base =
    filters.scope === "platform" ? "/audit-events" : `/tenants/${tenant.id}/audit-events`;
  const key = `${base}?${auditQuery(filters, undefined)}`;
  const first = useResource(() => api.get<Page>(key), key);
  // Older pages fetched with "show more", for the current filters only.
  const [more, setMore] = useState<{
    readonly key: string;
    readonly items: readonly AuditEvent[];
    readonly cursor: string | null;
  }>({ key: "", items: [], cursor: null });
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<unknown>();
  const extra = more.key === key ? more : undefined;
  const events = [...(first.data?.items ?? []), ...(extra?.items ?? [])];
  const cursor = extra === undefined ? (first.data?.nextCursor ?? null) : extra.cursor;

  const loadMore = async (from: string) => {
    setLoadingMore(true);
    setError(undefined);
    try {
      const page = await api.get<Page>(`${base}?${auditQuery(filters, from)}`);
      setMore({ key, items: [...(extra?.items ?? []), ...page.items], cursor: page.nextCursor });
    } catch (failure) {
      setError(failure);
    } finally {
      setLoadingMore(false);
    }
  };
  const loading = first.loading || loadingMore;

  const set = (key: keyof Filters, value: string) => setDraft({ ...draft, [key]: value });
  return (
    <>
      <PageHeader title={t.audit.title} description={t.audit.description} />
      <form
        className="pv-filters"
        data-testid="audit-filters"
        onSubmit={(event) => {
          event.preventDefault();
          setFilters(draft);
        }}
      >
        <Field label={t.audit.filterAction}>
          <TextInput
            value={draft.actionPrefix}
            placeholder="login"
            data-testid="filter-action"
            onChange={(event) => set("actionPrefix", event.target.value)}
          />
        </Field>
        <Field label={t.audit.filterActor}>
          <TextInput
            value={draft.actorId}
            onChange={(event) => set("actorId", event.target.value)}
          />
        </Field>
        <Field label={t.audit.filterSubject}>
          <TextInput
            value={draft.subjectId}
            onChange={(event) => set("subjectId", event.target.value)}
          />
        </Field>
        <Field label={t.audit.filterFrom}>
          <TextInput
            type="date"
            value={draft.from}
            onChange={(event) => set("from", event.target.value)}
          />
        </Field>
        <Field label={t.audit.filterTo}>
          <TextInput
            type="date"
            value={draft.to}
            onChange={(event) => set("to", event.target.value)}
          />
        </Field>
        {me.platform && (
          <Field label={t.nav.tenantSwitcher}>
            <Select value={draft.scope} onChange={(event) => set("scope", event.target.value)}>
              <option value="tenant">{tenant.name}</option>
              <option value="platform">{t.audit.allTenants}</option>
            </Select>
          </Field>
        )}
        <div className="pv-filter-actions">
          <Button type="submit" data-testid="apply-filters">
            {t.audit.applyFilters}
          </Button>
          <Button
            variant="ghost"
            onClick={() => {
              setDraft(EMPTY);
              setFilters(EMPTY);
            }}
          >
            {t.audit.clearFilters}
          </Button>
        </div>
      </form>
      <ActionError error={error ?? first.error} />
      <DataTable
        caption={t.audit.title}
        density="compact"
        loading={first.loading && events.length === 0}
        rows={[...events]}
        rowKey={(event) => event.id}
        empty={<EmptyState compact icon="bell" title={t.audit.empty} />}
        columns={[
          {
            key: "time",
            header: t.audit.time,
            cell: (event) => formatDate(event.occurredAt, locale, true),
          },
          {
            key: "action",
            header: t.audit.action,
            cell: (event) => (
              <code className="pv-code-inline" data-testid="audit-action">
                {event.action}
              </code>
            ),
          },
          {
            key: "outcome",
            header: t.audit.outcome,
            cell: (event) => (
              <Badge color={event.outcome === "success" ? "success" : "danger"}>
                {t.audit.outcomes[event.outcome]}
              </Badge>
            ),
          },
          {
            key: "actor",
            header: t.audit.actor,
            cell: (event) =>
              `${event.actor.type}${event.actor.id === null ? "" : ` ${event.actor.id.slice(0, 8)}`}`,
          },
          {
            key: "subject",
            header: t.audit.subject,
            cell: (event) =>
              event.subject === null
                ? "–"
                : `${event.subject.type} ${event.subject.id.slice(0, 8)}`,
          },
          {
            key: "details",
            header: t.audit.details,
            cell: (event) => (
              <code className="pv-code-inline pv-details">{JSON.stringify(event.details)}</code>
            ),
          },
        ]}
        footer={
          cursor === null ? undefined : (
            <Button
              variant="secondary"
              loading={loading}
              disabled={loading}
              data-testid="audit-more"
              onClick={() => void loadMore(cursor)}
            >
              {t.common.showMore}
            </Button>
          )
        }
      />
    </>
  );
}
