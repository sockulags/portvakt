import { Badge, Button, Card, Field, TextInput } from "@portvakt/design-system/components";
import { DataTable, EmptyState, PageHeader } from "@portvakt/design-system/patterns";
import { useState } from "react";
import { format, formatDate, plural, useI18n } from "../i18n";
import { hrefOf } from "../router";
import type { List, Person, PersonSummary } from "../types";
import { ActionError, ConfirmDialog, ErrorState, Loading, useAdmin, useResource } from "../ui";

/** A personal identity number (with or without century and separator) is searched exactly. */
export const looksLikePin = (value: string): boolean =>
  /^\d{6}(\d{2})?[-+]?\d{4}$/.test(value.trim());

export function PersonsPage() {
  const { location } = useAdmin();
  return location.id === undefined ? (
    <PersonSearch />
  ) : (
    <PersonDetail key={location.id} id={location.id} />
  );
}

function PersonSearch() {
  const { api, tenant, go } = useAdmin();
  const { t, locale } = useI18n();
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<readonly PersonSummary[] | undefined>();
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [invalid, setInvalid] = useState(false);

  const search = async () => {
    const value = query.trim();
    if (value.length < 2) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    setBusy(true);
    setError(undefined);
    try {
      const body = looksLikePin(value) ? { pin: value } : { query: value };
      const found = await api.send<List<PersonSummary>>(
        "POST",
        `/tenants/${tenant.id}/persons/search`,
        { body },
      );
      setResults(found.items);
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader title={t.persons.title} description={t.persons.description} />
      <form
        className="pv-search"
        role="search"
        onSubmit={(event) => {
          event.preventDefault();
          void search();
        }}
      >
        <Field
          label={t.persons.searchLabel}
          hint={t.persons.searchHint}
          error={invalid ? t.validation.required : undefined}
        >
          <TextInput
            type="search"
            value={query}
            autoComplete="off"
            invalid={invalid}
            data-testid="person-search"
            onChange={(event) => setQuery(event.target.value)}
          />
        </Field>
        <Button type="submit" loading={busy} disabled={busy} data-testid="person-search-submit">
          {t.common.search}
        </Button>
      </form>
      <ActionError error={error} />
      {results === undefined ? (
        <EmptyState icon="search" title={t.persons.startSearch} />
      ) : (
        <DataTable
          caption={t.persons.title}
          rows={[...results]}
          rowKey={(person) => person.id}
          empty={<EmptyState compact title={t.persons.noResults} />}
          columns={[
            {
              key: "name",
              header: t.common.name,
              cell: (person) => (
                <button
                  type="button"
                  className="pv-link-button"
                  data-testid={`person-row-${person.id}`}
                  onClick={() => go("persons", person.id)}
                >
                  {person.protectedIdentity
                    ? t.persons.protected
                    : (person.displayName ?? person.id.slice(0, 8))}
                </button>
              ),
            },
            { key: "email", header: t.methods.emailClaim, cell: (person) => person.email ?? "–" },
            {
              key: "last",
              header: t.persons.lastLogin,
              cell: (person) => formatDate(person.lastLoginAt, locale, true),
            },
          ]}
        />
      )}
    </>
  );
}

function PersonDetail({ id }: { readonly id: string }) {
  const { api, tenant, location, go } = useAdmin();
  const { t, locale } = useI18n();
  const person = useResource(
    () => api.get<Person>(`/tenants/${tenant.id}/persons/${id}`),
    `${tenant.id}-${id}`,
  );
  const [confirming, setConfirming] = useState(false);
  const [unlinking, setUnlinking] = useState<Person["identities"][number] | undefined>();
  const [deleting, setDeleting] = useState(false);
  const [ending, setEnding] = useState(false);
  const [ended, setEnded] = useState<{ sessions: number; grants: number } | undefined>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();

  if (person.error !== undefined)
    return <ErrorState error={person.error} onRetry={person.reload} />;
  const data = person.data;
  if (data === undefined) return <Loading />;
  const title = data.protectedIdentity ? t.persons.protected : (data.displayName ?? data.id);

  const clear = async () => {
    setBusy(true);
    setError(undefined);
    try {
      person.set(
        await api.send<Person>(
          "POST",
          `/tenants/${tenant.id}/persons/${id}/clear-protected-identity`,
          { etag: data.etag },
        ),
      );
      setConfirming(false);
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  const unlink = async (identityId: string) => {
    setBusy(true);
    setError(undefined);
    try {
      person.set(
        await api.send<Person>(
          "POST",
          `/tenants/${tenant.id}/persons/${id}/identities/${identityId}/unlink`,
          { etag: data.etag },
        ),
      );
      setUnlinking(undefined);
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };
  const endSessions = async () => {
    setBusy(true);
    setError(undefined);
    try {
      setEnded(
        await api.send<{ sessions: number; grants: number }>(
          "POST",
          `/tenants/${tenant.id}/persons/${id}/end-sessions`,
        ),
      );
      setEnding(false);
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await api.send("DELETE", `/tenants/${tenant.id}/persons/${id}`, { etag: data.etag });
      setDeleting(false);
      go("persons");
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };
  const only = data.identities.length <= 1;

  return (
    <>
      <PageHeader
        title={title}
        breadcrumbs={[
          { label: t.persons.title, href: hrefOf({ ...location, page: "persons", id: undefined }) },
          { label: title },
        ]}
        meta={
          <span className="pv-badges">
            {data.protectedIdentity && <Badge color="warning">{t.persons.protected}</Badge>}
            {data.email !== null && <Badge>{data.email}</Badge>}
          </span>
        }
        actions={
          <div className="pv-row-actions">
            {data.protectedIdentity && (
              <Button
                variant="secondary"
                data-testid="clear-protected"
                onClick={() => setConfirming(true)}
              >
                {t.persons.clearProtected}
              </Button>
            )}
            <Button
              variant="secondary"
              data-testid="end-sessions"
              onClick={() => {
                setError(undefined);
                setEnded(undefined);
                setEnding(true);
              }}
            >
              {t.persons.endSessions}
            </Button>
            <Button
              variant="danger"
              data-testid="delete-person"
              onClick={() => {
                setError(undefined);
                setDeleting(true);
              }}
            >
              {t.persons.deletePerson}
            </Button>
          </div>
        }
      />
      <ActionError error={error} onReload={person.reload} />
      {ended !== undefined && (
        <p className="pv-muted" role="status" data-testid="end-sessions-done">
          {format(t.persons.endSessionsDone, {
            sessions: String(ended.sessions),
            grants: String(ended.grants),
          })}
        </p>
      )}
      <section className="pv-section" aria-labelledby="identities-title">
        <h2 className="pv-section-title" id="identities-title">
          {t.persons.identities}
        </h2>
        <DataTable
          caption={t.persons.identities}
          density="compact"
          rows={[...data.identities]}
          rowKey={(identity) => identity.id}
          empty={<EmptyState compact title={t.common.nothing} />}
          columns={[
            {
              key: "method",
              header: t.roles.loginMethod,
              cell: (identity) => identity.loginMethodName ?? "–",
            },
            {
              key: "subject",
              header: t.roles.subject,
              cell: (identity) => identity.subject ?? t.persons.subjectHidden,
            },
            {
              key: "pin",
              header: t.persons.hasPin,
              cell: (identity) => (identity.hasPin ? t.common.yes : t.common.no),
            },
            {
              key: "last",
              header: t.persons.lastLogin,
              cell: (identity) => formatDate(identity.lastLoginAt, locale, true),
            },
            {
              key: "actions",
              header: t.common.actions,
              align: "end",
              cell: (identity) => (
                <Button
                  size="sm"
                  variant="ghost"
                  data-testid={`unlink-identity-${identity.id}`}
                  onClick={() => {
                    setError(undefined);
                    setUnlinking(identity);
                  }}
                >
                  {t.persons.unlink}
                </Button>
              ),
            },
          ]}
        />
      </section>
      <div className="pv-cards">
        <Card className="pv-card">
          <h2 className="pv-card-title">{t.persons.roleAssignments}</h2>
          {data.roleAssignments.length === 0 ? (
            <p className="pv-muted">{t.common.none}</p>
          ) : (
            <ul className="pv-plain-list">
              {data.roleAssignments.map((assignment) => (
                <li key={assignment.id}>
                  <Badge color="primary">{assignment.role}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card className="pv-card">
          <h2 className="pv-card-title">{t.persons.attributes}</h2>
          {data.attributeAssignments.length === 0 ? (
            <p className="pv-muted">{t.common.none}</p>
          ) : (
            <ul className="pv-plain-list">
              {data.attributeAssignments.map((attribute) => (
                <li key={attribute.id}>
                  <code className="pv-code-inline">{attribute.key}</code> {attribute.value}
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card className="pv-card">
          <h2 className="pv-card-title">{t.persons.grants}</h2>
          {data.grants.length === 0 ? (
            <p className="pv-muted">{t.common.none}</p>
          ) : (
            <ul className="pv-plain-list">
              {data.grants.map((grant) => (
                <li key={grant.id}>
                  {grant.party.displayName} <Badge>{t.representation.statuses[grant.status]}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
      {unlinking !== undefined && (
        <ConfirmDialog
          testId="unlink-identity-dialog"
          title={t.persons.unlinkTitle}
          body={only ? t.persons.unlinkOnlyBody : t.persons.unlinkBody}
          confirmLabel={only ? t.persons.deletePerson : t.persons.unlink}
          danger
          busy={busy}
          error={error}
          onCancel={() => setUnlinking(undefined)}
          onConfirm={() => {
            if (only) {
              setUnlinking(undefined);
              setDeleting(true);
            } else void unlink(unlinking.id);
          }}
        >
          <p className="pv-dialog-text">
            {unlinking.loginMethodName ?? "–"}: {unlinking.subject ?? t.persons.subjectHidden}
          </p>
        </ConfirmDialog>
      )}
      {ending && (
        <ConfirmDialog
          testId="end-sessions-dialog"
          title={format(t.persons.endSessionsTitle, { name: title })}
          body={t.persons.endSessionsBody}
          confirmLabel={t.persons.endSessions}
          danger
          busy={busy}
          error={error}
          onCancel={() => setEnding(false)}
          onConfirm={() => void endSessions()}
        />
      )}
      {deleting && (
        <ConfirmDialog
          testId="delete-person-dialog"
          title={format(t.persons.deleteTitle, { name: title })}
          body={t.persons.deleteBody}
          confirmLabel={t.persons.deletePerson}
          danger
          busy={busy}
          error={error}
          onCancel={() => setDeleting(false)}
          onConfirm={() => void remove()}
        >
          <ul className="pv-plain-list" data-testid="delete-person-impact">
            <li>
              <strong>{data.identities.length}</strong>{" "}
              {plural(t.persons.deleteImpact.identities, data.identities.length)}
            </li>
            <li>
              <strong>{data.roleAssignments.length}</strong>{" "}
              {plural(t.persons.deleteImpact.roleAssignments, data.roleAssignments.length)}
            </li>
            <li>
              <strong>{data.attributeAssignments.length}</strong>{" "}
              {plural(t.persons.deleteImpact.attributes, data.attributeAssignments.length)}
            </li>
            <li>
              <strong>{data.grants.length}</strong>{" "}
              {plural(t.persons.deleteImpact.grants, data.grants.length)}
            </li>
          </ul>
        </ConfirmDialog>
      )}
      {confirming && (
        <ConfirmDialog
          testId="clear-protected-dialog"
          title={t.persons.clearProtectedTitle}
          body={t.persons.clearProtectedBody}
          confirmLabel={t.persons.clearProtected}
          danger
          busy={busy}
          error={error}
          onCancel={() => setConfirming(false)}
          onConfirm={() => void clear()}
        />
      )}
    </>
  );
}
