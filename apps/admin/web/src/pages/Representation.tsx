import {
  Badge,
  Button,
  Checkbox,
  Field,
  Radio,
  Select,
  Switch,
  Tabs,
  TextInput,
} from "@portvakt/design-system/components";
import { DataTable, EmptyState, PageHeader } from "@portvakt/design-system/patterns";
import { useState } from "react";
import { ApiError } from "../api";
import { formatDate, useI18n } from "../i18n";
import type { Grant, List, Party, TenantApplication } from "../types";
import { ActionError, ConfirmDialog, ErrorState, Modal, useAdmin, useResource } from "../ui";

const STATUS_COLOR = {
  active: "success",
  scheduled: "info",
  expired: "neutral",
  revoked: "danger",
} as const;

export function RepresentationPage() {
  const { t } = useI18n();
  const [tab, setTab] = useState("grants");
  return (
    <>
      <PageHeader title={t.representation.title} description={t.representation.description}>
        <Tabs
          variant="underline"
          label={t.representation.title}
          value={tab}
          onChange={setTab}
          items={[
            { id: "grants", label: t.representation.grantsTab },
            { id: "parties", label: t.representation.partiesTab },
          ]}
        />
      </PageHeader>
      {tab === "grants" ? <Grants /> : <Parties />}
    </>
  );
}

function useAction(onDone: () => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [errors, setErrors] = useState<Record<string, string>>({});
  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
      setErrors({});
      onDone();
    } catch (failure) {
      setError(failure);
      if (failure instanceof ApiError) setErrors(failure.fieldErrors());
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, errors, setErrors, setError, run };
}

function Parties() {
  const { api, tenant } = useAdmin();
  const { t } = useI18n();
  const parties = useResource(
    () => api.get<List<Party>>(`/tenants/${tenant.id}/parties`),
    tenant.id,
  );
  const [editing, setEditing] = useState<Party | "new" | undefined>();
  const [draft, setDraft] = useState({
    type: "organisation" as Party["type"],
    identifier: "",
    displayName: "",
    protectedIdentity: false,
  });
  const action = useAction(() => {
    setEditing(undefined);
    parties.reload();
  });

  const save = () => {
    const found: Record<string, string> = {};
    if (draft.displayName.trim() === "") found.displayName = t.validation.required;
    if (editing === "new" && draft.identifier.trim() === "")
      found.identifier = t.validation.required;
    action.setErrors(found);
    if (Object.keys(found).length > 0) return;
    void action.run(() =>
      editing === "new"
        ? api.send("POST", `/tenants/${tenant.id}/parties`, {
            body: {
              ...draft,
              protectedIdentity: draft.type === "person" && draft.protectedIdentity,
            },
          })
        : api.send("PATCH", `/tenants/${tenant.id}/parties/${(editing as Party).id}`, {
            body: {
              displayName: draft.displayName,
              ...((editing as Party).type === "person"
                ? { protectedIdentity: draft.protectedIdentity }
                : {}),
            },
            etag: (editing as Party).etag,
          }),
    );
  };

  if (parties.error !== undefined)
    return <ErrorState error={parties.error} onRetry={parties.reload} />;
  return (
    <>
      <div className="pv-toolbar">
        <Button
          data-testid="create-party"
          onClick={() => {
            setDraft({
              type: "organisation",
              identifier: "",
              displayName: "",
              protectedIdentity: false,
            });
            action.setErrors({});
            action.setError(undefined);
            setEditing("new");
          }}
        >
          {t.representation.createParty}
        </Button>
      </div>
      <DataTable
        caption={t.representation.partiesTab}
        loading={parties.loading && parties.data === undefined}
        rows={[...(parties.data?.items ?? [])]}
        rowKey={(party) => party.id}
        empty={<EmptyState compact title={t.representation.noParties} />}
        columns={[
          { key: "name", header: t.common.name, cell: (party) => party.displayName },
          {
            key: "type",
            header: t.representation.type,
            cell: (party) => t.representation.types[party.type],
          },
          {
            key: "identifier",
            header: t.representation.identifier,
            cell: (party) =>
              party.protectedIdentity ? (
                <Badge color="warning">{t.persons.protected}</Badge>
              ) : (
                (party.identifier ?? "–")
              ),
          },
          {
            key: "actions",
            header: t.common.actions,
            align: "end",
            cell: (party) => (
              <Button
                size="sm"
                variant="ghost"
                onClick={() => {
                  setDraft({
                    type: party.type,
                    identifier: "",
                    displayName: party.displayName,
                    protectedIdentity: party.protectedIdentity,
                  });
                  action.setErrors({});
                  action.setError(undefined);
                  setEditing(party);
                }}
              >
                {t.common.edit}
              </Button>
            ),
          },
        ]}
      />
      {editing !== undefined && (
        <Modal
          title={editing === "new" ? t.representation.createParty : editing.displayName}
          onClose={() => setEditing(undefined)}
          testId="party-dialog"
          errors={action.errors}
          footer={
            <div className="pv-dialog-actions">
              <Button variant="ghost" onClick={() => setEditing(undefined)}>
                {t.common.cancel}
              </Button>
              <Button
                loading={action.busy}
                disabled={action.busy}
                onClick={save}
                data-testid="party-save"
              >
                {editing === "new" ? t.common.create : t.common.save}
              </Button>
            </div>
          }
        >
          <div className="pv-form">
            {editing === "new" && (
              <>
                <Field label={t.representation.type}>
                  <Select
                    value={draft.type}
                    onChange={(event) =>
                      setDraft({ ...draft, type: event.target.value as Party["type"] })
                    }
                  >
                    <option value="organisation">{t.representation.types.organisation}</option>
                    <option value="person">{t.representation.types.person}</option>
                  </Select>
                </Field>
                <Field label={t.representation.identifier} error={action.errors.identifier}>
                  <TextInput
                    value={draft.identifier}
                    autoComplete="off"
                    invalid={action.errors.identifier !== undefined}
                    onChange={(event) => setDraft({ ...draft, identifier: event.target.value })}
                  />
                </Field>
              </>
            )}
            <Field label={t.common.name} error={action.errors.displayName}>
              <TextInput
                value={draft.displayName}
                invalid={action.errors.displayName !== undefined}
                onChange={(event) => setDraft({ ...draft, displayName: event.target.value })}
              />
            </Field>
            {draft.type === "person" && (
              <Switch
                label={t.persons.protected}
                checked={draft.protectedIdentity}
                onChange={(event) =>
                  setDraft({ ...draft, protectedIdentity: event.target.checked })
                }
              />
            )}
            <ActionError
              error={action.error}
              onReload={() => {
                setEditing(undefined);
                parties.reload();
              }}
            />
          </div>
        </Modal>
      )}
    </>
  );
}

/** An ISO timestamp as the value of a date input (the local calendar day). */
function dateInput(iso: string | null): string {
  if (iso === null) return "";
  const date = new Date(iso);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

const isoOf = (day: string): string => new Date(`${day}T00:00:00`).toISOString();

function Grants() {
  const { api, tenant } = useAdmin();
  const { t, locale } = useI18n();
  const grants = useResource(() => api.get<List<Grant>>(`/tenants/${tenant.id}/grants`), tenant.id);
  const parties = useResource(
    () => api.get<List<Party>>(`/tenants/${tenant.id}/parties`),
    tenant.id,
  );
  const applications = useResource(
    () => api.get<List<TenantApplication>>(`/tenants/${tenant.id}/applications`),
    tenant.id,
  );
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Grant | undefined>();
  const [revoking, setRevoking] = useState<Grant | undefined>();
  const [agentKind, setAgentKind] = useState<"pin" | "person">("pin");
  const [draft, setDraft] = useState({
    partyId: "",
    pin: "",
    personId: "",
    all: true,
    applicationIds: [] as string[],
    validFrom: "",
    validTo: "",
  });
  const action = useAction(() => {
    setCreating(false);
    setEditing(undefined);
    setRevoking(undefined);
    grants.reload();
  });

  const create = () => {
    const found: Record<string, string> = {};
    if (draft.partyId === "") found.partyId = t.validation.required;
    if (agentKind === "pin" && draft.pin.trim() === "") found.pin = t.validation.required;
    if (agentKind === "person" && draft.personId.trim() === "")
      found.personId = t.validation.required;
    if (!draft.all && draft.applicationIds.length === 0)
      found.applicationIds = t.validation.required;
    action.setErrors(found);
    if (Object.keys(found).length > 0) return;
    void action.run(() =>
      api.send("POST", `/tenants/${tenant.id}/grants`, {
        body: {
          agent:
            agentKind === "pin" ? { pin: draft.pin.trim() } : { personId: draft.personId.trim() },
          partyId: draft.partyId,
          allApplications: draft.all,
          applicationIds: draft.all ? [] : draft.applicationIds,
          ...(draft.validFrom === ""
            ? {}
            : { validFrom: new Date(`${draft.validFrom}T00:00:00`).toISOString() }),
          validTo:
            draft.validTo === "" ? null : new Date(`${draft.validTo}T00:00:00`).toISOString(),
        },
      }),
    );
  };

  const update = (grant: Grant) => {
    if (!draft.all && draft.applicationIds.length === 0) {
      action.setErrors({ applicationIds: t.validation.required });
      return;
    }
    if (draft.validFrom === "") {
      action.setErrors({ validFrom: t.validation.required });
      return;
    }
    action.setErrors({});
    const sameApplications =
      draft.all === grant.allApplications &&
      (draft.all ||
        (draft.applicationIds.length === grant.applicationIds.length &&
          draft.applicationIds.every((id) => grant.applicationIds.includes(id))));
    const body = {
      ...(sameApplications
        ? {}
        : { allApplications: draft.all, applicationIds: draft.all ? [] : draft.applicationIds }),
      ...(draft.validFrom === dateInput(grant.validFrom)
        ? {}
        : { validFrom: isoOf(draft.validFrom) }),
      ...(draft.validTo === dateInput(grant.validTo)
        ? {}
        : { validTo: draft.validTo === "" ? null : isoOf(draft.validTo) }),
    };
    if (Object.keys(body).length === 0) {
      setEditing(undefined);
      return;
    }
    void action.run(() =>
      api.send("PATCH", `/tenants/${tenant.id}/grants/${grant.id}`, { body, etag: grant.etag }),
    );
  };

  const closeDialog = () => {
    setCreating(false);
    setEditing(undefined);
  };

  const error = grants.error ?? parties.error;
  if (error !== undefined) return <ErrorState error={error} onRetry={grants.reload} />;
  return (
    <>
      <div className="pv-toolbar">
        <Button
          data-testid="create-grant"
          onClick={() => {
            setDraft({
              partyId: "",
              pin: "",
              personId: "",
              all: true,
              applicationIds: [],
              validFrom: "",
              validTo: "",
            });
            action.setErrors({});
            action.setError(undefined);
            setCreating(true);
          }}
        >
          {t.representation.createGrant}
        </Button>
      </div>
      <DataTable
        caption={t.representation.grantsTab}
        loading={grants.loading && grants.data === undefined}
        rows={[...(grants.data?.items ?? [])]}
        rowKey={(grant) => grant.id}
        empty={<EmptyState compact title={t.representation.noGrants} />}
        columns={[
          {
            key: "party",
            header: t.representation.party,
            cell: (grant) => grant.party.displayName,
          },
          {
            key: "agent",
            header: t.representation.agent,
            cell: (grant) =>
              grant.agent.kind === "pin"
                ? t.representation.agentPinHidden
                : `${grant.agent.personId.slice(0, 8)}…`,
          },
          {
            key: "applications",
            header: t.representation.applications,
            cell: (grant) =>
              grant.allApplications
                ? t.representation.allApplications
                : grant.applicationIds
                    .map(
                      (id) =>
                        applications.data?.items.find((item) => item.applicationId === id)?.name ??
                        id.slice(0, 8),
                    )
                    .join(", "),
          },
          {
            key: "validity",
            header: t.representation.validTo,
            cell: (grant) =>
              `${formatDate(grant.validFrom, locale)} – ${grant.validTo === null ? "" : formatDate(grant.validTo, locale)}`,
          },
          {
            key: "status",
            header: t.common.status,
            cell: (grant) => (
              <Badge color={STATUS_COLOR[grant.status]}>
                {t.representation.statuses[grant.status]}
              </Badge>
            ),
          },
          {
            key: "actions",
            header: t.common.actions,
            align: "end",
            cell: (grant) =>
              grant.status === "revoked" ? null : (
                <div className="pv-row-actions">
                  <Button
                    size="sm"
                    variant="ghost"
                    data-testid={`edit-grant-${grant.id}`}
                    onClick={() => {
                      setDraft({
                        partyId: grant.party.id,
                        pin: "",
                        personId: "",
                        all: grant.allApplications,
                        applicationIds: [...grant.applicationIds],
                        validFrom: dateInput(grant.validFrom),
                        validTo: dateInput(grant.validTo),
                      });
                      action.setErrors({});
                      action.setError(undefined);
                      setEditing(grant);
                    }}
                  >
                    {t.common.edit}
                  </Button>
                  <Button
                    size="sm"
                    variant="danger"
                    data-testid={`revoke-grant-${grant.id}`}
                    onClick={() => setRevoking(grant)}
                  >
                    {t.representation.revoke}
                  </Button>
                </div>
              ),
          },
        ]}
      />
      {(creating || editing !== undefined) && (
        <Modal
          title={
            editing === undefined
              ? t.representation.createGrant
              : `${t.representation.editGrant}: ${editing.party.displayName}`
          }
          onClose={closeDialog}
          testId="grant-dialog"
          errors={action.errors}
          footer={
            <div className="pv-dialog-actions">
              <Button variant="ghost" onClick={closeDialog}>
                {t.common.cancel}
              </Button>
              <Button
                loading={action.busy}
                disabled={action.busy}
                onClick={() => (editing === undefined ? create() : update(editing))}
                data-testid="grant-save"
              >
                {editing === undefined ? t.common.create : t.common.save}
              </Button>
            </div>
          }
        >
          <div className="pv-form">
            {editing !== undefined && (
              <p className="pv-muted" data-testid="grant-edit-agent">
                {t.representation.agent}:{" "}
                {editing.agent.kind === "pin"
                  ? t.representation.agentPinHidden
                  : `${editing.agent.personId.slice(0, 8)}…`}
              </p>
            )}
            {editing === undefined && (
              <Field label={t.representation.party} error={action.errors.partyId}>
                <Select
                  value={draft.partyId}
                  invalid={action.errors.partyId !== undefined}
                  onChange={(event) => setDraft({ ...draft, partyId: event.target.value })}
                >
                  <option value="">–</option>
                  {parties.data?.items.map((party) => (
                    <option key={party.id} value={party.id}>
                      {party.displayName}
                    </option>
                  ))}
                </Select>
              </Field>
            )}
            {editing === undefined && (
              <fieldset className="pv-fieldset">
                <legend className="pv-legend">{t.representation.agent}</legend>
                <Radio
                  name="agent"
                  label={t.representation.agentPin}
                  checked={agentKind === "pin"}
                  onChange={() => setAgentKind("pin")}
                />
                <Radio
                  name="agent"
                  label={t.representation.agentPerson}
                  checked={agentKind === "person"}
                  onChange={() => setAgentKind("person")}
                />
              </fieldset>
            )}
            {editing === undefined && agentKind === "pin" ? (
              <Field
                label={t.representation.agentPin}
                error={action.errors.pin ?? action.errors["agent.pin"]}
              >
                <TextInput
                  invalid={(action.errors.pin ?? action.errors["agent.pin"]) !== undefined}
                  value={draft.pin}
                  autoComplete="off"
                  inputMode="numeric"
                  onChange={(event) => setDraft({ ...draft, pin: event.target.value })}
                />
              </Field>
            ) : editing === undefined ? (
              <Field
                label={t.representation.agentPerson}
                error={action.errors.personId ?? action.errors["agent.personId"]}
              >
                <TextInput
                  invalid={
                    (action.errors.personId ?? action.errors["agent.personId"]) !== undefined
                  }
                  value={draft.personId}
                  autoComplete="off"
                  onChange={(event) => setDraft({ ...draft, personId: event.target.value })}
                />
              </Field>
            ) : null}
            <Switch
              label={t.representation.allApplications}
              checked={draft.all}
              onChange={(event) => setDraft({ ...draft, all: event.target.checked })}
            />
            {!draft.all && (
              <fieldset className="pv-fieldset">
                <legend className="pv-legend">{t.representation.applications}</legend>
                {applications.data?.items.map((application) => (
                  <Checkbox
                    key={application.applicationId}
                    label={application.name}
                    checked={draft.applicationIds.includes(application.applicationId)}
                    onChange={(event) =>
                      setDraft({
                        ...draft,
                        applicationIds: event.target.checked
                          ? [...draft.applicationIds, application.applicationId]
                          : draft.applicationIds.filter((id) => id !== application.applicationId),
                      })
                    }
                  />
                ))}
                {action.errors.applicationIds !== undefined && (
                  <span className="pv-error">{action.errors.applicationIds}</span>
                )}
              </fieldset>
            )}
            <div className="pv-inline-fields">
              <Field label={t.representation.validFrom} error={action.errors.validFrom}>
                <TextInput
                  invalid={action.errors.validFrom !== undefined}
                  type="date"
                  value={draft.validFrom}
                  onChange={(event) => setDraft({ ...draft, validFrom: event.target.value })}
                />
              </Field>
              <Field label={t.representation.validTo} error={action.errors.validTo}>
                <TextInput
                  invalid={action.errors.validTo !== undefined}
                  type="date"
                  value={draft.validTo}
                  onChange={(event) => setDraft({ ...draft, validTo: event.target.value })}
                />
              </Field>
            </div>
            <ActionError error={action.error} />
          </div>
        </Modal>
      )}
      {revoking !== undefined && (
        <ConfirmDialog
          testId="revoke-grant-dialog"
          title={t.representation.revokeTitle}
          body={t.representation.revokeBody}
          confirmLabel={t.representation.revoke}
          danger
          busy={action.busy}
          error={action.error}
          onCancel={() => setRevoking(undefined)}
          onConfirm={() =>
            void action.run(() =>
              api.send("POST", `/tenants/${tenant.id}/grants/${revoking.id}/revoke`, {
                etag: revoking.etag,
              }),
            )
          }
        />
      )}
    </>
  );
}
