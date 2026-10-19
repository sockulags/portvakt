import {
  Badge,
  Button,
  Field,
  Select,
  Switch,
  Tabs,
  Textarea,
  TextInput,
} from "@portvakt/design-system/components";
import { DataTable, EmptyState, PageHeader } from "@portvakt/design-system/patterns";
import { useState } from "react";
import { ApiError } from "../api";
import { format, useI18n } from "../i18n";
import type {
  Application,
  ApplicationUsage,
  ApplicationWithSecret,
  List,
  RepresentationMode,
  TenantApplication,
} from "../types";
import {
  ActionError,
  ConfirmDialog,
  CopyButton,
  ErrorState,
  Modal,
  useAdmin,
  useResource,
} from "../ui";
import { ApplicationEditor, UsageList } from "./ApplicationEditor";

const lines = (value: string): string[] =>
  value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");

export function ApplicationsPage() {
  const { me } = useAdmin();
  const { t } = useI18n();
  const [tab, setTab] = useState("tenant");
  return (
    <>
      <PageHeader title={t.applications.title} description={t.applications.description}>
        {me.platform && (
          <Tabs
            variant="underline"
            label={t.applications.title}
            value={tab}
            onChange={setTab}
            items={[
              { id: "tenant", label: t.applications.tenantTab },
              { id: "registry", label: t.applications.registryTab },
            ]}
          />
        )}
      </PageHeader>
      {tab === "tenant" ? <TenantApplications /> : <Registry />}
    </>
  );
}

function TenantApplications() {
  const { api, tenant, me } = useAdmin();
  const { t } = useI18n();
  const key = `apps-${tenant.id}`;
  const attached = useResource(
    () => api.get<List<TenantApplication>>(`/tenants/${tenant.id}/applications`),
    key,
  );
  const registry = useResource(
    () =>
      me.platform ? api.get<List<Application>>("/applications") : Promise.resolve({ items: [] }),
    key,
  );
  const [error, setError] = useState<unknown>();
  const [pending, setPending] = useState<string | undefined>();
  const [attach, setAttach] = useState("");
  const [detaching, setDetaching] = useState<
    { readonly entry: TenantApplication; readonly usage: ApplicationUsage } | undefined
  >();
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [detachError, setDetachError] = useState<unknown>();

  const startDetach = async (entry: TenantApplication) => {
    setError(undefined);
    setDetachError(undefined);
    setTyped("");
    try {
      const usage = await api.get<ApplicationUsage>(
        `/tenants/${tenant.id}/applications/${entry.applicationId}/usage`,
      );
      setDetaching({ entry, usage });
    } catch (failure) {
      setError(failure);
    }
  };
  const detach = async () => {
    if (detaching === undefined) return;
    setBusy(true);
    setDetachError(undefined);
    try {
      await api.send(
        "POST",
        `/tenants/${tenant.id}/applications/${detaching.entry.applicationId}/detach`,
        { body: { confirmClientId: typed.trim() }, etag: detaching.entry.etag },
      );
      setDetaching(undefined);
      attached.reload();
    } catch (failure) {
      setDetachError(failure);
    } finally {
      setBusy(false);
    }
  };

  const toggle = async (entry: TenantApplication) => {
    setPending(entry.applicationId);
    setError(undefined);
    try {
      await api.send("PATCH", `/tenants/${tenant.id}/applications/${entry.applicationId}`, {
        body: { enabled: !entry.enabled },
        etag: entry.etag,
      });
      attached.reload();
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(undefined);
    }
  };
  const attachable = (registry.data?.items ?? []).filter(
    (application) =>
      !(attached.data?.items ?? []).some((entry) => entry.applicationId === application.id),
  );

  if (attached.error !== undefined)
    return <ErrorState error={attached.error} onRetry={attached.reload} />;
  return (
    <>
      <ActionError error={error} onReload={attached.reload} />
      {me.platform && attachable.length > 0 && (
        <div className="pv-toolbar">
          <Field label={t.applications.attach}>
            <Select
              value={attach}
              data-testid="attach-select"
              onChange={(event) => setAttach(event.target.value)}
            >
              <option value="">–</option>
              {attachable.map((application) => (
                <option key={application.id} value={application.id}>
                  {application.name} ({application.clientId})
                </option>
              ))}
            </Select>
          </Field>
          <Button
            variant="secondary"
            disabled={attach === ""}
            data-testid="attach-application"
            onClick={() => {
              void api
                .send("PUT", `/tenants/${tenant.id}/applications/${attach}`)
                .then(() => {
                  setAttach("");
                  attached.reload();
                })
                .catch(setError);
            }}
          >
            {t.applications.attach}
          </Button>
        </div>
      )}
      <DataTable
        caption={t.applications.tenantTab}
        loading={attached.loading && attached.data === undefined}
        rows={[...(attached.data?.items ?? [])]}
        rowKey={(entry) => entry.applicationId}
        empty={
          <EmptyState compact title={t.applications.empty} description={t.applications.emptyBody} />
        }
        columns={[
          {
            key: "name",
            header: t.common.name,
            cell: (entry) => (
              <span className="pv-cell-main" data-testid={`application-row-${entry.clientId}`}>
                {entry.name}
                <span className="pv-muted">{entry.clientId}</span>
              </span>
            ),
          },
          {
            key: "representation",
            header: t.applications.representation,
            cell: (entry) => t.applications.representationModes[entry.representationMode],
          },
          {
            key: "roles",
            header: t.applications.roles,
            cell: (entry) => entry.roles.map((role) => role.role).join(", ") || "–",
          },
          {
            key: "enabled",
            header: t.applications.enabledHere,
            align: "end",
            cell: (entry) => (
              <Switch
                checked={entry.enabled}
                disabled={pending === entry.applicationId}
                aria-label={`${t.applications.enabledHere}: ${entry.name}`}
                data-testid={`application-toggle-${entry.clientId}`}
                onChange={() => void toggle(entry)}
              />
            ),
          },
          ...(me.platform
            ? [
                {
                  key: "actions",
                  header: t.common.actions,
                  align: "end" as const,
                  cell: (entry: TenantApplication) => (
                    <Button
                      size="sm"
                      variant="ghost"
                      data-testid={`application-detach-${entry.clientId}`}
                      onClick={() => void startDetach(entry)}
                    >
                      {t.applications.detach}
                    </Button>
                  ),
                },
              ]
            : []),
        ]}
      />
      {detaching !== undefined && (
        <ConfirmDialog
          testId="application-detach-dialog"
          title={format(t.applications.detachTitle, { name: detaching.entry.name })}
          body={t.applications.detachBody}
          confirmLabel={t.applications.detach}
          danger
          busy={busy}
          confirmDisabled={typed.trim() !== detaching.entry.clientId}
          error={detachError}
          onCancel={() => setDetaching(undefined)}
          onConfirm={() => void detach()}
        >
          <div className="pv-form">
            <UsageList usage={detaching.usage} testId="application-detach-usage" />
            <Field
              label={format(t.applications.detachTypeLabel, { clientId: detaching.entry.clientId })}
            >
              <TextInput
                value={typed}
                autoComplete="off"
                spellCheck={false}
                data-testid="application-detach-confirm-input"
                onChange={(event) => setTyped(event.target.value)}
              />
            </Field>
          </div>
        </ConfirmDialog>
      )}
    </>
  );
}

interface Draft {
  clientId: string;
  name: string;
  method: "client_secret_basic" | "client_secret_post";
  redirectUris: string;
  postLogoutRedirectUris: string;
  roles: string;
  representationMode: RepresentationMode;
}

const EMPTY: Draft = {
  clientId: "",
  name: "",
  method: "client_secret_basic",
  redirectUris: "",
  postLogoutRedirectUris: "",
  roles: "",
  representationMode: "none",
};

function Registry() {
  const { api } = useAdmin();
  const { t } = useI18n();
  const applications = useResource(() => api.get<List<Application>>("/applications"), "registry");
  const [creating, setCreating] = useState(false);
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [rotating, setRotating] = useState<Application | undefined>();
  const [editing, setEditing] = useState<Application | undefined>();
  const [secret, setSecret] = useState<string | undefined>();

  const create = async () => {
    const found: Record<string, string> = {};
    if (!/^[A-Za-z0-9._~-]{3,128}$/.test(draft.clientId)) found.clientId = t.validation.slug;
    if (draft.name.trim() === "") found.name = t.validation.required;
    if (lines(draft.redirectUris).length === 0) found.redirectUris = t.validation.required;
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    setBusy(true);
    setError(undefined);
    try {
      const result = await api.send<ApplicationWithSecret>("POST", "/applications", {
        body: {
          clientId: draft.clientId,
          name: draft.name,
          clientAuth: { method: draft.method },
          redirectUris: lines(draft.redirectUris),
          postLogoutRedirectUris: lines(draft.postLogoutRedirectUris),
          roles: lines(draft.roles).map((role) => ({ role })),
          representationMode: draft.representationMode,
        },
      });
      setCreating(false);
      setSecret(result.clientSecret);
      applications.reload();
    } catch (failure) {
      setError(failure);
      if (failure instanceof ApiError) {
        const fields: Record<string, string> = {};
        for (const [field, message] of Object.entries(failure.fieldErrors())) {
          fields[field.split(".")[0]!] = message;
        }
        setErrors(fields);
      }
    } finally {
      setBusy(false);
    }
  };

  const rotate = async (application: Application) => {
    setBusy(true);
    setError(undefined);
    try {
      const result = await api.send<ApplicationWithSecret>(
        "POST",
        `/applications/${application.id}/rotate-secret`,
        {
          etag: application.etag,
        },
      );
      setRotating(undefined);
      setSecret(result.clientSecret);
      applications.reload();
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  if (applications.error !== undefined)
    return <ErrorState error={applications.error} onRetry={applications.reload} />;
  const set = <K extends keyof Draft>(key: K, value: Draft[K]) =>
    setDraft({ ...draft, [key]: value });
  return (
    <>
      <div className="pv-toolbar">
        <Button
          data-testid="create-application"
          onClick={() => {
            setDraft(EMPTY);
            setErrors({});
            setError(undefined);
            setCreating(true);
          }}
        >
          {t.applications.create}
        </Button>
      </div>
      <DataTable
        caption={t.applications.registryTab}
        loading={applications.loading && applications.data === undefined}
        rows={[...(applications.data?.items ?? [])]}
        rowKey={(application) => application.id}
        empty={<EmptyState compact title={t.applications.empty} />}
        columns={[
          {
            key: "name",
            header: t.common.name,
            cell: (application) => (
              <span className="pv-cell-main">
                {application.name}
                <span className="pv-muted">{application.clientId}</span>
              </span>
            ),
          },
          {
            key: "auth",
            header: t.applications.authMethod,
            cell: (application) => application.clientAuth.method,
          },
          {
            key: "status",
            header: t.common.status,
            cell: (application) => (
              <Badge color={application.enabled ? "success" : "neutral"}>
                {application.enabled ? t.common.enabled : t.common.disabled}
              </Badge>
            ),
          },
          {
            key: "actions",
            header: t.common.actions,
            align: "end",
            cell: (application) => (
              <div className="pv-row-actions">
                <Button
                  size="sm"
                  variant="ghost"
                  data-testid={`application-edit-${application.clientId}`}
                  onClick={() => setEditing(application)}
                >
                  {t.common.edit}
                </Button>
                {application.clientAuth.method === "private_key_jwt" ? null : (
                  <Button size="sm" variant="secondary" onClick={() => setRotating(application)}>
                    {t.applications.rotateSecret}
                  </Button>
                )}
              </div>
            ),
          },
        ]}
      />
      {creating && (
        <Modal
          title={t.applications.create}
          onClose={() => setCreating(false)}
          testId="application-dialog"
          footer={
            <div className="pv-dialog-actions">
              <Button variant="ghost" onClick={() => setCreating(false)}>
                {t.common.cancel}
              </Button>
              <Button
                loading={busy}
                disabled={busy}
                onClick={() => void create()}
                data-testid="application-save"
              >
                {t.common.create}
              </Button>
            </div>
          }
        >
          <div className="pv-form">
            <Field label={t.applications.clientId} error={errors.clientId}>
              <TextInput
                value={draft.clientId}
                invalid={errors.clientId !== undefined}
                onChange={(event) => set("clientId", event.target.value)}
              />
            </Field>
            <Field label={t.common.name} error={errors.name}>
              <TextInput
                value={draft.name}
                invalid={errors.name !== undefined}
                onChange={(event) => set("name", event.target.value)}
              />
            </Field>
            <Field label={t.applications.authMethod}>
              <Select
                value={draft.method}
                onChange={(event) => set("method", event.target.value as Draft["method"])}
              >
                <option value="client_secret_basic">client_secret_basic</option>
                <option value="client_secret_post">client_secret_post</option>
              </Select>
            </Field>
            <Field
              label={t.applications.redirectUris}
              hint={t.applications.redirectHint}
              error={errors.redirectUris}
            >
              <Textarea
                rows={3}
                value={draft.redirectUris}
                invalid={errors.redirectUris !== undefined}
                onChange={(event) => set("redirectUris", event.target.value)}
              />
            </Field>
            <Field label={t.applications.postLogoutUris} error={errors.postLogoutRedirectUris}>
              <Textarea
                rows={2}
                value={draft.postLogoutRedirectUris}
                onChange={(event) => set("postLogoutRedirectUris", event.target.value)}
              />
            </Field>
            <Field
              label={t.applications.roles}
              hint={t.applications.rolesHint}
              error={errors.roles}
            >
              <Textarea
                rows={3}
                value={draft.roles}
                onChange={(event) => set("roles", event.target.value)}
              />
            </Field>
            <Field label={t.applications.representation}>
              <Select
                value={draft.representationMode}
                onChange={(event) =>
                  set("representationMode", event.target.value as RepresentationMode)
                }
              >
                {(["none", "optional", "required"] as const).map((mode) => (
                  <option key={mode} value={mode}>
                    {t.applications.representationModes[mode]}
                  </option>
                ))}
              </Select>
            </Field>
            <ActionError error={error} />
          </div>
        </Modal>
      )}
      {editing !== undefined && (
        <ApplicationEditor
          application={editing}
          onClose={() => setEditing(undefined)}
          onSaved={(newSecret) => {
            setEditing(undefined);
            if (newSecret !== undefined) setSecret(newSecret);
            applications.reload();
          }}
        />
      )}
      {rotating !== undefined && (
        <ConfirmDialog
          testId="rotate-secret-dialog"
          title={t.applications.rotateTitle}
          body={t.applications.rotateBody}
          confirmLabel={t.applications.rotateSecret}
          danger
          busy={busy}
          error={error}
          onCancel={() => setRotating(undefined)}
          onConfirm={() => void rotate(rotating)}
        />
      )}
      {secret !== undefined && (
        <Modal
          title={t.applications.secretTitle}
          onClose={() => setSecret(undefined)}
          testId="secret-dialog"
          footer={
            <div className="pv-dialog-actions">
              <Button onClick={() => setSecret(undefined)}>{t.common.close}</Button>
            </div>
          }
        >
          <p className="pv-dialog-text">{t.applications.secretBody}</p>
          <div className="pv-copy-row">
            <code className="pv-code" data-testid="client-secret">
              {secret}
            </code>
            <CopyButton value={secret} testId="copy-secret" />
          </div>
        </Modal>
      )}
    </>
  );
}
