import {
  Badge,
  Button,
  Card,
  Field,
  Radio,
  Select,
  Tabs,
  TextInput,
} from "@portvakt/design-system/components";
import { DataTable, EmptyState, PageHeader } from "@portvakt/design-system/patterns";
import { useState } from "react";
import { ApiError } from "../api";
import { formatDate, useI18n } from "../i18n";
import type {
  AssignmentTarget,
  AttributeAssignment,
  List,
  LoginMethod,
  RoleAssignment,
  RoleCatalogue,
  RoleRule,
} from "../types";
import { ActionError, ConfirmDialog, ErrorState, Modal, useAdmin, useResource } from "../ui";

export function RolesPage() {
  const { api, tenant } = useAdmin();
  const { t } = useI18n();
  const [tab, setTab] = useState("catalogue");
  const catalogue = useResource(
    () => api.get<RoleCatalogue>(`/tenants/${tenant.id}/roles`),
    tenant.id,
  );
  const methods = useResource(
    () => api.get<List<LoginMethod>>(`/tenants/${tenant.id}/login-methods`),
    tenant.id,
  );
  const error = catalogue.error ?? methods.error;
  return (
    <>
      <PageHeader title={t.roles.title} description={t.roles.description}>
        <Tabs
          variant="underline"
          label={t.roles.title}
          value={tab}
          onChange={setTab}
          items={[
            { id: "catalogue", label: t.roles.catalogueTab },
            { id: "rules", label: t.roles.rulesTab },
            { id: "assignments", label: t.roles.assignmentsTab },
            { id: "attributes", label: t.roles.attributesTab },
          ]}
        />
      </PageHeader>
      {error !== undefined ? (
        <ErrorState
          error={error}
          onRetry={() => {
            catalogue.reload();
            methods.reload();
          }}
        />
      ) : tab === "catalogue" ? (
        <Catalogue catalogue={catalogue.data} />
      ) : tab === "rules" ? (
        <Rules catalogue={catalogue.data} methods={methods.data?.items ?? []} />
      ) : tab === "assignments" ? (
        <Assignments catalogue={catalogue.data} methods={methods.data?.items ?? []} />
      ) : (
        <Attributes catalogue={catalogue.data} methods={methods.data?.items ?? []} />
      )}
    </>
  );
}

function Catalogue({ catalogue }: { readonly catalogue: RoleCatalogue | undefined }) {
  const { t } = useI18n();
  if (catalogue === undefined)
    return (
      <DataTable caption={t.roles.catalogueTab} loading rows={[]} rowKey={() => ""} columns={[]} />
    );
  if (catalogue.applications.length === 0)
    return <EmptyState title={t.applications.empty} description={t.applications.emptyBody} />;
  return (
    <div className="pv-cards" data-testid="role-catalogue">
      {catalogue.applications.map((application) => (
        <Card key={application.applicationId} className="pv-card">
          <h2 className="pv-card-title">
            {application.name} <span className="pv-muted">{application.clientId}</span>
          </h2>
          {application.roles.length === 0 ? (
            <p className="pv-muted">{t.roles.noRoles}</p>
          ) : (
            <ul className="pv-plain-list">
              {application.roles.map((role) => (
                <li key={role.role}>
                  <Badge color="primary">{role.role}</Badge> {role.description ?? ""}
                </li>
              ))}
            </ul>
          )}
        </Card>
      ))}
    </div>
  );
}

const appName = (catalogue: RoleCatalogue | undefined, id: string): string =>
  catalogue?.applications.find((application) => application.applicationId === id)?.name ??
  id.slice(0, 8);

function Rules({
  catalogue,
  methods,
}: {
  readonly catalogue: RoleCatalogue | undefined;
  readonly methods: readonly LoginMethod[];
}) {
  const { api, tenant } = useAdmin();
  const { t, locale } = useI18n();
  const rules = useResource(
    () => api.get<List<RoleRule>>(`/tenants/${tenant.id}/role-rules`),
    tenant.id,
  );
  const [open, setOpen] = useState(false);
  const [removing, setRemoving] = useState<RoleRule | undefined>();
  const [draft, setDraft] = useState({
    applicationId: "",
    loginMethodId: "",
    groupValue: "",
    role: "",
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const roles =
    catalogue?.applications.find((application) => application.applicationId === draft.applicationId)
      ?.roles ?? [];

  const act = async (action: () => Promise<unknown>, after: () => void) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
      after();
      rules.reload();
    } catch (failure) {
      setError(failure);
      if (failure instanceof ApiError) setErrors(failure.fieldErrors());
    } finally {
      setBusy(false);
    }
  };
  const create = () => {
    const found: Record<string, string> = {};
    for (const field of ["applicationId", "loginMethodId", "groupValue", "role"] as const) {
      if (draft[field].trim() === "") found[field] = t.validation.required;
    }
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    void act(
      () => api.send("POST", `/tenants/${tenant.id}/role-rules`, { body: draft }),
      () => setOpen(false),
    );
  };

  if (rules.error !== undefined) return <ErrorState error={rules.error} onRetry={rules.reload} />;
  return (
    <>
      <div className="pv-toolbar">
        <Button
          data-testid="create-rule"
          onClick={() => {
            setDraft({ applicationId: "", loginMethodId: "", groupValue: "", role: "" });
            setErrors({});
            setError(undefined);
            setOpen(true);
          }}
        >
          {t.roles.createRule}
        </Button>
      </div>
      <DataTable
        caption={t.roles.rulesTab}
        loading={rules.loading && rules.data === undefined}
        rows={[...(rules.data?.items ?? [])]}
        rowKey={(rule) => rule.id}
        empty={<EmptyState compact title={t.roles.noRules} />}
        columns={[
          {
            key: "group",
            header: t.roles.group,
            cell: (rule) => <code className="pv-code-inline">{rule.groupValue}</code>,
          },
          {
            key: "role",
            header: t.roles.role,
            cell: (rule) => <Badge color="primary">{rule.role}</Badge>,
          },
          {
            key: "application",
            header: t.roles.application,
            cell: (rule) => appName(catalogue, rule.applicationId),
          },
          {
            key: "method",
            header: t.roles.loginMethod,
            cell: (rule) =>
              methods.find((method) => method.id === rule.loginMethodId)?.displayName ?? "–",
          },
          {
            key: "created",
            header: t.common.created,
            cell: (rule) => formatDate(rule.createdAt, locale),
          },
          {
            key: "actions",
            header: t.common.actions,
            align: "end",
            cell: (rule) => (
              <Button size="sm" variant="ghost" onClick={() => setRemoving(rule)}>
                {t.common.remove}
              </Button>
            ),
          },
        ]}
      />
      {open && (
        <Modal
          title={t.roles.createRule}
          onClose={() => setOpen(false)}
          testId="rule-dialog"
          footer={
            <div className="pv-dialog-actions">
              <Button variant="ghost" onClick={() => setOpen(false)}>
                {t.common.cancel}
              </Button>
              <Button loading={busy} disabled={busy} onClick={create} data-testid="rule-save">
                {t.common.create}
              </Button>
            </div>
          }
        >
          <div className="pv-form">
            <Field label={t.roles.application} error={errors.applicationId}>
              <Select
                value={draft.applicationId}
                onChange={(event) =>
                  setDraft({ ...draft, applicationId: event.target.value, role: "" })
                }
              >
                <option value="">–</option>
                {catalogue?.applications.map((application) => (
                  <option key={application.applicationId} value={application.applicationId}>
                    {application.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label={t.roles.role} error={errors.role}>
              <Select
                value={draft.role}
                onChange={(event) => setDraft({ ...draft, role: event.target.value })}
              >
                <option value="">–</option>
                {roles.map((role) => (
                  <option key={role.role} value={role.role}>
                    {role.role}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label={t.roles.loginMethod} error={errors.loginMethodId}>
              <Select
                value={draft.loginMethodId}
                onChange={(event) => setDraft({ ...draft, loginMethodId: event.target.value })}
              >
                <option value="">–</option>
                {methods.map((method) => (
                  <option key={method.id} value={method.id}>
                    {method.displayName}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label={t.roles.group} error={errors.groupValue}>
              <TextInput
                value={draft.groupValue}
                invalid={errors.groupValue !== undefined}
                onChange={(event) => setDraft({ ...draft, groupValue: event.target.value })}
              />
            </Field>
            <ActionError error={error} />
          </div>
        </Modal>
      )}
      {removing !== undefined && (
        <ConfirmDialog
          testId="rule-delete-dialog"
          title={`${t.common.remove}: ${removing.groupValue} → ${removing.role}`}
          body=""
          confirmLabel={t.common.remove}
          danger
          busy={busy}
          error={error}
          onCancel={() => setRemoving(undefined)}
          onConfirm={() =>
            void act(
              () => api.send("DELETE", `/tenants/${tenant.id}/role-rules/${removing.id}`),
              () => setRemoving(undefined),
            )
          }
        />
      )}
    </>
  );
}

type TargetKind = "person" | "identity" | "pin";

function targetLabel(
  target: AssignmentTarget,
  methods: readonly LoginMethod[],
  t: ReturnType<typeof useI18n>["t"],
): string {
  if (target.kind === "person") return target.personId;
  if (target.kind === "pin") return t.roles.pinHidden;
  const method = methods.find((item) => item.id === target.loginMethodId)?.displayName ?? "–";
  return `${target.subject} (${method})`;
}

function Assignments({
  catalogue,
  methods,
}: {
  readonly catalogue: RoleCatalogue | undefined;
  readonly methods: readonly LoginMethod[];
}) {
  const { api, tenant, go } = useAdmin();
  const { t, locale } = useI18n();
  const assignments = useResource(
    () => api.get<List<RoleAssignment>>(`/tenants/${tenant.id}/role-assignments`),
    tenant.id,
  );
  const [open, setOpen] = useState(false);
  const [removing, setRemoving] = useState<RoleAssignment | undefined>();
  const [kind, setKind] = useState<TargetKind>("identity");
  const [draft, setDraft] = useState({
    applicationId: "",
    role: "",
    personId: "",
    loginMethodId: "",
    subject: "",
    pin: "",
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const roles =
    catalogue?.applications.find((application) => application.applicationId === draft.applicationId)
      ?.roles ?? [];

  const act = async (action: () => Promise<unknown>, after: () => void) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
      after();
      assignments.reload();
    } catch (failure) {
      setError(failure);
      if (failure instanceof ApiError) {
        const fields: Record<string, string> = {};
        for (const [field, message] of Object.entries(failure.fieldErrors()))
          fields[field.replace(/^target\./, "")] = message;
        setErrors(fields);
      }
    } finally {
      setBusy(false);
    }
  };
  const create = () => {
    const required: string[] = [
      "applicationId",
      "role",
      ...(kind === "person"
        ? ["personId"]
        : kind === "pin"
          ? ["pin"]
          : ["loginMethodId", "subject"]),
    ];
    const found: Record<string, string> = {};
    for (const field of required)
      if ((draft as Record<string, string>)[field]!.trim() === "")
        found[field] = t.validation.required;
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    const target =
      kind === "person"
        ? { personId: draft.personId.trim() }
        : kind === "pin"
          ? { pin: draft.pin.trim() }
          : { loginMethodId: draft.loginMethodId, subject: draft.subject.trim() };
    void act(
      () =>
        api.send("POST", `/tenants/${tenant.id}/role-assignments`, {
          body: { applicationId: draft.applicationId, role: draft.role, target },
        }),
      () => setOpen(false),
    );
  };

  if (assignments.error !== undefined)
    return <ErrorState error={assignments.error} onRetry={assignments.reload} />;
  return (
    <>
      <div className="pv-toolbar">
        <Button
          data-testid="create-assignment"
          onClick={() => {
            setDraft({
              applicationId: "",
              role: "",
              personId: "",
              loginMethodId: "",
              subject: "",
              pin: "",
            });
            setErrors({});
            setError(undefined);
            setOpen(true);
          }}
        >
          {t.roles.createAssignment}
        </Button>
      </div>
      <DataTable
        caption={t.roles.assignmentsTab}
        loading={assignments.loading && assignments.data === undefined}
        rows={[...(assignments.data?.items ?? [])]}
        rowKey={(assignment) => assignment.id}
        empty={<EmptyState compact title={t.roles.noAssignments} />}
        columns={[
          {
            key: "role",
            header: t.roles.role,
            cell: (item) => <Badge color="primary">{item.role}</Badge>,
          },
          {
            key: "application",
            header: t.roles.application,
            cell: (item) => appName(catalogue, item.applicationId),
          },
          {
            key: "target",
            header: t.roles.target,
            cell: (item) =>
              item.target.kind === "person" ? (
                <button
                  type="button"
                  className="pv-link-button"
                  onClick={() => go("persons", (item.target as { personId: string }).personId)}
                >
                  {item.target.personId.slice(0, 8)}…
                </button>
              ) : (
                <span className="pv-cell-main">
                  {targetLabel(item.target, methods, t)}
                  <span className="pv-muted">{t.roles.pending}</span>
                </span>
              ),
          },
          {
            key: "created",
            header: t.common.created,
            cell: (item) => formatDate(item.createdAt, locale),
          },
          {
            key: "actions",
            header: t.common.actions,
            align: "end",
            cell: (item) => (
              <Button size="sm" variant="ghost" onClick={() => setRemoving(item)}>
                {t.common.remove}
              </Button>
            ),
          },
        ]}
      />
      {open && (
        <Modal
          title={t.roles.createAssignment}
          onClose={() => setOpen(false)}
          testId="assignment-dialog"
          footer={
            <div className="pv-dialog-actions">
              <Button variant="ghost" onClick={() => setOpen(false)}>
                {t.common.cancel}
              </Button>
              <Button loading={busy} disabled={busy} onClick={create} data-testid="assignment-save">
                {t.common.create}
              </Button>
            </div>
          }
        >
          <div className="pv-form">
            <Field label={t.roles.application} error={errors.applicationId}>
              <Select
                value={draft.applicationId}
                data-testid="assignment-application"
                onChange={(event) =>
                  setDraft({ ...draft, applicationId: event.target.value, role: "" })
                }
              >
                <option value="">–</option>
                {catalogue?.applications.map((application) => (
                  <option key={application.applicationId} value={application.applicationId}>
                    {application.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label={t.roles.role} error={errors.role}>
              <Select
                value={draft.role}
                data-testid="assignment-role"
                onChange={(event) => setDraft({ ...draft, role: event.target.value })}
              >
                <option value="">–</option>
                {roles.map((role) => (
                  <option key={role.role} value={role.role}>
                    {role.role}
                  </option>
                ))}
              </Select>
            </Field>
            <fieldset className="pv-fieldset">
              <legend className="pv-legend">{t.roles.target}</legend>
              <Radio
                name="target"
                label={t.roles.targetIdentity}
                checked={kind === "identity"}
                onChange={() => setKind("identity")}
              />
              <Radio
                name="target"
                label={t.roles.targetPin}
                checked={kind === "pin"}
                onChange={() => setKind("pin")}
              />
              <Radio
                name="target"
                label={t.roles.targetPerson}
                checked={kind === "person"}
                onChange={() => setKind("person")}
              />
            </fieldset>
            {kind === "identity" && (
              <>
                <Field label={t.roles.loginMethod} error={errors.loginMethodId}>
                  <Select
                    value={draft.loginMethodId}
                    onChange={(event) => setDraft({ ...draft, loginMethodId: event.target.value })}
                  >
                    <option value="">–</option>
                    {methods.map((method) => (
                      <option key={method.id} value={method.id}>
                        {method.displayName}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field label={t.roles.subject} error={errors.subject}>
                  <TextInput
                    value={draft.subject}
                    autoComplete="off"
                    onChange={(event) => setDraft({ ...draft, subject: event.target.value })}
                  />
                </Field>
              </>
            )}
            {kind === "pin" && (
              <Field label={t.roles.targetPin} error={errors.pin}>
                <TextInput
                  value={draft.pin}
                  autoComplete="off"
                  inputMode="numeric"
                  onChange={(event) => setDraft({ ...draft, pin: event.target.value })}
                />
              </Field>
            )}
            {kind === "person" && (
              <Field label={t.roles.targetPerson} error={errors.personId}>
                <TextInput
                  value={draft.personId}
                  autoComplete="off"
                  onChange={(event) => setDraft({ ...draft, personId: event.target.value })}
                />
              </Field>
            )}
            <ActionError error={error} />
          </div>
        </Modal>
      )}
      {removing !== undefined && (
        <ConfirmDialog
          testId="assignment-delete-dialog"
          title={`${t.common.remove}: ${removing.role}`}
          body={targetLabel(removing.target, methods, t)}
          confirmLabel={t.common.remove}
          danger
          busy={busy}
          error={error}
          onCancel={() => setRemoving(undefined)}
          onConfirm={() =>
            void act(
              () => api.send("DELETE", `/tenants/${tenant.id}/role-assignments/${removing.id}`),
              () => setRemoving(undefined),
            )
          }
        />
      )}
    </>
  );
}

interface TargetDraft {
  personId: string;
  loginMethodId: string;
  subject: string;
  pin: string;
}

const EMPTY_TARGET: TargetDraft = { personId: "", loginMethodId: "", subject: "", pin: "" };

/** Who an assignment is for: a person, an identity (pending until it signs in), or a pin. */
function TargetFields({
  kind,
  onKind,
  draft,
  onDraft,
  errors,
  methods,
  name,
}: {
  readonly kind: TargetKind;
  readonly onKind: (kind: TargetKind) => void;
  readonly draft: TargetDraft;
  readonly onDraft: (draft: TargetDraft) => void;
  readonly errors: Record<string, string>;
  readonly methods: readonly LoginMethod[];
  readonly name: string;
}) {
  const { t } = useI18n();
  return (
    <>
      <fieldset className="pv-fieldset">
        <legend className="pv-legend">{t.roles.target}</legend>
        <Radio
          name={name}
          label={t.roles.targetIdentity}
          checked={kind === "identity"}
          onChange={() => onKind("identity")}
        />
        <Radio
          name={name}
          label={t.roles.targetPin}
          checked={kind === "pin"}
          onChange={() => onKind("pin")}
        />
        <Radio
          name={name}
          label={t.roles.targetPerson}
          checked={kind === "person"}
          onChange={() => onKind("person")}
        />
      </fieldset>
      {kind === "identity" && (
        <>
          <Field label={t.roles.loginMethod} error={errors.loginMethodId}>
            <Select
              value={draft.loginMethodId}
              onChange={(event) => onDraft({ ...draft, loginMethodId: event.target.value })}
            >
              <option value="">–</option>
              {methods.map((method) => (
                <option key={method.id} value={method.id}>
                  {method.displayName}
                </option>
              ))}
            </Select>
          </Field>
          <Field label={t.roles.subject} error={errors.subject}>
            <TextInput
              value={draft.subject}
              autoComplete="off"
              onChange={(event) => onDraft({ ...draft, subject: event.target.value })}
            />
          </Field>
        </>
      )}
      {kind === "pin" && (
        <Field label={t.roles.targetPin} error={errors.pin}>
          <TextInput
            value={draft.pin}
            autoComplete="off"
            inputMode="numeric"
            onChange={(event) => onDraft({ ...draft, pin: event.target.value })}
          />
        </Field>
      )}
      {kind === "person" && (
        <Field label={t.roles.targetPerson} error={errors.personId}>
          <TextInput
            value={draft.personId}
            autoComplete="off"
            onChange={(event) => onDraft({ ...draft, personId: event.target.value })}
          />
        </Field>
      )}
    </>
  );
}

function targetErrors(
  kind: TargetKind,
  draft: TargetDraft,
  required: string,
): Record<string, string> {
  const fields: (keyof TargetDraft)[] =
    kind === "person" ? ["personId"] : kind === "pin" ? ["pin"] : ["loginMethodId", "subject"];
  const found: Record<string, string> = {};
  for (const field of fields) if (draft[field].trim() === "") found[field] = required;
  return found;
}

function targetOf(kind: TargetKind, draft: TargetDraft) {
  return kind === "person"
    ? { personId: draft.personId.trim() }
    : kind === "pin"
      ? { pin: draft.pin.trim() }
      : { loginMethodId: draft.loginMethodId, subject: draft.subject.trim() };
}

/** Attribute assignments: values of an application's declared keys, per person or pending. */
function Attributes({
  catalogue,
  methods,
}: {
  readonly catalogue: RoleCatalogue | undefined;
  readonly methods: readonly LoginMethod[];
}) {
  const { api, tenant, go } = useAdmin();
  const { t, locale } = useI18n();
  const attributes = useResource(
    () => api.get<List<AttributeAssignment>>(`/tenants/${tenant.id}/attribute-assignments`),
    tenant.id,
  );
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<AttributeAssignment | undefined>();
  const [removing, setRemoving] = useState<AttributeAssignment | undefined>();
  const [kind, setKind] = useState<TargetKind>("identity");
  const [draft, setDraft] = useState({ applicationId: "", key: "", value: "" });
  const [target, setTarget] = useState<TargetDraft>(EMPTY_TARGET);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const keys =
    catalogue?.applications.find((application) => application.applicationId === draft.applicationId)
      ?.attributeKeys ?? [];
  const withKeys = catalogue?.applications.filter((item) => item.attributeKeys.length > 0) ?? [];

  const act = async (action: () => Promise<unknown>, after: () => void) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
      after();
      attributes.reload();
    } catch (failure) {
      setError(failure);
      if (failure instanceof ApiError) {
        const fields: Record<string, string> = {};
        for (const [field, message] of Object.entries(failure.fieldErrors()))
          fields[field.replace(/^target\./, "")] = message;
        setErrors(fields);
      }
    } finally {
      setBusy(false);
    }
  };
  const create = () => {
    const found: Record<string, string> = {
      ...targetErrors(kind, target, t.validation.required),
    };
    if (draft.applicationId === "") found.applicationId = t.validation.required;
    if (draft.key === "") found.key = t.validation.required;
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    void act(
      () =>
        api.send("POST", `/tenants/${tenant.id}/attribute-assignments`, {
          body: { ...draft, target: targetOf(kind, target) },
        }),
      () => setCreating(false),
    );
  };
  const update = (assignment: AttributeAssignment) => {
    void act(
      () =>
        api.send("PATCH", `/tenants/${tenant.id}/attribute-assignments/${assignment.id}`, {
          body: { value: draft.value },
          etag: assignment.etag,
        }),
      () => setEditing(undefined),
    );
  };

  if (attributes.error !== undefined)
    return <ErrorState error={attributes.error} onRetry={attributes.reload} />;
  const close = () => {
    setCreating(false);
    setEditing(undefined);
  };
  return (
    <>
      <div className="pv-toolbar">
        <Button
          data-testid="create-attribute"
          disabled={withKeys.length === 0}
          onClick={() => {
            setDraft({ applicationId: "", key: "", value: "" });
            setTarget(EMPTY_TARGET);
            setErrors({});
            setError(undefined);
            setCreating(true);
          }}
        >
          {t.roles.createAttribute}
        </Button>
        {catalogue !== undefined && withKeys.length === 0 && (
          <span className="pv-muted">{t.roles.noKeys}</span>
        )}
      </div>
      <DataTable
        caption={t.roles.attributesTab}
        loading={attributes.loading && attributes.data === undefined}
        rows={[...(attributes.data?.items ?? [])]}
        rowKey={(item) => item.id}
        empty={<EmptyState compact title={t.roles.noAttributes} />}
        columns={[
          {
            key: "key",
            header: t.roles.key,
            cell: (item) => <code className="pv-code-inline">{item.key}</code>,
          },
          {
            key: "value",
            header: t.roles.value,
            cell: (item) => <span className="pv-break">{item.value}</span>,
          },
          {
            key: "application",
            header: t.roles.application,
            cell: (item) => appName(catalogue, item.applicationId),
          },
          {
            key: "target",
            header: t.roles.target,
            cell: (item) =>
              item.target.kind === "person" ? (
                <button
                  type="button"
                  className="pv-link-button"
                  onClick={() => go("persons", (item.target as { personId: string }).personId)}
                >
                  {item.target.personId.slice(0, 8)}…
                </button>
              ) : (
                <span className="pv-cell-main">
                  {targetLabel(item.target, methods, t)}
                  <span className="pv-muted">{t.roles.pending}</span>
                </span>
              ),
          },
          {
            key: "updated",
            header: t.roles.updated,
            cell: (item) => formatDate(item.updatedAt, locale),
          },
          {
            key: "actions",
            header: t.common.actions,
            align: "end",
            cell: (item) => (
              <div className="pv-row-actions">
                <Button
                  size="sm"
                  variant="ghost"
                  data-testid={`edit-attribute-${item.id}`}
                  onClick={() => {
                    setDraft({
                      applicationId: item.applicationId,
                      key: item.key,
                      value: item.value,
                    });
                    setErrors({});
                    setError(undefined);
                    setEditing(item);
                  }}
                >
                  {t.common.edit}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    setError(undefined);
                    setRemoving(item);
                  }}
                >
                  {t.common.remove}
                </Button>
              </div>
            ),
          },
        ]}
      />
      {(creating || editing !== undefined) && (
        <Modal
          title={
            editing === undefined ? t.roles.createAttribute : `${t.roles.editValue}: ${editing.key}`
          }
          onClose={close}
          testId="attribute-dialog"
          footer={
            <div className="pv-dialog-actions">
              <Button variant="ghost" onClick={close}>
                {t.common.cancel}
              </Button>
              <Button
                loading={busy}
                disabled={busy}
                data-testid="attribute-save"
                onClick={() => (editing === undefined ? create() : update(editing))}
              >
                {editing === undefined ? t.common.create : t.common.save}
              </Button>
            </div>
          }
        >
          <div className="pv-form">
            {editing === undefined && (
              <>
                <Field label={t.roles.application} error={errors.applicationId}>
                  <Select
                    value={draft.applicationId}
                    data-testid="attribute-application"
                    onChange={(event) =>
                      setDraft({ ...draft, applicationId: event.target.value, key: "" })
                    }
                  >
                    <option value="">–</option>
                    {withKeys.map((application) => (
                      <option key={application.applicationId} value={application.applicationId}>
                        {application.name}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field label={t.roles.key} error={errors.key}>
                  <Select
                    value={draft.key}
                    data-testid="attribute-key"
                    onChange={(event) => setDraft({ ...draft, key: event.target.value })}
                  >
                    <option value="">–</option>
                    {keys.map((key) => (
                      <option key={key.key} value={key.key}>
                        {key.description === null ? key.key : `${key.key} – ${key.description}`}
                      </option>
                    ))}
                  </Select>
                </Field>
              </>
            )}
            <Field label={t.roles.value} hint={t.roles.valueHint} error={errors.value}>
              <TextInput
                value={draft.value}
                autoComplete="off"
                data-testid="attribute-value"
                onChange={(event) => setDraft({ ...draft, value: event.target.value })}
              />
            </Field>
            {editing === undefined && (
              <TargetFields
                name="attribute-target"
                kind={kind}
                onKind={setKind}
                draft={target}
                onDraft={setTarget}
                errors={errors}
                methods={methods}
              />
            )}
            <ActionError error={error} onReload={attributes.reload} />
          </div>
        </Modal>
      )}
      {removing !== undefined && (
        <ConfirmDialog
          testId="attribute-delete-dialog"
          title={`${t.common.remove}: ${removing.key}`}
          body={targetLabel(removing.target, methods, t)}
          confirmLabel={t.common.remove}
          danger
          busy={busy}
          error={error}
          onCancel={() => setRemoving(undefined)}
          onConfirm={() =>
            void act(
              () =>
                api.send("DELETE", `/tenants/${tenant.id}/attribute-assignments/${removing.id}`),
              () => setRemoving(undefined),
            )
          }
        />
      )}
    </>
  );
}
