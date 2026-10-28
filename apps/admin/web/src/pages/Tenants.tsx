import { Badge, Button, Checkbox, Field, TextInput } from "@portvakt/design-system/components";
import { DataTable, EmptyState, PageHeader } from "@portvakt/design-system/patterns";
import { useState } from "react";
import { ApiError } from "../api";
import { validateTenant, type Errors } from "../forms";
import { format, formatDate, useI18n } from "../i18n";
import { hrefOf } from "../router";
import type { List, Tenant } from "../types";
import { ActionError, ConfirmDialog, ErrorState, Modal, useAdmin, useResource } from "../ui";

/** The representation sources Portvakt registers (the server validates the choice). */
export const REPRESENTATION_SOURCES = ["internal"] as const;

type Dialog =
  | { readonly kind: "create" }
  | { readonly kind: "edit"; readonly tenant: Tenant }
  | { readonly kind: "status"; readonly tenant: Tenant };

export function TenantsPage() {
  const { api, location, reloadTenants, me } = useAdmin();
  const { t, locale } = useI18n();
  const tenants = useResource(() => api.get<List<Tenant>>("/tenants"), "tenants");
  const [dialog, setDialog] = useState<Dialog | undefined>();
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [sources, setSources] = useState<readonly string[]>([]);
  const [errors, setErrors] = useState<Errors>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();

  const close = () => {
    setDialog(undefined);
    setErrors({});
    setError(undefined);
  };
  const done = async () => {
    close();
    tenants.reload();
    await reloadTenants();
  };
  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
      await done();
    } catch (failure) {
      setError(failure);
      if (failure instanceof ApiError) setErrors(failure.fieldErrors());
    } finally {
      setBusy(false);
    }
  };

  const submit = () => {
    if (dialog?.kind === "create") {
      const found = validateTenant(slug, name);
      setErrors(found);
      if (Object.keys(found).length > 0) return;
      void run(() => api.send("POST", "/tenants", { body: { slug, name } }));
    } else if (dialog?.kind === "edit") {
      if (name.trim() === "") {
        setErrors({ name: "required" });
        return;
      }
      const current = dialog.tenant;
      const sourcesChanged =
        sources.length !== current.representationSources.length ||
        sources.some((source, index) => current.representationSources[index] !== source);
      const body = {
        ...(name === current.name ? {} : { name }),
        ...(me.platform && sourcesChanged ? { representationSources: sources } : {}),
      };
      if (Object.keys(body).length === 0) {
        close();
        return;
      }
      void run(() => api.send("PATCH", `/tenants/${current.id}`, { body, etag: current.etag }));
    }
  };
  const message = (field: string): string | undefined => {
    const code = errors[field];
    if (code === undefined) return undefined;
    return code in t.validation ? t.validation[code as keyof typeof t.validation] : code;
  };

  const sourceError = Object.keys(errors).find((field) =>
    field.startsWith("representationSources"),
  );
  return (
    <>
      <PageHeader
        title={t.tenants.title}
        description={t.tenants.description}
        actions={
          <Button
            data-testid="create-tenant"
            onClick={() => {
              setSlug("");
              setName("");
              setDialog({ kind: "create" });
            }}
          >
            {t.tenants.create}
          </Button>
        }
      />
      {tenants.error !== undefined ? (
        <ErrorState error={tenants.error} onRetry={tenants.reload} />
      ) : (
        <DataTable
          caption={t.tenants.title}
          loading={tenants.loading && tenants.data === undefined}
          rows={[...(tenants.data?.items ?? [])]}
          rowKey={(tenant) => tenant.id}
          empty={<EmptyState compact title={t.tenants.empty} />}
          columns={[
            {
              key: "name",
              header: t.common.name,
              cell: (tenant) => (
                <span className="pv-cell-main" data-testid={`tenant-row-${tenant.slug}`}>
                  {tenant.name}
                  <span className="pv-muted">{tenant.slug}</span>
                </span>
              ),
            },
            {
              key: "status",
              header: t.common.status,
              cell: (tenant) => (
                <Badge color={tenant.status === "active" ? "success" : "danger"}>
                  {tenant.status === "active" ? t.tenants.statusActive : t.tenants.statusSuspended}
                </Badge>
              ),
            },
            {
              key: "created",
              header: t.common.created,
              cell: (tenant) => formatDate(tenant.createdAt, locale),
            },
            {
              key: "actions",
              header: t.common.actions,
              align: "end",
              cell: (tenant) => (
                <div className="pv-row-actions">
                  <a
                    className="pv-link"
                    href={hrefOf({
                      ...location,
                      page: "overview",
                      id: undefined,
                      tenant: tenant.id,
                    })}
                  >
                    {t.tenants.administer}
                  </a>
                  <Button
                    size="sm"
                    variant="ghost"
                    data-testid={`tenant-edit-${tenant.slug}`}
                    onClick={() => {
                      setName(tenant.name);
                      setSources(tenant.representationSources);
                      setDialog({ kind: "edit", tenant });
                    }}
                  >
                    {t.common.edit}
                  </Button>
                  {tenant.slug !== "system" && (
                    <Button
                      size="sm"
                      variant={tenant.status === "active" ? "danger" : "secondary"}
                      data-testid={`tenant-status-${tenant.slug}`}
                      onClick={() => setDialog({ kind: "status", tenant })}
                    >
                      {tenant.status === "active" ? t.tenants.suspend : t.tenants.reactivate}
                    </Button>
                  )}
                </div>
              ),
            },
          ]}
        />
      )}

      {(dialog?.kind === "create" || dialog?.kind === "edit") && (
        <Modal
          title={
            dialog.kind === "create"
              ? t.tenants.create
              : format(t.tenants.editTitle, { name: dialog.tenant.name })
          }
          onClose={close}
          testId="tenant-dialog"
          errors={errors}
          footer={
            <div className="pv-dialog-actions">
              <Button variant="ghost" onClick={close}>
                {t.common.cancel}
              </Button>
              <Button loading={busy} disabled={busy} onClick={submit} data-testid="tenant-save">
                {dialog.kind === "create" ? t.common.create : t.common.save}
              </Button>
            </div>
          }
        >
          <form
            className="pv-form"
            onSubmit={(event) => {
              event.preventDefault();
              submit();
            }}
          >
            {dialog.kind === "create" && (
              <Field label={t.tenants.slug} hint={t.tenants.slugHint} error={message("slug")}>
                <TextInput
                  value={slug}
                  invalid={errors.slug !== undefined}
                  autoComplete="off"
                  data-testid="tenant-slug"
                  onChange={(event) => setSlug(event.target.value.toLowerCase())}
                />
              </Field>
            )}
            <Field label={t.common.name} error={message("name")}>
              <TextInput
                value={name}
                invalid={errors.name !== undefined}
                data-testid="tenant-name-input"
                onChange={(event) => setName(event.target.value)}
              />
            </Field>
            {dialog.kind === "edit" && me.platform && (
              <fieldset className="pv-fieldset" data-testid="tenant-sources">
                <legend className="pv-legend">{t.tenants.sources}</legend>
                <p className="pv-muted">{t.tenants.sourcesHint}</p>
                {REPRESENTATION_SOURCES.map((source) => (
                  <Checkbox
                    key={source}
                    label={t.tenants.sourceNames[source]}
                    checked={sources.includes(source)}
                    data-testid={`tenant-source-${source}`}
                    onChange={(event) =>
                      setSources(
                        event.target.checked
                          ? REPRESENTATION_SOURCES.filter(
                              (item) => item === source || sources.includes(item),
                            )
                          : sources.filter((item) => item !== source),
                      )
                    }
                  />
                ))}
                {sourceError !== undefined && (
                  <p className="pv-error" role="alert">
                    {message(sourceError)}
                  </p>
                )}
              </fieldset>
            )}
            <ActionError error={error} onReload={() => void done()} />
          </form>
        </Modal>
      )}
      {dialog?.kind === "status" && (
        <ConfirmDialog
          testId="tenant-status-dialog"
          title={
            dialog.tenant.status === "active"
              ? format(t.tenants.suspendTitle, { name: dialog.tenant.name })
              : t.tenants.reactivate
          }
          body={dialog.tenant.status === "active" ? t.tenants.suspendBody : ""}
          confirmLabel={
            dialog.tenant.status === "active" ? t.tenants.suspend : t.tenants.reactivate
          }
          danger={dialog.tenant.status === "active"}
          busy={busy}
          error={error}
          onCancel={close}
          onConfirm={() =>
            void run(() =>
              api.send(
                "POST",
                `/tenants/${dialog.tenant.id}/${dialog.tenant.status === "active" ? "suspend" : "reactivate"}`,
                { etag: dialog.tenant.etag },
              ),
            )
          }
        />
      )}
    </>
  );
}
