import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Field,
  Radio,
  Select,
  Switch,
  Textarea,
  TextInput,
} from "@portvakt/design-system/components";
import {
  DataTable,
  EmptyState,
  FormActions,
  FormLayout,
  FormSection,
  PageHeader,
} from "@portvakt/design-system/patterns";
import { useState, type ReactNode } from "react";
import { ApiError } from "../api";
import {
  createBody,
  draftFieldOf,
  draftFromMethod,
  emptyDraft,
  updateBody,
  validateDraft,
  type Errors,
  type LoginMethodDraft,
  type OidcDraft,
  type SamlDraft,
} from "../forms";
import { format, formatDate, useI18n } from "../i18n";
import { hrefOf } from "../router";
import type { List, LoginMethod } from "../types";
import {
  ActionError,
  ConfirmDialog,
  CopyValue,
  ErrorState,
  Loading,
  serverFieldMessage,
  useAdmin,
  useResource,
} from "../ui";
import { warningText } from "./Overview";

export function LoginMethodsPage() {
  const { location } = useAdmin();
  if (location.id === "new-oidc" || location.id === "new-saml") {
    return (
      <LoginMethodEditor
        key={location.id}
        protocol={location.id === "new-saml" ? "saml" : "oidc"}
      />
    );
  }
  if (location.id !== undefined) return <LoginMethodEditor key={location.id} id={location.id} />;
  return <LoginMethodList />;
}

function LoginMethodList() {
  const { api, tenant, go } = useAdmin();
  const { t } = useI18n();
  const methods = useResource(
    () => api.get<List<LoginMethod>>(`/tenants/${tenant.id}/login-methods`),
    tenant.id,
  );
  return (
    <>
      <PageHeader
        title={t.methods.title}
        description={t.methods.description}
        actions={
          <div className="pv-header-actions">
            <Button
              variant="secondary"
              data-testid="create-saml"
              onClick={() => go("login-methods", "new-saml")}
            >
              {t.methods.createSaml}
            </Button>
            <Button data-testid="create-oidc" onClick={() => go("login-methods", "new-oidc")}>
              {t.methods.createOidc}
            </Button>
          </div>
        }
      />
      {methods.error !== undefined ? (
        <ErrorState error={methods.error} onRetry={methods.reload} />
      ) : (
        <DataTable
          caption={t.methods.title}
          loading={methods.loading && methods.data === undefined}
          rows={[...(methods.data?.items ?? [])]}
          rowKey={(method) => method.id}
          empty={
            <EmptyState
              compact
              icon="settings"
              title={t.methods.empty}
              description={t.methods.emptyBody}
            />
          }
          columns={[
            {
              key: "name",
              header: t.methods.displayName,
              cell: (method) => (
                <span className="pv-cell-main">
                  <button
                    type="button"
                    className="pv-link-button"
                    data-testid={`login-method-row-${method.id}`}
                    onClick={() => go("login-methods", method.id)}
                  >
                    {method.displayName}
                  </button>
                  {/* Protocol and kind live here, so name and status fit on a phone. */}
                  <span className="pv-muted">
                    {method.protocol.toUpperCase()} · {t.methods.kinds[method.kind]}
                  </span>
                </span>
              ),
            },
            {
              key: "status",
              header: t.common.status,
              cell: (method) => (
                <span className="pv-badges">
                  <Badge color={method.enabled ? "success" : "neutral"}>
                    {method.enabled ? t.common.enabled : t.common.disabled}
                  </Badge>
                  {method.warnings.length > 0 && (
                    <Badge color="warning">
                      {format(t.methods.warningsCount, { count: method.warnings.length })}
                    </Badge>
                  )}
                </span>
              ),
            },
          ]}
        />
      )}
    </>
  );
}

type Confirm = "prepare" | "rotate" | "delete" | undefined;

function LoginMethodEditor({
  id,
  protocol = "oidc",
}: {
  readonly id?: string;
  readonly protocol?: "oidc" | "saml";
}) {
  const { api, tenant, go, location } = useAdmin();
  const { t, locale } = useI18n();
  const creating = id === undefined;
  const method = useResource(
    () =>
      creating
        ? Promise.resolve(undefined)
        : api.get<LoginMethod>(`/tenants/${tenant.id}/login-methods/${id}`),
    `${tenant.id}-${id ?? "new"}`,
  );
  const [draft, setDraft] = useState<LoginMethodDraft>(() => emptyDraft(protocol));
  const [errors, setErrors] = useState<Errors>({});
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [confirm, setConfirm] = useState<Confirm>();
  const [deleteError, setDeleteError] = useState<unknown>();
  const current = method.data;

  // A newly loaded version (after a save or a reload) replaces the draft.
  const [loadedTag, setLoadedTag] = useState<string | undefined>();
  if (current !== undefined && current.etag !== loadedTag) {
    setLoadedTag(current.etag);
    setDraft(draftFromMethod(current));
  }

  if (!creating && method.error !== undefined)
    return <ErrorState error={method.error} onRetry={method.reload} />;
  if (!creating && current === undefined) return <Loading />;

  const reload = () => {
    setError(undefined);
    setErrors({});
    setSaved(false);
    method.reload();
  };

  const save = async () => {
    const found = validateDraft(draft, creating);
    setErrors(found);
    setSaved(false);
    if (Object.keys(found).length > 0) {
      setError(new ApiError(400, "validation_failed"));
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      if (creating) {
        const created = await api.send<LoginMethod>("POST", `/tenants/${tenant.id}/login-methods`, {
          body: createBody(draft),
        });
        go("login-methods", created.id);
        return;
      }
      const updated = await api.send<LoginMethod>(
        "PATCH",
        `/tenants/${tenant.id}/login-methods/${current!.id}`,
        {
          body: updateBody(draft),
          etag: current!.etag,
        },
      );
      method.set(updated);
      setSaved(true);
    } catch (failure) {
      setError(failure);
      if (failure instanceof ApiError) {
        const mapped: Errors = {};
        for (const [field, message] of Object.entries(failure.fieldErrors())) {
          mapped[draftFieldOf(field)] ??= serverFieldMessage(message, t);
        }
        setErrors(mapped);
      }
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    setBusy(true);
    setDeleteError(undefined);
    try {
      await api.send("DELETE", `/tenants/${tenant.id}/login-methods/${current!.id}`, {
        etag: current!.etag,
      });
      setConfirm(undefined);
      go("login-methods");
    } catch (failure) {
      setDeleteError(failure);
    } finally {
      setBusy(false);
    }
  };
  const disableInstead = async () => {
    setBusy(true);
    setDeleteError(undefined);
    try {
      const updated = await api.send<LoginMethod>(
        "PATCH",
        `/tenants/${tenant.id}/login-methods/${current!.id}`,
        { body: { enabled: false }, etag: current!.etag },
      );
      method.set(updated);
      setConfirm(undefined);
    } catch (failure) {
      setDeleteError(failure);
    } finally {
      setBusy(false);
    }
  };

  const keys = async (action: "prepare" | "rotate") => {
    setBusy(true);
    setError(undefined);
    try {
      const updated = await api.send<LoginMethod>(
        "POST",
        `/tenants/${tenant.id}/login-methods/${current!.id}/sp-keys/${action}`,
        { body: {}, etag: current!.etag },
      );
      method.set(updated);
      setConfirm(undefined);
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  const message = (field: string): string | undefined => {
    const code = errors[field];
    if (code === undefined) return undefined;
    return code in t.validation ? t.validation[code as keyof typeof t.validation] : code;
  };
  const text = (field: string, label: string, hint?: string, type = "text"): ReactNode => (
    <Field label={label} hint={hint} error={message(field)}>
      <TextInput
        type={type}
        value={(draft as unknown as Record<string, string>)[field] ?? ""}
        invalid={errors[field] !== undefined}
        data-testid={`field-${field}`}
        onChange={(event) => setDraft({ ...draft, [field]: event.target.value })}
      />
    </Field>
  );
  const flag = (field: string, label: string): ReactNode => (
    <Switch
      label={label}
      checked={(draft as unknown as Record<string, boolean>)[field] === true}
      data-testid={`field-${field}`}
      onChange={(event) => setDraft({ ...draft, [field]: event.target.checked })}
    />
  );

  const title = creating ? t.methods.newTitle : current!.displayName;
  const inUse = deleteError instanceof ApiError && deleteError.code === "in_use";
  return (
    <>
      <PageHeader
        title={title}
        breadcrumbs={[
          {
            label: t.methods.title,
            href: hrefOf({ ...location, page: "login-methods", id: undefined }),
          },
          { label: title },
        ]}
        meta={<Badge color="primary">{draft.protocol.toUpperCase()}</Badge>}
        actions={
          <div className="pv-row-actions">
            {!creating && (
              <Button
                variant="danger"
                data-testid="delete-login-method"
                onClick={() => {
                  setDeleteError(undefined);
                  setConfirm("delete");
                }}
              >
                {t.common.delete}
              </Button>
            )}
            <Button variant="ghost" onClick={() => go("login-methods")} data-testid="back-to-list">
              {t.common.back}
            </Button>
          </div>
        }
      />
      {current !== undefined && current.warnings.length > 0 && (
        <div className="pv-alerts" data-testid="method-warnings">
          {current.warnings.map((warning, index) => (
            <Alert
              key={`${warning.code}-${index}`}
              tone={warning.code.includes("expir") ? "danger" : "warning"}
              title={warningText(warning, t, locale)}
            >
              {warning.expiresAt === undefined ? "" : formatDate(warning.expiresAt, locale)}
            </Alert>
          ))}
        </div>
      )}
      <FormLayout
        noValidate
        data-testid="login-method-form"
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <FormSection
          title={t.methods.sections.connection}
          description={t.methods.sections.connectionHint}
        >
          {text("displayName", t.methods.displayName)}
          <Field label={t.methods.kind}>
            <Select
              value={draft.kind}
              data-testid="field-kind"
              onChange={(event) =>
                setDraft({ ...draft, kind: event.target.value as LoginMethodDraft["kind"] })
              }
            >
              <option value="employee">{t.methods.kinds.employee}</option>
              <option value="citizen">{t.methods.kinds.citizen}</option>
            </Select>
          </Field>
          {draft.protocol === "oidc" ? (
            <>
              {text("issuer", t.methods.issuer)}
              {text("clientId", t.methods.clientId)}
              <Field label={t.methods.clientAuthMethod}>
                <Select
                  value={draft.clientAuthMethod}
                  onChange={(event) =>
                    setDraft({
                      ...draft,
                      clientAuthMethod: event.target.value as OidcDraft["clientAuthMethod"],
                    })
                  }
                >
                  <option value="client_secret_basic">client_secret_basic</option>
                  <option value="client_secret_post">client_secret_post</option>
                  <option value="private_key_jwt">private_key_jwt</option>
                </Select>
              </Field>
              {draft.clientAuthMethod !== "private_key_jwt" &&
                text(
                  "clientSecret",
                  t.methods.clientSecret,
                  creating
                    ? undefined
                    : current?.oidc?.hasClientSecret === true
                      ? `${t.methods.clientSecretSet} ${t.methods.clientSecretKeep}`
                      : t.methods.clientSecretKeep,
                  "password",
                )}
              {text("secretExpiresAt", t.methods.secretExpiresAt, undefined, "date")}
              {text("scopes", t.methods.scopes)}
              {current?.oidc !== undefined && (
                <CopyValue
                  label={t.methods.redirectUri}
                  value={current.oidc.redirectUri}
                  testId="redirect-uri"
                />
              )}
            </>
          ) : (
            <SamlConnection
              draft={draft}
              setDraft={setDraft}
              message={message}
              errors={errors}
              creating={creating}
              current={current}
            />
          )}
        </FormSection>

        <FormSection title={t.methods.sections.claims} description={t.methods.sections.claimsHint}>
          {draft.protocol === "oidc" ? (
            <>
              {text("subjectClaim", t.methods.subjectClaim)}
              {text("nameClaim", t.methods.nameClaim)}
              {text("emailClaim", t.methods.emailClaim)}
              {text("pinClaim", t.methods.pinClaim)}
              {text("groupsClaim", t.methods.groupsClaim)}
              {text("acrClaim", t.methods.acrClaim)}
              {flag("trustUpstreamEmail", t.methods.trustEmail)}
            </>
          ) : (
            <>
              <Field label={t.methods.subjectSource}>
                <Select
                  value={draft.subjectSource}
                  data-testid="field-subjectSource"
                  onChange={(event) =>
                    setDraft({
                      ...draft,
                      subjectSource: event.target.value as SamlDraft["subjectSource"],
                    })
                  }
                >
                  {(["personalIdentityNumber", "prid", "employeeHsaId", "nameId"] as const).map(
                    (source) => (
                      <option key={source} value={source}>
                        {t.methods.subjectSources[source]}
                      </option>
                    ),
                  )}
                </Select>
              </Field>
              <Field label={t.methods.entityCategories} error={message("entityCategories")}>
                <Textarea
                  rows={3}
                  value={draft.entityCategories}
                  onChange={(event) => setDraft({ ...draft, entityCategories: event.target.value })}
                />
              </Field>
              {text("uiDisplayName", t.methods.uiDisplayName)}
              {text("uiDescription", t.methods.uiDescription)}
              {text("logoUrl", t.methods.logoUrl)}
              <div className="pv-inline-fields">
                {text("logoWidth", t.methods.logoWidth)}
                {text("logoHeight", t.methods.logoHeight)}
              </div>
              {flag("trustEmail", t.methods.trustEmail)}
            </>
          )}
          {text("homeRealmDomains", t.methods.homeRealmDomains)}
        </FormSection>

        <FormSection
          title={t.methods.sections.session}
          description={t.methods.sections.sessionHint}
        >
          <div className="pv-inline-fields">
            {text("maxAgeMinutes", t.methods.maxAge, undefined, "number")}
            {text("idleMinutes", t.methods.idle, undefined, "number")}
          </div>
          {flag("allowSso", t.methods.allowSso)}
        </FormSection>

        <FormSection
          title={t.methods.sections.security}
          description={t.methods.sections.securityHint}
        >
          {text("assertedAcr", t.methods.assertedAcr)}
          {draft.protocol === "saml" && (
            <>
              <Field label={t.methods.requestedLoa} error={message("requestedLoa")}>
                <Textarea
                  rows={2}
                  value={draft.requestedLoa}
                  invalid={errors.requestedLoa !== undefined}
                  onChange={(event) => setDraft({ ...draft, requestedLoa: event.target.value })}
                />
              </Field>
              {flag("requireEncryptedAssertions", t.methods.requireEncrypted)}
              {flag("requireSignedResponse", t.methods.requireSigned)}
            </>
          )}
          {flag("linkByPin", t.methods.linkByPin)}
          {flag("trustPinForRepresentation", t.methods.trustPin)}
          {flag("enabled", t.methods.enabledLabel)}
        </FormSection>

        <ActionError error={error} onReload={reload} />
        {saved && (
          <div className="pv-notice" data-testid="saved-notice">
            <Alert tone="success" title={t.methods.saved}>
              {formatDate(new Date().toISOString(), locale, true)}
            </Alert>
          </div>
        )}
        <FormActions>
          <Button variant="ghost" onClick={() => go("login-methods")}>
            {t.common.cancel}
          </Button>
          <Button type="submit" loading={busy} disabled={busy} data-testid="save-login-method">
            {creating ? t.common.create : t.common.save}
          </Button>
        </FormActions>
      </FormLayout>

      {current?.saml !== undefined && (
        <SpKeysSection
          method={current}
          busy={busy}
          onPrepare={() => setConfirm("prepare")}
          onRotate={() => setConfirm("rotate")}
        />
      )}
      {confirm === "delete" && current !== undefined && (
        <ConfirmDialog
          testId="login-method-delete-dialog"
          title={format(t.methods.deleteTitle, { name: current.displayName })}
          body={t.methods.deleteBody}
          confirmLabel={t.common.delete}
          danger
          busy={busy}
          confirmDisabled={inUse}
          error={inUse ? undefined : deleteError}
          onCancel={() => setConfirm(undefined)}
          onConfirm={() => void remove()}
        >
          {inUse && (
            <div className="pv-notice" data-testid="login-method-in-use">
              <Alert tone="warning" title={t.errors.inUse}>
                {current.enabled ? (
                  <Button
                    variant="secondary"
                    size="sm"
                    loading={busy}
                    data-testid="login-method-disable-instead"
                    onClick={() => void disableInstead()}
                  >
                    {t.methods.disableInstead}
                  </Button>
                ) : null}
              </Alert>
            </div>
          )}
        </ConfirmDialog>
      )}
      {(confirm === "prepare" || confirm === "rotate") && (
        <ConfirmDialog
          testId={`sp-keys-${confirm}-dialog`}
          title={confirm === "prepare" ? t.methods.prepareKeys : t.methods.rotateKeys}
          body={confirm === "prepare" ? t.methods.prepareBody : t.methods.rotateBody}
          confirmLabel={confirm === "prepare" ? t.methods.prepareKeys : t.methods.rotateKeys}
          busy={busy}
          error={error}
          onCancel={() => setConfirm(undefined)}
          onConfirm={() => void keys(confirm)}
        />
      )}
    </>
  );
}

function SamlConnection({
  draft,
  setDraft,
  message,
  errors,
  creating,
  current,
}: {
  readonly draft: SamlDraft;
  readonly setDraft: (draft: LoginMethodDraft) => void;
  readonly message: (field: string) => string | undefined;
  readonly errors: Errors;
  readonly creating: boolean;
  readonly current: LoginMethod | undefined;
}) {
  const { t, locale } = useI18n();
  return (
    <>
      <Field label={t.methods.idpEntityId} error={message("idpEntityId")}>
        <TextInput
          value={draft.idpEntityId}
          invalid={errors.idpEntityId !== undefined}
          data-testid="field-idpEntityId"
          onChange={(event) => setDraft({ ...draft, idpEntityId: event.target.value })}
        />
      </Field>
      <fieldset className="pv-fieldset">
        <legend className="pv-legend">{t.methods.metadataSource}</legend>
        <Radio
          label={t.methods.metadataFromUrl}
          name="metadataSource"
          checked={draft.metadataSource === "url"}
          onChange={() => setDraft({ ...draft, metadataSource: "url" })}
        />
        <Radio
          label={t.methods.metadataInline}
          name="metadataSource"
          checked={draft.metadataSource === "xml"}
          onChange={() => setDraft({ ...draft, metadataSource: "xml" })}
        />
      </fieldset>
      {draft.metadataSource === "url" ? (
        <Field label={t.methods.metadataUrl} error={message("metadataUrl")}>
          <TextInput
            value={draft.metadataUrl}
            invalid={errors.metadataUrl !== undefined}
            data-testid="field-metadataUrl"
            onChange={(event) => setDraft({ ...draft, metadataUrl: event.target.value })}
          />
        </Field>
      ) : (
        <Field
          label={t.methods.metadataXml}
          hint={creating ? undefined : t.methods.metadataXmlKeep}
          error={message("metadataXml")}
        >
          <Textarea
            rows={5}
            value={draft.metadataXml}
            invalid={errors.metadataXml !== undefined}
            onChange={(event) => setDraft({ ...draft, metadataXml: event.target.value })}
          />
        </Field>
      )}
      <Field label={t.methods.signingCertificate} error={message("metadataSigningCertificate")}>
        <Textarea
          rows={4}
          value={draft.metadataSigningCertificate}
          invalid={errors.metadataSigningCertificate !== undefined}
          onChange={(event) =>
            setDraft({ ...draft, metadataSigningCertificate: event.target.value })
          }
        />
      </Field>
      {draft.metadataSource === "url" && draft.metadataSigningCertificate.trim() === "" && (
        <Checkbox
          label={t.methods.allowUnsigned}
          checked={draft.allowUnsignedMetadata}
          onChange={(event) => setDraft({ ...draft, allowUnsignedMetadata: event.target.checked })}
        />
      )}
      {current?.saml !== undefined && (
        <>
          <CopyValue
            label={t.methods.spMetadata}
            value={current.saml.spMetadataUrl}
            testId="sp-metadata"
          />
          <p className="pv-muted">
            {t.methods.spMetadataHint}{" "}
            {current.saml.metadataStatus.cachedAt !== null &&
              format(t.methods.metadataStatus, {
                date: formatDate(current.saml.metadataStatus.cachedAt, locale, true),
              })}
          </p>
        </>
      )}
    </>
  );
}

function SpKeysSection({
  method,
  busy,
  onPrepare,
  onRotate,
}: {
  readonly method: LoginMethod;
  readonly busy: boolean;
  readonly onPrepare: () => void;
  readonly onRotate: () => void;
}) {
  const { t, locale } = useI18n();
  const keys = method.saml?.spKeys ?? [];
  const hasNext = keys.some((key) => key.state === "next");
  return (
    <section className="pv-section" aria-labelledby="sp-keys-title" data-testid="sp-keys">
      <div className="pv-section-head">
        <h2 className="pv-section-title" id="sp-keys-title">
          {t.methods.spKeys}
        </h2>
        <div className="pv-header-actions">
          <Button
            variant="secondary"
            size="sm"
            disabled={busy || hasNext}
            onClick={onPrepare}
            data-testid="prepare-sp-keys"
          >
            {t.methods.prepareKeys}
          </Button>
          <Button
            size="sm"
            disabled={busy || !hasNext}
            onClick={onRotate}
            data-testid="rotate-sp-keys"
          >
            {t.methods.rotateKeys}
          </Button>
        </div>
      </div>
      <DataTable
        caption={t.methods.spKeys}
        density="compact"
        rows={[...keys]}
        rowKey={(key) => key.id}
        columns={[
          {
            key: "purpose",
            header: t.methods.keyUse,
            cell: (key) => t.methods.keyPurpose[key.purpose],
          },
          {
            key: "state",
            header: t.common.status,
            cell: (key) => (
              <Badge
                color={
                  key.state === "active" ? "success" : key.state === "next" ? "info" : "neutral"
                }
              >
                {t.methods.keyState[key.state]}
              </Badge>
            ),
          },
          {
            key: "notAfter",
            header: t.methods.validUntil,
            cell: (key) => formatDate(key.notAfter, locale),
          },
        ]}
      />
    </section>
  );
}
