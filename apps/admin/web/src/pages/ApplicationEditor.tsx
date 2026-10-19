import {
  Button,
  Checkbox,
  Field,
  Select,
  Switch,
  Textarea,
  TextInput,
} from "@portvakt/design-system/components";
import { useState } from "react";
import { ApiError } from "../api";
import { plural, useI18n } from "../i18n";
import type {
  Application,
  ApplicationUsage,
  ApplicationWithSecret,
  DeclaredKey,
  DeclaredRole,
  RepresentationMode,
} from "../types";
import { ActionError, ConfirmDialog, Modal, useAdmin } from "../ui";

const lines = (value: string): string[] =>
  value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "");

type AuthMethod = Application["clientAuth"]["method"];
const EXTRA_SCOPES = ["pin", "hsa"] as const;

interface Draft {
  name: string;
  enabled: boolean;
  method: AuthMethod;
  jwksUri: string;
  redirectUris: string;
  postLogoutRedirectUris: string;
  roles: string;
  attributeKeys: string;
  representationMode: RepresentationMode;
  allowedExtraScopes: readonly ("pin" | "hsa")[];
}

function draftOf(application: Application): Draft {
  return {
    name: application.name,
    enabled: application.enabled,
    method: application.clientAuth.method,
    jwksUri:
      application.clientAuth.method === "private_key_jwt"
        ? (application.clientAuth.jwksUri ?? "")
        : "",
    redirectUris: application.redirectUris.join("\n"),
    postLogoutRedirectUris: application.postLogoutRedirectUris.join("\n"),
    roles: application.roles.map((role) => role.role).join("\n"),
    attributeKeys: application.attributeKeys.map((key) => key.key).join("\n"),
    representationMode: application.representationMode,
    allowedExtraScopes: application.allowedExtraScopes,
  };
}

/** The usage counts worth listing (non-zero), as label and number. */
export function usageLines(
  usage: ApplicationUsage,
  t: ReturnType<typeof useI18n>["t"],
): readonly { readonly key: string; readonly label: string; readonly count: number }[] {
  return (Object.keys(t.applications.usage) as (keyof ApplicationUsage)[])
    .map((key) => ({
      key,
      label: plural(t.applications.usage[key], usage[key]),
      count: usage[key],
    }))
    .filter((line) => line.count > 0);
}

export function UsageList({
  usage,
  testId,
}: {
  readonly usage: ApplicationUsage;
  readonly testId: string;
}) {
  const { t } = useI18n();
  const items = usageLines(usage, t);
  if (items.length === 0) return <p className="pv-muted">{t.applications.usageNone}</p>;
  return (
    <ul className="pv-plain-list" data-testid={testId}>
      {items.map((item) => (
        <li key={item.key}>
          <strong>{item.count}</strong> {item.label}
        </li>
      ))}
    </ul>
  );
}

/**
 * Edits an application of the registry (platform administrators). Removing roles or attribute
 * keys removes every assignment and rule of them: the dialog says how many first.
 */
export function ApplicationEditor({
  application,
  onClose,
  onSaved,
}: {
  readonly application: Application;
  readonly onClose: () => void;
  readonly onSaved: (secret: string | undefined) => void;
}) {
  const { api } = useAdmin();
  const { t } = useI18n();
  const [draft, setDraft] = useState<Draft>(() => draftOf(application));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [impact, setImpact] = useState<
    | {
        readonly usage: ApplicationUsage;
        readonly roles: readonly string[];
        readonly keys: readonly string[];
      }
    | undefined
  >();
  const set = <K extends keyof Draft>(key: K, value: Draft[K]) =>
    setDraft({ ...draft, [key]: value });

  const roles = (): DeclaredRole[] =>
    lines(draft.roles).map((role) => ({
      role,
      description: application.roles.find((item) => item.role === role)?.description ?? null,
    }));
  const keys = (): DeclaredKey[] =>
    lines(draft.attributeKeys).map((key) => ({
      key,
      description: application.attributeKeys.find((item) => item.key === key)?.description ?? null,
    }));

  const body = () => {
    const changed = <T,>(next: T, current: T) =>
      JSON.stringify(next) === JSON.stringify(current) ? undefined : next;
    const clientAuth =
      draft.method === application.clientAuth.method &&
      (draft.method !== "private_key_jwt" || draft.jwksUri === draftOf(application).jwksUri)
        ? undefined
        : draft.method === "private_key_jwt"
          ? { method: draft.method, jwksUri: draft.jwksUri.trim() }
          : { method: draft.method };
    const nextRoles = roles();
    const nextKeys = keys();
    const entries = {
      name: changed(draft.name.trim(), application.name),
      enabled: changed(draft.enabled, application.enabled),
      clientAuth,
      redirectUris: changed(lines(draft.redirectUris), [...application.redirectUris]),
      postLogoutRedirectUris: changed(lines(draft.postLogoutRedirectUris), [
        ...application.postLogoutRedirectUris,
      ]),
      roles: changed(
        nextRoles.map((role) => role.role),
        application.roles.map((role) => role.role),
      )
        ? nextRoles.map((role) => (role.description === null ? { role: role.role } : { ...role }))
        : undefined,
      attributeKeys: changed(
        nextKeys.map((key) => key.key),
        application.attributeKeys.map((key) => key.key),
      )
        ? nextKeys.map((key) => (key.description === null ? { key: key.key } : { ...key }))
        : undefined,
      representationMode: changed(draft.representationMode, application.representationMode),
      allowedExtraScopes: changed(
        [...draft.allowedExtraScopes].sort(),
        [...application.allowedExtraScopes].sort(),
      ),
    };
    return Object.fromEntries(Object.entries(entries).filter(([, value]) => value !== undefined));
  };

  const save = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const result = await api.send<ApplicationWithSecret>(
        "PATCH",
        `/applications/${application.id}`,
        { body: body(), etag: application.etag },
      );
      setImpact(undefined);
      onSaved(result.clientSecret);
    } catch (failure) {
      setImpact(undefined);
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

  const submit = async () => {
    const found: Record<string, string> = {};
    if (draft.name.trim() === "") found.name = t.validation.required;
    if (lines(draft.redirectUris).length === 0) found.redirectUris = t.validation.required;
    // An application already on private_key_jwt may keep inline keys (no URI to show).
    if (
      draft.method === "private_key_jwt" &&
      draft.jwksUri.trim() === "" &&
      (application.clientAuth.method !== "private_key_jwt" || draftOf(application).jwksUri !== "")
    )
      found.jwksUri = t.validation.required;
    setErrors(found);
    if (Object.keys(found).length > 0) return;
    const nextRoles = new Set(lines(draft.roles));
    const nextKeys = new Set(lines(draft.attributeKeys));
    const removedRoles = application.roles
      .map((role) => role.role)
      .filter((role) => !nextRoles.has(role));
    const removedKeys = application.attributeKeys
      .map((key) => key.key)
      .filter((key) => !nextKeys.has(key));
    if (removedRoles.length === 0 && removedKeys.length === 0) {
      await save();
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      const usage = await api.send<ApplicationUsage>(
        "POST",
        `/applications/${application.id}/removal-impact`,
        { body: { roles: removedRoles, attributeKeys: removedKeys } },
      );
      setImpact({ usage, roles: removedRoles, keys: removedKeys });
    } catch (failure) {
      setError(failure);
    } finally {
      setBusy(false);
    }
  };

  if (impact !== undefined) {
    return (
      <ConfirmDialog
        testId="application-removal-dialog"
        title={t.applications.removalTitle}
        body={t.applications.removalBody}
        confirmLabel={t.applications.removalConfirm}
        danger
        busy={busy}
        error={error}
        onCancel={() => setImpact(undefined)}
        onConfirm={() => void save()}
      >
        <p className="pv-dialog-text">
          {[...impact.roles, ...impact.keys].map((name) => (
            <code key={name} className="pv-code-inline">
              {name}
            </code>
          ))}
        </p>
        <UsageList usage={impact.usage} testId="application-removal-usage" />
      </ConfirmDialog>
    );
  }

  return (
    <Modal
      title={`${t.common.edit}: ${application.name}`}
      onClose={onClose}
      testId="application-edit-dialog"
      footer={
        <div className="pv-dialog-actions">
          <Button variant="ghost" onClick={onClose}>
            {t.common.cancel}
          </Button>
          <Button
            loading={busy}
            disabled={busy}
            onClick={() => void submit()}
            data-testid="application-edit-save"
          >
            {t.common.save}
          </Button>
        </div>
      }
    >
      <div className="pv-form">
        <p className="pv-muted">
          {t.applications.clientId}: <code className="pv-code-inline">{application.clientId}</code>
        </p>
        <Field label={t.common.name} error={errors.name}>
          <TextInput
            value={draft.name}
            invalid={errors.name !== undefined}
            data-testid="application-edit-name"
            onChange={(event) => set("name", event.target.value)}
          />
        </Field>
        <Switch
          label={t.applications.enabledGlobally}
          checked={draft.enabled}
          data-testid="application-edit-enabled"
          onChange={(event) => set("enabled", event.target.checked)}
        />
        <Field
          label={t.applications.authMethod}
          hint={t.applications.authMethodHint}
          error={errors.clientAuth}
        >
          <Select
            value={draft.method}
            onChange={(event) => set("method", event.target.value as AuthMethod)}
          >
            <option value="client_secret_basic">client_secret_basic</option>
            <option value="client_secret_post">client_secret_post</option>
            <option value="private_key_jwt">private_key_jwt</option>
          </Select>
        </Field>
        {draft.method === "private_key_jwt" && (
          <Field label={t.applications.jwksUri} error={errors.jwksUri}>
            <TextInput
              value={draft.jwksUri}
              inputMode="url"
              invalid={errors.jwksUri !== undefined}
              onChange={(event) => set("jwksUri", event.target.value)}
            />
          </Field>
        )}
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
        <Field label={t.applications.roles} hint={t.applications.rolesHint} error={errors.roles}>
          <Textarea
            rows={3}
            value={draft.roles}
            data-testid="application-edit-roles"
            onChange={(event) => set("roles", event.target.value)}
          />
        </Field>
        <Field
          label={t.applications.attributeKeys}
          hint={t.applications.attributeKeysHint}
          error={errors.attributeKeys}
        >
          <Textarea
            rows={2}
            value={draft.attributeKeys}
            onChange={(event) => set("attributeKeys", event.target.value)}
          />
        </Field>
        <Field label={t.applications.representation} error={errors.representationMode}>
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
        <fieldset className="pv-fieldset">
          <legend className="pv-legend">{t.applications.extraScopes}</legend>
          {EXTRA_SCOPES.map((scope) => (
            <Checkbox
              key={scope}
              label={t.applications.extraScopeNames[scope]}
              checked={draft.allowedExtraScopes.includes(scope)}
              onChange={(event) =>
                set(
                  "allowedExtraScopes",
                  event.target.checked
                    ? [...draft.allowedExtraScopes, scope]
                    : draft.allowedExtraScopes.filter((item) => item !== scope),
                )
              }
            />
          ))}
        </fieldset>
        <ActionError error={error} />
      </div>
    </Modal>
  );
}
