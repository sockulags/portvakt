import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Field,
  Textarea,
} from "@portvakt/design-system/components";
import { DataTable, PageHeader } from "@portvakt/design-system/patterns";
import { useState } from "react";
import { ApiError } from "../api";
import { format, formatDate, formatTime, useI18n } from "../i18n";
import type { KeyRotation, SigningKeys } from "../types";
import { ConfirmDialog, ErrorState, useAdmin, useResource } from "../ui";

const STATE_COLOR = {
  active: "success",
  next: "info",
  retiring: "warning",
  retired: "neutral",
} as const;

export function KeysPage() {
  const { api, me } = useAdmin();
  const { t, locale } = useI18n();
  const keys = useResource(() => api.get<SigningKeys>("/signing-keys"), "keys");
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [emergency, setEmergency] = useState(false);
  const [reasonError, setReasonError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  /** The last rotation's outcome: activated now, or published and activated later. */
  const [done, setDone] = useState<KeyRotation["status"] | undefined>();

  const rotate = async () => {
    if (reason.trim() === "") {
      setReasonError(t.validation.required);
      return;
    }
    setBusy(true);
    setError(undefined);
    setReasonError(undefined);
    try {
      const result = await api.send<KeyRotation>("POST", "/signing-keys/rotate", {
        body: { reason: reason.trim(), emergency },
        etag: keys.data?.etag,
      });
      keys.set(result.keys);
      setOpen(false);
      setDone(result.status);
    } catch (failure) {
      setError(failure);
      if (failure instanceof ApiError) setReasonError(failure.fieldErrors().reason);
      if (failure instanceof ApiError && failure.isConflict) keys.reload();
    } finally {
      setBusy(false);
    }
  };

  // A manual rotation's published key, waiting for its activation time.
  const pending = keys.data?.keys.find((key) => key.state === "next" && key.activateAt !== null);

  return (
    <>
      <PageHeader
        title={t.keys.title}
        description={t.keys.description}
        actions={
          me.platform && (
            <Button
              data-testid="rotate-keys"
              disabled={keys.data === undefined}
              onClick={() => {
                setReason("");
                setEmergency(false);
                setReasonError(undefined);
                setError(undefined);
                setDone(undefined);
                setOpen(true);
              }}
            >
              {t.keys.rotate}
            </Button>
          )
        }
      />
      {done === "activated" && (
        <div className="pv-notice" data-testid="keys-rotated">
          <Alert tone="success" title={t.keys.rotated}>
            {formatDate(new Date().toISOString(), locale, true)}
          </Alert>
        </div>
      )}
      {pending?.activateAt != null && (
        <div className="pv-notice" data-testid="keys-scheduled" data-kid={pending.kid}>
          <Alert
            tone="info"
            title={format(t.keys.scheduled, { time: formatTime(pending.activateAt, locale) })}
          >
            {formatDate(pending.activateAt, locale, true)}
          </Alert>
        </div>
      )}
      {keys.error !== undefined ? (
        <ErrorState error={keys.error} onRetry={keys.reload} />
      ) : (
        <>
          {keys.data?.nextScheduledRotationAt != null && (
            <p className="pv-muted">
              {format(t.keys.nextRotation, {
                date: formatDate(keys.data.nextScheduledRotationAt, locale),
              })}
            </p>
          )}
          <DataTable
            caption={t.keys.title}
            loading={keys.loading && keys.data === undefined}
            rows={[...(keys.data?.keys ?? [])]}
            rowKey={(key) => key.kid}
            columns={[
              {
                key: "kid",
                header: t.keys.kid,
                cell: (key) => (
                  <code className="pv-code-inline" data-testid={`key-${key.state}`}>
                    {key.kid}
                  </code>
                ),
              },
              {
                key: "state",
                header: t.keys.state,
                cell: (key) => (
                  <Badge color={STATE_COLOR[key.state]}>{t.keys.states[key.state]}</Badge>
                ),
              },
              {
                key: "created",
                header: t.common.created,
                cell: (key) => formatDate(key.createdAt, locale, true),
              },
              {
                key: "activated",
                header: t.keys.activated,
                cell: (key) => formatDate(key.activatedAt, locale, true),
              },
              {
                key: "retiring",
                header: t.keys.retiring,
                cell: (key) => formatDate(key.retiringAt, locale, true),
              },
              {
                key: "activates",
                header: t.keys.activatesAt,
                cell: (key) =>
                  key.activateAt === null ? "–" : formatDate(key.activateAt, locale, true),
              },
            ]}
          />
        </>
      )}
      {open && (
        <ConfirmDialog
          testId="rotate-keys-dialog"
          title={t.keys.rotateTitle}
          body={t.keys.rotateBody}
          confirmLabel={t.keys.rotate}
          danger={emergency}
          busy={busy}
          error={reasonError === undefined ? error : undefined}
          onCancel={() => setOpen(false)}
          onConfirm={() => void rotate()}
        >
          <div className="pv-form">
            <Field label={t.keys.reason} hint={t.keys.reasonHint} error={reasonError}>
              <Textarea
                rows={2}
                value={reason}
                invalid={reasonError !== undefined}
                data-testid="rotate-reason"
                onChange={(event) => setReason(event.target.value)}
              />
            </Field>
            {me.platform && (
              <>
                <Checkbox
                  label={t.keys.emergency}
                  checked={emergency}
                  data-testid="rotate-emergency"
                  onChange={(event) => setEmergency(event.target.checked)}
                />
                {emergency && (
                  <Alert tone="danger" title={t.keys.emergency}>
                    {t.keys.emergencyHint}
                  </Alert>
                )}
              </>
            )}
          </div>
        </ConfirmDialog>
      )}
    </>
  );
}
