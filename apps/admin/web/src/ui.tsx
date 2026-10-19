import { Alert, Button, DialogStage, Spinner } from "@portvakt/design-system/components";
import { EmptyState } from "@portvakt/design-system/patterns";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { ApiError, type ApiClient } from "./api";
import { format, useI18n, type Messages } from "./i18n";
import type { Location, Page } from "./router";
import type { Me, Tenant } from "./types";

/** What every page works with: the API, the administrator and the tenant administered. */
export interface Admin {
  readonly api: ApiClient;
  readonly me: Me;
  /** The tenant being administered (the own tenant, or the platform admin's choice). */
  readonly tenant: Tenant;
  /** Platform administrators: every tenant (for the switcher); others: their own. */
  readonly tenants: readonly Tenant[];
  readonly location: Location;
  readonly go: (page: Page, id?: string) => void;
  readonly reloadTenants: () => Promise<void>;
}

export const AdminContext = createContext<Admin | undefined>(undefined);

export function useAdmin(): Admin {
  const admin = useContext(AdminContext);
  if (admin === undefined) throw new Error("useAdmin outside the portal");
  return admin;
}

export interface Resource<T> {
  readonly data: T | undefined;
  readonly error: unknown;
  readonly loading: boolean;
  readonly reload: () => void;
  readonly set: (data: T) => void;
}

/** Loads data for a page and reloads it on demand (or when `key` changes). */
export function useResource<T>(load: () => Promise<T>, key: string): Resource<T> {
  const [generation, setGeneration] = useState(0);
  const token = `${key}#${generation}`;
  // The last result and the request it answers: loading while it answers an older one.
  const [result, setResult] = useState<{
    readonly token: string;
    readonly data: T | undefined;
    readonly error: unknown;
  }>({ token: "", data: undefined, error: undefined });
  const loadRef = useRef(load);
  useEffect(() => {
    loadRef.current = load;
  });
  useEffect(() => {
    let current = true;
    loadRef.current().then(
      (data) => {
        if (current) setResult({ token, data, error: undefined });
      },
      (error: unknown) => {
        if (current) setResult({ token, data: undefined, error });
      },
    );
    return () => {
      current = false;
    };
  }, [token]);
  const reload = useCallback(() => setGeneration((value) => value + 1), []);
  const set = useCallback((data: T) => setResult({ token, data, error: undefined }), [token]);
  const loading = result.token !== token;
  return {
    // Data stays visible while the same resource reloads, never across another key (tenant).
    data: result.token.startsWith(`${key}#`) ? result.data : undefined,
    error: loading ? undefined : result.error,
    loading,
    reload,
    set,
  };
}

/** The message for an API error, in the current language. */
export function errorText(error: unknown, t: Messages): string {
  if (!(error instanceof ApiError)) return t.errors.body;
  if (error.code === "network") return t.errors.network;
  if (error.status === 403) return t.errors.forbidden;
  if (error.status === 404) return t.errors.notFound;
  if (error.isConflict) return t.errors.conflictBody;
  if (error.code === "self_lockout") return t.errors.selfLockout;
  if (error.code === "in_use") return t.errors.inUse;
  if (error.code === "last_identity") return t.errors.lastIdentity;
  if (error.code === "conflict") return t.errors.duplicate;
  if (error.status === 400) return t.errors.validation;
  return t.errors.body;
}

export function Loading({ label }: { readonly label?: string }) {
  const { t } = useI18n();
  return (
    <div className="pv-loading" role="status" data-testid="loading">
      <Spinner />
      <span>{label ?? t.common.loading}</span>
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
}: {
  readonly error: unknown;
  readonly onRetry?: () => void;
}) {
  const { t } = useI18n();
  return (
    <div data-testid="error-state">
      <EmptyState
        icon="alert"
        tone="danger"
        title={t.errors.title}
        description={errorText(error, t)}
        actions={
          onRetry === undefined ? undefined : (
            <Button variant="secondary" onClick={onRetry}>
              {t.common.retry}
            </Button>
          )
        }
      />
    </div>
  );
}

/** Shown when a save was refused with 412: somebody else changed the resource. */
export function ConflictNotice({ onReload }: { readonly onReload: () => void }) {
  const { t } = useI18n();
  return (
    <div className="pv-notice" data-testid="conflict-notice">
      <Alert tone="warning" title={t.errors.conflictTitle}>
        {t.errors.conflictBody}
      </Alert>
      <Button variant="secondary" size="sm" onClick={onReload} data-testid="conflict-reload">
        {t.common.reload}
      </Button>
    </div>
  );
}

/** An error banner for a failed action (conflicts get their own notice with a reload). */
export function ActionError({
  error,
  onReload,
}: {
  readonly error: unknown;
  readonly onReload?: () => void;
}) {
  const { t } = useI18n();
  if (error === undefined) return null;
  if (error instanceof ApiError && error.isConflict && onReload !== undefined) {
    return <ConflictNotice onReload={onReload} />;
  }
  return (
    <div className="pv-notice" data-testid="action-error">
      <Alert tone="danger" title={t.errors.title}>
        {errorText(error, t)}
      </Alert>
    </div>
  );
}

const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * A modal dialog: the design system's dialog over a fixed scrim. Escape and the close button
 * close it, focus moves into it and stays there (Tab cycles), and returns when it closes.
 */
export function Modal({
  title,
  children,
  footer,
  onClose,
  testId,
}: {
  readonly title: string;
  readonly children: ReactNode;
  readonly footer: ReactNode;
  readonly onClose: () => void;
  readonly testId: string;
}) {
  const container = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  });
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const element = container.current;
    // The design system's dialog element carries the dialog semantics: modal, and labelled by
    // its visible heading (instead of a duplicate aria-label).
    const dialog = element?.querySelector<HTMLElement>("[role=dialog]");
    const heading = dialog?.querySelector<HTMLElement>("h1, h2, h3");
    if (dialog !== null && dialog !== undefined) {
      dialog.setAttribute("aria-modal", "true");
      if (heading !== null && heading !== undefined) {
        heading.id = titleId;
        dialog.setAttribute("aria-labelledby", titleId);
        dialog.removeAttribute("aria-label");
      }
    }
    const first = element?.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab" || element === null) return;
      const items = [...element.querySelectorAll<HTMLElement>(FOCUSABLE)];
      if (items.length === 0) return;
      const firstItem = items[0]!;
      const lastItem = items[items.length - 1]!;
      if (event.shiftKey && document.activeElement === firstItem) {
        event.preventDefault();
        lastItem.focus();
      } else if (!event.shiftKey && document.activeElement === lastItem) {
        event.preventDefault();
        firstItem.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      previous?.focus();
    };
  }, [titleId]);
  return (
    <div className="pv-modal" ref={container} data-testid={testId}>
      <DialogStage title={title} footer={footer}>
        {children}
      </DialogStage>
    </div>
  );
}

/** Asks before a consequential action. */
export function ConfirmDialog({
  title,
  body,
  confirmLabel,
  danger = false,
  busy = false,
  confirmDisabled = false,
  error,
  onConfirm,
  onCancel,
  children,
  testId,
}: {
  readonly title: string;
  readonly body: string;
  readonly confirmLabel: string;
  readonly danger?: boolean;
  readonly busy?: boolean;
  /** Keeps the confirm button disabled (for example until a typed confirmation matches). */
  readonly confirmDisabled?: boolean;
  readonly error?: unknown;
  readonly onConfirm: () => void;
  readonly onCancel: () => void;
  readonly children?: ReactNode;
  readonly testId: string;
}) {
  const { t } = useI18n();
  return (
    <Modal
      title={title}
      onClose={onCancel}
      testId={testId}
      footer={
        <div className="pv-dialog-actions">
          <Button variant="ghost" onClick={onCancel} data-testid={`${testId}-cancel`}>
            {t.common.cancel}
          </Button>
          <Button
            variant={danger ? "danger" : "primary"}
            loading={busy}
            disabled={busy || confirmDisabled}
            onClick={onConfirm}
            data-testid={`${testId}-confirm`}
          >
            {confirmLabel}
          </Button>
        </div>
      }
    >
      {body === "" ? null : <p className="pv-dialog-text">{body}</p>}
      {children}
      <ActionError error={error} />
    </Modal>
  );
}

/** Copies a value to the clipboard and says so. */
export function CopyButton({ value, testId }: { readonly value: string; readonly testId: string }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 2000);
    return () => clearTimeout(timer);
  }, [copied]);
  return (
    <Button
      variant="secondary"
      size="sm"
      data-testid={testId}
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => setCopied(true));
      }}
    >
      {copied ? t.common.copied : t.common.copy}
    </Button>
  );
}

/** A value with a copy button, for URLs administrators register elsewhere. */
export function CopyValue({
  label,
  value,
  testId,
}: {
  readonly label: string;
  readonly value: string;
  readonly testId: string;
}) {
  const id = useId();
  return (
    <div className="pv-copy">
      <span className="pv-copy-label" id={id}>
        {label}
      </span>
      {/* The group carries the label: `code` may not be named (ARIA prohibits it for its role). */}
      <div className="pv-copy-row" role="group" aria-labelledby={id}>
        <code className="pv-code" data-testid={`${testId}-value`}>
          {value}
        </code>
        <CopyButton value={value} testId={`${testId}-copy`} />
      </div>
    </div>
  );
}

/** Field errors of the server, translated into the form's message. */
export function serverFieldMessage(message: string, t: Messages): string {
  return format(t.validation.server, { message });
}
