import { Alert, Button, Spinner, StatusIcon } from "@portvakt/design-system/components";
import { useEffect, useRef, useState } from "react";
import type {
  LoginErrorCode,
  RepresentationApi,
  RepresentationChoice,
  RepresentationDetails,
} from "../api";
import { PartyList } from "../components/PartyList";
import { Page } from "../components/Page";
import { format, useI18n } from "../i18n";
import { ErrorView } from "./ErrorView";

type State =
  | { readonly status: "loading" }
  | { readonly status: "failed"; readonly error: LoginErrorCode }
  | { readonly status: "ready"; readonly details: RepresentationDetails }
  | { readonly status: "redirecting" };

interface RepresentationViewProps {
  readonly api: RepresentationApi;
  /** `no_representation_available`: nothing can be chosen, only the way back is offered. */
  readonly error?: LoginErrorCode | undefined;
  readonly navigate: (url: string) => void;
}

/**
 * Choose whom to act for in this application: "Myself" (when the application allows it) or a
 * party the person holds a valid authorisation for. The server re-checks the choice; a refused
 * one shows an alert above the list, which is the retry.
 */
export function RepresentationView({ api, error, navigate }: RepresentationViewProps) {
  const { t } = useI18n();
  const r = t.representation;
  const [state, setState] = useState<State>({ status: "loading" });
  const [actionError, setActionError] = useState<LoginErrorCode | undefined>();
  const [busy, setBusy] = useState(false);
  const statusRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let active = true;
    void api.details().then((result) => {
      if (!active) return;
      setState(
        result.ok
          ? { status: "ready", details: result.details }
          : { status: "failed", error: result.error },
      );
    });
    return () => {
      active = false;
    };
  }, [api]);

  useEffect(() => {
    if (state.status === "redirecting") statusRef.current?.focus();
  }, [state.status]);

  if (state.status === "failed") return <ErrorView code={state.error} />;
  if (state.status === "loading") {
    return (
      <Page heading={r.heading} viewKey="loading" testId="representation-loading">
        <div className="pv-status" role="status">
          <Spinner />
          <span>{t.loading}</span>
        </div>
      </Page>
    );
  }
  if (state.status === "redirecting") {
    return (
      <Page heading={t.redirecting.title} viewKey="redirecting" testId="redirecting">
        <div className="pv-status" role="status" aria-live="polite" tabIndex={-1} ref={statusRef}>
          <Spinner />
          <span>{r.continuing}</span>
        </div>
      </Page>
    );
  }

  const { details } = state;
  const leave = (result: { ok: true; redirectTo: string } | { ok: false; error: string }) => {
    setBusy(false);
    if (result.ok) {
      setState({ status: "redirecting" });
      navigate(result.redirectTo);
    } else setActionError(actionErrorCode(result.error));
  };
  const choose = (choice: RepresentationChoice): void => {
    setActionError(undefined);
    setBusy(true);
    void api.choose(choice, details.csrfToken).then(leave);
  };
  const cancel = (): void => {
    setBusy(true);
    void api.abort(details.csrfToken).then(leave);
  };

  const cancelButton = (
    <div className="pv-actions">
      <Button variant="ghost" data-testid="cancel-representation" disabled={busy} onClick={cancel}>
        {t.cancel}
      </Button>
    </div>
  );

  if (error === "no_representation_available") {
    const text = t.errors.no_representation_available;
    return (
      <Page
        heading={text.title}
        viewKey="representation-none"
        context={details.tenant.name}
        testId="representation-view"
      >
        <div className="pv-error" data-testid="representation-error" data-error={error}>
          <StatusIcon tone="warning" />
          <p className="pv-intro">{text.body}</p>
        </div>
        {cancelButton}
      </Page>
    );
  }

  const shownError = actionError ?? error;
  return (
    <Page
      heading={r.heading}
      viewKey="representation"
      context={details.tenant.name}
      testId="representation-view"
    >
      <p className="pv-intro">{format(r.intro, { app: details.application.name })}</p>
      {shownError !== undefined && (
        <div className="pv-alert" data-testid="representation-error" data-error={shownError}>
          <Alert tone="danger" title={t.errors[shownError].title}>
            {t.errors[shownError].body}
          </Alert>
        </div>
      )}
      <PartyList
        parties={details.parties}
        allowSelf={details.allowSelf}
        onChoose={choose}
        disabled={busy}
      />
      {cancelButton}
    </Page>
  );
}

function actionErrorCode(error: string): LoginErrorCode {
  switch (error) {
    case "representation_not_allowed":
    case "interaction_expired":
      return error;
    case "interaction_not_found":
      return "interaction_expired";
    default:
      return "request_failed";
  }
}
