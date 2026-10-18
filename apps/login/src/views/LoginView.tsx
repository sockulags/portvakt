import { Alert, Button, Spinner } from "@portvakt/design-system/components";
import { useEffect, useRef, useState } from "react";
import type { InteractionDetails, LoginApi, LoginChoice, LoginErrorCode } from "../api";
import { HomeRealmForm, type HomeRealmOutcome } from "../components/HomeRealmForm";
import { MethodList } from "../components/MethodList";
import { Page } from "../components/Page";
import { format, useI18n } from "../i18n";
import { ErrorView } from "./ErrorView";

/** Errors after which the chooser cannot help: there is nothing left to try here. */
const TERMINAL: ReadonlySet<LoginErrorCode> = new Set(["no_acceptable_method"]);

type State =
  | { readonly status: "loading" }
  | { readonly status: "failed"; readonly error: LoginErrorCode }
  | { readonly status: "ready"; readonly details: InteractionDetails }
  | { readonly status: "redirecting" };

interface LoginViewProps {
  readonly api: LoginApi;
  /** The error the server reported for this interaction (a failed upstream login). */
  readonly error?: LoginErrorCode | undefined;
  /** Leaves the page (`window.location.assign`); replaceable in tests. */
  readonly navigate: (url: string) => void;
}

/**
 * Choose a login method: cards per method (employees and citizens grouped), home realm
 * discovery by email when a method has home realm domains, and the error of a failed attempt
 * with the methods below it as the retry.
 */
export function LoginView({ api, error, navigate }: LoginViewProps) {
  const { t } = useI18n();
  const [state, setState] = useState<State>({ status: "loading" });
  const [actionError, setActionError] = useState<string | undefined>();
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
      <Page heading={t.signIn.heading} viewKey="loading" testId="login-loading">
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
          <span>{t.redirecting.body}</span>
        </div>
      </Page>
    );
  }

  const { details } = state;
  const choose = async (choice: LoginChoice): Promise<string> => {
    setActionError(undefined);
    const result = await api.login(choice, details.csrfToken);
    if (result.ok) {
      setState({ status: "redirecting" });
      navigate(result.redirectTo);
      return "redirecting";
    }
    return result.error;
  };
  const chooseMethod = (loginMethodId: string): void => {
    void choose({ loginMethodId }).then((outcome) => {
      if (outcome !== "redirecting") setActionError(outcome);
    });
  };
  const chooseEmail = async (email: string): Promise<HomeRealmOutcome> => {
    const outcome = await choose({ email });
    if (outcome === "redirecting") return "redirecting";
    return outcome === "no_home_realm" ? "not_found" : "failed";
  };
  const cancel = (): void => {
    void api.abort(details.csrfToken).then((result) => {
      if (result.ok) {
        setState({ status: "redirecting" });
        navigate(result.redirectTo);
      } else setActionError(result.error);
    });
  };

  const shownError =
    (actionError === undefined ? error : actionErrorCode(actionError)) ?? undefined;
  const terminal = shownError !== undefined && TERMINAL.has(shownError);
  const intro =
    details.application === null
      ? t.signIn.intro
      : format(t.signIn.introApp, { app: details.application.name });

  return (
    <Page
      heading={t.signIn.heading}
      viewKey="login"
      context={details.tenant.name}
      testId="login-view"
    >
      <p className="pv-intro">{intro}</p>
      {shownError !== undefined && (
        <div className="pv-alert" data-testid="login-error" data-error={shownError}>
          <Alert
            tone={shownError === "upstream_denied" ? "warning" : "danger"}
            title={t.errors[shownError].title}
          >
            {t.errors[shownError].body}
          </Alert>
        </div>
      )}
      {!terminal && details.homeRealmDiscovery && (
        <>
          <HomeRealmForm initialEmail={details.loginHint} onSubmit={chooseEmail} />
          <p className="pv-divider" aria-hidden="true">
            <span>{t.hrd.or}</span>
          </p>
        </>
      )}
      {!terminal && (
        <MethodList methods={details.methods} onChoose={(method) => chooseMethod(method.id)} />
      )}
      <div className="pv-actions">
        <Button variant="ghost" data-testid="cancel-login" onClick={cancel}>
          {t.cancel}
        </Button>
      </div>
    </Page>
  );
}

/** API error strings mapped to the error views; unknown ones are generic failures. */
function actionErrorCode(error: string): LoginErrorCode {
  switch (error) {
    case "login_method_unavailable":
    case "upstream_unavailable":
    case "upstream_error":
    case "interaction_expired":
      return error;
    case "interaction_not_found":
      return "interaction_expired";
    default:
      return "request_failed";
  }
}
