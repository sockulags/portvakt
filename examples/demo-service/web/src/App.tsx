import { Alert, Badge, Button, Card, Spinner } from "@portvakt/design-system/components";
import { PageHeader } from "@portvakt/design-system/patterns";
import { useEffect, useState, type ReactNode } from "react";
import {
  callApi,
  loadConfig,
  loadSession,
  loginUrl,
  selectRepresentationUrl,
  stepUpUrl,
  type ApiCallResult,
  type AppConfig,
  type Session,
  type SessionPrincipal,
} from "./api";
import { acrName, formatTime, TEXT } from "./text";

type State =
  | { readonly kind: "loading" }
  | { readonly kind: "failed" }
  | { readonly kind: "ready"; readonly config: AppConfig; readonly session: Session };

const go = (url: string) => {
  window.location.assign(url);
};

export function App() {
  const [state, setState] = useState<State>({ kind: "loading" });
  /** Bumped to load the configuration and session again (after the session ended). */
  const [generation, setGeneration] = useState(0);

  useEffect(() => {
    let current = true;
    Promise.all([loadConfig(), loadSession()])
      .then(([config, session]) => {
        if (!current) return;
        document.title = config.appName;
        setState({ kind: "ready", config, session });
      })
      .catch(() => {
        if (current) setState({ kind: "failed" });
      });
    return () => {
      current = false;
    };
  }, [generation]);

  if (state.kind === "loading") {
    return (
      <main className="demo-page" aria-busy="true">
        <Spinner />
        <span className="demo-visually-hidden">{TEXT.loading}</span>
      </main>
    );
  }
  if (state.kind === "failed") {
    return (
      <main className="demo-page">
        <div data-testid="load-error">
          <Alert tone="danger" title={TEXT.errorTitle}>
            {TEXT.loadFailed}
          </Alert>
        </div>
      </main>
    );
  }
  const { config, session } = state;
  return (
    <main className="demo-page">
      <div className="demo-column">
        {session.authenticated ? (
          <SignedIn
            config={config}
            principal={session.principal}
            expiresAt={session.expiresAt}
            csrfToken={session.csrfToken}
            onSessionEnded={() => setGeneration((value) => value + 1)}
          />
        ) : (
          <SignedOut config={config} />
        )}
      </div>
    </main>
  );
}

function SignedOut({ config }: { readonly config: AppConfig }) {
  return (
    <div data-testid="signed-out-view" className="demo-stack">
      <PageHeader title={config.appName} description={TEXT.signedOut.heading} />
      <Card className="demo-card">
        <p className="demo-text">{TEXT.signedOut.body}</p>
        <div className="demo-actions">
          <Button data-testid="sign-in" onClick={() => go(loginUrl("/"))}>
            {TEXT.signedOut.signIn}
          </Button>
        </div>
      </Card>
    </div>
  );
}

function displayName(principal: SessionPrincipal): string {
  if (principal.protectedIdentity === true) return TEXT.signedIn.protectedIdentity;
  return principal.name ?? TEXT.signedIn.unknownName;
}

function representationText(principal: SessionPrincipal): string {
  const rep = principal.rep;
  if (rep === undefined) return TEXT.signedIn.self;
  const kind = rep.type === "organisation" ? TEXT.signedIn.organisation : TEXT.signedIn.person;
  return `${TEXT.signedIn.actingFor} ${rep.name ?? TEXT.signedIn.protectedIdentity} (${kind})`;
}

function SignedIn({
  config,
  principal,
  expiresAt,
  csrfToken,
  onSessionEnded,
}: {
  readonly config: AppConfig;
  readonly principal: SessionPrincipal;
  readonly expiresAt: string;
  readonly csrfToken: string;
  readonly onSessionEnded: () => void;
}) {
  const [api, setApi] = useState<
    | { readonly kind: "idle" }
    | { readonly kind: "busy" }
    | { readonly kind: "done"; readonly result: ApiCallResult }
    | { readonly kind: "failed" }
  >({ kind: "idle" });

  const call = async () => {
    setApi({ kind: "busy" });
    try {
      const result = await callApi();
      if (result === null) {
        onSessionEnded();
        return;
      }
      setApi({ kind: "done", result });
    } catch {
      setApi({ kind: "failed" });
    }
  };

  const rows: readonly { label: string; value: ReactNode; testId: string }[] = [
    { label: TEXT.signedIn.name, value: displayName(principal), testId: "user-name" },
    {
      label: TEXT.signedIn.roles,
      value:
        principal.roles.length === 0 ? (
          TEXT.signedIn.noRoles
        ) : (
          <span className="demo-badges">
            {principal.roles.map((role) => (
              <Badge key={role} color="primary">
                {role}
              </Badge>
            ))}
          </span>
        ),
      testId: "user-roles",
    },
    {
      label: TEXT.signedIn.acr,
      value: <span title={principal.acr}>{acrName(principal.acr)}</span>,
      testId: "user-acr",
    },
    {
      label: TEXT.signedIn.idpKind,
      value: TEXT.idpKinds[principal.idpKind],
      testId: "user-idp-kind",
    },
    {
      label: TEXT.signedIn.authTime,
      value: formatTime(new Date(principal.authTime * 1000)),
      testId: "user-auth-time",
    },
    {
      label: TEXT.signedIn.sessionExpires,
      value: formatTime(new Date(expiresAt)),
      testId: "session-expires",
    },
    {
      label: TEXT.signedIn.representation,
      value: representationText(principal),
      testId: "representation",
    },
  ];

  return (
    <div data-testid="signed-in-view" className="demo-stack">
      <PageHeader
        title={config.appName}
        description={TEXT.signedIn.description}
        actions={
          <form method="post" action="/auth/logout">
            <input type="hidden" name="_csrf" value={csrfToken} />
            <Button type="submit" variant="secondary" data-testid="sign-out">
              {TEXT.signedIn.signOut}
            </Button>
          </form>
        }
      />
      <Card className="demo-card">
        <h2 className="demo-heading">{TEXT.signedIn.details}</h2>
        <dl className="demo-details">
          {rows.map((row) => (
            <div className="demo-detail" key={row.testId}>
              <dt>{row.label}</dt>
              <dd data-testid={row.testId}>{row.value}</dd>
            </div>
          ))}
        </dl>
        <div className="demo-actions">
          <Button
            variant="outline"
            data-testid="switch-representation"
            onClick={() => go(selectRepresentationUrl("/"))}
          >
            {TEXT.signedIn.switchRepresentation}
          </Button>
          <Button
            variant="outline"
            data-testid="step-up"
            onClick={() => go(stepUpUrl(config.stepUpAcr, "/"))}
          >
            {TEXT.signedIn.stepUp}
          </Button>
          <Button data-testid="call-api" loading={api.kind === "busy"} onClick={() => void call()}>
            {TEXT.signedIn.callApi}
          </Button>
        </div>
      </Card>
      {api.kind === "done" && (
        <Card className="demo-card">
          <h2 className="demo-heading">{TEXT.signedIn.apiResult}</h2>
          <p className="demo-text" data-testid="api-status">
            HTTP {api.result.status}
          </p>
          <pre className="demo-pre" data-testid="api-result">
            {JSON.stringify(api.result.body, null, 2)}
          </pre>
        </Card>
      )}
      {api.kind === "failed" && (
        <div data-testid="api-error">
          <Alert tone="danger" title={TEXT.errorTitle}>
            {TEXT.signedIn.apiFailed}
          </Alert>
        </div>
      )}
    </div>
  );
}
