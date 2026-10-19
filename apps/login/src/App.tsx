import { useEffect, useMemo, useState } from "react";
import {
  createLoginApi,
  createRepresentationApi,
  type Bootstrap,
  type LoginApi,
  type RepresentationApi,
} from "./api";
import { I18nContext, MESSAGES, pickLocale, type I18n, type Locale } from "./i18n";
import { ErrorView } from "./views/ErrorView";
import { LoginView } from "./views/LoginView";
import { LoggedOutView, LogoutView } from "./views/LogoutViews";
import { RepresentationView } from "./views/RepresentationView";

export interface AppProps {
  /** The page's bootstrap block; `null` when it is missing (shows a generic error). */
  readonly bootstrap: Bootstrap | null;
  /** Interaction API; defaults to the same-origin API of the bootstrap's interaction. */
  readonly api?: LoginApi;
  /** Representation chooser API; defaults to the same-origin API of the bootstrap's interaction. */
  readonly representationApi?: RepresentationApi;
  readonly navigate?: (url: string) => void;
}

const leave = (url: string): void => {
  window.location.assign(url);
};

/** The login UI: the view the server asked for, in Swedish or English. */
export function App({ bootstrap, api, representationApi, navigate = leave }: AppProps) {
  const [locale, setLocale] = useState<Locale>(() =>
    pickLocale(bootstrap?.locale ?? { uiLocales: [], acceptLanguage: [] }),
  );
  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);
  const i18n = useMemo<I18n>(() => ({ locale, t: MESSAGES[locale], setLocale }), [locale]);
  const loginApi = useMemo(
    () =>
      api ??
      (bootstrap?.view === "login" ? createLoginApi(bootstrap.tenant, bootstrap.uid) : undefined),
    [api, bootstrap],
  );
  const chooserApi = useMemo(
    () =>
      representationApi ??
      (bootstrap?.view === "representation"
        ? createRepresentationApi(bootstrap.tenant, bootstrap.uid)
        : undefined),
    [representationApi, bootstrap],
  );

  let view;
  if (bootstrap === null) view = <ErrorView code="request_failed" />;
  else if (bootstrap.view === "login" && loginApi !== undefined) {
    view = <LoginView api={loginApi} error={bootstrap.error} navigate={navigate} />;
  } else if (bootstrap.view === "representation" && chooserApi !== undefined) {
    view = <RepresentationView api={chooserApi} error={bootstrap.error} navigate={navigate} />;
  } else if (bootstrap.view === "error") {
    view = <ErrorView code={bootstrap.code} oauthError={bootstrap.oauthError} />;
  } else if (bootstrap.view === "logout") view = <LogoutView />;
  else if (bootstrap.view === "logged_out") view = <LoggedOutView />;
  else view = <ErrorView code="request_failed" />;

  return <I18nContext.Provider value={i18n}>{view}</I18nContext.Provider>;
}
