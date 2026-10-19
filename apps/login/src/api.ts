/**
 * Contract with the server (apps/server/src/login): the bootstrap block every page carries and
 * the interaction API. Keep in sync with `ui-shell.ts` and `routes.ts` there.
 */

export const LOGIN_ERROR_CODES = [
  "interaction_expired",
  "app_unavailable",
  "no_acceptable_method",
  "login_method_unavailable",
  "upstream_denied",
  "upstream_cancelled",
  "authentication_failed",
  "upstream_error",
  "upstream_response_invalid",
  "upstream_unavailable",
  "insufficient_assurance",
  "account_not_allowed",
  "invalid_identity",
  "state_invalid",
  "state_replayed",
  "state_expired",
  "no_representation_available",
  "representation_not_allowed",
  "step_up_person_mismatch",
  "request_failed",
] as const;
export type LoginErrorCode = (typeof LOGIN_ERROR_CODES)[number];

export const isLoginErrorCode = (value: unknown): value is LoginErrorCode =>
  typeof value === "string" && (LOGIN_ERROR_CODES as readonly string[]).includes(value);

export interface LocaleHints {
  readonly uiLocales: readonly string[];
  readonly acceptLanguage: readonly string[];
}

export type Bootstrap = { readonly locale: LocaleHints } & (
  | {
      readonly view: "login";
      readonly tenant: string;
      readonly uid: string;
      readonly error?: LoginErrorCode;
    }
  | {
      readonly view: "representation";
      readonly tenant: string;
      readonly uid: string;
      readonly error?: LoginErrorCode;
    }
  | { readonly view: "error"; readonly code: LoginErrorCode; readonly oauthError?: string }
  | { readonly view: "logout" }
  | { readonly view: "logged_out" }
);

export type MethodKind = "employee" | "citizen";

export interface LoginMethodView {
  readonly id: string;
  readonly displayName: string;
  readonly kind: MethodKind;
}

export interface InteractionDetails {
  readonly tenant: { readonly name: string };
  readonly application: { readonly name: string } | null;
  readonly methods: readonly LoginMethodView[];
  readonly homeRealmDiscovery: boolean;
  readonly loginHint: string | null;
  readonly csrfToken: string;
}

export type PartyType = "person" | "organisation";

/** A party's identifier as the server sends it: never a full personal identity number. */
export type PartyIdentifier =
  | { readonly kind: "organisation_number"; readonly value: string }
  /** The date part (`YYYYMMDD`) of a personal identity or coordination number. */
  | { readonly kind: "birth_date"; readonly value: string };

export interface PartyOption {
  readonly id: string;
  readonly type: PartyType;
  readonly name: string;
  /** `null` for a person with a protected identity: nothing is shown. */
  readonly identifier: PartyIdentifier | null;
}

/** `GET .../representation`: whom the person may act for. */
export interface RepresentationDetails {
  readonly tenant: { readonly name: string };
  readonly application: { readonly name: string };
  readonly allowSelf: boolean;
  readonly parties: readonly PartyOption[];
  readonly csrfToken: string;
}

export type RepresentationChoice = { readonly self: true } | { readonly partyId: string };

const strings = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Parses the bootstrap block; `null` when it is missing or malformed. */
export function parseBootstrap(text: string | null | undefined): Bootstrap | null {
  if (text === null || text === undefined) return null;
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(data)) return null;
  const localeData = isRecord(data.locale) ? data.locale : {};
  const locale: LocaleHints = {
    uiLocales: strings(localeData.uiLocales),
    acceptLanguage: strings(localeData.acceptLanguage),
  };
  switch (data.view) {
    case "login":
      if (typeof data.tenant !== "string" || typeof data.uid !== "string") return null;
      return {
        view: "login",
        tenant: data.tenant,
        uid: data.uid,
        ...(isLoginErrorCode(data.error) ? { error: data.error } : {}),
        locale,
      };
    case "representation":
      if (typeof data.tenant !== "string" || typeof data.uid !== "string") return null;
      return {
        view: "representation",
        tenant: data.tenant,
        uid: data.uid,
        ...(isLoginErrorCode(data.error) ? { error: data.error } : {}),
        locale,
      };
    case "error":
      return {
        view: "error",
        code: isLoginErrorCode(data.code) ? data.code : "request_failed",
        ...(typeof data.oauthError === "string" ? { oauthError: data.oauthError } : {}),
        locale,
      };
    case "logout":
    case "logged_out":
      return { view: data.view, locale };
    default:
      return null;
  }
}

export function readBootstrap(doc: Document): Bootstrap | null {
  return parseBootstrap(doc.getElementById("pv-bootstrap")?.textContent);
}

function parseDetails(data: unknown): InteractionDetails | null {
  if (!isRecord(data) || !isRecord(data.tenant) || typeof data.tenant.name !== "string") {
    return null;
  }
  if (typeof data.csrfToken !== "string" || !Array.isArray(data.methods)) return null;
  const methods: LoginMethodView[] = [];
  for (const method of data.methods) {
    if (
      isRecord(method) &&
      typeof method.id === "string" &&
      typeof method.displayName === "string" &&
      (method.kind === "employee" || method.kind === "citizen")
    ) {
      methods.push({ id: method.id, displayName: method.displayName, kind: method.kind });
    }
  }
  const application =
    isRecord(data.application) && typeof data.application.name === "string"
      ? { name: data.application.name }
      : null;
  return {
    tenant: { name: data.tenant.name },
    application,
    methods,
    homeRealmDiscovery: data.homeRealmDiscovery === true,
    loginHint: typeof data.loginHint === "string" ? data.loginHint : null,
    csrfToken: data.csrfToken,
  };
}

const ORGANISATION_NUMBER = /^\d{10}$/;
const DATE_PART = /^\d{8}$/;

function parseIdentifier(value: unknown): PartyIdentifier | null {
  if (!isRecord(value) || typeof value.value !== "string") return null;
  if (value.kind === "organisation_number" && ORGANISATION_NUMBER.test(value.value)) {
    return { kind: "organisation_number", value: value.value };
  }
  if (value.kind === "birth_date" && DATE_PART.test(value.value)) {
    return { kind: "birth_date", value: value.value };
  }
  return null;
}

function parseRepresentationDetails(data: unknown): RepresentationDetails | null {
  if (!isRecord(data) || !isRecord(data.tenant) || typeof data.tenant.name !== "string") {
    return null;
  }
  if (!isRecord(data.application) || typeof data.application.name !== "string") return null;
  if (typeof data.csrfToken !== "string" || !Array.isArray(data.parties)) return null;
  const parties: PartyOption[] = [];
  for (const party of data.parties) {
    if (
      isRecord(party) &&
      typeof party.id === "string" &&
      typeof party.name === "string" &&
      (party.type === "person" || party.type === "organisation")
    ) {
      parties.push({
        id: party.id,
        type: party.type,
        name: party.name,
        identifier: parseIdentifier(party.identifier),
      });
    }
  }
  return {
    tenant: { name: data.tenant.name },
    application: { name: data.application.name },
    allowSelf: data.allowSelf === true,
    parties,
    csrfToken: data.csrfToken,
  };
}

export type DetailsResult =
  | { readonly ok: true; readonly details: InteractionDetails }
  | { readonly ok: false; readonly error: LoginErrorCode };

export type ActionResult =
  | { readonly ok: true; readonly redirectTo: string }
  | { readonly ok: false; readonly error: string };

export type LoginChoice = { readonly loginMethodId: string } | { readonly email: string };

export type RepresentationDetailsResult =
  | { readonly ok: true; readonly details: RepresentationDetails }
  | { readonly ok: false; readonly error: LoginErrorCode };

export interface RepresentationApi {
  details(): Promise<RepresentationDetailsResult>;
  choose(choice: RepresentationChoice, csrfToken: string): Promise<ActionResult>;
  abort(csrfToken: string): Promise<ActionResult>;
}

export interface LoginApi {
  details(): Promise<DetailsResult>;
  login(choice: LoginChoice, csrfToken: string): Promise<ActionResult>;
  abort(csrfToken: string): Promise<ActionResult>;
}

const interactionBase = (tenant: string, uid: string): string =>
  `/t/${encodeURIComponent(tenant)}/interaction/${encodeURIComponent(uid)}`;

/** A CSRF-protected JSON POST of the interaction API, answered with `{ redirectTo }`. */
function poster(base: string, fetchImpl: typeof fetch) {
  return async (path: string, body: unknown, csrfToken: string): Promise<ActionResult> => {
    try {
      const response = await fetchImpl(`${base}${path}`, {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json", "x-csrf-token": csrfToken },
        body: JSON.stringify(body),
      });
      const data: unknown = await response.json().catch(() => null);
      if (response.ok && isRecord(data) && typeof data.redirectTo === "string") {
        return { ok: true, redirectTo: data.redirectTo };
      }
      return {
        ok: false,
        error: isRecord(data) && typeof data.error === "string" ? data.error : "request_failed",
      };
    } catch {
      return { ok: false, error: "request_failed" };
    }
  };
}

/** The interaction API below `/t/{tenant}/interaction/{uid}` (same origin, cookies included). */
export function createLoginApi(
  tenant: string,
  uid: string,
  fetchImpl: typeof fetch = (input, init) => fetch(input, init),
): LoginApi {
  const base = interactionBase(tenant, uid);
  const post = poster(base, fetchImpl);
  return {
    async details() {
      try {
        const response = await fetchImpl(`${base}/details`, { credentials: "same-origin" });
        if (response.status === 404) return { ok: false, error: "interaction_expired" };
        const details = response.ok ? parseDetails(await response.json()) : null;
        return details === null ? { ok: false, error: "request_failed" } : { ok: true, details };
      } catch {
        return { ok: false, error: "request_failed" };
      }
    },
    login: (choice, csrfToken) => post("/login", choice, csrfToken),
    abort: (csrfToken) => post("/abort", {}, csrfToken),
  };
}

/** The representation chooser's API below `/t/{tenant}/interaction/{uid}`. */
export function createRepresentationApi(
  tenant: string,
  uid: string,
  fetchImpl: typeof fetch = (input, init) => fetch(input, init),
): RepresentationApi {
  const base = interactionBase(tenant, uid);
  const post = poster(base, fetchImpl);
  return {
    async details() {
      try {
        const response = await fetchImpl(`${base}/representation`, {
          credentials: "same-origin",
        });
        if (response.status === 404) return { ok: false, error: "interaction_expired" };
        const details = response.ok ? parseRepresentationDetails(await response.json()) : null;
        return details === null ? { ok: false, error: "request_failed" } : { ok: true, details };
      } catch {
        return { ok: false, error: "request_failed" };
      }
    },
    choose: (choice, csrfToken) => post("/representation", choice, csrfToken),
    abort: (csrfToken) => post("/abort", {}, csrfToken),
  };
}
