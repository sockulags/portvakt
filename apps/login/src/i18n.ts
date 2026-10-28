import { createContext, useContext } from "react";
import type { LocaleHints, LoginErrorCode } from "./api";

/** Swedish first (the default), English available. */
export const LOCALES = ["sv", "en"] as const;
export type Locale = (typeof LOCALES)[number];
export const DEFAULT_LOCALE: Locale = "sv";

interface ErrorText {
  readonly title: string;
  readonly body: string;
}

export interface Messages {
  readonly languageName: string;
  readonly switchLanguage: string;
  readonly loading: string;
  readonly signIn: { readonly heading: string; readonly introApp: string; readonly intro: string };
  readonly groups: Readonly<Record<"employee" | "citizen", string>>;
  readonly method: string;
  readonly hrd: {
    readonly heading: string;
    readonly label: string;
    readonly hint: string;
    readonly submit: string;
    readonly invalid: string;
    readonly notFound: string;
    readonly or: string;
  };
  readonly redirecting: { readonly title: string; readonly body: string };
  readonly representation: {
    readonly heading: string;
    readonly intro: string;
    readonly listLabel: string;
    readonly self: string;
    readonly selfDetail: string;
    readonly chooseSelf: string;
    readonly choose: string;
    readonly types: Readonly<Record<"person" | "organisation", string>>;
    readonly organisationNumber: string;
    readonly personalNumber: string;
    readonly continuing: string;
  };
  readonly cancel: string;
  readonly retry: string;
  readonly errorCode: string;
  readonly errors: Readonly<Record<LoginErrorCode, ErrorText>>;
  readonly logout: {
    readonly heading: string;
    readonly body: string;
    readonly confirm: string;
    readonly stay: string;
  };
  readonly loggedOut: { readonly heading: string; readonly body: string };
}

const sv: Messages = {
  languageName: "Svenska",
  switchLanguage: "Byt språk till svenska",
  loading: "Laddar …",
  signIn: {
    heading: "Logga in",
    introApp: "Logga in för att fortsätta till {app}.",
    intro: "Välj hur du vill logga in.",
  },
  groups: { employee: "Logga in som medarbetare", citizen: "Logga in som privatperson" },
  method: "Logga in med {name}",
  hrd: {
    heading: "Logga in med din jobbadress",
    label: "E-postadress",
    hint: "Vi skickar dig vidare till din organisations inloggning.",
    submit: "Fortsätt",
    invalid: "Ange en giltig e-postadress.",
    notFound: "Vi hittar ingen inloggning för den adressen. Välj ett av alternativen.",
    or: "eller",
  },
  redirecting: {
    title: "Du skickas vidare …",
    body: "Vänta medan vi öppnar inloggningen.",
  },
  representation: {
    heading: "Välj vem du företräder",
    intro: "Välj om du vill använda {app} för din egen räkning eller som ombud.",
    listLabel: "Vem du kan företräda",
    self: "Mig själv",
    selfDetail: "För din egen räkning",
    chooseSelf: "Fortsätt som mig själv",
    choose: "Företräd {name}",
    types: { person: "Privatperson", organisation: "Organisation" },
    organisationNumber: "Organisationsnummer {value}",
    personalNumber: "Personnummer {value}",
    continuing: "Du skickas vidare till tjänsten …",
  },
  cancel: "Avbryt och gå tillbaka",
  retry: "Försök igen",
  errorCode: "Felkod: {code}",
  errors: {
    interaction_expired: {
      title: "Inloggningen har gått ut",
      body: "Gå tillbaka till tjänsten och börja om.",
    },
    app_unavailable: {
      title: "Tjänsten är inte tillgänglig",
      body: "Tjänsten du försöker nå går inte att logga in till här. Kontakta tjänstens support om felet kvarstår.",
    },
    no_acceptable_method: {
      title: "Ingen inloggning uppfyller kraven",
      body: "Tjänsten kräver en högre säkerhetsnivå än de inloggningar som finns här.",
    },
    login_method_unavailable: {
      title: "Inloggningsmetoden är inte tillgänglig",
      body: "Välj en annan metod eller försök igen senare.",
    },
    upstream_denied: { title: "Inloggningen avbröts", body: "Du kan försöka igen." },
    upstream_cancelled: {
      title: "Du avbröt inloggningen",
      body: "Inloggningen avbröts i e-legitimationen. Du kan försöka igen när du vill.",
    },
    authentication_failed: {
      title: "Inloggningen kunde inte genomföras",
      body: "E-legitimationen kunde inte bekräfta vem du är. Försök igen eller välj en annan metod.",
    },
    upstream_error: {
      title: "Inloggningen misslyckades",
      body: "Inloggningstjänsten kunde inte slutföra inloggningen. Försök igen.",
    },
    upstream_unavailable: {
      title: "Inloggningstjänsten svarar inte",
      body: "Försök igen om en stund.",
    },
    upstream_response_invalid: {
      title: "Ogiltigt svar från inloggningstjänsten",
      body: "Svaret kunde inte godkännas av säkerhetsskäl. Börja om från tjänsten.",
    },
    insufficient_assurance: {
      title: "För låg säkerhetsnivå",
      body: "Inloggningen gav inte den säkerhetsnivå som krävs. Försök igen eller välj en annan metod.",
    },
    account_not_allowed: {
      title: "Kontot får inte logga in här",
      body: "Kontot hör till en organisation som inte har tillgång till den här tjänsten. Logga in med ett annat konto.",
    },
    invalid_identity: {
      title: "Vi kunde inte ta emot inloggningen",
      body: "Uppgifterna från inloggningstjänsten var ofullständiga. Kontakta support om felet kvarstår.",
    },
    state_invalid: {
      title: "Ogiltigt inloggningssvar",
      body: "Svaret hörde inte till någon pågående inloggning. Börja om från tjänsten.",
    },
    state_replayed: {
      title: "Inloggningen har redan använts",
      body: "Börja om från tjänsten.",
    },
    state_expired: { title: "Inloggningen tog för lång tid", body: "Försök igen." },
    no_representation_available: {
      title: "Du kan inte företräda någon här",
      body: "Tjänsten kräver att du loggar in som ombud, men du har ingen giltig behörighet för den. Kontakta den du ska företräda eller tjänstens support.",
    },
    representation_not_allowed: {
      title: "Valet kan inte användas",
      body: "Behörigheten gäller inte längre. Välj igen.",
    },
    step_up_person_mismatch: {
      title: "En annan person legitimerade sig",
      body: "Tjänsten kräver att samma person som redan är inloggad legitimerar sig igen. Du är fortfarande inloggad som tidigare.",
    },
    rate_limited: {
      title: "För många försök",
      body: "Vänta en stund och försök sedan igen.",
    },
    request_failed: { title: "Något gick fel", body: "Försök igen senare." },
  },
  logout: {
    heading: "Vill du logga ut?",
    body: "Du loggas ut från alla tjänster som använder den här inloggningen.",
    confirm: "Logga ut",
    stay: "Stanna inloggad",
  },
  loggedOut: { heading: "Du är utloggad", body: "Du kan stänga fönstret." },
};

const en: Messages = {
  languageName: "English",
  switchLanguage: "Switch language to English",
  loading: "Loading …",
  signIn: {
    heading: "Sign in",
    introApp: "Sign in to continue to {app}.",
    intro: "Choose how you want to sign in.",
  },
  groups: { employee: "Sign in as an employee", citizen: "Sign in as a private individual" },
  method: "Sign in with {name}",
  hrd: {
    heading: "Sign in with your work email",
    label: "Email address",
    hint: "We will send you on to your organisation's sign-in.",
    submit: "Continue",
    invalid: "Enter a valid email address.",
    notFound: "No sign-in matches that address. Choose one of the options.",
    or: "or",
  },
  redirecting: { title: "Redirecting you …", body: "Please wait while we open the sign-in." },
  representation: {
    heading: "Choose whom you represent",
    intro: "Choose whether you use {app} on your own behalf or as a representative.",
    listLabel: "Whom you can represent",
    self: "Myself",
    selfDetail: "On your own behalf",
    chooseSelf: "Continue as myself",
    choose: "Represent {name}",
    types: { person: "Private individual", organisation: "Organisation" },
    organisationNumber: "Organisation number {value}",
    personalNumber: "Personal identity number {value}",
    continuing: "Taking you to the service …",
  },
  cancel: "Cancel and go back",
  retry: "Try again",
  errorCode: "Error code: {code}",
  errors: {
    interaction_expired: {
      title: "The sign-in has expired",
      body: "Go back to the service and start again.",
    },
    app_unavailable: {
      title: "The service is not available",
      body: "You cannot sign in to this service here. Contact the service's support if the problem persists.",
    },
    no_acceptable_method: {
      title: "No sign-in method meets the requirements",
      body: "The service requires a higher level of assurance than the sign-in methods here provide.",
    },
    login_method_unavailable: {
      title: "The sign-in method is not available",
      body: "Choose another method or try again later.",
    },
    upstream_denied: { title: "The sign-in was cancelled", body: "You can try again." },
    upstream_cancelled: {
      title: "You cancelled the sign-in",
      body: "The sign-in was cancelled in your electronic identification. You can try again whenever you like.",
    },
    authentication_failed: {
      title: "The sign-in could not be completed",
      body: "Your electronic identification could not confirm who you are. Try again or choose another method.",
    },
    upstream_error: {
      title: "The sign-in failed",
      body: "The sign-in service could not complete the sign-in. Please try again.",
    },
    upstream_unavailable: {
      title: "The sign-in service is not responding",
      body: "Please try again in a moment.",
    },
    upstream_response_invalid: {
      title: "Invalid response from the sign-in service",
      body: "The response could not be accepted for security reasons. Start again from the service.",
    },
    insufficient_assurance: {
      title: "Level of assurance too low",
      body: "The sign-in did not reach the required level of assurance. Try again or choose another method.",
    },
    account_not_allowed: {
      title: "This account cannot sign in here",
      body: "The account belongs to an organisation without access to this service. Sign in with another account.",
    },
    invalid_identity: {
      title: "We could not accept the sign-in",
      body: "The sign-in service sent incomplete information. Contact support if the problem persists.",
    },
    state_invalid: {
      title: "Invalid sign-in response",
      body: "The response did not belong to a sign-in in progress. Start again from the service.",
    },
    state_replayed: {
      title: "This sign-in has already been used",
      body: "Start again from the service.",
    },
    state_expired: { title: "The sign-in took too long", body: "Please try again." },
    no_representation_available: {
      title: "You cannot represent anyone here",
      body: "The service requires you to sign in as a representative, but you have no valid authorisation for it. Contact the party you represent or the service's support.",
    },
    representation_not_allowed: {
      title: "That choice cannot be used",
      body: "The authorisation is no longer valid. Please choose again.",
    },
    step_up_person_mismatch: {
      title: "Another person signed in",
      body: "The service requires the person who is already signed in to identify again. You are still signed in as before.",
    },
    rate_limited: {
      title: "Too many attempts",
      body: "Please wait a moment and try again.",
    },
    request_failed: { title: "Something went wrong", body: "Please try again later." },
  },
  logout: {
    heading: "Do you want to sign out?",
    body: "You will be signed out of every service that uses this sign-in.",
    confirm: "Sign out",
    stay: "Stay signed in",
  },
  loggedOut: { heading: "You are signed out", body: "You can close this window." },
};

export const MESSAGES: Readonly<Record<Locale, Messages>> = { sv, en };

/** The supported locale of a language tag (`sv-SE` is Swedish), or `undefined`. */
function localeOf(tag: string): Locale | undefined {
  const primary = tag.trim().toLowerCase().split("-")[0];
  return LOCALES.find((locale) => locale === primary);
}

/**
 * `ui_locales` from the authorization request wins, then the browser's Accept-Language (in
 * preference order), then Swedish.
 */
export function pickLocale(hints: LocaleHints): Locale {
  for (const tag of [...hints.uiLocales, ...hints.acceptLanguage]) {
    const locale = localeOf(tag);
    if (locale !== undefined) return locale;
  }
  return DEFAULT_LOCALE;
}

/** Fills `{name}` placeholders. */
export function format(template: string, values: Readonly<Record<string, string>>): string {
  return template.replace(/\{(\w+)\}/g, (match, key: string) => values[key] ?? match);
}

export interface I18n {
  readonly locale: Locale;
  readonly t: Messages;
  readonly setLocale: (locale: Locale) => void;
}

export const I18nContext = createContext<I18n>({
  locale: DEFAULT_LOCALE,
  t: MESSAGES[DEFAULT_LOCALE],
  setLocale: () => undefined,
});

export const useI18n = (): I18n => useContext(I18nContext);
