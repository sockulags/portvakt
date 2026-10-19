/** UI text (Swedish). */
export const TEXT = {
  loading: "Laddar …",
  errorTitle: "Något gick fel",
  loadFailed: "Tjänsten kunde inte nå sin server. Försök igen om en stund.",
  signedOut: {
    heading: "Välkommen",
    body: "Du är inte inloggad. Logga in med din e-legitimation eller ditt arbetskonto.",
    signIn: "Logga in",
  },
  signedIn: {
    description: "Du är inloggad via Portvakt.",
    details: "Inloggning",
    name: "Namn",
    protectedIdentity: "Skyddad identitet",
    unknownName: "Okänt namn",
    roles: "Roller",
    noRoles: "Inga roller",
    acr: "Säkerhetsnivå",
    idpKind: "Typ av inloggning",
    authTime: "Inloggad",
    sessionExpires: "Sessionen gäller till",
    representation: "Företräder",
    self: "Dig själv",
    actingFor: "Agerar för",
    organisation: "organisation",
    person: "person",
    switchRepresentation: "Byt företrädd",
    stepUp: "Kräv högre säkerhetsnivå",
    callApi: "Anropa API",
    apiResult: "Svar från API:t",
    apiFailed: "API-anropet misslyckades.",
    sessionEnded: "Din session har upphört. Logga in igen.",
    signOut: "Logga ut",
  },
  idpKinds: { employee: "Anställd", citizen: "Medborgare" },
} as const;

const LOA_NAMES: Record<string, string> = {
  "http://id.elegnamnden.se/loa/1.0/loa2": "Tillitsnivå 2",
  "http://id.elegnamnden.se/loa/1.0/loa3": "Tillitsnivå 3",
  "http://id.elegnamnden.se/loa/1.0/loa4": "Tillitsnivå 4",
};

/** A readable name for an acr (the raw value when unknown). */
export const acrName = (acr: string): string => LOA_NAMES[acr] ?? acr;

const dateTime = new Intl.DateTimeFormat("sv-SE", { dateStyle: "short", timeStyle: "medium" });
export const formatTime = (date: Date): string => dateTime.format(date);
