# Integrating an application

How an organisation's application signs people in through Portvakt, calls its APIs with
Portvakt access tokens and calls other applications as a service. Web applications use the
backend-for-frontend (BFF) pattern: the browser holds an opaque session cookie, the application's
server holds the tokens. The token contents are specified in [claims.md](claims.md); the SDK
manuals are [`packages/sdk-node/README.md`](../packages/sdk-node/README.md) (TypeScript, Express)
and [`sdk-java/README.md`](../sdk-java/README.md) (Java 21, Spring Boot 4.1).

## 1. Register the application

A platform administrator registers the application once per install (admin portal, system
tenant, Applikationer; or `POST /admin/api/v1/applications`, [admin-api.md](admin-api.md)):

```json
{
  "clientId": "bygglov",
  "name": "Bygglov",
  "clientAuth": { "method": "client_secret_basic" },
  "redirectUris": ["https://bygglov.kommun.example/auth/callback"],
  "postLogoutRedirectUris": ["https://bygglov.kommun.example/"],
  "roles": [{ "role": "handlaggare", "description": "Handlägger ärenden" }],
  "attributeKeys": [{ "key": "unit", "description": "Organisatorisk enhet" }],
  "allowedExtraScopes": [],
  "serviceAudiences": [],
  "representationMode": "none"
}
```

- `clientAuth`: `client_secret_basic` or `client_secret_post` (Portvakt generates the secret and
  shows it once; `POST /applications/{id}/rotate-secret` replaces it), or `private_key_jwt` with a
  `jwksUri` or inline `jwks` (recommended for services that can hold a key).
- `redirectUris` are exact; `{tenant}` as a whole path segment stands for the tenant's slug,
  for an application serving several tenants under one host.
- `roles` and `attributeKeys` are what the application understands; Portvakt assigns them and
  never interprets them.
- `allowedExtraScopes`: `pin` (personal identity number in the ID token) and `hsa` (SITHS HSA-id
  and organisation affiliations). Request them only if the application needs them.
- `serviceAudiences`: the applications this one may call with service tokens (below).
- `representationMode`: `none`, `optional` or `required` (below).

## 2. Enable it in the tenant

A platform administrator or the tenant's administrator attaches and enables the application in
the tenant (`PUT /tenants/{tenantId}/applications/{applicationId}`). Only enabled applications
can authenticate in a tenant; enabling a second application in a tenant gives single sign-on
between them. Disabling or detaching it, in the tenant or globally, ends its sessions and refresh
tokens at once. Then grant roles: direct assignments, pending assignments by upstream subject or
personal identity number, or group rules (an upstream group of a login method gives a role).

The application's issuer is the tenant's: `https://{portvakt}/t/{tenant}`. Configure that exact
URL; the SDKs pin it and refuse tokens of other tenants.

## 3. Sign people in (BFF)

TypeScript (Express 4 or 5):

```ts
import express from "express";
import { createPortvaktClient, PgSessionStore } from "@portvakt/sdk-node";

const portvakt = createPortvaktClient({
  issuer: "https://login.kommun.example/t/kommunen",
  clientId: "bygglov",
  clientAuth: { method: "client_secret_basic", clientSecret: process.env.CLIENT_SECRET! },
  redirectUri: "https://bygglov.kommun.example/auth/callback",
  postLogoutRedirectUri: "https://bygglov.kommun.example/",
});
const bff = portvakt.bff({
  sessionStore: new PgSessionStore({ pool, tableName: "bygglov_sessions" }),
  encryptionKey: process.env.SESSION_ENCRYPTION_KEY!,
  cookie: { name: "__Host-bygglov", secrets: [process.env.COOKIE_SECRET!], secure: true },
});

const app = express();
app.use(bff); // /auth/login, /auth/callback, /auth/logout, /auth/session, /auth/step-up, ...
app.get("/arenden", bff.requireLogin(), async (req, res) => {
  const person = bff.principal(req)!; // from the ID token
  const token = await bff.getAccessToken(req); // refreshed under a per-session lock
  res.json({ sub: person.sub, roles: person.roles, token: Boolean(token) });
});
app.use(bff.errorHandler());
```

Java (Spring Boot 4.1 starter):

```yaml
portvakt:
  issuer: https://login.kommun.example/t/kommunen
  client-id: bygglov
  client-secret: ${CLIENT_SECRET}
  login:
    enabled: true
    redirect-uri: https://bygglov.kommun.example/auth/callback
    post-logout-redirect-uri: https://bygglov.kommun.example/
```

```java
PortvaktPrincipal person = PortvaktSecurity.currentPrincipal().orElseThrow();
String token = accessTokens.getAccessToken(request, response);
```

What the SDKs do for you: authorization code flow with PKCE and nonce, ID token validation
against the pinned issuer and JWKS, refresh token rotation under a lock (also across instances
with the Postgres or JDBC store), the session ended no later than the broker's `session_exp`,
CSRF protection for unsafe methods, a cross-site guard for step-up and representation switches,
logout through Portvakt's end-session endpoint, and a 503 page while Portvakt is unreachable.
Each application on one host needs its own session cookie name.

## 4. Protect APIs

APIs validate access tokens locally (ES256 JWT, `typ` `at+jwt`, `iss` pinned, `aud` = the API's
client id):

```ts
app.get(
  "/api/arenden",
  portvakt.requireAccessToken({ audience: "bygglov", anyRole: ["handlaggare"] }),
  (req, res) => res.json({ caller: portvakt.principal(req)!.sub }),
);
```

```java
http.authorizeHttpRequests(a -> a
    .requestMatchers("/api/beslut/**").access(portvakt.accessToken(r -> r.acr(AcrRanking.LOA4)))
    .anyRequest().access(portvakt.accessToken(r -> r.anyRole("handlaggare"))));
```

A token for another application is refused (`aud`), service tokens are refused unless the route
allows them, representation tokens are accepted unless the route refuses them. Failures are
RFC 6750 errors.

## Claims to use

| Use                                | Claim                                                                             |
| ---------------------------------- | --------------------------------------------------------------------------------- |
| Who is signed in (stable key)      | `sub` (a UUID per person and tenant; never the personal identity number or email) |
| Which tenant                       | `tid` (and `iss`)                                                                 |
| What the person may do in your app | `roles`, `attrs` (only yours)                                                     |
| How strongly they authenticated    | `acr` (compare with `acrAtLeast` / `AcrRanking`), `auth_time`                     |
| Employee or citizen                | `idp_kind`                                                                        |
| Acting for someone                 | `rep` (`sub` of the party, `type`; `name` in the ID token)                        |
| Display                            | `name`, `email` from the ID token (BFF principal), never from access tokens       |
| Personal identity number           | `pin` (scope `pin`, if allowed), ID token only                                    |

Never identify people by `email` or `name`. `pin` exists for applications that must match a
national register; store it only if you have to.

## Representation

With `representationMode` `optional` or `required`, Portvakt shows a chooser after the login and
the tokens carry `rep` when the person acts for a party (an organisation or another person). `sub`
stays the signed-in person and `roles` stay theirs: **authorise every action for `rep.sub` with
your own rules**. Portvakt attests only that the person holds a representation right for the
party in your application at issuance. The BFF route `/auth/select-representation` (both SDKs)
lets the person switch; a switch replaces the grant, so old
refresh tokens stop working. A revoked right ends the session's tokens at the next refresh.

## Step-up

For a sensitive action, require a higher level: `bff.requireAcr(LOA4)` or `@RequireAcr(LOA4)`
sends the person through `/auth/step-up`, Portvakt asks for a login method that provides the
level (naming the same person upstream when it can), and the new login must be the same person.
On APIs, an `acr` requirement answers 401 `insufficient_user_authentication` with `acr_values`
(RFC 9470); the calling web application then starts the step-up itself.

## Service tokens

A backend calls another application's API without a person:

1. An administrator lists the target's client id in the caller's `serviceAudiences`; both must
   be enabled in the same tenant.
2. The caller gets a client_credentials token for the target (`resource=urn:portvakt:app:{target}`):
   `portvakt.clientCredentials({ audience: "arkiv" }).getToken()` /
   `clientCredentials.forAudience("arkiv").getToken()`. The SDKs cache it.
3. The target accepts service callers explicitly: `allowService: ["bygglov"]` /
   `allowed-services: [bygglov]`. A service token has `sub` = `client_id` = the caller and none
   of the person claims.

## Protected identity

When `protected_identity` is `true` (skyddad identitet), Portvakt never issues the person's
`name` or `email`, and the ID token's `rep` has no name when the represented person is protected.
Applications must minimise what they show and store: no name in page headers, receipts, logs or
notifications; do not send letters or emails derived from other sources without the
organisation's procedure for protected identities. The flag is sticky until an administrator
clears it.

## Sessions, logout and outages

- The BFF session ends no later than `session_exp` (the broker session's end), after its own idle
  timeout, or when a refresh is refused (an administrator ended the session, a right was revoked).
- Logout is a POST to `/auth/logout` (with the CSRF token); the SDK continues to Portvakt's
  end-session endpoint, which also ends upstream SAML sessions, and returns to your
  `postLogoutRedirectUri`.
- While Portvakt is down, signed-in people keep working until their access token needs a refresh;
  `outageGraceSeconds` (TypeScript) or `portvakt.login.outage-grace` (Java) keeps sessions alive
  longer, default 0.

## Trying it locally

`npm run dev:stack` (or `npm run compose:local` with the production images) starts Portvakt, the
mock IdPs, the admin portal and the demo service as Tjänst A and B with a seeded `demo` tenant.
The demo ([`examples/demo-service`](../examples/demo-service)) and the Java demo
([`examples/demo-service-java`](../examples/demo-service-java)) are complete integrations of the
two SDKs, including step-up, representation and service tokens.
