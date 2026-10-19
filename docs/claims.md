# Claims contract v1

This is the contract between Portvakt and the applications of a tenant: which claims the ID
token and the access token carry, and what they mean. It follows the claims table in
[plan.md](plan.md) ("Claims contract (v1)"). Renaming or removing a claim, or changing its
meaning or type, is a breaking change and needs a new contract version; adding a claim is not.

## Principles

- `sub` is always the UUID of the signed-in person in the tenant, stable across logins and login
  methods (identities linked by personal identity number share one person). It stays the signed-in
  person when representing someone; the represented party arrives as `rep`. There is no `act`
  claim.
- Access tokens are JWTs for exactly one application (`aud` is its `client_id`). They carry
  identity and authorization data only, never `name`, `email` or `pin` (data minimisation).
- ID tokens carry the profile claims the granted scopes allow. The userinfo endpoint is
  disabled: applications read profile claims from the ID token.
- Roles and attributes are always for the token's audience application only.

## Claims

| Claim                | ID token                           | Access token  | Meaning                                                                                                   |
| -------------------- | ---------------------------------- | ------------- | --------------------------------------------------------------------------------------------------------- |
| `iss`                | yes                                | yes           | `{PUBLIC_URL}/t/{tenant slug}`, one issuer per tenant                                                     |
| `aud`                | yes                                | yes           | `client_id` of the application                                                                            |
| `sub`                | yes                                | yes           | The signed-in person's UUID                                                                               |
| `tid`                | yes                                | yes           | Tenant slug                                                                                               |
| `idp`                | yes                                | yes           | Id (UUID) of the login method used                                                                        |
| `idp_kind`           | yes                                | yes           | `employee` or `citizen`                                                                                   |
| `acr`                | yes                                | yes           | Assurance level the login method asserts (see below)                                                      |
| `amr`                | yes                                | no            | Authentication methods, from the upstream IdP                                                             |
| `auth_time`          | yes                                | yes           | Epoch seconds of the authentication: the upstream `auth_time` (never later than now), else the login time |
| `session_exp`        | yes                                | no            | Epoch seconds: absolute end of the broker session for this login                                          |
| `roles`              | yes                                | yes           | Roles of the person in this application: direct assignments plus matched group rules                      |
| `attrs`              | yes                                | yes           | Attribute map of the person in this application                                                           |
| `rep`                | when representing                  | `sub`, `type` | Only when representing: `{ "sub": <party UUID>, "type": "person" \| "organisation", "name" }` (see below) |
| `name`               | with scope `profile`               | no            | Display name from the upstream IdP                                                                        |
| `email`              | with scope `email`                 | no            | Verified email address from the upstream IdP; never an identifier                                         |
| `pin`                | with scope `pin`, if allowed       | no            | Personal identity number (personnummer or samordningsnummer), 12 digits `YYYYMMDDNNNC`                    |
| `hsa_id`             | with scope `hsa`, if allowed       | no            | HSA-id of a SITHS employee (SAML employeeHsaId)                                                           |
| `org_affiliation`    | with scope `hsa`, if allowed       | no            | Array of `uid@orgnr` organisation affiliations (SAML orgAffiliation, scope-checked)                       |
| `protected_identity` | `true` when protected, else absent | no            | The person has a protected identity (skyddad identitet)                                                   |

The JWT and OAuth basics (`exp`, `iat`, `jti`, `client_id` in access tokens; `nonce`, `sid`,
`at_hash` in ID tokens) are as oidc-provider issues them.

### `acr`

For an OIDC login method the acr is the login method's configured `assertedAcr`, never a value
the upstream IdP chose. When the login method maps an upstream acr claim, Portvakt asks the
upstream for the asserted level (`acr_values`) and refuses the login unless the upstream acr
reaches it. For a SAML login method the acr is the level of assurance the IdP returned
(AuthnContextClassRef), and only a level Portvakt requested is accepted: with the framework's
`exact` comparison it must be one of the requested LoA URIs, and it must always rank at least as
high as the method's `assertedAcr` (see "SAML login methods" below). Levels are ordered
by `ACR_RANKING` (default: the Swedish eID Framework levels
`http://id.elegnamnden.se/loa/1.0/loa2` < `.../loa3` < `.../loa4`). An application that sends
`acr_values` is only offered login methods whose acr equals one of the values or ranks at least
as high as a ranked one; values outside the ranking only match themselves. A session whose acr
does not satisfy the request requires a new login.

### `rep` (representation, ombud)

An application decides whether it offers representation with its `representationMode`:

- `none` (default): no chooser is shown and `rep` is never issued.
- `optional`: after the login, the person chooses "Myself" (no `rep`) or a party they hold a
  valid representation right for. With no such party there is nothing to choose and no chooser.
- `required`: the person must choose a party; without a valid right the login UI shows
  `no_representation_available` and the application gets no tokens.

`rep` is `{ "sub": <party UUID>, "type": "person" | "organisation", "name": <display name> }`.
`rep.sub` is the party's id in Portvakt's party register for the tenant (stable; never a
personal identity or organisation number). Access tokens carry `rep` without `name` (data
minimisation); ID tokens carry `name`, except when the represented party is a person with a
protected identity (marked so in the register, or a protected person of the tenant has that
personal identity number), whose name is never issued. `sub` stays the signed-in person and
`roles` and `attrs` stay that person's roles and attributes for the application.

**Applications must authorise every action on behalf of `rep.sub` with their own rules.**
Portvakt only attests that the signed-in person (`sub`) holds a representation right for the
party in this application at the time of issuance; it says nothing about what the person may do
for the party in the application. Roles in `roles` are the agent's own, never the party's.

The choice belongs to one application's grant, never to the browser session:

- SSO into another application shows that application's chooser (when its mode is not `none`);
  another application's choice is never carried over.
- A new authorization of the same application reuses its choice while it is still valid.
  `prompt=select_account` re-opens the chooser without a new upstream login. Choosing another
  representation replaces the application's grant: refresh tokens issued with the earlier choice
  stop working (`invalid_grant`).
- At every refresh and every authorization that reuses the grant, Portvakt checks that the right
  still holds: not revoked, inside its validity window, the application still covered, the
  application still enabled. Otherwise the refresh fails with `invalid_grant` and the grant is
  revoked; a new authorization shows the chooser again (or `no_representation_available`).
- `prompt=none` with a chooser to show answers `account_selection_required`.

Rights come from representation sources enabled per tenant; v1 has Portvakt's own register
(grants made out to a person, or to a personal identity number before that person first signs
in, limited to applications or valid for all of the tenant's applications). A grant made out to
a personal identity number counts only when the person signed in through a login method trusted
for it (`trustPinForRepresentation`: at least loa3, and the method maps the number) and the
number is the one this login asserted; a number known from another login method of the same
person does not count. Bolagsverket or Mina
ombud can be added as sources later without changing the claim.

### Step-up (`acr_values`, `max_age`)

An application asks for a higher assurance level with `acr_values` (or for a fresh
authentication with `max_age`) while the person is signed in: Portvakt then requires a new
upstream login through a login method that satisfies the request (the same ranking and method
filtering as above; no method: `no_acceptable_method`). When Portvakt knows the person's
personal identity number it names the person upstream: SAML PrincipalSelection (when the IdP
advertises it), or for OIDC the number as `login_hint` when the login method accepts it
(`pinLoginHint`, off by default). The step-up must sign in the same person: a login that
resolves to another person (after identity linking) is refused with `step_up_person_mismatch`
and the existing session is kept as it was. The higher `acr` and the new `auth_time` apply to
this application's grant (ID token and access token); other applications keep the claims of
their own logins. The step-up login becomes the session's latest login: its login method's
session policy (`maxAgeSeconds`, `idleSeconds`, `allowSso`) applies to the session from then
on, so SSO into another application can become possible or require a new login, and a later
authorization of another application sees the higher acr.

### `amr`

The upstream ID token's `amr` values (RFC 8176, for example `pwd`, `mfa`). When the upstream
sends none, `amr` is `["fed"]`: authenticated by a federated IdP that did not say how.

### `auth_time`, `session_exp` and session policies

`auth_time` is when the person authenticated upstream (the upstream ID token's `auth_time`,
never later than now); without one it is the time of the login at Portvakt. When an application
sends `max_age`, Portvakt passes it upstream and refuses an upstream ID token without a recent
enough `auth_time`. `session_exp` is the time of the login at Portvakt plus the login method's
`maxAgeSeconds` (capped to `SESSION_TTL`), so it does not shrink when the upstream reuses an older
authentication.
A backend-for-frontend must end its own session no later than this. Refresh tokens live at most
`min(idleSeconds, session_exp - now)`; after `idleSeconds` without an authorization or refresh the
next authorization requires a login. Each application keeps the claims of the login it was
issued tokens for: a fresh login for another application in the same browser does not change
them.

### `pin`

Only in ID tokens, only when the application requested scope `pin` and is allowed it
(`allowedExtraScopes` contains `pin`). An application that is not allowed the scope cannot
request it (`invalid_scope`). The value is the canonical 12-digit form; a samordningsnummer keeps
its day + 60.

### `hsa_id` and `org_affiliation`

Only in ID tokens, only when the application requested scope `hsa` and is allowed it
(`allowedExtraScopes` contains `hsa`), like `pin`. They come from SAML login methods (SITHS
style): `hsa_id` is the employeeHsaId, `org_affiliation` the orgAffiliation values whose scope
Portvakt accepted. `prid` is not issued as a claim.

### `protected_identity`

Present (`true`) when the person has a protected identity. It is sticky on the person: as soon
as any identity of the person (any login method, linked by personal identity number) is flagged
upstream (`true`, `"true"`, `1` or `"1"` in the mapped claim), Portvakt removes the stored name
and email from all of the person's identities and never issues `name` or `email` for the person
again, whichever login method is used. Only an administrator can clear the flag. Applications
must minimise what they display and store about the person.

### `email`

The upstream email is mapped only when the upstream marks it verified (`email_verified: true`)
or the login method is configured to trust the upstream's addresses (`trustUpstreamEmail`, for
example Entra ID work accounts, which carry no `email_verified`). Email is never an identifier:
identities are linked by the upstream subject (and, between citizen methods, the personal
identity number), never by email. Applications must not use it to identify a person either.

### Multi-tenant upstream issuers

A login method on a multi-tenant issuer (Entra ID `/common`, `/organizations`, `/consumers`, or
any issuer whose discovery returns `{tenantid}`) must list the upstream tenant ids allowed to sign
in; such a method cannot be saved without the list. The ID token's `tid` must be one of them and
its issuer must be that tenant's issuer, otherwise the login fails (`account_not_allowed`).

### SAML login methods (Swedish eID Framework)

SAML login methods map the attributes of the Attribute Specification for the Swedish eID
Framework (version 1.8) to the same claims as OIDC methods. The attribute names below are the
defaults; each can be changed per login method (`attributeMapping`).

| SAML attribute                                                           | Claim / use                                                                                                                                                                                                                                        |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `urn:oid:1.2.752.29.4.13` personalIdentityNumber                         | `pin` (validated and canonicalised, 12 digits); links identities between citizen methods with `linkByPin`                                                                                                                                          |
| `urn:oid:2.16.840.1.113730.3.1.241` displayName                          | `name`                                                                                                                                                                                                                                             |
| `urn:oid:2.5.4.42` givenName, `urn:oid:2.5.4.4` sn                       | `name` when there is no displayName (given name and surname joined)                                                                                                                                                                                |
| `urn:oid:1.2.752.201.3.4` prid                                           | the identity's subject with subject source `prid` (no claim of its own)                                                                                                                                                                            |
| `urn:oid:1.2.752.201.3.5` pridPersistence                                | not mapped (prid's stability: A, B or C)                                                                                                                                                                                                           |
| `urn:oid:1.2.752.29.6.2.1` employeeHsaId                                 | `hsa_id` (scope `hsa`); the identity's subject with subject source `employeeHsaId` (SITHS)                                                                                                                                                         |
| `urn:oid:1.2.752.201.3.1` orgAffiliation                                 | `org_affiliation` (scope `hsa`) and upstream groups for role rules (`roles`), only values whose scope (after the last `@`) is a `shibmd:Scope` of the IdP's metadata or one of the login method's `orgAffiliationScopes`; other values are dropped |
| `urn:oid:0.9.2342.19200300.100.1.3` mail                                 | `email`, only when the login method trusts the IdP's addresses (`trustEmail`)                                                                                                                                                                      |
| NameID (persistent)                                                      | the identity's subject with subject source `nameId`; a transient NameID is refused as a subject                                                                                                                                                    |
| AuthnContextClassRef                                                     | `acr` (the returned LoA, for example `http://id.elegnamnden.se/loa/1.0/loa3`)                                                                                                                                                                      |
| AuthnStatement `AuthnInstant`                                            | `auth_time` (never later than now)                                                                                                                                                                                                                 |
| configurable attribute and values (`attributeMapping.protectedIdentity`) | `protected_identity` (sticky, as above); the framework defines no attribute or status for protected identity                                                                                                                                       |

`amr` is `["fed"]` for SAML logins (SAML carries no RFC 8176 methods). The identity's subject
follows the login method's subject source: `personalIdentityNumber` (stored as the number's
blind index, never the number), `prid`, `employeeHsaId` or `nameId`. An attribute used as the
subject or as `pin` must have exactly one value.

An application that sends `acr_values` is offered a SAML method when one of the levels it
requests satisfies them, and Portvakt then requests only those levels (step-up through
RequestedAuthnContext). `prompt=login`, `max_age`, an expired or idle session, a higher acr, and
`allowSso = false` across applications send ForceAuthn, and the returned AuthnInstant must be
later than the request; with `max_age` it must also be recent enough.

### `roles` from upstream groups

Group rules map upstream group values of a login method to application roles; they are evaluated
for every token. For Entra ID, a user in more groups than fit in a token gets a groups overage
(`_claim_names` / `_claim_sources` instead of `groups`). Portvakt does not call Microsoft Graph:
the groups are then treated as empty (no rule matches), an audit event `login.groups_overage` is
written and a warning logged. Recommended Entra ID setting: in the app registration, under
Token configuration, emit the groups claim for "Groups assigned to the application" only (and
assign the relevant groups to the enterprise application), so the token stays below the overage
limit.

## Examples

Employee (Entra ID login method, scopes `openid profile email`), ID token:

```json
{
  "iss": "https://login.example.org/t/kommunen",
  "aud": "case-service",
  "sub": "3f2b8c4e-91d7-4a3e-8b6f-2d4c9e1a7b55",
  "tid": "kommunen",
  "idp": "0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7",
  "idp_kind": "employee",
  "acr": "urn:portvakt:acr:employee",
  "amr": ["pwd", "mfa"],
  "auth_time": 1792330000,
  "session_exp": 1792358800,
  "roles": ["handlaggare"],
  "attrs": { "unit": "north" },
  "name": "Anna Andersson",
  "email": "anna.andersson@kommun.example",
  "nonce": "…",
  "iat": 1792330001,
  "exp": 1792330301
}
```

The access token for the same login:

```json
{
  "iss": "https://login.example.org/t/kommunen",
  "aud": "case-service",
  "client_id": "case-service",
  "sub": "3f2b8c4e-91d7-4a3e-8b6f-2d4c9e1a7b55",
  "tid": "kommunen",
  "idp": "0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7",
  "idp_kind": "employee",
  "acr": "urn:portvakt:acr:employee",
  "auth_time": 1792330000,
  "roles": ["handlaggare"],
  "attrs": { "unit": "north" },
  "jti": "…",
  "iat": 1792330001,
  "exp": 1792330301
}
```

Citizen (BankID-style login method, scopes `openid profile pin`, application allowed `pin`), ID
token:

```json
{
  "iss": "https://login.example.org/t/kommunen",
  "aud": "e-service",
  "sub": "8a41c2d0-5e3b-4f7a-9c18-6b2e0d4f3a91",
  "tid": "kommunen",
  "idp": "5d0c7e12-3a4b-4c8d-9e6f-1a2b3c4d5e6f",
  "idp_kind": "citizen",
  "acr": "http://id.elegnamnden.se/loa/1.0/loa3",
  "amr": ["mfa"],
  "auth_time": 1792330000,
  "session_exp": 1792333600,
  "roles": [],
  "attrs": {},
  "name": "Sven Medborgare",
  "pin": "191212121212"
}
```

Citizen with a protected identity (same request): no `name`, `protected_identity` present:

```json
{
  "sub": "c19e0b7a-2f4d-4e8b-a6c3-7d5f1e9b2a40",
  "tid": "kommunen",
  "idp": "5d0c7e12-3a4b-4c8d-9e6f-1a2b3c4d5e6f",
  "idp_kind": "citizen",
  "acr": "http://id.elegnamnden.se/loa/1.0/loa3",
  "amr": ["mfa"],
  "auth_time": 1792330000,
  "session_exp": 1792333600,
  "roles": [],
  "attrs": {},
  "pin": "200001010008",
  "protected_identity": true
}
```

The access tokens of both citizen logins carry `sub`, `tid`, `idp`, `idp_kind`, `acr`,
`auth_time`, `roles` and `attrs` only.

A citizen acting for a company (application with `representationMode` `optional` or
`required`), ID token:

```json
{
  "iss": "https://login.example.org/t/kommunen",
  "aud": "bygglov",
  "sub": "8a41c2d0-5e3b-4f7a-9c18-6b2e0d4f3a91",
  "tid": "kommunen",
  "idp": "5d0c7e12-3a4b-4c8d-9e6f-1a2b3c4d5e6f",
  "idp_kind": "citizen",
  "acr": "http://id.elegnamnden.se/loa/1.0/loa3",
  "amr": ["mfa"],
  "auth_time": 1792330000,
  "session_exp": 1792333600,
  "roles": [],
  "attrs": {},
  "name": "Sven Medborgare",
  "rep": {
    "sub": "e7c1a9b2-4d3f-4a8e-b6c5-0f9d2e1a3b47",
    "type": "organisation",
    "name": "Bygg AB"
  }
}
```

Its access token carries `rep` without the name:

```json
{
  "iss": "https://login.example.org/t/kommunen",
  "aud": "bygglov",
  "client_id": "bygglov",
  "sub": "8a41c2d0-5e3b-4f7a-9c18-6b2e0d4f3a91",
  "tid": "kommunen",
  "idp": "5d0c7e12-3a4b-4c8d-9e6f-1a2b3c4d5e6f",
  "idp_kind": "citizen",
  "acr": "http://id.elegnamnden.se/loa/1.0/loa3",
  "auth_time": 1792330000,
  "roles": [],
  "attrs": {},
  "rep": { "sub": "e7c1a9b2-4d3f-4a8e-b6c5-0f9d2e1a3b47", "type": "organisation" },
  "jti": "…",
  "iat": 1792330001,
  "exp": 1792330301
}
```

Acting for a person with a protected identity, the ID token's `rep` has no name either:

```json
{
  "sub": "8a41c2d0-5e3b-4f7a-9c18-6b2e0d4f3a91",
  "rep": { "sub": "1b6f0e2d-9c4a-4e7b-a3d8-5c2f7e9a0b16", "type": "person" }
}
```
