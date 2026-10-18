# Claims contract v1

This is the contract between Portvakt and the applications of a tenant: which claims the ID
token and the access token carry, and what they mean. It follows the claims table in
[plan.md](plan.md) ("Claims contract (v1)"). Renaming or removing a claim, or changing its
meaning or type, is a breaking change and needs a new contract version; adding a claim is not.

## Principles

- `sub` is always the UUID of the signed-in person in the tenant, stable across logins and login
  methods (identities linked by personal identity number share one person). It stays the signed-in
  person when representing someone; the represented party arrives as `rep` (M4). There is no
  `act` claim.
- Access tokens are JWTs for exactly one application (`aud` is its `client_id`). They carry
  identity and authorization data only, never `name`, `email` or `pin` (data minimisation).
- ID tokens carry the profile claims the granted scopes allow. The userinfo endpoint is
  disabled: applications read profile claims from the ID token.
- Roles and attributes are always for the token's audience application only.

## Claims

| Claim                | ID token                           | Access token | Meaning                                                                                                   |
| -------------------- | ---------------------------------- | ------------ | --------------------------------------------------------------------------------------------------------- |
| `iss`                | yes                                | yes          | `{PUBLIC_URL}/t/{tenant slug}`, one issuer per tenant                                                     |
| `aud`                | yes                                | yes          | `client_id` of the application                                                                            |
| `sub`                | yes                                | yes          | The signed-in person's UUID                                                                               |
| `tid`                | yes                                | yes          | Tenant slug                                                                                               |
| `idp`                | yes                                | yes          | Id (UUID) of the login method used                                                                        |
| `idp_kind`           | yes                                | yes          | `employee` or `citizen`                                                                                   |
| `acr`                | yes                                | yes          | Assurance level the login method asserts (see below)                                                      |
| `amr`                | yes                                | no           | Authentication methods, from the upstream IdP                                                             |
| `auth_time`          | yes                                | yes          | Epoch seconds of the authentication: the upstream `auth_time` (never later than now), else the login time |
| `session_exp`        | yes                                | no           | Epoch seconds: absolute end of the broker session for this login                                          |
| `roles`              | yes                                | yes          | Roles of the person in this application: direct assignments plus matched group rules                      |
| `attrs`              | yes                                | yes          | Attribute map of the person in this application                                                           |
| `rep`                | M4                                 | M4           | Only when representing: `{ "sub": <party UUID>, "type": "person" \| "organisation", "name" }`             |
| `name`               | with scope `profile`               | no           | Display name from the upstream IdP                                                                        |
| `email`              | with scope `email`                 | no           | Verified email address from the upstream IdP; never an identifier                                         |
| `pin`                | with scope `pin`, if allowed       | no           | Personal identity number (personnummer or samordningsnummer), 12 digits `YYYYMMDDNNNC`                    |
| `protected_identity` | `true` when protected, else absent | no           | The person has a protected identity (skyddad identitet)                                                   |

The JWT and OAuth basics (`exp`, `iat`, `jti`, `client_id` in access tokens; `nonce`, `sid`,
`at_hash` in ID tokens) are as oidc-provider issues them.

### `acr`

The acr is the login method's configured `assertedAcr`, never a value the upstream IdP chose.
When the login method maps an upstream acr claim, Portvakt asks the upstream for the asserted
level (`acr_values`) and refuses the login unless the upstream acr reaches it. Levels are ordered
by `ACR_RANKING` (default: the Swedish eID Framework levels
`http://id.elegnamnden.se/loa/1.0/loa2` < `.../loa3` < `.../loa4`). An application that sends
`acr_values` is only offered login methods whose acr equals one of the values or ranks at least
as high as a ranked one; values outside the ranking only match themselves. A session whose acr
does not satisfy the request requires a new login.

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
