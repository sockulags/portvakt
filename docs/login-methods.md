# Login methods

A login method is an upstream identity provider configured for one tenant: generic OIDC (Entra
ID, Criipto, Signicat and similar) or SAML 2.0 following the Swedish eID Framework (BankID,
Freja eID and SITHS through framework IdPs). Tenants configure them in the admin portal
(Inloggningsmetoder) or with `POST /admin/api/v1/tenants/{tenantId}/login-methods`
([admin-api.md](admin-api.md); the OpenAPI document at `/admin/api/v1/openapi.json` has every
field). Nothing in Portvakt is specific to one provider.

**Verification status.** The Portvakt side of everything below is implemented and tested against
the mock IdPs. Provider-specific values (claim names, URLs, levels a provider asserts) come from
the providers' public documentation as known when this was written and are marked _(verify)_
where they were not checked against the provider's current documentation or a live tenant.
Check them with the provider before going live.

## Common settings

| Setting                     | Meaning                                                                                                                                                                                                                                                             |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kind`                      | `employee` or `citizen`; issued as `idp_kind`                                                                                                                                                                                                                       |
| `displayName`               | The button text in the login UI                                                                                                                                                                                                                                     |
| `assertedAcr`               | The acr Portvakt asserts for logins through the method (OIDC), or the lowest level a login must reach (SAML). A value in `ACR_RANKING` (loa2, loa3, loa4) requires proof from the upstream: an acr claim mapping (OIDC) or the returned AuthnContextClassRef (SAML) |
| `homeRealmDomains`          | Email domains whose `login_hint` goes straight to this method                                                                                                                                                                                                       |
| `sessionPolicy`             | `maxAgeSeconds` (at most `SESSION_TTL`), `idleSeconds`, `allowSso` (see [claims.md](claims.md))                                                                                                                                                                     |
| `linkByPin`                 | Link identities of methods that map a personal identity number and assert at least loa3 to one person                                                                                                                                                               |
| `trustPinForRepresentation` | Representation grants made out to a personal identity number count for logins through this method (needs at least loa3 and a mapped number)                                                                                                                         |
| `secretExpiresAt`           | When the upstream client secret expires: flagged 30 days ahead                                                                                                                                                                                                      |

Disabling or deleting a method ends every session and grant whose login came through it.

## OIDC methods

| Setting                    | Meaning                                                                                                                                                                         |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuer`                   | The upstream issuer; discovery at `{issuer}/.well-known/openid-configuration` (https in production)                                                                             |
| `clientId`, `clientSecret` | The registration at the upstream (the secret is stored encrypted, never returned)                                                                                               |
| `clientAuthMethod`         | `client_secret_basic` (default), `client_secret_post` or `private_key_jwt` (an ES256 key Portvakt generates per method; its public JWKS is at `/t/{slug}/federation/{id}/jwks`) |
| `clientAssertionAudience`  | `token_endpoint` (default) or `issuer` for `private_key_jwt`                                                                                                                    |
| `scopes`                   | Requested scopes (`openid` is required)                                                                                                                                         |
| `claimMapping`             | Upstream claims for `subject` (default `sub`), `name`, `email`, `pin`, `groups`, `acr`, `protectedIdentity` (dotted paths allowed)                                              |
| `useUserinfo`              | Read claims from the upstream userinfo endpoint too                                                                                                                             |
| `trustUpstreamEmail`       | Map `email` without `email_verified` (for providers that never send it)                                                                                                         |
| `pinLoginHint`             | At a step-up, send the personal identity number as `login_hint`, only through PAR                                                                                               |
| `allowedUpstreamTenants`   | Required for multi-tenant issuers (Entra `/common`, `/organizations`, `{tenantid}`): the allowed tenant ids                                                                     |

The redirect URI to register at the upstream is
`{PUBLIC_URL}/t/{tenantSlug}/federation/{loginMethodId}/callback` (shown in the portal after the
method is created). Upstream ID tokens are validated fully (issuer, audience, expiry, nonce,
signature against the upstream JWKS with asymmetric algorithms only); every request to the
upstream goes through the outbound guard (no private addresses, https, bounded redirects and
sizes). Code: [`federation/upstream.ts`](../apps/server/src/federation/upstream.ts).

Rotating the client key (`private_key_jwt`): `POST
/tenants/{id}/login-methods/{id}/client-key/prepare` adds a `next` key, published at the
method's `jwksUri` next to the active one and not used to sign yet. Wait until the upstream has
fetched the JWKS again (Portvakt serves it with `max-age=300`; add the upstream's own cache
time), or register the new public key there, then `POST .../client-key/rotate`: the next key
signs the client assertions from then on, and the former key loses its private part and stays
published as `retiring` for one hour, so assertions signed just before the promotion still
verify. The view's `oidc.clientKeys` lists the keys with their state; both steps are audited
(`admin.login_method.client_key_prepare`, `admin.login_method.client_key_rotate`).

### Entra ID (employees)

1. In Entra ID, register an application (single tenant), platform **Web**, redirect URI as
   above. Create a client secret (note its expiry for `secretExpiresAt`). Entra ID does not fetch
   a client's JWKS from a URL, so use `client_secret_basic` or `client_secret_post` _(verify if
   you need certificate credentials: Portvakt's `private_key_jwt` key is ES256 and published as a
   JWKS URL)_.
2. Token configuration: add the `groups` claim with **Groups assigned to the application** and
   assign the relevant groups to the enterprise application, so the token stays below the
   groups overage limit (Portvakt does not call Microsoft Graph; an overage counts as no groups
   and is audited as `login.groups_overage`). Add the optional claim `email` if you need it.
3. Create the method:

```json
{
  "protocol": "oidc",
  "kind": "employee",
  "displayName": "Kommunens konto",
  "issuer": "https://login.microsoftonline.com/{entra-tenant-id}/v2.0",
  "clientId": "{application (client) id}",
  "clientSecret": "{secret}",
  "scopes": ["openid", "profile", "email"],
  "claimMapping": { "subject": "oid", "name": "name", "email": "email", "groups": "groups" },
  "trustUpstreamEmail": true,
  "assertedAcr": "urn:portvakt:acr:employee",
  "homeRealmDomains": ["kommun.example"],
  "sessionPolicy": { "maxAgeSeconds": 28800, "idleSeconds": 3600, "allowSso": true }
}
```

- Subject: `oid` (the user's object id in the Entra tenant) is the same for every application of
  that tenant; `sub` is pairwise per application. Use one of them consistently; pending role
  assignments by upstream subject name the same value.
- Entra ID does not prove a Swedish level of assurance: assert an unranked value such as
  `urn:portvakt:acr:employee` (applications that require loa3 will not accept it). An Entra ID
  that federates to an eID provider and emits a level in a claim can map `claimMapping.acr`
  _(verify)_.
- Entra ID sends no `email_verified`; `trustUpstreamEmail` maps the address of work accounts.
- Multi-tenant (`/organizations` or `/common`): list the allowed tenant ids in
  `allowedUpstreamTenants`; the method cannot be saved without them.
- Groups to roles: role rules in the tenant map a group object id of this method to an
  application role.

### Criipto and Signicat (citizens: BankID, Freja eID)

Both are OIDC brokers in front of Swedish eIDs. Register Portvakt's redirect URI as a callback
in the broker's application, then create an OIDC method. The broker chooses the eID by an
`acr_values` request or by the application's configuration _(verify for your broker)_; one
Portvakt method per eID gives people one button each.

Criipto Verify _(verify every value against Criipto's documentation)_:

```json
{
  "protocol": "oidc",
  "kind": "citizen",
  "displayName": "BankID",
  "issuer": "https://{your-domain}.criipto.id",
  "clientId": "urn:my:application:identifier:{id}",
  "clientSecret": "{secret}",
  "scopes": ["openid"],
  "claimMapping": { "subject": "sub", "name": "name", "pin": "ssn" },
  "assertedAcr": "urn:portvakt:acr:bankid",
  "linkByPin": true,
  "sessionPolicy": { "maxAgeSeconds": 3600, "idleSeconds": 900, "allowSso": false }
}
```

Signicat _(verify every value against Signicat's documentation)_: the issuer is the tenant's
OIDC base URL (for example `https://{tenant}.signicat.com/auth/open`); the Swedish personal
identity number arrives in a claim such as `nin` (with `nin_type`/`nin_issuing_country`), which
`claimMapping.pin` names.

Levels of assurance: BankID and Freja eID+ are delivered at loa3 in the Swedish framework
_(verify for your broker and agreement)_. To
assert `http://id.elegnamnden.se/loa/1.0/loa3` (a ranked level, required for `linkByPin` and
`trustPinForRepresentation`), the broker must state the level in a claim that `claimMapping.acr`
maps, and Portvakt then requests it (`acr_values`) and refuses logins that do not reach it. If the
broker does not emit a framework level, assert an unranked value such as
`urn:portvakt:acr:bankid`: logins work, but identities are not linked by number, pin-based
representation grants do not count, and applications requiring loa3 do not accept the method.
`pinLoginHint` names the person at a step-up only when the broker advertises PAR.

The personal identity number is validated (Luhn, date, samordningsnummer) and stored encrypted
with a blind index; it reaches applications only as `pin` with scope `pin`.

## SAML methods (Swedish eID Framework)

Portvakt implements the SP side of the Swedish eID Framework as published at
docs.swedenconnect.se/technical-framework/latest: Deployment Profile 1.8, Attribute
Specification 1.8, Registry for identifiers 1.8, Entity Categories 1.9 and Principal Selection
1.0 (identifiers in [`domain/saml.ts`](../apps/server/src/domain/saml.ts)). Each login method is
its own SP:

| SP endpoint                                | Use                                                    |
| ------------------------------------------ | ------------------------------------------------------ |
| `{PUBLIC_URL}/t/{slug}/saml/{id}`          | The SP's entityID                                      |
| `{PUBLIC_URL}/t/{slug}/saml/{id}/metadata` | SP metadata to register with the federation or the IdP |
| `{PUBLIC_URL}/t/{slug}/saml/{id}/acs`      | AssertionConsumerService (HTTP-POST)                   |
| `{PUBLIC_URL}/t/{slug}/saml/{id}/slo`      | SingleLogoutService (HTTP-Redirect and HTTP-POST)      |

The SP metadata carries the signing and encryption certificates (RSA 3072, generated by Portvakt,
private keys encrypted with MASTER_KEY), the entity categories, the requested attributes,
`mdui:UIInfo` (display name, description and logo; production requires a logo) and the
supported encryption methods (AES-GCM, and CBC only inside a signed Response; RSA-OAEP).
Rotating SP keys: `sp-keys/prepare` publishes the next keys next to the active ones; re-register
or let the federation pick up the metadata; then `sp-keys/rotate`.

| Setting                       | Meaning                                                                                                                                           |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `idpEntityId`                 | The IdP's entityID                                                                                                                                |
| `metadataUrl` / `metadataXml` | Where the IdP's metadata comes from (a federation aggregate or the IdP's own); exactly one                                                        |
| `metadataSigningCertificate`  | Certificate the metadata must be signed with (required for a URL in production unless `allowUnsignedMetadata`, which is audited)                  |
| `metadataRefreshSeconds`      | Refresh interval (default 3600); logins never fetch metadata while a cached copy is valid; stale metadata fails closed                            |
| `requestedLoa`                | RequestedAuthnContext URIs, for example `http://id.elegnamnden.se/loa/1.0/loa3`                                                                   |
| `authnContextComparison`      | `exact` (the framework's rule; default) or `minimum` (IdPs outside the framework)                                                                 |
| `entityCategories`            | Service entity categories in the SP metadata, for example `http://id.elegnamnden.se/ec/1.0/loa3-pnr`                                              |
| `requestedAttributes`         | Extra `md:RequestedAttribute`s                                                                                                                    |
| `subjectSource`               | What identifies the person: `personalIdentityNumber`, `prid`, `employeeHsaId` or `nameId` (persistent)                                            |
| `attributeMapping`            | Attribute names (defaults from the Attribute Specification) and `protectedIdentity` (`{ attribute, values }`; the framework has no signal for it) |
| `authnRequestBinding`         | `redirect` (default) or `post` (required for PrincipalSelection)                                                                                  |
| `requireEncryptedAssertions`  | Default `true` (the framework requires encryption)                                                                                                |
| `requireSignedResponse`       | Default `true`                                                                                                                                    |
| `requireGcm`                  | Refuse AES-CBC content encryption altogether                                                                                                      |
| `clockSkewSeconds`            | Default 60 (Deployment Profile 1.9 draft; 1.8 allows 3 to 5 minutes)                                                                              |
| `trustEmail`                  | Map `mail` to `email`                                                                                                                             |
| `orgAffiliationScopes`        | Accepted scopes of orgAffiliation values, besides the IdP metadata's `shibmd:Scope`s                                                              |
| `uiInfo`                      | `mdui:UIInfo` of the SP metadata (`displayName`, `description` in Swedish and English, `logos` with https URLs)                                   |

Attribute mapping to claims is in [claims.md](claims.md#saml-login-methods-swedish-eid-framework).
The ACS checks are listed in [architecture.md](architecture.md#saml-login-swedish-eid-framework)
and [threat-model.md](threat-model.md).

### Levels of assurance and entity categories

- Request the levels your applications need in `requestedLoa` (with `exact`, the returned
  AuthnContextClassRef must be one of them) and set `assertedAcr` to the lowest; a step-up with
  `acr_values` narrows RequestedAuthnContext to the levels that satisfy it.
- Choose the service entity category that matches the attributes you need, for example
  `http://id.elegnamnden.se/ec/1.0/loa3-pnr` (a person with a personal identity number at loa3:
  personalIdentityNumber, givenName, sn, displayName, dateOfBirth) or
  `http://id.swedenconnect.se/ec/1.0/loa3-hsaid` for SITHS-style HSA-id releases _(the latter is
  listed in the Registry 1.8; Entity Categories 1.9 leaves HSA categories to the federation
  operator: verify with yours)_. Add the service type
  `http://id.elegnamnden.se/st/1.0/public-sector-sp` for a public-sector service, and
  `http://id.swedenconnect.se/general-ec/1.0/accepts-coordination-number` when samordningsnummer
  are accepted. The IdP releases attributes by matching its own categories with the SP's.
- `subjectSource: personalIdentityNumber` keys identities by the number's blind index (never the
  number itself) and is the usual choice for citizens; `prid` follows the framework's provisional
  id; `employeeHsaId` for SITHS.

### PrincipalSelection (step-up)

At a step-up Portvakt names the person with the framework's PrincipalSelection extension
(`http://id.swedenconnect.se/authn/1.0/principal-selection/ns`, personalIdentityNumber) when the
IdP's metadata advertises support for it, and only over HTTP-POST (`authnRequestBinding:
post`): the number must not appear in a URL. The returned number must match either way.

### BankID and Freja eID through a framework IdP

Sweden Connect federation members reach BankID and Freja eID through IdPs listed in the
federation metadata _(verify the current aggregate URLs and signing certificate with the
federation operator, DIGG; at the time of writing the production aggregate was published under
md.swedenconnect.se and a QA aggregate under qa.md.swedenconnect.se)_:

```json
{
  "protocol": "saml",
  "kind": "citizen",
  "displayName": "BankID",
  "assertedAcr": "http://id.elegnamnden.se/loa/1.0/loa3",
  "linkByPin": true,
  "trustPinForRepresentation": true,
  "sessionPolicy": { "maxAgeSeconds": 3600, "idleSeconds": 900, "allowSso": false },
  "saml": {
    "idpEntityId": "{the IdP's entityID from the federation metadata}",
    "metadataUrl": "{the federation's metadata aggregate}",
    "metadataSigningCertificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "requestedLoa": ["http://id.elegnamnden.se/loa/1.0/loa3"],
    "entityCategories": [
      "http://id.elegnamnden.se/ec/1.0/loa3-pnr",
      "http://id.elegnamnden.se/st/1.0/public-sector-sp"
    ],
    "subjectSource": "personalIdentityNumber",
    "authnRequestBinding": "post",
    "uiInfo": {
      "displayName": { "sv": "Kommunens e-tjänster", "en": "Municipal e-services" },
      "logos": [{ "url": "https://kommun.example/logo.png", "width": 120, "height": 60 }]
    }
  }
}
```

Register the SP metadata URL with the federation (or the IdP operator), and wait for it to appear
in the aggregate the IdP reads. Freja eID+ is configured the same way with its IdP's entityID
_(verify which levels Freja's IdP returns for your agreement: loa2 and loa3 exist)_.

### SITHS (employees in healthcare and municipalities)

SITHS eID logins reach Portvakt through a SAML IdP such as Inera's IdP. Use `kind: employee`,
`subjectSource: employeeHsaId`, `requestedLoa` loa3 _(verify with the IdP)_, and give
applications that need the HSA-id the extra scope `hsa`:

- `hsa_id` comes from employeeHsaId (`urn:oid:1.2.752.29.6.2.1`); `org_affiliation` from
  orgAffiliation (`urn:oid:1.2.752.201.3.1`, `uid@orgnr`), kept only for scopes the IdP's
  metadata declares (`shibmd:Scope`) or listed in `orgAffiliationScopes`. Both values also serve
  as upstream groups for role rules (for example an HSA-id or `@orgnr` affiliation to a role).
- Inera specifics _(not verified: confirm with Inera)_: Inera publishes IdP metadata for its
  SITHS IdP and runs the Sambi federation for healthcare with its own metadata and attribute
  rules; the entityID, metadata URL, signing certificate, released attributes (HSA attributes
  beyond employeeHsaId) and the entity categories it expects come from Inera's onboarding. Map
  any extra attribute with `attributeMapping` or `requestedAttributes`; Portvakt issues only the
  claims of the contract.

### Single logout

When the IdP's metadata has a SingleLogoutService, an RP-initiated logout at Portvakt also sends
a LogoutRequest to the IdP, and IdP-initiated LogoutRequests end the broker sessions that hold
that IdP session. A failing or missing SLO never blocks the local logout.

## Testing a configuration

- The admin API validates a method when it is saved (the issuer URL against the outbound
  policy; for SAML the metadata is fetched or parsed and its signature checked; level, scope and
  linking rules) and returns `warnings`
  (expiring secrets or certificates, missing logo, unsigned metadata, PAR missing for
  `pinLoginHint`).
- Sign in through an application of the tenant with `login_hint` set to an email of a
  `homeRealmDomains` domain to go straight to an employee method.
- `login.failure` audit events carry the reason code of every refused login (no personal data);
  `portvakt_upstream_request_failures_total` counts upstream failures per method.
