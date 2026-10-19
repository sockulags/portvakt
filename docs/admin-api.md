# Admin API v1

The admin API lives in the broker below `{PUBLIC_URL}/admin/api/v1`. It is JSON over HTTPS. The
OpenAPI 3.1 document is served at
[`/admin/api/v1/openapi.json`](http://localhost:3000/admin/api/v1/openapi.json) (generated from
the same zod schemas that validate requests, and checked against the routes in tests). The admin
portal (`apps/admin`) is its main client.

## Authentication

Every operation needs `Authorization: Bearer <access token>` of the application
`portvakt-admin`. Each tenant has its own issuer, so tokens of any active tenant are accepted, but:

- the token must be an ES256 JWT with `typ: at+jwt`, signed by a published Portvakt key;
- `iss` must be exactly `{PUBLIC_URL}/t/{tid}`, and the `tid` claim must name that same tenant
  (Portvakt signs every tenant's tokens with the same keys, so the issuer is what proves the
  tenant);
- `aud` must be exactly `portvakt-admin`;
- the tenant must be active, `portvakt-admin` must be enabled in it, and the person must exist;
- service tokens (client credentials) are refused (`service_token_not_allowed`), and so are
  tokens issued while representing someone (`rep` present: `representation_not_allowed`).

Roles are checked live: the token's `roles` count only while the person still holds them right
now (direct assignments, and rules matched against the groups stored on the identity the person
signed in with). Removing an admin role or rule takes effect at the next request, not when the
token expires.

## Scope

| Caller                                    | May administer                                      |
| ----------------------------------------- | --------------------------------------------------- |
| `platform-admin` in the `system` tenant   | every tenant, the global application registry, keys |
| `tenant-admin` in tenant X (not `system`) | tenant X only                                       |
| `tenant-admin` in the `system` tenant     | only `/me`; everything else is `404 not_found`      |
| anyone else (also `platform-admin` in X)  | nothing (`403 forbidden`)                           |

Tenant-scoped operations live below `/tenants/{tenantId}`. A tenant administrator addressing any
other tenant id gets `404 not_found`, before the request body is even read, so tenants cannot be
enumerated. Operations marked `x-portvakt-access: platform-admin` in the OpenAPI document
(creating and changing tenants, representation sources, the application registry, attaching and
detaching applications, the system-wide audit log, signing key rotation) answer `403` to tenant
administrators. Key rotation is audited as a platform event (`admin.signing_key.rotate`, no
tenant), written in the same transaction as the rotation, and its `If-Match` is checked under the
rotation's exclusive lock: of concurrent rotations with the same tag exactly one succeeds.

`POST /signing-keys/rotate` publishes ahead unless `emergency` is set: the new key is in JWKS at
once and becomes active `policy.manualPublishAheadSeconds` later (KEY_MANUAL_PUBLISH_AHEAD,
default 10 minutes; the rotation job activates it then). The answer is `status: "scheduled"` with
`nextKid` and `activatesAt`; the key set lists the key as `next` with its `activateAt`. A
`next` key that has already been published that long (from the scheduled rotation) is activated
at once (`status: "activated"`). With `emergency: true` (key compromise) a new key signs at once
and the previous one is retired immediately (`status: "activated"`, `retiredKids`).

The role `platform-admin` of `portvakt-admin` can only be given in the `system` tenant, by a
platform administrator: in assignments, pending assignments and rules anywhere else it is refused
with a field error on `role`.

Safeguards against locking administrators out (`409 self_lockout`):

- the system tenant (and the caller's own tenant) cannot be suspended, and `portvakt-admin`
  cannot be disabled, stripped of its roles, given a representation mode or detached from the
  caller's own tenant;
- no change may leave the `system` tenant without an enabled login method, or without a way to
  become platform admin: an assignment of a person with an identity at an enabled method, a
  pending assignment that can resolve, or a rule at an enabled method. This covers deleting
  assignments, pending assignments and rules, disabling or deleting login methods, changing a
  method's issuer (OIDC) or IdP entity ID (SAML), which orphans its identities, unlinking
  identities and deleting persons.

## Optimistic concurrency

Every mutable resource carries an `etag` (also sent as the `ETag` header). Changing it requires
`If-Match` with that tag: without one the answer is `428 precondition_required`, with a stale one
`412 precondition_failed` (someone else changed it; read it again). `*` is not accepted. The row
is locked for the check and the write, so two concurrent updates cannot both pass.

## Errors

Errors are RFC 9457 problem details (`application/problem+json`), with the request's id and
W3C trace id (`X-Request-Id`, `traceparent`: an incoming `traceparent` is continued) for log
correlation:

```json
{
  "type": "urn:portvakt:problem:validation_failed",
  "title": "The request is invalid",
  "status": 400,
  "code": "validation_failed",
  "errors": [{ "field": "slug", "message": "unknown or immutable field" }],
  "requestId": "4bf92f3577b34da6a3ce929d0e0e4736",
  "traceId": "4bf92f3577b34da6a3ce929d0e0e4736"
}
```

`code` is stable: `unauthorized`, `invalid_token`, `forbidden`, `service_token_not_allowed`,
`representation_not_allowed`, `not_found`, `conflict`, `self_lockout`, `in_use` (a login method
that people have signed in with: disable it instead), `last_identity` (a person's only identity:
delete the person instead), `precondition_failed`,
`precondition_required`, `validation_failed` (with `errors`), `invalid_json`,
`unsupported_media_type`, `payload_too_large`, `rate_limited` (`429` with `Retry-After`:
RATE_LIMIT_ADMIN_API per administrator, failed authentications per client IP), `unavailable`,
`internal_error`. Messages never echo request values or internals. Responses of operations are
`Cache-Control: no-store`.

## Secrets and personal data

- Client secrets (applications and OIDC login methods) are write-only. Portvakt generates
  application secrets and returns them once (create, `rotate-secret`). SAML SP private keys are
  generated by Portvakt and never leave it.
- Personal identity numbers are accepted (assignment targets, grant agents, person search) but
  never returned: pending targets and grant agents by number show `{ "kind": "pin" }`, person
  parties show only the date part, identities keyed by the number show no subject. Searches are
  POSTs, so names and numbers never appear in URLs.
- Every change writes an `admin.*` audit event (catalogue in `apps/server/src/audit/catalogue.ts`)
  with the administrator, the target and `changes`, a diff of non-secret fields. Secrets, party
  names and identifiers and attribute values appear only as `{ "changed": true }`; the catalogue
  refuses a diff that carries their values.

## Pending assignments

Role and attribute assignments can be made before someone has signed in: the target is an
identity reference (`{ loginMethodId, subject }`, the upstream subject) or a personal identity
number (`{ pin }`). If that identity or number already belongs to a person, the assignment is made
for the person at once; otherwise it is pending and resolves at the first matching login (audited
as `assignment.pending_resolved`). A number resolves only through a login method trusted for
personal identity numbers (`trustPinForRepresentation`: at least loa3, maps the number), and only
for the number that login asserted. The bootstrap admin is such a pending assignment.

## Removing things

Everything below needs `If-Match` and is audited.

- `DELETE /tenants/{id}/login-methods/{methodId}` deletes a method nobody has signed in with;
  one with identities answers `409 in_use` (disable it with `PATCH { "enabled": false }`).
- `POST /tenants/{id}/applications/{appId}/detach` with `{ "confirmClientId": "<client id>" }`
  detaches an application from a tenant together with its role and attribute assignments
  (pending ones too), rules and grant limits there. `GET .../usage` returns those counts first,
  so the portal can list them in its confirmation; the audit event carries the counts.
- `PATCH /applications/{appId}` replaces `roles` and `attributeKeys` as whole lists: a removed role
  or key goes with every assignment and rule of it, in every tenant.
  `POST /applications/{appId}/removal-impact` with `{ roles, attributeKeys }` counts them first.
- `POST /tenants/{id}/persons/{personId}/identities/{identityId}/unlink` removes one identity from
  a person (the next login with it creates a new person, or links by number); the person's only
  identity answers `409 last_identity`. `DELETE /tenants/{id}/persons/{personId}` deletes the
  person with their identities, assignments and grants as agent.

## Resources

`/me`; `/tenants` (list, create, change name and `representationSources`, suspend, reactivate);
`/tenants/{id}/dashboard`; `/applications` (registry: create, change name, redirect and
post-logout URIs, roles, attribute keys, global enable, client authentication, representation
mode and allowed extra scopes, `rotate-secret`, `removal-impact`) and
`/tenants/{id}/applications` (attach, enable, disable, `usage`, `detach`);
`/tenants/{id}/login-methods` (OIDC and SAML, `session-policy`, `sp-keys/prepare`,
`sp-keys/rotate`, warnings, delete); `/tenants/{id}/roles`, `role-rules`, `role-assignments`,
`attribute-assignments` (create, change value, remove; direct and pending);
`/tenants/{id}/persons/search` and `/tenants/{id}/persons/{personId}`
(`clear-protected-identity`, `identities/{identityId}/unlink`, delete); `/tenants/{id}/parties`
and `grants` (change applications and validity window, `revoke`); `/signing-keys` (`rotate`,
platform administrators only); `/tenants/{id}/audit-events` and the
platform-wide `/audit-events` (keyset pagination: pass `nextCursor` as `cursor`). Redirect URIs
may contain `{tenant}` as a path segment, replaced by the tenant's slug (the admin portal
registers `{ADMIN_PUBLIC_URL}/t/{tenant}/auth/callback`).
