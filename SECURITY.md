# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately, never in a public issue: use the repository host's
private vulnerability reporting (on GitHub: Security, "Report a vulnerability"), or email the
maintainer listed in the repository. Include the affected version, a description, and steps or
a proof of concept if you have one. Do not include real personal data.

What to expect: an acknowledgement within 5 working days, an assessment and a planned fix date
within 15 working days, and a coordinated disclosure once a fixed release is available. We
credit reporters who want to be credited.

## Supported versions

| Version | Security fixes |
| ------- | -------------- |
| 1.0.x   | Yes            |
| < 1.0   | No             |

Fixes are released for the latest minor version of the current major version. Upgrade within
1.x to receive them ([docs/operations.md](docs/operations.md#upgrades)).

## Hardening summary

Portvakt's design and the threats it addresses are in [docs/threat-model.md](docs/threat-model.md),
including the residual risks operators must handle. In short:

- **Tokens**: ES256 access tokens for one application each, issuer per tenant pinned by the
  SDKs; refresh tokens rotate, are single use (a replay revokes the grant) and are re-validated
  at every refresh; administrators' kill switches end sessions at once.
- **Upstream**: upstream ID tokens fully validated with asymmetric algorithms only; SAML with an
  algorithm allowlist, signature-wrapping defences, bounded parsing, encrypted assertions,
  replay cache and signed metadata; every configured URL behind an SSRF guard.
- **Browser**: strict CSP without inline scripts, frame denial, CSRF tokens and same-origin
  checks, cookies scoped per tenant and `Secure` in production, Host and forwarded headers
  pinned to the configured origin.
- **Data**: secrets, private keys and personal identity numbers encrypted at rest (AES-256-GCM,
  bound to their row) with blind indexes for lookups; no personal data in logs, metrics labels
  or the audit trail's details.
- **Database**: separate owner and runtime roles; the runtime role has DML only and cannot
  rewrite the append-only audit trail; statement and transaction timeouts.
- **Operations**: production refuses development keys, http and local URLs, shared secrets,
  unprotected metrics and private upstream addresses; rate limits per IP and client; images run
  as non-root with a read-only root filesystem and no package manager.
- **Supply chain**: `npm audit` and a license allowlist in CI, Maven Enforcer and strict
  checksums, GitHub Actions pinned by commit SHA, container base images pinned by digest,
  Dependabot for npm, Maven, Actions and Docker, SBOMs for the release images.

The mock IdP (`apps/mock-idp`, image `portvakt-mock-idp`) signs anyone in. It exists for
development and tests, refuses `NODE_ENV=production`, and must never be reachable from a
deployment.
