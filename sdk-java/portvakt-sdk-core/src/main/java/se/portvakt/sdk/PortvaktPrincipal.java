package se.portvakt.sdk;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import se.portvakt.sdk.internal.Claims;

/**
 * Who a request is for: a signed-in person (from an ID token in a browser session, or a person
 * access token) or a calling application (a client_credentials access token).
 *
 * <p>Person: {@code sub} is the signed-in person's UUID, also when representing someone; {@code
 * rep} is the party they act for; {@code roles} and {@code attrs} are the person's own in this
 * application. Service: {@code sub} equals {@code clientId}, and there are no roles, attributes,
 * login or profile fields.
 *
 * <p>Profile fields ({@code name}, {@code email}, {@code pin}, {@code hsaId}, {@code
 * orgAffiliation}, {@code protectedIdentity}, {@code rep.name}) are only set when the principal
 * was built from an ID token; access tokens never carry them. For a person with a protected
 * identity, name and email are never kept. {@link #toString()} never prints personal data.
 *
 * @param service whether this is a calling application rather than a person
 * @param sub the person's UUID, or the calling client_id for a service
 * @param tenant the tenant slug ({@code tid})
 * @param clientId the application the token was issued to (the caller, for a service)
 * @param idp the login method's id; {@code null} for a service
 * @param idpKind employee or citizen; {@code null} for a service
 * @param acr the assurance level; {@code null} for a service
 * @param authTime when the person authenticated; {@code null} for a service
 * @param roles the person's roles in this application, never the represented party's
 * @param attrs the person's attributes in this application
 * @param rep the represented party, or {@code null}
 * @param name display name (ID token, scope {@code profile})
 * @param email email address (ID token, scope {@code email}); never an identifier
 * @param pin personal identity number (ID token, scope {@code pin})
 * @param hsaId HSA-id (ID token, scope {@code hsa})
 * @param orgAffiliation organisation affiliations (ID token, scope {@code hsa})
 * @param protectedIdentity the person has a protected identity (skyddad identitet)
 */
public record PortvaktPrincipal(
    boolean service,
    String sub,
    String tenant,
    String clientId,
    String idp,
    IdpKind idpKind,
    String acr,
    Instant authTime,
    List<String> roles,
    Map<String, String> attrs,
    Representation rep,
    String name,
    String email,
    String pin,
    String hsaId,
    List<String> orgAffiliation,
    boolean protectedIdentity)
    implements Serializable {

  public PortvaktPrincipal {
    Objects.requireNonNull(sub, "sub");
    Objects.requireNonNull(tenant, "tenant");
    roles = roles == null ? List.of() : List.copyOf(roles);
    attrs = attrs == null ? Map.of() : Map.copyOf(attrs);
    orgAffiliation = orgAffiliation == null ? null : List.copyOf(orgAffiliation);
    if (protectedIdentity) {
      // Portvakt never issues name or email for a protected identity; never keep them anyway.
      name = null;
      email = null;
    }
  }

  /** Whether this is a calling application (client_credentials token). */
  public boolean isService() {
    return service;
  }

  /** The represented party, when acting for one. */
  public Optional<Representation> representation() {
    return Optional.ofNullable(rep);
  }

  /** Whether the person acts for another party. */
  public boolean isRepresenting() {
    return rep != null;
  }

  /** Whether the principal has the role in this application. Services have none. */
  public boolean hasRole(String role) {
    return roles.contains(role);
  }

  /** Whether the principal has at least one of the roles. */
  public boolean hasAnyRole(String... candidates) {
    for (String role : candidates) {
      if (roles.contains(role)) return true;
    }
    return false;
  }

  /** Whether the person's acr meets {@code required} (a service never does). */
  public boolean acrAtLeast(String required, AcrRanking ranking) {
    return !service && ranking.atLeast(acr, required);
  }

  /** {@link #acrAtLeast(String, AcrRanking)} with {@link AcrRanking#DEFAULT}. */
  public boolean acrAtLeast(String required) {
    return acrAtLeast(required, AcrRanking.DEFAULT);
  }

  @Override
  public String toString() {
    if (service) return "PortvaktPrincipal[service, clientId=" + clientId + ", tenant=" + tenant + "]";
    return "PortvaktPrincipal[sub="
        + sub
        + ", tenant="
        + tenant
        + ", idpKind="
        + (idpKind == null ? null : idpKind.claimValue())
        + ", acr="
        + acr
        + ", roles="
        + roles
        + ", rep="
        + rep
        + ", clientId="
        + clientId
        + "]";
  }

  // Claims -------------------------------------------------------------------------------------

  private static final List<String> LOGIN_CLAIMS =
      List.of("idp", "idp_kind", "acr", "auth_time", "roles", "attrs", "rep");

  /**
   * The principal of a verified access token, or {@code null} when the claims are neither a
   * person token nor a service token as Portvakt issues them. Person tokens always carry the
   * login claims ({@code idp}, {@code idp_kind}, {@code acr}, {@code auth_time}, {@code roles},
   * {@code attrs}) and their {@code sub} is the person's UUID; client_credentials tokens carry
   * none of them and their {@code sub} is the calling client_id. Anything in between is refused.
   */
  public static PortvaktPrincipal fromAccessTokenClaims(Map<String, Object> payload) {
    Claims claims = new Claims(payload);
    boolean hasLoginClaims = LOGIN_CLAIMS.stream().anyMatch(claims::has);
    try {
      if (!hasLoginClaims) {
        String sub = claims.shortString("sub");
        String clientId = claims.shortString("client_id");
        String tenant = claims.shortString("tid");
        if (!sub.equals(clientId)) return null;
        return new PortvaktPrincipal(
            true, sub, tenant, clientId, null, null, null, null, List.of(), Map.of(), null, null,
            null, null, null, null, false);
      }
      Person person = person(claims, false);
      String clientId = claims.shortString("client_id");
      if (person.sub.equals(clientId)) return null;
      // Both must be present: a token that only lacks them is no token Portvakt issues.
      if (!(payload.get("roles") instanceof List<?>) || !(payload.get("attrs") instanceof Map<?, ?>)) {
        return null;
      }
      return new PortvaktPrincipal(
          false, person.sub, person.tenant, clientId, person.idp, person.idpKind, person.acr,
          person.authTime, person.roles, person.attrs, person.rep, null, null, null, null, null,
          false);
    } catch (Claims.Invalid invalid) {
      return null;
    }
  }

  /**
   * A person principal with profile fields, from verified ID token claims.
   *
   * @throws IllegalArgumentException when the claims do not follow the claims contract (the
   *     message names the claim, never its value)
   */
  public static PortvaktPrincipal fromIdTokenClaims(Map<String, Object> payload) {
    try {
      return idToken(new Claims(payload));
    } catch (Claims.Invalid invalid) {
      throw new IllegalArgumentException(invalid.getMessage());
    }
  }

  private static PortvaktPrincipal idToken(Claims claims) throws Claims.Invalid {
    Person person = person(claims, true);
    List<String> audience = claims.audience();
    claims.optionalPositiveInteger("session_exp");
    String name = claims.optionalString("name", 1000);
    String email = claims.optionalString("email", 1000);
    String pin = claims.optionalString("pin", 32);
    String hsaId = claims.optionalString("hsa_id", 255);
    List<String> orgAffiliation = claims.optionalStringList("org_affiliation", 100, 512);
    boolean protectedIdentity = false;
    if (claims.has("protected_identity")) {
      if (!Boolean.TRUE.equals(claims.raw("protected_identity"))) {
        throw new Claims.Invalid("protected_identity");
      }
      protectedIdentity = true;
    }
    return new PortvaktPrincipal(
        false,
        person.sub,
        person.tenant,
        audience.isEmpty() ? null : audience.get(0),
        person.idp,
        person.idpKind,
        person.acr,
        person.authTime,
        person.roles,
        person.attrs,
        person.rep,
        name,
        email,
        pin,
        hsaId,
        orgAffiliation,
        protectedIdentity);
  }

  private record Person(
      String sub,
      String tenant,
      String idp,
      IdpKind idpKind,
      String acr,
      Instant authTime,
      List<String> roles,
      Map<String, String> attrs,
      Representation rep) {}

  private static Person person(Claims claims, boolean withRepName) throws Claims.Invalid {
    String sub = claims.shortString("sub");
    String tenant = claims.shortString("tid");
    String idp = claims.shortString("idp");
    IdpKind kind = IdpKind.fromClaim(claims.raw("idp_kind"));
    if (kind == null) throw new Claims.Invalid("idp_kind");
    String acr = claims.shortString("acr");
    long authTime = claims.nonNegativeInteger("auth_time");
    List<String> roles = claims.roles();
    Map<String, String> attrs = claims.attrs();
    Representation rep = null;
    Claims repClaims = claims.optionalObject("rep");
    if (repClaims != null) {
      String repSub = repClaims.shortString("sub");
      Representation.Type type = Representation.Type.fromClaim(repClaims.raw("type"));
      if (type == null) throw new Claims.Invalid("rep");
      String repName = repClaims.optionalString("name", 1000);
      // Access tokens carry rep without a name (data minimisation); a name there is ignored.
      rep = new Representation(repSub, type, withRepName ? repName : null);
    }
    return new Person(
        sub, tenant, idp, kind, acr, Instant.ofEpochSecond(authTime), roles, attrs, rep);
  }
}
