package se.portvakt.sdk;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * What an API route requires of the access token (see {@link PortvaktTokenVerifier#authorize}).
 *
 * @param audience the token's {@code aud}: this API's client_id
 * @param roles person tokens must carry every one of these roles
 * @param anyRole person tokens must carry at least one of these (empty: no requirement)
 * @param acr person tokens must have an acr at least this high, or {@code null}
 * @param allowService accept client_credentials tokens from any application of the tenant
 * @param allowedServices accept client_credentials tokens from these client_ids only
 * @param allowRepresentation accept person tokens acting for another party ({@code rep})
 */
public record AccessTokenRequirements(
    String audience,
    List<String> roles,
    List<String> anyRole,
    String acr,
    boolean allowService,
    List<String> allowedServices,
    boolean allowRepresentation) {

  public AccessTokenRequirements {
    Objects.requireNonNull(audience, "audience");
    roles = List.copyOf(roles);
    anyRole = List.copyOf(anyRole);
    allowedServices = List.copyOf(allowedServices);
  }

  /** Requirements for {@code audience}: person tokens only, representation allowed. */
  public static Builder forAudience(String audience) {
    return new Builder(audience);
  }

  /** Whether a service token from {@code clientId} is accepted. */
  public boolean acceptsService(String clientId) {
    return allowService || allowedServices.contains(clientId);
  }

  /** Builder; role and acr requirements apply to person tokens only. */
  public static final class Builder {
    private final String audience;
    private final List<String> roles = new ArrayList<>();
    private final List<String> anyRole = new ArrayList<>();
    private String acr;
    private boolean allowService;
    private final List<String> allowedServices = new ArrayList<>();
    private boolean allowRepresentation = true;

    private Builder(String audience) {
      this.audience = audience;
    }

    /** Every one of these roles is required. */
    public Builder roles(String... values) {
      roles.addAll(List.of(values));
      return this;
    }

    /** At least one of these roles is required. */
    public Builder anyRole(String... values) {
      anyRole.addAll(List.of(values));
      return this;
    }

    /** The minimum assurance level (with the configured ranking). */
    public Builder acr(String value) {
      this.acr = value;
      return this;
    }

    /** Accept client_credentials tokens from every application of the tenant. */
    public Builder allowService(boolean value) {
      this.allowService = value;
      return this;
    }

    /** Accept client_credentials tokens from these applications. */
    public Builder allowServices(String... clientIds) {
      allowedServices.addAll(List.of(clientIds));
      return this;
    }

    /** Default true. The application must still authorise actions on behalf of {@code rep.sub}. */
    public Builder allowRepresentation(boolean value) {
      this.allowRepresentation = value;
      return this;
    }

    public AccessTokenRequirements build() {
      List<String> issues = new ArrayList<>();
      if (audience == null || audience.isEmpty() || audience.length() > 255) {
        issues.add("audience: required, 1 to 255 characters");
      }
      for (List<String> list : List.of(roles, anyRole, allowedServices)) {
        if (list.size() > 100 || list.stream().anyMatch(v -> v == null || v.isEmpty() || v.length() > 255)) {
          issues.add("roles, anyRole and allowServices: at most 100 values of 1 to 255 characters");
          break;
        }
      }
      if (acr != null && (acr.isEmpty() || acr.length() > 255)) issues.add("acr: 1 to 255 characters");
      if (!issues.isEmpty()) throw new PortvaktConfigException(issues);
      return new AccessTokenRequirements(
          audience, roles, anyRole, acr, allowService, allowedServices, allowRepresentation);
    }
  }
}
