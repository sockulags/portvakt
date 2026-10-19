package se.portvakt.spring;

import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import se.portvakt.sdk.AccessTokenException;
import se.portvakt.sdk.AccessTokenRequirements;
import se.portvakt.sdk.AcrRanking;
import se.portvakt.sdk.PortvaktPrincipal;
import se.portvakt.sdk.PortvaktTokenVerifier;
import se.portvakt.spring.login.PortvaktLoginConfigurer;
import se.portvakt.spring.login.PortvaktOidcUser;
import se.portvakt.spring.resource.PortvaktJwtAuthenticationToken;
import se.portvakt.spring.resource.PortvaktResourceServerConfigurer;

/**
 * Portvakt security helpers, available as the bean {@code portvakt}:
 *
 * <ul>
 *   <li>{@link #login()} and {@link #resourceServer()} apply the starter to your own filter
 *       chains;
 *   <li>{@link #requireAcr(String)} and {@link #accessToken(Consumer)} are authorization managers
 *       for {@code authorizeHttpRequests} (a step-up for browser sessions, RFC 6750/9470 answers
 *       for bearer tokens);
 *   <li>{@link #hasRole}, {@link #acrAtLeast}, {@link #isService} and {@link #isRepresenting}
 *       work in method security: {@code @PreAuthorize("@portvakt.hasRole('handlaggare')")}.
 * </ul>
 */
public class PortvaktSecurity {
  private final PortvaktTokenVerifier verifier;
  private final AcrRanking ranking;
  private final AccessTokenRequirements defaults;

  /**
   * @param defaults the resource server's default requirements ({@code portvakt.resource-server.*}),
   *     or {@code null} when it is disabled
   */
  public PortvaktSecurity(PortvaktTokenVerifier verifier, AcrRanking ranking, AccessTokenRequirements defaults) {
    this.verifier = verifier;
    this.ranking = ranking;
    this.defaults = defaults;
  }

  /** The browser login configurer: {@code http.with(PortvaktSecurity.login(), withDefaults())}. */
  public static PortvaktLoginConfigurer login() {
    return new PortvaktLoginConfigurer();
  }

  /** The resource server configurer: {@code http.with(PortvaktSecurity.resourceServer(), ...)}. */
  public static PortvaktResourceServerConfigurer resourceServer() {
    return new PortvaktResourceServerConfigurer();
  }

  /** The principal of the current request (browser session or bearer token). */
  public static Optional<PortvaktPrincipal> currentPrincipal() {
    return Optional.ofNullable(principalOf(SecurityContextHolder.getContext().getAuthentication()));
  }

  /** The principal of an authentication, or {@code null} when it is none of Portvakt's. */
  public static PortvaktPrincipal principalOf(Authentication authentication) {
    if (authentication instanceof OAuth2AuthenticationToken token
        && token.getPrincipal() instanceof PortvaktOidcUser user) {
      return user.getPortvaktPrincipal();
    }
    if (authentication instanceof PortvaktJwtAuthenticationToken token) return token.getPortvaktPrincipal();
    return null;
  }

  /**
   * Requires a person whose acr is at least {@code acr}. Browser sessions below it are sent to
   * the step-up (XHR: 401 {@code step_up_required}); bearer tokens get 401 {@code
   * insufficient_user_authentication} with {@code acr_values}; services are refused.
   */
  public AuthorizationManager<RequestAuthorizationContext> requireAcr(String acr) {
    if (acr == null || !acr.matches("^[\\x21-\\x7e]{1,255}$")) throw new IllegalArgumentException("invalid acr value");
    return (authentication, context) -> decideAcr(authentication.get(), acr);
  }

  /** The decision of an acr requirement (also used by {@link RequireAcr}). */
  public PortvaktAuthorizationDecision decideAcr(Authentication authentication, String acr) {
    PortvaktPrincipal principal = principalOf(authentication);
    if (principal == null) return new PortvaktAuthorizationDecision(false, null, null);
    if (authentication instanceof PortvaktJwtAuthenticationToken token && token.restriction() != null) {
      return new PortvaktAuthorizationDecision(
          false, null, se.portvakt.spring.resource.PortvaktBearerErrorHandler.restricted(token.restriction()));
    }
    if (principal.isService()) {
      return new PortvaktAuthorizationDecision(
          false,
          null,
          AccessTokenException.insufficientScope("A person's access token is required", "service_not_allowed"));
    }
    if (ranking.atLeast(principal.acr(), acr)) return PortvaktAuthorizationDecision.granted();
    return new PortvaktAuthorizationDecision(false, acr, null);
  }

  /** The resource server's default requirements ({@code portvakt.resource-server.*}). */
  public AuthorizationManager<RequestAuthorizationContext> accessToken() {
    return accessToken(builder -> {});
  }

  /**
   * Access token requirements for a route, starting from the resource server's defaults: {@code
   * accessToken(r -> r.roles("admin").acr(AcrRanking.LOA3))}. Role and acr requirements apply to
   * person tokens only; denials answer with RFC 6750 errors.
   */
  public AuthorizationManager<RequestAuthorizationContext> accessToken(Consumer<AccessTokenRequirements.Builder> customizer) {
    if (defaults == null) throw new IllegalStateException("portvakt.resource-server.enabled is false");
    AccessTokenRequirements.Builder builder =
        AccessTokenRequirements.forAudience(defaults.audience())
            .allowService(defaults.allowService())
            .allowServices(defaults.allowedServices().toArray(String[]::new))
            .allowRepresentation(defaults.allowRepresentation());
    customizer.accept(builder);
    AccessTokenRequirements requirements = builder.build();
    return (authentication, context) -> {
      // The route's own requirements decide, also for a token the defaults restrict.
      if (!(authentication.get() instanceof PortvaktJwtAuthenticationToken token)) {
        return new PortvaktAuthorizationDecision(false, null, null);
      }
      try {
        verifier.authorize(token.getPortvaktPrincipal(), requirements);
        return PortvaktAuthorizationDecision.granted();
      } catch (AccessTokenException denied) {
        return new PortvaktAuthorizationDecision(false, null, denied);
      }
    };
  }

  // Method security (SpEL) ---------------------------------------------------------------------

  /** The current principal, unless the resource server's defaults restrict its token. */
  private static java.util.Optional<PortvaktPrincipal> allowed() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication instanceof PortvaktJwtAuthenticationToken token && token.restriction() != null) {
      return java.util.Optional.empty();
    }
    return java.util.Optional.ofNullable(principalOf(authentication));
  }

  /** {@code @PreAuthorize("@portvakt.hasRole('handlaggare')")} */
  public boolean hasRole(String role) {
    return allowed().map(principal -> principal.hasRole(role)).orElse(false);
  }

  /** {@code @PreAuthorize("@portvakt.hasAnyRole('admin', 'handlaggare')")} */
  public boolean hasAnyRole(String... roles) {
    return allowed().map(principal -> principal.hasAnyRole(roles)).orElse(false);
  }

  /** Whether the current person's acr meets {@code acr} (services never do). */
  public boolean acrAtLeast(String acr) {
    return allowed().map(principal -> principal.acrAtLeast(acr, ranking)).orElse(false);
  }

  /** Whether the caller is an application (client_credentials token). */
  public boolean isService() {
    return allowed().map(PortvaktPrincipal::isService).orElse(false);
  }

  /** Whether the caller is a person (browser session or person token). */
  public boolean isPerson() {
    return allowed().map(principal -> !principal.isService()).orElse(false);
  }

  /** Whether the current person acts for another party ({@code rep}). */
  public boolean isRepresenting() {
    return allowed().map(PortvaktPrincipal::isRepresenting).orElse(false);
  }

  /** Whether the caller is one of these applications. */
  public boolean isServiceOf(String... clientIds) {
    return allowed()
        .map(principal -> principal.isService() && List.of(clientIds).contains(principal.clientId()))
        .orElse(false);
  }

  /** The ranking in use. */
  public AcrRanking ranking() {
    return ranking;
  }
}
