package se.portvakt.spring.resource;

import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import se.portvakt.sdk.PortvaktPrincipal;

/**
 * An authenticated bearer token: the Spring {@link Jwt} plus the {@link PortvaktPrincipal} (a
 * person or a calling application). The name is {@code sub}.
 *
 * <p>A token the resource server's defaults do not accept ({@code
 * portvakt.resource-server.allow-service}, {@code allow-representation}) is <em>restricted</em>:
 * it is not authenticated and has no authorities, so {@code authenticated()}, {@code
 * hasAuthority(...)} and the {@code @portvakt} checks refuse it (403 {@code insufficient_scope}
 * with the {@link #restriction()} as reason). A route accepts it only by saying so, with {@code
 * portvakt.accessToken(r -> r.allowService(true))} or {@code r.allowRepresentation(true)}.
 */
public class PortvaktJwtAuthenticationToken extends JwtAuthenticationToken {
  private static final long serialVersionUID = 1L;

  private final PortvaktPrincipal principal;
  private final String restriction;

  public PortvaktJwtAuthenticationToken(
      Jwt jwt, PortvaktPrincipal principal, Collection<? extends GrantedAuthority> authorities) {
    this(jwt, principal, authorities, null);
  }

  /** @param restriction {@code service_not_allowed}, {@code representation_not_allowed} or {@code null} */
  public PortvaktJwtAuthenticationToken(
      Jwt jwt, PortvaktPrincipal principal, Collection<? extends GrantedAuthority> authorities, String restriction) {
    super(jwt, restriction == null ? authorities : List.of(), principal.sub());
    this.principal = principal;
    this.restriction = restriction;
    if (restriction != null) super.setAuthenticated(false);
  }

  public PortvaktPrincipal getPortvaktPrincipal() {
    return principal;
  }

  /** Why the defaults refuse this token, or {@code null}. */
  public String restriction() {
    return restriction;
  }

  @Override
  public void setAuthenticated(boolean authenticated) {
    if (authenticated && restriction != null) throw new IllegalArgumentException("a restricted token stays unauthenticated");
    super.setAuthenticated(authenticated);
  }

  @Override
  public String toString() {
    return "PortvaktJwtAuthenticationToken[" + principal + (restriction == null ? "" : ", " + restriction) + "]";
  }
}
