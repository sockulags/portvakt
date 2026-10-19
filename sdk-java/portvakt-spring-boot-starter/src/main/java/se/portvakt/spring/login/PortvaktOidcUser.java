package se.portvakt.spring.login;

import java.time.Instant;
import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import se.portvakt.sdk.PortvaktPrincipal;
import se.portvakt.spring.PortvaktAuthorities;

/**
 * The signed-in person of a browser session, built from the ID token only (Portvakt disables
 * userinfo). {@link #getPortvaktPrincipal()} carries the claims model with profile fields;
 * {@link #getName()} is the person's UUID ({@code sub}).
 */
public class PortvaktOidcUser extends DefaultOidcUser {
  private static final long serialVersionUID = 1L;

  private final PortvaktPrincipal principal;
  private final Instant sessionExp;

  public PortvaktOidcUser(
      Collection<? extends GrantedAuthority> authorities,
      OidcIdToken idToken,
      PortvaktPrincipal principal,
      Instant sessionExp) {
    super(authorities, idToken, "sub");
    this.principal = principal;
    this.sessionExp = sessionExp;
  }

  /** A user for a validated ID token: its principal, roles as authorities. */
  public static PortvaktOidcUser of(OidcIdToken idToken) {
    PortvaktPrincipal principal = PortvaktPrincipal.fromIdTokenClaims(idToken.getClaims());
    Object sessionExp = idToken.getClaims().get("session_exp");
    return new PortvaktOidcUser(
        PortvaktAuthorities.of(principal),
        idToken,
        principal,
        sessionExp instanceof Number number ? Instant.ofEpochSecond(number.longValue()) : null);
  }

  public PortvaktPrincipal getPortvaktPrincipal() {
    return principal;
  }

  /** The broker session's end ({@code session_exp}), or {@code null} when the token has none. */
  public Instant getSessionExp() {
    return sessionExp;
  }

  @Override
  public String toString() {
    // DefaultOidcUser prints every claim (name, email, pin): never in logs.
    return "PortvaktOidcUser[" + principal + "]";
  }
}
