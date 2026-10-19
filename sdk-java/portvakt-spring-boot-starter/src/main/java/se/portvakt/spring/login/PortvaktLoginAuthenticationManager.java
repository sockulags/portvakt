package se.portvakt.spring.login;

import java.time.Clock;
import java.time.Instant;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import se.portvakt.sdk.AcrRanking;
import se.portvakt.sdk.PortvaktUnavailableException;

/**
 * Wraps the authentication manager of the login callback. After Spring's OIDC code flow
 * (code exchange with PKCE, ID token validation through the core, nonce) it refuses:
 *
 * <ul>
 *   <li>a step-up whose login did not reach the requested acr ({@code acr_not_met}): the
 *       exception is thrown before Spring stores the new context or authorized client, so the
 *       existing session stays exactly as it was;
 *   <li>a login whose broker session has already ended ({@code session_exp}).
 * </ul>
 *
 * A Portvakt outage during the callback becomes {@code portvakt_unavailable}. It also passes
 * {@code returnTo} on to the success handler through {@link PortvaktLoginDetails}.
 */
public class PortvaktLoginAuthenticationManager implements AuthenticationManager {
  private final AuthenticationManager delegate;
  private final AcrRanking ranking;
  private final Clock clock;

  public PortvaktLoginAuthenticationManager(AuthenticationManager delegate, AcrRanking ranking, Clock clock) {
    this.delegate = delegate;
    this.ranking = ranking;
    this.clock = clock;
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    if (!(authentication instanceof OAuth2LoginAuthenticationToken login)) {
      return delegate.authenticate(authentication);
    }
    OAuth2AuthorizationRequest authorizationRequest = login.getAuthorizationExchange().getAuthorizationRequest();
    Authentication result;
    try {
      result = delegate.authenticate(authentication);
    } catch (PortvaktUnavailableException unavailable) {
      throw error("portvakt_unavailable", unavailable);
    } catch (OAuth2AuthenticationException failure) {
      if (Failures.isUnavailable(failure)) throw error("portvakt_unavailable", failure);
      throw failure;
    }
    if (!(result.getPrincipal() instanceof PortvaktOidcUser user)) {
      throw error("login_failed", null);
    }
    String acr = authorizationRequest.getAttribute(PortvaktAuthorizationRequestResolver.ACR_ATTRIBUTE);
    if (acr != null && !ranking.atLeast(user.getPortvaktPrincipal().acr(), acr)) {
      throw error("acr_not_met", null);
    }
    Instant sessionExp = user.getSessionExp();
    if (sessionExp != null && !sessionExp.isAfter(clock.instant())) {
      throw error("login_failed", null);
    }
    if (authentication.getDetails() instanceof PortvaktLoginDetails details) {
      details.setReturnTo(authorizationRequest.getAttribute(PortvaktAuthorizationRequestResolver.RETURN_TO_ATTRIBUTE));
    }
    return result;
  }

  private static OAuth2AuthenticationException error(String code, Throwable cause) {
    OAuth2Error error = new OAuth2Error(code);
    return cause == null
        ? new OAuth2AuthenticationException(error)
        : new OAuth2AuthenticationException(error, code, cause);
  }
}
