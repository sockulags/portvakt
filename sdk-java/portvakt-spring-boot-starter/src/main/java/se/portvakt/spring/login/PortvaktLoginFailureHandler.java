package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import se.portvakt.sdk.PortvaktException;
import se.portvakt.sdk.PortvaktUnavailableException;
import se.portvakt.spring.web.Responses;

/**
 * Failed logins and refused login starts: a minimal Swedish error page with the error code
 * ({@code data-testid="portvakt-error-code"}), or {@code {"error": code}} for fetch. Codes:
 * {@code acr_not_met} (403; the existing session is kept), {@code portvakt_unavailable} (503),
 * {@code login_expired}, {@code state_mismatch}, {@code invalid_request}, {@code
 * cross_site_request} (403), {@code login_failed}, or Portvakt's OAuth error (such as {@code
 * access_denied}). Nothing about the person or the tokens is logged.
 */
public class PortvaktLoginFailureHandler implements AuthenticationFailureHandler {
  private static final Logger LOG = LoggerFactory.getLogger(PortvaktLoginFailureHandler.class);
  private static final Pattern OAUTH_ERROR = Pattern.compile("^[a-z_]{1,64}$");

  private static final Map<String, Integer> STATUS =
      Map.of(
          "acr_not_met", 403,
          "cross_site_request", 403,
          "portvakt_unavailable", 503,
          "invalid_client", 502,
          "login_failed", 400);

  private final PortvaktLoginSettings settings;

  public PortvaktLoginFailureHandler(PortvaktLoginSettings settings) {
    this.settings = settings;
  }

  @Override
  public void onAuthenticationFailure(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
    CrossSiteNavigationException crossSite = Failures.find(exception, CrossSiteNavigationException.class);
    if (crossSite != null) {
      Responses.interstitial(response, crossSite.target());
      return;
    }
    String code = codeOf(exception);
    PortvaktException portvakt = Failures.find(exception, PortvaktException.class);
    int status = portvakt != null && portvakt.code().equals(code) ? portvakt.status() : STATUS.getOrDefault(code, 400);
    LOG.info("Portvakt login failed: {}", code);
    if (status == 503) {
      response.setHeader(
          "Retry-After", Responses.retryAfterSeconds(Failures.find(exception, PortvaktUnavailableException.class)));
    }
    Responses.error(request, response, status, code, settings.defaultReturnTo());
  }

  static String codeOf(AuthenticationException exception) {
    if (Failures.isUnavailable(exception)) return "portvakt_unavailable";
    PortvaktException portvakt = Failures.find(exception, PortvaktException.class);
    if (portvakt != null) return portvakt.code();
    if (exception instanceof OAuth2AuthenticationException oauth && oauth.getError() != null) {
      String code = oauth.getError().getErrorCode();
      return switch (code) {
        case "authorization_request_not_found" -> "login_expired";
        case "invalid_state_parameter" -> "state_mismatch";
        case "invalid_id_token", "invalid_nonce", "missing_id_token", "invalid_token_response",
            "invalid_redirect_uri_parameter", "client_registration_not_found" -> "login_failed";
        default -> OAUTH_ERROR.matcher(code).matches() ? code : "login_failed";
      };
    }
    return "login_failed";
  }
}
