package se.portvakt.spring.resource;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import se.portvakt.sdk.AccessTokenException;
import se.portvakt.sdk.BearerError;
import se.portvakt.sdk.PortvaktUnavailableException;
import se.portvakt.spring.PortvaktAuthorizationDecision;
import se.portvakt.spring.login.Failures;
import se.portvakt.spring.web.Responses;

/**
 * RFC 6750 answers of the resource server, as the TypeScript SDK's: 400 {@code invalid_request}
 * (malformed header), 401 without error (no token), 401 {@code invalid_token}, 403 {@code
 * insufficient_scope} with a {@code reason}, 401 {@code insufficient_user_authentication} with
 * {@code acr_values} (RFC 9470), and 503 {@code temporarily_unavailable} when Portvakt's keys
 * cannot be fetched. Always {@code WWW-Authenticate: Bearer realm="portvakt", ...} and a JSON
 * body. Used as entry point, authentication failure handler and access denied handler.
 */
public class PortvaktBearerErrorHandler
    implements AuthenticationEntryPoint, AuthenticationFailureHandler, AccessDeniedHandler {
  private static final Logger LOG = LoggerFactory.getLogger(PortvaktBearerErrorHandler.class);

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException failure)
      throws IOException {
    if (Failures.find(failure, PortvaktUnavailableException.class) != null) {
      Responses.temporarilyUnavailable(response);
      return;
    }
    AccessTokenException error = Failures.find(failure, AccessTokenException.class);
    if (error == null && failure instanceof OAuth2AuthenticationException oauth
        && oauth.getError() instanceof BearerTokenError bearer) {
      error = fromBearerError(bearer);
    }
    if (error == null) {
      if (failure instanceof org.springframework.security.authentication.AuthenticationServiceException) {
        LOG.warn("access token validation failed: {}", failure.getClass().getSimpleName());
        error = AccessTokenException.invalidToken();
      } else {
        error = AccessTokenException.missingToken();
      }
    }
    Responses.bearerError(response, error);
  }

  @Override
  public void onAuthenticationFailure(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException failure) throws IOException {
    commence(request, response, failure);
  }

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException denied)
      throws IOException {
    if (denied instanceof AuthorizationDeniedException authorization
        && authorization.getAuthorizationResult() instanceof PortvaktAuthorizationDecision decision) {
      if (decision.bearerError() != null) {
        Responses.bearerError(response, decision.bearerError());
        return;
      }
      if (decision.requiredAcr() != null) {
        Responses.bearerError(response, AccessTokenException.insufficientUserAuthentication(decision.requiredAcr()));
        return;
      }
    }
    if (org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication()
            instanceof PortvaktJwtAuthenticationToken token
        && token.restriction() != null) {
      Responses.bearerError(response, restricted(token.restriction()));
      return;
    }
    Responses.bearerError(response, AccessTokenException.insufficientScope("Access denied", null));
  }

  /** The answer for a token the resource server's defaults refuse. */
  public static AccessTokenException restricted(String reason) {
    return reason.equals("service_not_allowed")
        ? AccessTokenException.insufficientScope("A person's access token is required", reason)
        : AccessTokenException.insufficientScope("Acting on behalf of another party is not allowed here", reason);
  }

  private static AccessTokenException fromBearerError(BearerTokenError bearer) {
    for (BearerError code : BearerError.values()) {
      if (code.code().equals(bearer.getErrorCode())) {
        String description =
            code == BearerError.INVALID_TOKEN ? "The access token is invalid" : bearer.getDescription();
        return new AccessTokenException(bearer.getHttpStatus().value(), code, description, null, null);
      }
    }
    return AccessTokenException.invalidToken();
  }
}
