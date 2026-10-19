package se.portvakt.spring.resource;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import se.portvakt.sdk.AccessTokenException;
import se.portvakt.sdk.BearerTokens;

/**
 * The bearer token of a request: exactly one {@code Authorization: Bearer} header, nothing else
 * (no query or form parameter). Another scheme or a malformed header is 400 {@code
 * invalid_request}, as in the TypeScript SDK.
 */
public class PortvaktBearerTokenResolver implements BearerTokenResolver {
  @Override
  public String resolve(HttpServletRequest request) {
    List<String> headers = Collections.list(request.getHeaders("Authorization"));
    if (headers.size() > 1) throw failure(AccessTokenException.invalidRequest());
    try {
      return BearerTokens.fromAuthorizationHeader(headers.isEmpty() ? null : headers.get(0));
    } catch (AccessTokenException invalid) {
      throw failure(invalid);
    }
  }

  private static OAuth2AuthenticationException failure(AccessTokenException error) {
    BearerTokenError bearer =
        new BearerTokenError(error.error().code(), HttpStatus.valueOf(error.status()), error.description(), null);
    return new OAuth2AuthenticationException(bearer, error.description(), error);
  }
}
