package se.portvakt.spring.login;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.ResponseErrorHandler;
import se.portvakt.sdk.PortvaktRetryLaterException;

/**
 * Error answers of Portvakt's token endpoint. Spring's own handler reads the OAuth error body of a
 * 400 only; Portvakt answers {@code invalid_client} with 401, which would otherwise surface as an
 * unreadable response (and end the session). Here a 400 or 401 with an OAuth error becomes an
 * {@link OAuth2AuthorizationException} with that error. A 429, or the OAuth error {@code
 * temporarily_unavailable} with any status, is {@link PortvaktRetryLaterException} (transient:
 * the session keeps its refresh token, no outage starts). Everything else (5xx in particular, an
 * outage) gets the default handling.
 */
public class PortvaktTokenEndpointErrors implements ResponseErrorHandler {
  private final OAuth2ErrorHttpMessageConverter errors = new OAuth2ErrorHttpMessageConverter();
  private final DefaultResponseErrorHandler fallback = new DefaultResponseErrorHandler();

  @Override
  public boolean hasError(ClientHttpResponse response) throws IOException {
    return response.getStatusCode().isError();
  }

  @Override
  public void handleError(URI url, HttpMethod method, ClientHttpResponse response) throws IOException {
    int status = response.getStatusCode().value();
    Duration retryAfter =
        PortvaktRetryLaterException.parseRetryAfter(response.getHeaders().getFirst("Retry-After"), Instant.now());
    if (status == 429) throw new PortvaktRetryLaterException(retryAfter);
    boolean json =
        response.getHeaders().getContentType() != null
            && MediaType.APPLICATION_JSON.isCompatibleWith(response.getHeaders().getContentType());
    if (status == 400 || status == 401 || (status >= 500 && json)) {
      OAuth2Error error;
      try {
        error = errors.read(OAuth2Error.class, response);
      } catch (RuntimeException unreadable) {
        error = null;
      }
      String code = error == null ? null : error.getErrorCode();
      if ("temporarily_unavailable".equals(code)) throw new PortvaktRetryLaterException(retryAfter);
      if (status < 500 && code != null && code.matches("^[a-z_]{1,64}$")) {
        throw new OAuth2AuthorizationException(new OAuth2Error(code));
      }
    }
    fallback.handleError(url, method, response);
  }
}
