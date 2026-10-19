package se.portvakt.spring.login;

import java.io.IOException;
import java.net.URI;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.ResponseErrorHandler;

/**
 * Error answers of Portvakt's token endpoint. Spring's own handler reads the OAuth error body of a
 * 400 only; Portvakt answers {@code invalid_client} with 401, which would otherwise surface as an
 * unreadable response (and end the session). Here a 400 or 401 with an OAuth error becomes an
 * {@link OAuth2AuthorizationException} with that error; everything else (5xx in particular, an
 * outage) the default handling.
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
    if (status == 400 || status == 401) {
      OAuth2Error error;
      try {
        error = errors.read(OAuth2Error.class, response);
      } catch (RuntimeException unreadable) {
        error = null;
      }
      if (error != null && error.getErrorCode() != null && error.getErrorCode().matches("^[a-z_]{1,64}$")) {
        throw new OAuth2AuthorizationException(new OAuth2Error(error.getErrorCode()));
      }
    }
    fallback.handleError(url, method, response);
  }
}
