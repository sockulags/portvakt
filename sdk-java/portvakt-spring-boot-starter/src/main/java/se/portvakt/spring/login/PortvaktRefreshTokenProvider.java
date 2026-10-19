package se.portvakt.spring.login;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import se.portvakt.sdk.PortvaktUnavailableException;

/**
 * Refreshes the session's access token when it has less than {@code minValidity} left, but at
 * most half of the token's lifetime by default (a token living no longer than {@code minValidity},
 * a short access token TTL, would otherwise be refreshed on every request); an explicit {@link
 * #MIN_VALIDITY_ATTRIBUTE} is used as given. Portvakt
 * rotates refresh tokens on every use. A network error, timeout or 5xx answer becomes {@link
 * PortvaktUnavailableException}; a refusal ({@code invalid_grant}: revoked, replayed, broker
 * session ended) a {@link ClientAuthorizationException}. The token response (with the new ID
 * token) is handed to the caller through the context attribute {@link #RESPONSE_ATTRIBUTE}.
 */
public class PortvaktRefreshTokenProvider implements OAuth2AuthorizedClientProvider {
  /** Context attribute: a {@link ResponseHolder} that receives the token response. */
  public static final String RESPONSE_ATTRIBUTE = PortvaktRefreshTokenProvider.class.getName() + ".response";

  /** Context attribute: a {@link Duration} overriding the minimum remaining validity. */
  public static final String MIN_VALIDITY_ATTRIBUTE = PortvaktRefreshTokenProvider.class.getName() + ".minValidity";

  /** Receives the refresh token response of one authorization. */
  public static final class ResponseHolder {
    private OAuth2AccessTokenResponse response;

    public OAuth2AccessTokenResponse response() {
      return response;
    }
  }

  private final OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> client;
  private final Duration minValidity;
  private final Clock clock;

  public PortvaktRefreshTokenProvider(
      OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> client, Duration minValidity, Clock clock) {
    this.client = client;
    this.minValidity = minValidity;
    this.clock = clock;
  }

  @Override
  public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
    OAuth2AuthorizedClient authorized = context.getAuthorizedClient();
    if (authorized == null) return null;
    Duration validity =
        context.getAttribute(MIN_VALIDITY_ATTRIBUTE) instanceof Duration requested
            ? requested
            : threshold(authorized.getAccessToken(), minValidity);
    if (!expiring(authorized.getAccessToken(), validity)) return null;
    String registrationId = authorized.getClientRegistration().getRegistrationId();
    if (authorized.getRefreshToken() == null) {
      throw new ClientAuthorizationException(new OAuth2Error("invalid_grant"), registrationId);
    }
    OAuth2AccessTokenResponse response;
    try {
      response =
          client.getTokenResponse(
              new OAuth2RefreshTokenGrantRequest(
                  authorized.getClientRegistration(), authorized.getAccessToken(), authorized.getRefreshToken()));
    } catch (OAuth2AuthorizationException failure) {
      if (Failures.isUnavailable(failure)) {
        throw new PortvaktUnavailableException("Portvakt is unavailable", failure);
      }
      if (failure instanceof ClientAuthorizationException clientFailure) throw clientFailure;
      throw new ClientAuthorizationException(failure.getError(), registrationId, failure);
    } catch (RuntimeException failure) {
      if (Failures.isUnavailable(failure)) {
        throw new PortvaktUnavailableException("Portvakt is unavailable", failure);
      }
      throw failure;
    }
    if (context.getAttribute(RESPONSE_ATTRIBUTE) instanceof ResponseHolder holder) holder.response = response;
    return new OAuth2AuthorizedClient(
        authorized.getClientRegistration(),
        context.getPrincipal().getName(),
        response.getAccessToken(),
        response.getRefreshToken() != null ? response.getRefreshToken() : authorized.getRefreshToken());
  }

  /**
   * The default refresh threshold of {@code token}: {@code minValidity}, at most half its lifetime
   * (issued to expiry).
   */
  static Duration threshold(OAuth2AccessToken token, Duration minValidity) {
    Instant issuedAt = token.getIssuedAt();
    Instant expiresAt = token.getExpiresAt();
    if (issuedAt == null || expiresAt == null || !expiresAt.isAfter(issuedAt)) return minValidity;
    Duration half = Duration.between(issuedAt, expiresAt).dividedBy(2);
    return half.compareTo(minValidity) < 0 ? half : minValidity;
  }

  private boolean expiring(OAuth2AccessToken token, Duration validity) {
    Instant expiresAt = token.getExpiresAt();
    return expiresAt == null || !clock.instant().plus(validity).isBefore(expiresAt);
  }
}
