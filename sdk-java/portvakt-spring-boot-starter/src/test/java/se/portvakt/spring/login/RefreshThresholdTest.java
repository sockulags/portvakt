package se.portvakt.spring.login;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

/**
 * The default refresh threshold is the configured minimum validity, but at most half of the
 * token's lifetime: a token living no longer than the minimum (a short access token TTL) is not
 * refreshed on every request. An explicit minimum is used as given.
 */
class RefreshThresholdTest {
  static final Instant NOW = Instant.parse("2026-10-19T12:00:00Z");
  static final Duration MIN_VALIDITY = Duration.ofSeconds(60);

  static OAuth2AccessToken token(Instant issuedAt, Instant expiresAt) {
    return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access", issuedAt, expiresAt, Set.of("openid"));
  }

  @Test
  void capsTheDefaultAtHalfTheLifetime() {
    assertThat(PortvaktRefreshTokenProvider.threshold(token(NOW, NOW.plusSeconds(300)), MIN_VALIDITY))
        .isEqualTo(MIN_VALIDITY);
    assertThat(PortvaktRefreshTokenProvider.threshold(token(NOW, NOW.plusSeconds(60)), MIN_VALIDITY))
        .isEqualTo(Duration.ofSeconds(30));
    assertThat(PortvaktRefreshTokenProvider.threshold(token(NOW, NOW.plusSeconds(20)), MIN_VALIDITY))
        .isEqualTo(Duration.ofSeconds(10));
    assertThat(PortvaktRefreshTokenProvider.threshold(token(null, NOW.plusSeconds(20)), MIN_VALIDITY))
        .isEqualTo(MIN_VALIDITY);
  }

  @Test
  void refreshesAShortLivedTokenOnlyPastHalfItsLifetime() {
    AtomicInteger refreshes = new AtomicInteger();
    OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> client =
        request -> {
          refreshes.incrementAndGet();
          return OAuth2AccessTokenResponse.withToken("access-" + refreshes.get())
              .tokenType(OAuth2AccessToken.TokenType.BEARER)
              .expiresIn(20)
              .refreshToken("refresh-" + refreshes.get())
              .build();
        };
    ClientRegistration registration =
        ClientRegistration.withRegistrationId("portvakt")
            .clientId("app")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("https://app.example/callback")
            .authorizationUri("https://login.example/t/demo/auth")
            .tokenUri("https://login.example/t/demo/token")
            .build();
    OAuth2AuthorizedClient authorized =
        new OAuth2AuthorizedClient(
            registration, "person", token(NOW, NOW.plusSeconds(20)), new OAuth2RefreshToken("refresh-0", NOW));
    OAuth2AuthorizationContext context =
        OAuth2AuthorizationContext.withAuthorizedClient(authorized)
            .principal(new TestingAuthenticationToken("person", null))
            .build();

    // 5 s into a 20 s token: 15 s left, more than half the lifetime, so no refresh, although
    // the configured minimum (60 s) is longer than the whole lifetime.
    PortvaktRefreshTokenProvider early =
        new PortvaktRefreshTokenProvider(client, MIN_VALIDITY, Clock.fixed(NOW.plusSeconds(5), ZoneOffset.UTC));
    assertThat(early.authorize(context)).isNull();
    assertThat(refreshes.get()).isZero();

    // 11 s in: 9 s left, below half the lifetime: refreshed once.
    PortvaktRefreshTokenProvider later =
        new PortvaktRefreshTokenProvider(client, MIN_VALIDITY, Clock.fixed(NOW.plusSeconds(11), ZoneOffset.UTC));
    assertThat(later.authorize(context)).isNotNull();
    assertThat(refreshes.get()).isEqualTo(1);

    // An explicit minimum is the caller's requirement: used as given.
    OAuth2AuthorizationContext explicit =
        OAuth2AuthorizationContext.withAuthorizedClient(authorized)
            .principal(new TestingAuthenticationToken("person", null))
            .attribute(PortvaktRefreshTokenProvider.MIN_VALIDITY_ATTRIBUTE, Duration.ofSeconds(18))
            .build();
    assertThat(early.authorize(explicit)).isNotNull();
    assertThat(refreshes.get()).isEqualTo(2);
  }
}
