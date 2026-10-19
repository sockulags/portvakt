package se.portvakt.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import se.portvakt.sdk.AcrRanking;
import se.portvakt.sdk.LoginRequiredException;
import se.portvakt.sdk.PortvaktException;
import se.portvakt.sdk.PortvaktUnavailableException;
import se.portvakt.spring.login.InMemoryTokenStore;
import se.portvakt.spring.login.PortvaktAuthorizationRequestResolver;
import se.portvakt.spring.login.PortvaktLoginAuthenticationManager;
import se.portvakt.spring.login.PortvaktLoginDetails;
import se.portvakt.spring.login.PortvaktLoginSettings;
import se.portvakt.spring.login.PortvaktLogoutSuccessHandler;
import se.portvakt.spring.login.PortvaktOidcUser;
import se.portvakt.spring.login.PortvaktSessionState;

/**
 * The session's access token against a real HTTP token endpoint: one refresh for concurrent
 * session snapshots, refused refreshes (invalid_grant ends, invalid_client 401 keeps the
 * session), outage grace, the session end after a refresh, and the login callback's checks.
 */
class AccessTokensTest {
  static final FakeProvider PROVIDER;

  static {
    try {
      PROVIDER = new FakeProvider();
    } catch (Exception exception) {
      throw new IllegalStateException(exception);
    }
  }

  @AfterAll
  static void stop() {
    PROVIDER.close();
  }

  @AfterEach
  void reset() {
    SecurityContextHolder.clearContext();
    PROVIDER.down = false;
    PROVIDER.jwksDown = false;
    PROVIDER.tokenErrorStatus = 0;
    PROVIDER.tokenDelayMillis = 0;
    PROVIDER.refreshIdToken = true;
    PROVIDER.accessTokenLifetime = 300;
    PROVIDER.trickleToken = false;
    PROVIDER.sessionExp = Instant.now().getEpochSecond() + 3600;
  }

  static TestLogin login(Duration grace) {
    return new TestLogin(PROVIDER, grace, InMemoryTokenStore::new);
  }

  static String token(TestLogin login, MockHttpSession session, Duration minValidity) {
    MockHttpServletRequest request = TestLogin.request(session);
    return login.tokens.getAccessToken(request, new MockHttpServletResponse(), minValidity);
  }

  @Test
  void returnsTheStoredTokenAndRequiresASession() throws Exception {
    TestLogin login = login(Duration.ZERO);
    assertThatThrownBy(() -> login.tokens.getAccessToken(new MockHttpServletRequest(), new MockHttpServletResponse()))
        .isInstanceOf(LoginRequiredException.class);
    MockHttpSession session = login.signIn(Instant.now().plusSeconds(3600));
    assertThat(token(login, session, null)).isEqualTo("access-initial");
    // The HTTP session holds the grant id only: no token, no client registration.
    for (String name : java.util.Collections.list(session.getAttributeNames())) {
      assertThat(String.valueOf(session.getAttribute(name))).doesNotContain("access-initial").doesNotContain("refresh-");
      assertThat(session.getAttribute(name)).isNotInstanceOf(org.springframework.security.oauth2.client.OAuth2AuthorizedClient.class);
    }
  }

  @Test
  void refreshesOnceForTwoConcurrentRequestsWithSeparateSessionSnapshots() throws Exception {
    TestLogin login = login(Duration.ZERO);
    MockHttpSession first = login.signIn(Instant.now().plusSeconds(3600));
    MockHttpSession second = TestLogin.copy(first);
    int before = PROVIDER.refreshGrants.get();
    PROVIDER.tokenDelayMillis = 400;
    // The refreshed token lives two hours: the waiting request finds it fresh enough.
    PROVIDER.accessTokenLifetime = 7200;
    CountDownLatch start = new CountDownLatch(1);
    ExecutorService threads = Executors.newFixedThreadPool(2);
    try {
      List<Callable<String>> calls =
          List.of(first, second).stream()
              .map(
                  session ->
                      (Callable<String>)
                          () -> {
                            start.await();
                            try {
                              return token(login, session, Duration.ofHours(1));
                            } finally {
                              SecurityContextHolder.clearContext();
                            }
                          })
              .toList();
      List<Future<String>> results = calls.stream().map(threads::submit).toList();
      start.countDown();
      String a = results.get(0).get();
      String b = results.get(1).get();
      assertThat(a).isEqualTo(b).isNotEqualTo("access-initial");
    } finally {
      threads.shutdownNow();
    }
    assertThat(PROVIDER.refreshGrants.get() - before).isEqualTo(1);
    // A later request with the first (stale) snapshot uses the stored, rotated tokens.
    assertThat(token(login, first, null)).isNotEqualTo("access-initial");
    assertThat(PROVIDER.refreshGrants.get() - before).isEqualTo(1);
  }

  @Test
  void endsTheSessionWhenPortvaktRefusesTheRefreshButKeepsItForInvalidClient() throws Exception {
    TestLogin login = login(Duration.ZERO);
    MockHttpSession session = login.signIn(Instant.now().plusSeconds(3600));
    String grantId = PortvaktSessionState.of(session).grantId();
    // Portvakt answers invalid_client with 401: read as an OAuth error, the session stays.
    PROVIDER.tokenErrorStatus = 401;
    PROVIDER.tokenError = "invalid_client";
    assertThatThrownBy(() -> token(login, session, Duration.ofHours(1)))
        .isInstanceOf(PortvaktException.class)
        .satisfies(error -> {
          assertThat(((PortvaktException) error).code()).isEqualTo("invalid_client");
          assertThat(((PortvaktException) error).status()).isEqualTo(502);
        });
    assertThat(session.isInvalid()).isFalse();
    assertThat(login.store.load(grantId)).isNotNull();
    PROVIDER.tokenErrorStatus = 400;
    PROVIDER.tokenError = "invalid_grant";
    assertThatThrownBy(() -> token(login, session, Duration.ofHours(1)))
        .isInstanceOf(LoginRequiredException.class)
        .satisfies(error -> assertThat(((LoginRequiredException) error).reason()).isEqualTo(LoginRequiredException.Reason.REFRESH_FAILED));
    assertThat(session.isInvalid()).isTrue();
    assertThat(login.store.load(grantId)).isNull();
  }

  @Test
  void endsTheSessionAtTheFirstOutageWithoutGrace() throws Exception {
    TestLogin login = login(Duration.ZERO);
    MockHttpSession session = login.signIn(Instant.now().plusSeconds(3600));
    login.registrations.findByRegistrationId("portvakt");
    PROVIDER.tokenErrorStatus = 503;
    PROVIDER.tokenError = "temporarily_unavailable";
    assertThatThrownBy(() -> token(login, session, Duration.ofHours(1)))
        .isInstanceOf(LoginRequiredException.class)
        .satisfies(error -> assertThat(((LoginRequiredException) error).reason()).isEqualTo(LoginRequiredException.Reason.OUTAGE_GRACE_EXCEEDED));
  }

  @Test
  void keepsTheSessionWithinTheOutageGraceAndEndsItAfter() throws Exception {
    TestLogin login = login(Duration.ofSeconds(60));
    MockHttpSession session = login.signIn(Instant.now().plusSeconds(3600));
    login.registrations.findByRegistrationId("portvakt");
    PROVIDER.down = true;
    assertThatThrownBy(() -> token(login, session, Duration.ofHours(1))).isInstanceOf(PortvaktUnavailableException.class);
    assertThat(PortvaktSessionState.of(session).outageSince()).isNotNull();
    login.clock.offset = Duration.ofSeconds(30);
    assertThatThrownBy(() -> token(login, session, Duration.ofHours(1))).isInstanceOf(PortvaktUnavailableException.class);
    login.clock.offset = Duration.ofSeconds(61);
    assertThatThrownBy(() -> token(login, session, Duration.ofHours(1))).isInstanceOf(LoginRequiredException.class);
  }

  @Test
  void keepsTheRotatedTokensWhenTheNewIdTokenCannotBeCheckedYet() throws Exception {
    TestLogin login = login(Duration.ofSeconds(60));
    MockHttpSession session = login.signIn(Instant.now().plusSeconds(3600));
    String grantId = PortvaktSessionState.of(session).grantId();
    // The keys were never fetched by this client and the JWKS is down: the refresh succeeds,
    // the check of the refreshed ID token cannot be made.
    TestLogin fresh = new TestLogin(PROVIDER, Duration.ofSeconds(60), clock -> login.store);
    PROVIDER.jwksDown = true;
    int before = PROVIDER.refreshGrants.get();
    assertThatThrownBy(() -> token(fresh, session, Duration.ofHours(1))).isInstanceOf(PortvaktUnavailableException.class);
    assertThat(PROVIDER.refreshGrants.get() - before).isEqualTo(1);
    assertThat(fresh.store.load(grantId).refreshToken()).isEqualTo(PROVIDER.currentRefreshToken);
    assertThat(PortvaktSessionState.of(session).outageSince()).isNotNull();
    PROVIDER.jwksDown = false;
    // The next use needs no refresh: the stored access token is the refreshed one.
    String token = token(fresh, session, null);
    assertThat(token).isEqualTo(fresh.store.load(grantId).accessToken()).isNotEqualTo("access-initial");
    assertThat(PROVIDER.refreshGrants.get() - before).isEqualTo(1);
  }

  @Test
  void boundsTheWholeTokenRequestNotOnlyItsHeaders() throws Exception {
    TestLogin login = new TestLogin(PROVIDER, Duration.ofSeconds(60), InMemoryTokenStore::new, Duration.ofSeconds(1));
    MockHttpSession session = login.signIn(Instant.now().plusSeconds(3600));
    login.registrations.findByRegistrationId("portvakt");
    PROVIDER.trickleToken = true;
    long started = System.nanoTime();
    assertThatThrownBy(() -> token(login, session, Duration.ofHours(1))).isInstanceOf(PortvaktUnavailableException.class);
    assertThat((System.nanoTime() - started) / 1_000_000).isLessThan(5_000);
  }

  @Test
  void neverMovesTheSessionEndLaterAfterARefresh() throws Exception {
    TestLogin login = login(Duration.ZERO);
    Instant endsAt = Instant.now().plusSeconds(1800).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    // Without session_exp in the refreshed ID token the end stays.
    MockHttpSession withoutExp = login.signIn(endsAt);
    PROVIDER.sessionExp = null;
    token(login, withoutExp, Duration.ofHours(1));
    assertThat(PortvaktSessionState.of(withoutExp).endsAt()).isEqualTo(endsAt);
    // A later session_exp does not extend it either; an earlier one shortens it.
    MockHttpSession later = login.signIn(endsAt);
    PROVIDER.sessionExp = endsAt.getEpochSecond() + 7200;
    token(login, later, Duration.ofHours(1));
    assertThat(PortvaktSessionState.of(later).endsAt()).isEqualTo(endsAt);
    MockHttpSession earlier = login.signIn(endsAt);
    PROVIDER.sessionExp = endsAt.getEpochSecond() - 600;
    token(login, earlier, Duration.ofHours(1));
    assertThat(PortvaktSessionState.of(earlier).endsAt()).isEqualTo(endsAt.minusSeconds(600));
  }

  @Test
  void endsAnIdleOrExpiredSessionBeforeAskingPortvakt() throws Exception {
    TestLogin login = login(Duration.ZERO);
    MockHttpSession session = login.signIn(Instant.now().plusSeconds(7200));
    login.clock.offset = Duration.ofMinutes(31);
    assertThatThrownBy(() -> token(login, session, null))
        .isInstanceOf(LoginRequiredException.class)
        .satisfies(error -> assertThat(((LoginRequiredException) error).reason()).isEqualTo(LoginRequiredException.Reason.SESSION_EXPIRED));
  }

  // The login callback and logout ----------------------------------------------------------------

  static ClientRegistration registration() {
    return ClientRegistration.withRegistrationId("portvakt")
        .clientId("case-service")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("http://localhost/auth/callback")
        .authorizationUri("https://login.example.org/t/k/auth")
        .tokenUri("https://login.example.org/t/k/token")
        .build();
  }

  static PortvaktOidcUser user(String acr, Instant sessionExp) {
    long now = Instant.now().getEpochSecond();
    Map<String, Object> claims =
        Map.ofEntries(
            Map.entry("aud", List.of("case-service")),
            Map.entry("sub", FakeProvider.SUB),
            Map.entry("tid", "k"),
            Map.entry("idp", "m"),
            Map.entry("idp_kind", "citizen"),
            Map.entry("acr", acr),
            Map.entry("auth_time", now),
            Map.entry("session_exp", sessionExp.getEpochSecond()),
            Map.entry("roles", List.of()),
            Map.entry("attrs", Map.of()));
    return PortvaktOidcUser.of(new OidcIdToken("id", Instant.ofEpochSecond(now), Instant.ofEpochSecond(now + 300), claims));
  }

  static OAuth2LoginAuthenticationToken callback(String acr) {
    OAuth2AuthorizationRequest.Builder request =
        OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri("https://login.example.org/t/k/auth")
            .clientId("case-service")
            .redirectUri("http://localhost/auth/callback")
            .state("state");
    if (acr != null) request.attributes(attributes -> attributes.put(PortvaktAuthorizationRequestResolver.ACR_ATTRIBUTE, acr));
    request.attributes(attributes -> attributes.put(PortvaktAuthorizationRequestResolver.RETURN_TO_ATTRIBUTE, "/cases"));
    OAuth2AuthorizationExchange exchange =
        new OAuth2AuthorizationExchange(
            request.build(), OAuth2AuthorizationResponse.success("code").state("state").redirectUri("http://localhost/auth/callback").build());
    OAuth2LoginAuthenticationToken token = new OAuth2LoginAuthenticationToken(registration(), exchange);
    token.setDetails(new PortvaktLoginDetails(new MockHttpServletRequest()));
    return token;
  }

  static AuthenticationManager succeedingWith(PortvaktOidcUser user) {
    return authentication -> {
      OAuth2LoginAuthenticationToken login = (OAuth2LoginAuthenticationToken) authentication;
      return new OAuth2LoginAuthenticationToken(
          login.getClientRegistration(),
          login.getAuthorizationExchange(),
          user,
          user.getAuthorities(),
          new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "a", Instant.now(), Instant.now().plusSeconds(60)));
    };
  }

  @Test
  void refusesAStepUpThatDidNotReachTheLevelBeforeAnythingIsStored() {
    PortvaktLoginAuthenticationManager manager =
        new PortvaktLoginAuthenticationManager(
            succeedingWith(user(AcrRanking.LOA3, Instant.now().plusSeconds(600))), AcrRanking.DEFAULT, java.time.Clock.systemUTC());
    assertThatThrownBy(() -> manager.authenticate(callback(AcrRanking.LOA4)))
        .isInstanceOf(OAuth2AuthenticationException.class)
        .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode()).isEqualTo("acr_not_met"));
    OAuth2LoginAuthenticationToken accepted = callback(AcrRanking.LOA3);
    Authentication result = manager.authenticate(accepted);
    assertThat(result.isAuthenticated()).isTrue();
    assertThat(((PortvaktLoginDetails) accepted.getDetails()).getReturnTo()).isEqualTo("/cases");
  }

  @Test
  void refusesALoginWhoseBrokerSessionEndedAndMapsOutagesToUnavailable() {
    PortvaktLoginAuthenticationManager ended =
        new PortvaktLoginAuthenticationManager(
            succeedingWith(user(AcrRanking.LOA3, Instant.now().minusSeconds(1))), AcrRanking.DEFAULT, java.time.Clock.systemUTC());
    assertThatThrownBy(() -> ended.authenticate(callback(null)))
        .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode()).isEqualTo("login_failed"));
    PortvaktLoginAuthenticationManager down =
        new PortvaktLoginAuthenticationManager(
            authentication -> {
              throw new OAuth2AuthenticationException(
                  new OAuth2Error("invalid_token_response"), "x", new org.springframework.web.client.ResourceAccessException("refused"));
            },
            AcrRanking.DEFAULT,
            java.time.Clock.systemUTC());
    assertThatThrownBy(() -> down.authenticate(callback(null)))
        .satisfies(error -> assertThat(((OAuth2AuthenticationException) error).getError().getErrorCode()).isEqualTo("portvakt_unavailable"));
  }

  @Test
  void logsOutLocallyWithinTheContextPath() throws Exception {
    PortvaktLoginSettings settings =
        new PortvaktLoginSettings(
            "/auth", "{baseUrl}/auth/callback", "{baseUrl}/", "/", Duration.ofMinutes(30), Duration.ofHours(12), Duration.ZERO, List.of());
    PortvaktOidcUser user = user(AcrRanking.LOA3, Instant.now().plusSeconds(600));
    Authentication authentication =
        new org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken(user, user.getAuthorities(), "portvakt");
    // No end-session endpoint, and Portvakt unreachable: both stay within the context path.
    ClientRegistrationRepository withoutEndSession = id -> registration();
    ClientRegistrationRepository unreachable =
        id -> {
          throw new PortvaktUnavailableException("down");
        };
    for (ClientRegistrationRepository registrations : List.of(withoutEndSession, unreachable)) {
      MockHttpServletRequest request = new MockHttpServletRequest("POST", "/app/auth/logout");
      request.setContextPath("/app");
      MockHttpServletResponse response = new MockHttpServletResponse();
      new PortvaktLogoutSuccessHandler(registrations, settings).onLogoutSuccess(request, response, authentication);
      assertThat(response.getStatus()).isEqualTo(303);
      assertThat(response.getHeader("Location")).isEqualTo("/app/");
    }
  }
}
