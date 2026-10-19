package se.portvakt.spring;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import se.portvakt.sdk.ClientAuth;
import se.portvakt.sdk.PortvaktClient;
import se.portvakt.sdk.PortvaktConfig;
import se.portvakt.spring.login.PortvaktAccessTokens;
import se.portvakt.spring.login.PortvaktAuthorizedClientManager;
import se.portvakt.spring.login.PortvaktAuthorizedClientRepository;
import se.portvakt.spring.login.PortvaktClientRegistrationRepository;
import se.portvakt.spring.login.PortvaktLoginSettings;
import se.portvakt.spring.login.PortvaktOidcUser;
import se.portvakt.spring.login.PortvaktRefreshTokenProvider;
import se.portvakt.spring.login.PortvaktSessionState;
import se.portvakt.spring.login.PortvaktSessions;
import se.portvakt.spring.login.PortvaktTokenStore;

/**
 * The browser login's token parts wired by hand against a {@link FakeProvider} (real HTTP), with a
 * movable clock and any token store: what the auto-configuration builds, without a context.
 */
final class TestLogin {
  static final class MovableClock extends Clock {
    volatile Duration offset = Duration.ZERO;

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return Instant.now().plus(offset);
    }
  }

  final FakeProvider provider;
  final MovableClock clock = new MovableClock();
  final PortvaktClient client;
  final PortvaktLoginSettings settings;
  final PortvaktTokenStore store;
  final PortvaktSessions sessions;
  final PortvaktClientRegistrationRepository registrations;
  final PortvaktAccessTokens tokens;

  TestLogin(FakeProvider provider, Duration outageGrace, java.util.function.Function<Clock, PortvaktTokenStore> stores) {
    this(provider, outageGrace, stores, Duration.ofSeconds(10));
  }

  TestLogin(
      FakeProvider provider,
      Duration outageGrace,
      java.util.function.Function<Clock, PortvaktTokenStore> stores,
      Duration httpTimeout) {
    this.provider = provider;
    this.client =
        PortvaktClient.create(
            PortvaktConfig.builder()
                .issuer(provider.issuer)
                .clientId(FakeProvider.CLIENT_ID)
                .clientAuth(ClientAuth.clientSecretBasic("a-client-secret-0123456789abcdef"))
                .allowInsecureRequests(true)
                .failureCacheTtl(Duration.ZERO)
                .httpTimeout(httpTimeout)
                .clock(clock)
                .build());
    this.settings =
        new PortvaktLoginSettings(
            "/auth",
            "http://localhost/auth/callback",
            "http://localhost/",
            "/",
            Duration.ofMinutes(30),
            Duration.ofHours(12),
            outageGrace,
            List.of("/error"));
    this.store = stores.apply(clock);
    this.sessions = new PortvaktSessions(store, settings, clock);
    this.registrations = new PortvaktClientRegistrationRepository(client.config(), client.discovery(), settings);
    PortvaktAutoConfiguration.PortvaktTokenEndpoint endpoint = new PortvaktAutoConfiguration.PortvaktTokenEndpoint(client.config());
    PortvaktAuthorizedClientManager manager =
        new PortvaktAuthorizedClientManager(
            registrations,
            store,
            new PortvaktRefreshTokenProvider(endpoint.refreshTokenClient(), Duration.ofSeconds(60), clock));
    this.tokens = new PortvaktAccessTokens(manager, client.verifier(), sessions);
  }

  /**
   * A signed-in session as the login callback leaves it: the context and state in the session,
   * the tokens (with Portvakt's current refresh token) in the store.
   */
  MockHttpSession signIn(Instant endsAt) throws Exception {
    OidcIdToken idToken = verifiedIdToken();
    PortvaktOidcUser user = PortvaktOidcUser.of(idToken);
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(new OAuth2AuthenticationToken(user, user.getAuthorities(), "portvakt"));
    MockHttpSession session = new MockHttpSession();
    session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
    String grantId = PortvaktAuthorizedClientRepository.newGrantId();
    String refresh = "refresh-initial-" + grantId;
    provider.currentRefreshToken = refresh;
    Instant now = clock.instant();
    store.save(
        grantId,
        new PortvaktTokenStore.StoredTokens("access-initial", now.minusSeconds(10), now.plusSeconds(300), java.util.Set.of("openid"), refresh),
        endsAt);
    new PortvaktSessionState(now, endsAt, null, now, grantId).storeIn(session);
    return session;
  }

  OidcIdToken verifiedIdToken() throws Exception {
    return se.portvakt.spring.login.IdTokens.toOidcIdToken(
        client.verifier().verifyIdToken(provider.sign(provider.idTokenClaims(null), null)));
  }

  /** A copy of a session (a Spring Session snapshot read by a concurrent request). */
  static MockHttpSession copy(MockHttpSession session) {
    MockHttpSession copy = new MockHttpSession(session.getServletContext(), session.getId());
    for (String name : java.util.Collections.list(session.getAttributeNames())) {
      copy.setAttribute(name, session.getAttribute(name));
    }
    return copy;
  }

  /** A request of the session, with its security context active on this thread. */
  static MockHttpServletRequest request(MockHttpSession session) {
    SecurityContext context =
        (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
    SecurityContextHolder.setContext(context);
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/x");
    request.setSession(session);
    return request;
  }
}
