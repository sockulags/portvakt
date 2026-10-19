package se.portvakt.spring;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;
import se.portvakt.sdk.AcrRanking;
import se.portvakt.spring.login.PortvaktAccessTokens;
import se.portvakt.spring.login.PortvaktAuthorizedClientRepository;
import se.portvakt.spring.login.PortvaktSessionState;
import se.portvakt.spring.login.PortvaktTokenStore;

/**
 * The browser login with MockMvc against a fake issuer (real HTTP: discovery, JWKS, token
 * endpoint): PKCE, acr_values, prompt, login_hint, returnTo, same-site starts, the full callback
 * (once for concurrent callbacks), login redirects and 401 JSON, step-up, session_exp and idle
 * timeout, the session JSON, invalid_client and logout.
 */
@SpringBootTest(
    classes = LoginRoutesTest.App.class,
    properties = {
      "portvakt.client-id=case-service",
      "portvakt.client-secret=a-client-secret-0123456789abcdef",
      "portvakt.allow-insecure-requests=true",
      "portvakt.login.enabled=true",
      "portvakt.login.redirect-uri=http://localhost/auth/callback",
      "portvakt.login.post-logout-redirect-uri=http://localhost/",
      "portvakt.login.public-paths=/,/error"
    })
@AutoConfigureMockMvc
class LoginRoutesTest {
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
    PROVIDER.tokenErrorStatus = 0;
    PROVIDER.tokenRetryAfter = null;
    PROVIDER.tokenDelayMillis = 0;
    PROVIDER.extraClaims = Map.of();
  }

  @DynamicPropertySource
  static void issuer(DynamicPropertyRegistry registry) {
    registry.add("portvakt.issuer", () -> PROVIDER.issuer);
  }

  @Configuration(proxyBeanMethods = false)
  @EnableAutoConfiguration
  @Import(Routes.class)
  static class App {}

  @RestController
  static class Routes {
    private final PortvaktAccessTokens tokens;

    Routes(PortvaktAccessTokens tokens) {
      this.tokens = tokens;
    }

    @GetMapping("/")
    String home() {
      return "home";
    }

    @GetMapping("/private")
    String privatePage() {
      return "private";
    }

    @RequireAcr(AcrRanking.LOA4)
    @GetMapping("/sensitive")
    String sensitive() {
      return "sensitive";
    }

    @GetMapping("/token")
    Map<String, String> token(HttpServletRequest request, HttpServletResponse response) {
      return Map.of("token", tokens.getAccessToken(request, response, Duration.ofHours(1)));
    }
  }

  @Autowired MockMvc mvc;
  @Autowired PortvaktTokenStore store;
  /** The ID token of the last {@link #session} (to check it never reaches a response). */
  String lastIdToken;

  /** The decoded query parameters of a URL. */
  static Map<String, List<String>> query(String location) {
    Map<String, List<String>> decoded = new java.util.LinkedHashMap<>();
    UriComponentsBuilder.fromUri(URI.create(location)).build().getQueryParams()
        .forEach(
            (name, values) ->
                decoded.put(
                    name,
                    values.stream()
                        .map(value -> value == null ? null : java.net.URLDecoder.decode(value, java.nio.charset.StandardCharsets.UTF_8))
                        .toList()));
    return decoded;
  }

  @Test
  void startsALoginWithPkceStateNonceAndReturnTo() throws Exception {
    MvcResult result =
        mvc.perform(get("/auth/login").param("returnTo", "/cases/7").param("loginHint", "anna@kommun.example"))
            .andExpect(status().isFound())
            .andReturn();
    String location = result.getResponse().getRedirectedUrl();
    assertThat(location).startsWith(PROVIDER.issuer + "/auth?");
    Map<String, List<String>> query = query(location);
    assertThat(query.get("response_type")).containsExactly("code");
    assertThat(query.get("client_id")).containsExactly("case-service");
    assertThat(query.get("code_challenge_method")).containsExactly("S256");
    assertThat(query.get("code_challenge").get(0)).hasSizeGreaterThan(40);
    assertThat(query).containsKeys("state", "nonce");
    assertThat(query.get("login_hint").get(0)).isEqualTo("anna@kommun.example");
    assertThat(query).doesNotContainKeys("acr_values", "prompt");
    // The pending login is in the token store; the session holds a pointer only.
    MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
    for (String name : java.util.Collections.list(session.getAttributeNames())) {
      assertThat(String.valueOf(session.getAttribute(name))).doesNotContain("code_verifier");
    }
  }

  @Test
  void addsAcrValuesForAStepUpAndPromptSelectAccountForTheRepresentationSwitch() throws Exception {
    String stepUp =
        mvc.perform(get("/auth/step-up").param("acr", AcrRanking.LOA4).header("Sec-Fetch-Site", "same-origin"))
            .andExpect(status().isFound())
            .andReturn()
            .getResponse()
            .getRedirectedUrl();
    assertThat(query(stepUp)).containsKey("acr_values");
    String select =
        mvc.perform(get("/auth/select-representation").header("Sec-Fetch-Site", "same-origin"))
            .andExpect(status().isFound())
            .andReturn()
            .getResponse()
            .getRedirectedUrl();
    assertThat(query(select).get("prompt")).containsExactly("select_account");
    String login =
        mvc.perform(get("/auth/login").param("prompt", "login").header("Sec-Fetch-Site", "same-origin"))
            .andReturn()
            .getResponse()
            .getRedirectedUrl();
    assertThat(query(login).get("prompt")).containsExactly("login");
  }

  @Test
  void refusesCrossSiteStartsAndInvalidParameters() throws Exception {
    mvc.perform(get("/auth/step-up").param("acr", AcrRanking.LOA4).header("Sec-Fetch-Site", "cross-site").accept("application/json"))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error").value("cross_site_request"));
    // Without Sec-Fetch-Site: a same-origin Referer, or nothing.
    mvc.perform(get("/auth/select-representation").header("Referer", "http://localhost/page")).andExpect(status().isFound());
    mvc.perform(get("/auth/select-representation").header("Referer", "https://evil.example/").accept("application/json"))
        .andExpect(status().isForbidden());
    mvc.perform(get("/auth/step-up").header("Sec-Fetch-Site", "same-origin").accept("application/json"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.error").value("invalid_request"));
    mvc.perform(get("/auth/login").param("prompt", "consent").accept("application/json")).andExpect(status().isBadRequest());
    mvc.perform(get("/auth/login").param("returnTo", "/a", "/b").accept("application/json")).andExpect(status().isBadRequest());
    mvc.perform(get("/auth/login").param("returnTo", "//evil.example")).andExpect(status().isFound());
  }

  @Test
  void guardsLoginsThatSteerOrReplaceASessionAgainstCrossSiteStarts() throws Exception {
    // A plain login may come from anywhere (a "Logga in" link on another site).
    mvc.perform(get("/auth/login").header("Sec-Fetch-Site", "cross-site")).andExpect(status().isFound());
    // With prompt or acr it may not: it would replace the person's session or representation.
    mvc.perform(get("/auth/login").param("prompt", "select_account").header("Sec-Fetch-Site", "cross-site").accept("application/json"))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error").value("cross_site_request"));
    mvc.perform(get("/auth/login").param("acr", AcrRanking.LOA4).header("Sec-Fetch-Site", "cross-site").accept("application/json"))
        .andExpect(status().isForbidden());
    // Nor while a session exists.
    MockHttpSession session = session(AcrRanking.LOA3, Instant.now().plusSeconds(3600));
    mvc.perform(get("/auth/login").session(session).header("Sec-Fetch-Site", "cross-site").accept("application/json"))
        .andExpect(status().isForbidden());
    mvc.perform(get("/auth/login").session(session).header("Sec-Fetch-Site", "same-origin")).andExpect(status().isFound());
  }

  @Test
  void answersUnauthenticatedRequestsWithALoginRedirectOr401Json() throws Exception {
    mvc.perform(get("/").accept("text/html")).andExpect(status().isOk());
    mvc.perform(get("/private").header("Sec-Fetch-Mode", "navigate"))
        .andExpect(status().isFound())
        .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).isEqualTo("/auth/login?returnTo=%2Fprivate"));
    mvc.perform(get("/private").accept("application/json"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").value("login_required"))
        .andExpect(jsonPath("$.loginUrl").value("/auth/login?returnTo=%2F"));
    mvc.perform(get("/auth/session").accept("application/json"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.authenticated").value(false));
  }

  @Test
  void completesALoginOnceForTwoConcurrentCallbacksWithOneState() throws Exception {
    MvcResult start = mvc.perform(get("/auth/login").param("returnTo", "/private")).andExpect(status().isFound()).andReturn();
    Map<String, List<String>> query = query(start.getResponse().getRedirectedUrl());
    PROVIDER.nonce = query.get("nonce").get(0);
    String state = query.get("state").get(0);
    MockHttpSession first = (MockHttpSession) start.getRequest().getSession(false);
    MockHttpSession second = TestLogin.copy(first);
    int before = PROVIDER.codeGrants.get();
    PROVIDER.tokenDelayMillis = 300;
    CountDownLatch go = new CountDownLatch(1);
    ExecutorService threads = Executors.newFixedThreadPool(2);
    List<Integer> statuses;
    try {
      List<Future<Integer>> results =
          List.of(first, second).stream()
              .map(
                  session ->
                      threads.submit(
                          () -> {
                            go.await();
                            return mvc.perform(
                                    get("/auth/callback")
                                        .param("code", "used-code")
                                        .param("state", state)
                                        .session(session)
                                        .accept("application/json"))
                                .andReturn()
                                .getResponse()
                                .getStatus();
                          }))
              .toList();
      go.countDown();
      statuses = List.of(results.get(0).get(), results.get(1).get());
    } finally {
      threads.shutdownNow();
    }
    assertThat(statuses).containsExactlyInAnyOrder(303, 400);
    assertThat(PROVIDER.codeGrants.get() - before).isEqualTo(1);
    MockHttpSession winner = statuses.get(0) == 303 ? first : second;
    PortvaktSessionState stateOfWinner = PortvaktSessionState.of(winner);
    assertThat(stateOfWinner.grantId()).isNotNull();
    assertThat(store.load(stateOfWinner.grantId())).isNotNull();
    mvc.perform(get("/auth/session").session(winner))
        .andExpect(jsonPath("$.authenticated").value(true))
        .andExpect(jsonPath("$.principal.name").value("Sven Medborgare"));
    mvc.perform(get("/private").session(winner)).andExpect(status().isOk());
  }

  /** A signed-in session as the login callback leaves it (tokens in the store). */
  MockHttpSession session(String acr, Instant endsAt) {
    return session(acr, endsAt, Instant.now());
  }

  MockHttpSession session(String acr, Instant endsAt, Instant lastSeenAt) {
    try {
      return signedSession(acr, endsAt, lastSeenAt);
    } catch (Exception exception) {
      throw new IllegalStateException(exception);
    }
  }

  MockHttpSession signedSession(String acr, Instant endsAt, Instant lastSeenAt) throws Exception {
    long now = Instant.now().getEpochSecond();
    Map<String, Object> claims =
        Map.ofEntries(
            Map.entry("iss", PROVIDER.issuer),
            Map.entry("aud", List.of("case-service")),
            Map.entry("sub", FakeProvider.SUB),
            Map.entry("tid", "fake"),
            Map.entry("idp", "0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7"),
            Map.entry("idp_kind", "citizen"),
            Map.entry("acr", acr),
            Map.entry("auth_time", now),
            Map.entry("session_exp", endsAt.getEpochSecond()),
            Map.entry("roles", List.of("handlaggare")),
            Map.entry("attrs", Map.of()),
            Map.entry("name", "Sven Medborgare"),
            Map.entry("pin", "191212121212"),
            Map.entry("iat", now),
            Map.entry("exp", now + 300));
    // As the login leaves it: the signed ID token next to the tokens in the store, the session
    // holds the state (grant id, timestamps) only.
    String idToken = PROVIDER.sign(new java.util.HashMap<>(claims), null);
    lastIdToken = idToken;
    MockHttpSession session = new MockHttpSession();
    String grantId = PortvaktAuthorizedClientRepository.newGrantId();
    String refresh = "refresh-" + grantId;
    PROVIDER.currentRefreshToken = refresh;
    store.save(
        grantId,
        new PortvaktTokenStore.StoredTokens(
            "access-1", Instant.now().minusSeconds(5), Instant.now().plusSeconds(300), java.util.Set.of(), refresh, idToken),
        endsAt);
    new PortvaktSessionState(Instant.now(), endsAt, null, lastSeenAt, grantId).storeIn(session);
    return session;
  }

  @Test
  @SuppressWarnings("unchecked")
  void servesTheSessionWithoutThePinAndEndsItAtSessionExp() throws Exception {
    MockHttpSession session = session(AcrRanking.LOA3, Instant.now().plusSeconds(3600));
    MvcResult info = mvc.perform(get("/auth/session").session(session)).andExpect(status().isOk()).andReturn();
    String json = info.getResponse().getContentAsString();
    assertThat((Boolean) JsonPath.read(json, "$.authenticated")).isTrue();
    assertThat((String) JsonPath.read(json, "$.principal.name")).isEqualTo("Sven Medborgare");
    assertThat((List<String>) JsonPath.read(json, "$.principal.roles")).containsExactly("handlaggare");
    assertThat(json).doesNotContain("191212121212").doesNotContain(lastIdToken).doesNotContain("access-1");
    assertThat((String) JsonPath.read(json, "$.csrfToken")).isNotBlank();
    mvc.perform(get("/private").session(session)).andExpect(status().isOk());

    MockHttpSession ended = session(AcrRanking.LOA3, Instant.now().minusSeconds(1));
    String grantId = PortvaktSessionState.of(ended).grantId();
    mvc.perform(get("/private").session(ended).accept("application/json"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").value("login_required"));
    assertThat(ended.isInvalid()).isTrue();
    assertThat(store.load(grantId)).isNull();
  }

  @Test
  void countsOnlyProtectedRequestsAsActivityForTheIdleTimeout() throws Exception {
    Instant twentyMinutesAgo = Instant.now().minus(Duration.ofMinutes(20));
    MockHttpSession session = session(AcrRanking.LOA3, Instant.now().plusSeconds(7200), twentyMinutesAgo);
    // Reading the session state and public pages is no activity.
    mvc.perform(get("/auth/session").session(session)).andExpect(jsonPath("$.authenticated").value(true));
    mvc.perform(get("/").session(session)).andExpect(status().isOk());
    assertThat(PortvaktSessionState.of(session).lastSeenAt()).isEqualTo(twentyMinutesAgo);
    // A protected request is.
    mvc.perform(get("/private").session(session)).andExpect(status().isOk());
    assertThat(PortvaktSessionState.of(session).lastSeenAt()).isAfter(twentyMinutesAgo);
    // After the idle timeout (30 min) without activity the session ends, also for the session JSON.
    MockHttpSession idle = session(AcrRanking.LOA3, Instant.now().plusSeconds(7200), Instant.now().minus(Duration.ofMinutes(31)));
    mvc.perform(get("/auth/session").session(idle)).andExpect(jsonPath("$.authenticated").value(false));
    assertThat(idle.isInvalid()).isTrue();
  }

  @Test
  void sendsALowerAcrToTheStepUp() throws Exception {
    MockHttpSession loa3 = session(AcrRanking.LOA3, Instant.now().plusSeconds(3600));
    mvc.perform(get("/sensitive").session(loa3).accept("application/json"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.error").value("step_up_required"))
        .andExpect(jsonPath("$.acr").value(AcrRanking.LOA4))
        .andExpect(jsonPath("$.stepUpUrl").value("/auth/step-up?acr=http%3A%2F%2Fid.elegnamnden.se%2Floa%2F1.0%2Floa4&returnTo=%2F"));
    mvc.perform(get("/sensitive").session(loa3).header("Sec-Fetch-Mode", "navigate").header("Sec-Fetch-Site", "same-origin"))
        .andExpect(status().isFound())
        .andExpect(
            result ->
                assertThat(result.getResponse().getRedirectedUrl())
                    .isEqualTo("/auth/step-up?acr=http%3A%2F%2Fid.elegnamnden.se%2Floa%2F1.0%2Floa4&returnTo=%2Fsensitive"));
    mvc.perform(get("/sensitive").session(session(AcrRanking.LOA4, Instant.now().plusSeconds(3600)))).andExpect(status().isOk());
  }

  @Test
  void answers502ForInvalidClientAndKeepsTheSession() throws Exception {
    MockHttpSession session = session(AcrRanking.LOA3, Instant.now().plusSeconds(3600));
    PROVIDER.tokenErrorStatus = 401;
    PROVIDER.tokenError = "invalid_client";
    mvc.perform(get("/token").session(session).accept("application/json"))
        .andExpect(status().isBadGateway())
        .andExpect(jsonPath("$.error").value("invalid_client"));
    assertThat(session.isInvalid()).isFalse();
    PROVIDER.tokenErrorStatus = 0;
    mvc.perform(get("/token").session(session).accept("application/json"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.token").value(org.hamcrest.Matchers.startsWith("access-")));
  }

  /** The interstitial page: its button's GET (path and fields). */
  static String interstitialTarget(MvcResult result) throws Exception {
    assertThat(result.getResponse().getStatus()).isEqualTo(200);
    assertThat(result.getResponse().getHeader("Content-Security-Policy"))
        .isEqualTo("default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    assertThat(result.getResponse().getHeader("Referrer-Policy")).isEqualTo("same-origin");
    String page = result.getResponse().getContentAsString();
    assertThat(page).contains("Fortsätt till inloggning").doesNotContain("<script").doesNotContain("<style");
    java.util.regex.Matcher action = java.util.regex.Pattern.compile("<form method=\"get\" action=\"([^\"]+)\">").matcher(page);
    assertThat(action.find()).isTrue();
    UriComponentsBuilder target = UriComponentsBuilder.fromPath(action.group(1));
    java.util.regex.Matcher field = java.util.regex.Pattern.compile("name=\"([^\"]+)\" value=\"([^\"]*)\"").matcher(page);
    while (field.find()) target.queryParam(field.group(1), field.group(2).replace("&#38;", "&"));
    return target.build().toUriString();
  }

  @Test
  void answersCrossSiteNavigationsThatWouldReplaceTheLoginWithAPageThatStartsThemHere() throws Exception {
    MockHttpSession session = session(AcrRanking.LOA3, Instant.now().plusSeconds(3600));
    for (String url :
        List.of(
            "/auth/step-up?acr=" + AcrRanking.LOA4 + "&returnTo=/cases",
            "/auth/select-representation?returnTo=/",
            "/auth/login?prompt=login")) {
      for (Map<String, String> headers :
          List.of(
              Map.of("Sec-Fetch-Site", "cross-site"),
              Map.of("Sec-Fetch-Site", "same-site"),
              Map.<String, String>of(),
              Map.of("Referer", "https://evil.example/"))) {
        var request = get(url).session(session).header("Sec-Fetch-Mode", "navigate");
        headers.forEach(request::header);
        String target = interstitialTarget(mvc.perform(request).andReturn());
        assertThat(query(target)).isEqualTo(query(url));
        assertThat(URI.create(target).getPath()).isEqualTo(URI.create(url).getPath());
        // The button sends the same GET from this page: the flow starts.
        mvc.perform(get(target).session(session).header("Sec-Fetch-Site", "same-origin")).andExpect(status().isFound());
      }
    }
    // The session's CSRF token as a query parameter no longer counts.
    MvcResult csrf =
        mvc.perform(
                get("/auth/step-up?acr=" + AcrRanking.LOA4 + "&csrf=anything")
                    .session(session)
                    .header("Sec-Fetch-Mode", "navigate"))
            .andReturn();
    interstitialTarget(csrf);
    // A deep link behind @RequireAcr from another site: the interstitial instead of a redirect.
    String deepLink =
        interstitialTarget(
            mvc.perform(get("/sensitive").session(session).header("Sec-Fetch-Mode", "navigate").header("Sec-Fetch-Site", "cross-site"))
                .andReturn());
    assertThat(URI.create(deepLink).getPath()).isEqualTo("/auth/step-up");
    assertThat(query(deepLink).get("returnTo")).containsExactly("/sensitive");
  }

  @Test
  void keepsTheIdTokenAndPersonalDataOutOfTheSerialisedHttpSession() throws Exception {
    PROVIDER.extraClaims = Map.of("pin", "191212121212", "email", "sven@example.org");
    MvcResult start = mvc.perform(get("/auth/login").param("returnTo", "/private")).andExpect(status().isFound()).andReturn();
    Map<String, List<String>> query = query(start.getResponse().getRedirectedUrl());
    PROVIDER.nonce = query.get("nonce").get(0);
    MockHttpSession session = (MockHttpSession) start.getRequest().getSession(false);
    MvcResult callback =
        mvc.perform(get("/auth/callback").param("code", "fresh-code").param("state", query.get("state").get(0)).session(session))
            .andExpect(status().isSeeOther())
            .andReturn();
    MockHttpSession signedIn = (MockHttpSession) callback.getRequest().getSession(false);
    mvc.perform(get("/private").session(signedIn)).andExpect(status().isOk());
    mvc.perform(get("/auth/session").session(signedIn)).andExpect(jsonPath("$.principal.name").value("Sven Medborgare"));
    String idToken = store.load(PortvaktSessionState.of(signedIn).grantId()).idToken();
    assertThat(idToken).isNotBlank();
    // Serialise the session as Spring Session or a servlet container would.
    java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
    try (java.io.ObjectOutputStream out = new java.io.ObjectOutputStream(bytes)) {
      for (String name : java.util.Collections.list(signedIn.getAttributeNames())) {
        out.writeObject(name);
        out.writeObject(signedIn.getAttribute(name));
      }
    }
    String serialised = bytes.toString(java.nio.charset.StandardCharsets.ISO_8859_1);
    assertThat(serialised)
        .doesNotContain(idToken)
        .doesNotContain(idToken.split("\\.")[1])
        .doesNotContain("191212121212")
        .doesNotContain("Sven Medborgare")
        .doesNotContain("sven@example.org")
        .doesNotContain(FakeProvider.SUB);
    assertThat(signedIn.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).isNull();
  }

  @Test
  void answersTheCodeExchangesRetryLaterWithTheUnavailablePage() throws Exception {
    MvcResult start = mvc.perform(get("/auth/login")).andExpect(status().isFound()).andReturn();
    Map<String, List<String>> query = query(start.getResponse().getRedirectedUrl());
    PROVIDER.nonce = query.get("nonce").get(0);
    PROVIDER.tokenErrorStatus = 429;
    PROVIDER.tokenError = "temporarily_unavailable";
    PROVIDER.tokenRetryAfter = "11";
    MvcResult callback =
        mvc.perform(
                get("/auth/callback")
                    .param("code", "fresh-code")
                    .param("state", query.get("state").get(0))
                    .session((MockHttpSession) start.getRequest().getSession(false))
                    .accept("text/html"))
            .andExpect(status().isServiceUnavailable())
            .andReturn();
    assertThat(callback.getResponse().getHeader("Retry-After")).isEqualTo("11");
    assertThat(callback.getResponse().getContentAsString()).contains("portvakt_unavailable");
  }

  @Test
  void logsOutAtPortvaktAlsoWithoutALocalSession() throws Exception {
    // No session, no CSRF token to present: the browser still goes through Portvakt's logout.
    MvcResult logout = mvc.perform(post("/auth/logout")).andExpect(status().isSeeOther()).andReturn();
    String location = logout.getResponse().getHeader("Location");
    assertThat(location).startsWith(PROVIDER.issuer + "/session/end?");
    assertThat(query(location).get("client_id")).containsExactly("case-service");
    assertThat(query(location).get("post_logout_redirect_uri")).containsExactly("http://localhost/");
    assertThat(query(location)).doesNotContainKey("id_token_hint");
  }

  @Test
  void logsOutWithCsrfThroughPortvaktsEndSessionEndpoint() throws Exception {
    MockHttpSession session = session(AcrRanking.LOA3, Instant.now().plusSeconds(3600));
    String grantId = PortvaktSessionState.of(session).grantId();
    mvc.perform(post("/auth/logout").session(session).accept("application/json"))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.error").value("invalid_csrf_token"));
    MvcResult logout =
        mvc.perform(post("/auth/logout").session(session).with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(status().isSeeOther())
            .andReturn();
    String location = logout.getResponse().getHeader("Location");
    assertThat(location).startsWith(PROVIDER.issuer + "/session/end?");
    assertThat(query(location)).containsKeys("id_token_hint", "post_logout_redirect_uri");
    assertThat(session.isInvalid()).isTrue();
    assertThat(store.load(grantId)).isNull();
  }
}
