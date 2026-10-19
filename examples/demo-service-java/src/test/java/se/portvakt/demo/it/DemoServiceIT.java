package se.portvakt.demo.it;

import static org.assertj.core.api.Assertions.assertThat;

import tools.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import se.portvakt.demo.DemoApplication;
import se.portvakt.sdk.AcrRanking;
import se.portvakt.sdk.ClientAuth;
import se.portvakt.sdk.ClientCredentialsTokenProvider;
import se.portvakt.sdk.PortvaktClient;
import se.portvakt.sdk.PortvaktConfig;
import se.portvakt.spring.login.PortvaktAccessTokens;

/**
 * The Java demo (Spring Boot starter) against a real Portvakt and mock IdP (npm run test:java):
 * OIDC and SAML logins, roles, step-up, representation switch, the API with the session's access
 * token, resource server refusals (wrong audience, another tenant), client credentials,
 * refresh, logout and session_exp enforcement.
 */
@ExtendWith(PortvaktStack.class)
@SpringBootTest(
    classes = DemoApplication.class,
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    properties = {
      "server.port=3300",
      "logging.level.se.portvakt=debug",
      // session_exp (8 h) is tested with a moved clock: the idle timeout must not end it first.
      "portvakt.login.idle-timeout=1d"
    })
@Import({DemoServiceIT.TestSupport.class, DemoServiceIT.TestSupport.TokenController.class})
class DemoServiceIT {
  static final String APP = PortvaktStack.APP;
  static final String LOA3 = AcrRanking.LOA3;
  static final String LOA4 = AcrRanking.LOA4;
  static final String EMPLOYEE = "anna.andersson@kommun.example";

  @DynamicPropertySource
  static void portvakt(DynamicPropertyRegistry registry) {
    registry.add("portvakt.issuer", () -> PortvaktStack.ISSUER);
    registry.add("portvakt.client-secret", () -> PortvaktStack.CLIENT_SECRET);
    registry.add("portvakt.allow-insecure-requests", () -> "true");
  }

  /** A clock the tests can move (session_exp), and a route that forces a refresh. */
  @TestConfiguration
  static class TestSupport {
    @Bean
    MovableClock portvaktClock() {
      return new MovableClock();
    }

    @RestController
    static class TokenController {
      private final PortvaktAccessTokens tokens;

      TokenController(PortvaktAccessTokens tokens) {
        this.tokens = tokens;
      }

      /** The session's access token, valid at least {@code min} seconds longer. */
      @GetMapping("/test/token")
      Map<String, String> token(
          @RequestParam(name = "min", required = false) Long min, HttpServletRequest request, HttpServletResponse response) {
        String token = tokens.getAccessToken(request, response, min == null ? null : Duration.ofSeconds(min));
        return Map.of("token", token);
      }
    }
  }

  /** The real time plus an offset. */
  static final class MovableClock extends Clock {
    private volatile Duration offset = Duration.ZERO;

    void set(Duration value) {
      offset = value;
    }

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

  @Autowired MovableClock clock;
  @Autowired ClientCredentialsTokenProvider clientCredentials;

  @AfterEach
  void resetClock() {
    clock.set(Duration.ZERO);
  }

  FlowDriver driver() {
    return new FlowDriver(new TestBrowser(), PortvaktStack.portvaktOrigin(), FlowDriver.originOf(PortvaktStack.MOCK_IDP));
  }

  /** Follows a flow until the application's callback and requests it: back at the application. */
  static String finish(FlowDriver driver, FlowDriver.Landing landing) {
    assertThat(landing).as("landing").isInstanceOf(FlowDriver.App.class);
    String callback = ((FlowDriver.App) landing).url();
    assertThat(callback).startsWith(APP + "/auth/callback");
    TestBrowser.Response response = driver.browser().get(callback);
    assertThat(response.status()).as("callback: " + response.body()).isEqualTo(303);
    return response.header("Location");
  }

  static JsonNode session(FlowDriver driver) {
    return FlowDriver.json(driver.browser().get(APP + "/auth/session", "Accept", "application/json"));
  }

  static String loginStart(String query) {
    return APP + "/auth/login?" + query;
  }

  /** An employee (mock Entra over OIDC, home realm by login_hint): no page on the way. */
  static void signInEmployee(FlowDriver driver) {
    FlowDriver.Landing landing = driver.follow(loginStart("returnTo=%2F&loginHint=" + EMPLOYEE));
    assertThat(finish(driver, landing)).isEqualTo("/");
  }

  @Test
  void signsAnEmployeeInOverOidcWithRolesCallsTheApiAndLogsOut() {
    FlowDriver driver = driver();
    signInEmployee(driver);
    assertThat(driver.visited).anyMatch(url -> url.startsWith(PortvaktStack.MOCK_IDP + "/entra"));

    JsonNode session = session(driver);
    assertThat(session.get("authenticated").asBoolean()).isTrue();
    JsonNode principal = session.get("principal");
    assertThat(principal.get("idpKind").asString()).isEqualTo("employee");
    assertThat(principal.get("acr").asString()).isEqualTo("urn:portvakt:acr:employee");
    assertThat(principal.get("roles").toString()).isEqualTo("[\"handlaggare\"]");
    assertThat(principal.get("name").asString()).isEqualTo("Anna Andersson");
    assertThat(principal.get("email").asString()).isEqualTo(EMPLOYEE);
    assertThat(principal.get("clientId").asString()).isEqualTo("service-c");
    assertThat(principal.has("pin")).isFalse();

    // The page shows the person (Swedish, stable test ids).
    String page = driver.browser().get(APP + "/", "Accept", "text/html").body();
    assertThat(page).contains("data-testid=\"signed-in-view\"");
    assertThat(testId(page, "user-name")).isEqualTo("Anna Andersson");
    assertThat(testId(page, "user-idp-kind")).isEqualTo("Anställd");
    assertThat(page).contains("handlaggare");

    // "Anropa API": the demo calls its own API with the session's access token.
    JsonNode api = FlowDriver.json(driver.browser().get(APP + "/app/api-call", "Accept", "application/json"));
    assertThat(api.get("status").asInt()).isEqualTo(200);
    JsonNode caller = api.get("body").get("principal");
    assertThat(caller.get("isService").asBoolean()).isFalse();
    assertThat(caller.get("sub").asString()).isEqualTo(principal.get("sub").asString());
    assertThat(caller.get("roles").toString()).isEqualTo("[\"handlaggare\"]");
    assertThat(caller.has("name")).isFalse();
    String apiPage = driver.browser().get(APP + "/call-api", "Accept", "text/html").body();
    assertThat(testId(apiPage, "api-status")).isEqualTo("HTTP 200");

    // The access token is refreshed (rotation) and stays the same person's.
    String first = token(driver, null);
    String refreshed = token(driver, 3600L);
    assertThat(refreshed).isNotEqualTo(first);
    assertThat(session(driver).get("principal").get("sub").asString()).isEqualTo(principal.get("sub").asString());

    // RP-initiated logout: CSRF token, Portvakt's confirmation, back to the application.
    TestBrowser.Response logout =
        driver.browser()
            .request("POST", APP + "/auth/logout", "", true, "X-CSRF-TOKEN", session.get("csrfToken").asString());
    assertThat(logout.status()).isEqualTo(303);
    String endSession = logout.location();
    assertThat(endSession).startsWith(PortvaktStack.ISSUER + "/session/end");
    assertThat(endSession).contains("id_token_hint=");
    assertThat(confirmPortvaktLogout(driver, endSession)).isEqualTo(APP + "/");
    assertThat(session(driver).get("authenticated").asBoolean()).isFalse();
    TestBrowser.Response protectedCall = driver.browser().get(APP + "/app/api-call", "Accept", "application/json");
    assertThat(protectedCall.status()).isEqualTo(401);
    assertThat(FlowDriver.json(protectedCall).get("error").asString()).isEqualTo("login_required");
  }

  @Test
  void signsACitizenInOverSamlAndSwitchesRepresentation() {
    FlowDriver driver = driver();
    FlowDriver.Landing landing = driver.follow(loginStart("returnTo=%2F"));
    landing = driver.chooseMethod(landing, "Mock BankID (SAML)");
    landing = driver.persona(landing, "saml-sven");
    assertThat(driver.representationDetails(landing).get("allowSelf").asBoolean()).isTrue();
    landing = driver.chooseRepresentation(landing, "Bygg AB");
    finish(driver, landing);

    JsonNode principal = session(driver).get("principal");
    assertThat(principal.get("idpKind").asString()).isEqualTo("citizen");
    assertThat(principal.get("acr").asString()).isEqualTo(LOA3);
    assertThat(principal.get("name").asString()).isEqualTo("Sven Medborgare");
    assertThat(principal.get("rep").get("type").asString()).isEqualTo("organisation");
    assertThat(principal.get("rep").get("name").asString()).isEqualTo("Bygg AB");
    String party = principal.get("rep").get("sub").asString();
    String page = driver.browser().get(APP + "/", "Accept", "text/html").body();
    assertThat(testId(page, "representation")).isEqualTo("Agerar för Bygg AB (organisation)");

    // The API sees rep without its name.
    JsonNode caller = FlowDriver.json(driver.browser().get(APP + "/app/api-call", "Accept", "application/json"))
        .get("body").get("principal");
    assertThat(caller.get("rep").toString()).isEqualTo("{\"sub\":\"" + party + "\",\"type\":\"organisation\"}");

    // "Byt företrädd": the chooser again, without a new upstream login.
    int before = driver.visited.size();
    FlowDriver.Landing chooser =
        driver.follow("GET", APP + "/auth/select-representation?returnTo=%2F", null, null, true);
    // The start must come from the application's own page.
    assertThat(chooser).isInstanceOf(FlowDriver.Other.class);
    assertThat(((FlowDriver.Other) chooser).status()).isEqualTo(403);
    TestBrowser.Response start =
        driver.browser().get(APP + "/auth/select-representation?returnTo=%2F", "Sec-Fetch-Site", "same-origin");
    assertThat(start.status()).isEqualTo(302);
    chooser = driver.follow(start.location());
    finish(driver, driver.chooseRepresentation(chooser, null));
    assertThat(driver.visited.subList(before, driver.visited.size()))
        .noneMatch(url -> url.startsWith(PortvaktStack.MOCK_IDP));
    assertThat(session(driver).get("principal").has("rep")).isFalse();
    assertThat(testId(driver.browser().get(APP + "/", "Accept", "text/html").body(), "representation"))
        .isEqualTo("Dig själv");
  }

  @Test
  void stepsUpToLoa4ThroughRequireAcr() {
    FlowDriver driver = driver();
    FlowDriver.Landing landing = driver.follow(loginStart("returnTo=%2F&loginHint=maja-loa4"));
    landing = driver.chooseMethod(landing, "Mock BankID (OIDC)");
    if (landing instanceof FlowDriver.IdpPage) landing = driver.persona(landing, "maja-loa4");
    finish(driver, landing);
    JsonNode before = session(driver).get("principal");
    assertThat(before.get("acr").asString()).isEqualTo(LOA3);

    TestBrowser.Response refused = driver.browser().get(APP + "/app/sensitive", "Accept", "application/json");
    assertThat(refused.status()).isEqualTo(401);
    JsonNode body = FlowDriver.json(refused);
    assertThat(body.get("error").asString()).isEqualTo("step_up_required");
    assertThat(body.get("acr").asString()).isEqualTo(LOA4);
    String stepUpUrl = APP + body.get("stepUpUrl").asString();

    // Another site cannot start it.
    TestBrowser.Response crossSite = driver.browser().get(stepUpUrl, "Sec-Fetch-Site", "cross-site", "Accept", "text/html");
    assertThat(crossSite.status()).isEqualTo(403);
    assertThat(crossSite.body()).contains("cross_site_request");

    int visited = driver.visited.size();
    TestBrowser.Response start = driver.browser().get(stepUpUrl, "Sec-Fetch-Site", "same-origin");
    assertThat(start.status()).isEqualTo(302);
    assertThat(start.location()).contains("acr_values=").contains("code_challenge_method=S256");
    FlowDriver.Landing stepUp = driver.follow(start.location());
    if (stepUp instanceof FlowDriver.IdpPage) stepUp = driver.persona(stepUp, "maja-loa4");
    assertThat(finish(driver, stepUp)).isEqualTo("/");
    // Upstream again (the mock signs the person named by login_hint in without its page).
    assertThat(driver.visited.subList(visited, driver.visited.size()))
        .anyMatch(url -> url.startsWith(PortvaktStack.MOCK_IDP + "/bankid"));

    TestBrowser.Response sensitive = driver.browser().get(APP + "/app/sensitive", "Accept", "application/json");
    assertThat(sensitive.status()).isEqualTo(200);
    JsonNode after = FlowDriver.json(sensitive).get("principal");
    assertThat(after.get("sub").asString()).isEqualTo(before.get("sub").asString());
    assertThat(after.get("acr").asString()).isEqualTo(LOA4);
    JsonNode caller = FlowDriver.json(driver.browser().get(APP + "/app/api-call", "Accept", "application/json"))
        .get("body").get("principal");
    assertThat(caller.get("acr").asString()).isEqualTo(LOA4);
  }

  @Test
  void theResourceServerRefusesTokensForAnotherAudienceAndFromAnotherTenant() {
    TestBrowser browser = new TestBrowser();
    // No token, a malformed header, garbage.
    TestBrowser.Response missing = browser.get(APP + "/api/whoami", "Accept", "application/json");
    assertThat(missing.status()).isEqualTo(401);
    assertThat(missing.header("WWW-Authenticate")).isEqualTo("Bearer realm=\"portvakt\"");
    TestBrowser.Response basic = browser.get(APP + "/api/whoami", "Authorization", "Basic dXNlcjpwYXNz");
    assertThat(basic.status()).isEqualTo(400);
    assertThat(basic.header("WWW-Authenticate")).contains("error=\"invalid_request\"");
    TestBrowser.Response garbage = browser.get(APP + "/api/whoami", "Authorization", "Bearer abc.def.ghi");
    assertThat(garbage.status()).isEqualTo(401);
    assertThat(garbage.header("WWW-Authenticate")).contains("error=\"invalid_token\"");

    // A token of the same tenant for service-a (aud) is refused by service-c's API.
    String forServiceA = clientCredentials.forAudience("service-a").getToken();
    TestBrowser.Response wrongAudience = browser.get(APP + "/api/whoami", "Authorization", "Bearer " + forServiceA);
    assertThat(wrongAudience.status()).isEqualTo(401);
    assertThat(wrongAudience.header("WWW-Authenticate")).contains("error=\"invalid_token\"");

    // A token for service-c from another tenant: signed with the same keys, but another iss.
    PortvaktClient otherTenant =
        PortvaktClient.create(
            PortvaktConfig.builder()
                .issuer(PortvaktStack.ISOLATION_ISSUER)
                .clientId("service-c")
                .clientAuth(ClientAuth.clientSecretBasic(PortvaktStack.CLIENT_SECRET))
                .allowInsecureRequests(true)
                .build());
    String fromOtherTenant = otherTenant.clientCredentials().getToken("service-c");
    TestBrowser.Response wrongIssuer = browser.get(APP + "/api/whoami", "Authorization", "Bearer " + fromOtherTenant);
    assertThat(wrongIssuer.status()).isEqualTo(401);
    assertThat(FlowDriver.json(wrongIssuer).get("error").asString()).isEqualTo("invalid_token");
  }

  @Test
  void callsTheApiWithAClientCredentialsToken() {
    String token = clientCredentials.forAudience("service-c").getToken();
    assertThat(clientCredentials.forAudience("service-c").getToken()).isEqualTo(token);
    TestBrowser.Response response =
        new TestBrowser().get(APP + "/api/whoami", "Authorization", "Bearer " + token, "Accept", "application/json");
    assertThat(response.status()).isEqualTo(200);
    JsonNode principal = FlowDriver.json(response).get("principal");
    assertThat(principal.get("isService").asBoolean()).isTrue();
    assertThat(principal.get("clientId").asString()).isEqualTo("service-c");
  }

  @Test
  void redirectsBrowsersToTheLoginAndAnswersXhrWith401() {
    TestBrowser browser = new TestBrowser();
    assertThat(browser.get(APP + "/", "Accept", "text/html").body()).contains("data-testid=\"signed-out-view\"");
    TestBrowser.Response navigation = browser.get(APP + "/call-api", "Accept", "text/html", "Sec-Fetch-Mode", "navigate");
    assertThat(navigation.status()).isEqualTo(302);
    assertThat(navigation.header("Location")).endsWith("/auth/login?returnTo=%2Fcall-api");
    TestBrowser.Response xhr = browser.get(APP + "/app/api-call", "Accept", "application/json");
    assertThat(xhr.status()).isEqualTo(401);
    assertThat(FlowDriver.json(xhr).get("loginUrl").asString()).isEqualTo("/auth/login?returnTo=%2F");
    assertThat(FlowDriver.json(browser.get(APP + "/auth/session", "Accept", "application/json")).toString())
        .isEqualTo("{\"authenticated\":false}");
  }

  @Test
  void endsTheSessionAtSessionExp() {
    FlowDriver driver = driver();
    signInEmployee(driver);
    JsonNode session = session(driver);
    Instant endsAt = Instant.parse(session.get("sessionEndsAt").asString());
    // Mock Entra's method has maxAgeSeconds 8 h: session_exp, below the application's 12 h.
    assertThat(Duration.between(Instant.now(), endsAt)).isBetween(Duration.ofHours(8).minusMinutes(2), Duration.ofHours(8));

    clock.set(Duration.between(Instant.now(), endsAt).minusSeconds(30));
    assertThat(session(driver).get("authenticated").asBoolean()).isTrue();
    clock.set(Duration.between(Instant.now(), endsAt).plusSeconds(1));
    assertThat(session(driver).get("authenticated").asBoolean()).isFalse();
    TestBrowser.Response call = driver.browser().get(APP + "/app/api-call", "Accept", "application/json");
    assertThat(call.status()).isEqualTo(401);
    assertThat(FlowDriver.json(call).get("error").asString()).isEqualTo("login_required");
  }

  @Test
  void endsTheSessionWhenPortvaktRefusesTheRefresh() {
    FlowDriver driver = driver();
    signInEmployee(driver);
    assertThat(token(driver, null)).isNotEmpty();
    // The broker session ends at Portvakt (another tab signs out there): its refresh tokens end.
    TestBrowser.Response end = driver.browser().get(PortvaktStack.ISSUER + "/session/end", "Accept", "text/html");
    assertThat(confirmPortvaktLogoutPage(driver, end, PortvaktStack.ISSUER + "/session/end")).isNotNull();
    TestBrowser.Response refresh = driver.browser().get(APP + "/test/token?min=3600", "Accept", "application/json");
    assertThat(refresh.status()).isEqualTo(401);
    assertThat(FlowDriver.json(refresh).get("error").asString()).isEqualTo("login_required");
    assertThat(session(driver).get("authenticated").asBoolean()).isFalse();
  }

  @Test
  void signsInRefreshesAndCallsTheApiWithPrivateKeyJwt() {
    // A second instance of the demo as service-d, authenticating at Portvakt with a signed client
    // assertion (Spring's Nimbus converter) at the code exchange and at every refresh.
    String app = "http://localhost:3301";
    try (org.springframework.context.ConfigurableApplicationContext serviceD =
        new org.springframework.boot.builder.SpringApplicationBuilder(
                DemoApplication.class, TestSupport.class, TestSupport.TokenController.class)
            .run(
                "--server.port=3301",
                "--server.servlet.session.cookie.name=demo_d_session",
                "--portvakt.issuer=" + PortvaktStack.ISSUER,
                "--portvakt.allow-insecure-requests=true",
                "--portvakt.client-id=service-d",
                "--portvakt.client-secret=",
                "--portvakt.client-auth-method=private-key-jwt",
                "--portvakt.private-jwk=" + PortvaktStack.PRIVATE_JWK,
                "--portvakt.login.redirect-uri=" + app + "/auth/callback",
                "--portvakt.login.post-logout-redirect-uri=" + app + "/",
                "--demo.api-url=http://127.0.0.1:3301",
                "--demo.app-name=Tjänst D")) {
      FlowDriver driver = driver();
      FlowDriver.Landing landing = driver.follow(app + "/auth/login?returnTo=%2F&loginHint=" + EMPLOYEE);
      assertThat(landing).isInstanceOf(FlowDriver.App.class);
      TestBrowser.Response callback = driver.browser().get(((FlowDriver.App) landing).url());
      assertThat(callback.status()).as(callback.body()).isEqualTo(303);
      JsonNode session = FlowDriver.json(driver.browser().get(app + "/auth/session", "Accept", "application/json"));
      assertThat(session.get("principal").get("clientId").asString()).isEqualTo("service-d");
      TestBrowser.Response first = driver.browser().get(app + "/test/token", "Accept", "application/json");
      TestBrowser.Response refreshed = driver.browser().get(app + "/test/token?min=3600", "Accept", "application/json");
      assertThat(refreshed.status()).as(refreshed.body()).isEqualTo(200);
      assertThat(FlowDriver.json(refreshed).get("token").asString()).isNotEqualTo(FlowDriver.json(first).get("token").asString());
      JsonNode api = FlowDriver.json(driver.browser().get(app + "/app/api-call", "Accept", "application/json"));
      assertThat(api.get("status").asInt()).isEqualTo(200);
      assertThat(api.get("body").get("principal").get("clientId").asString()).isEqualTo("service-d");
    }
  }

  // Helpers --------------------------------------------------------------------------------------

  static String token(FlowDriver driver, Long min) {
    TestBrowser.Response response =
        driver.browser().get(APP + "/test/token" + (min == null ? "" : "?min=" + min), "Accept", "application/json");
    assertThat(response.status()).as(response.body()).isEqualTo(200);
    return FlowDriver.json(response).get("token").asString();
  }

  /** Follows Portvakt's end-session URL and confirms the logout form; returns where it ended. */
  static String confirmPortvaktLogout(FlowDriver driver, String endSession) {
    return confirmPortvaktLogoutPage(driver, driver.browser().get(endSession, "Accept", "text/html"), endSession);
  }

  static String confirmPortvaktLogoutPage(FlowDriver driver, TestBrowser.Response page, String url) {
    assertThat(page.status()).as(page.body()).isEqualTo(200);
    Matcher action = Pattern.compile("<form id=\"op\\.logoutForm\" method=\"post\" action=\"([^\"]+)\">").matcher(page.body());
    Matcher xsrf = Pattern.compile("name=\"xsrf\" value=\"([^\"]+)\"").matcher(page.body());
    assertThat(action.find()).as("logout form").isTrue();
    assertThat(xsrf.find()).as("xsrf").isTrue();
    TestBrowser.Response confirmed =
        driver.browser()
            .postForm(
                java.net.URI.create(url).resolve(action.group(1).replace("&amp;", "&")).toString(),
                Map.of("xsrf", xsrf.group(1), "logout", "yes"),
                true);
    assertThat(confirmed.status()).isBetween(300, 399);
    return confirmed.location();
  }

  /** The text of the element with {@code data-testid}. */
  static String testId(String page, String id) {
    Matcher matcher =
        Pattern.compile("data-testid=\"" + Pattern.quote(id) + "\"[^>]*>(.*?)</", Pattern.DOTALL).matcher(page);
    assertThat(matcher.find()).as("test id " + id).isTrue();
    return matcher.group(1).replaceAll("<[^>]+>", "").trim();
  }
}
