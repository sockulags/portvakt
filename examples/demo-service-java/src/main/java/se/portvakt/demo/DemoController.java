package se.portvakt.demo;

import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestClient;
import se.portvakt.sdk.AcrRanking;
import se.portvakt.sdk.PortvaktPrincipal;
import se.portvakt.sdk.Representation;
import se.portvakt.spring.PortvaktSecurity;
import se.portvakt.spring.RequireAcr;
import se.portvakt.spring.login.PortvaktAccessTokens;
import se.portvakt.spring.login.PortvaktLoginSettings;
import se.portvakt.spring.login.PortvaktSessionInfoFilter;
import se.portvakt.spring.login.PortvaktSessionState;

/** The demo's pages (Swedish) and the "Anropa API" call through the session's access token. */
@Controller
class DemoController {
  private static final ZoneId STOCKHOLM = ZoneId.of("Europe/Stockholm");
  private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(STOCKHOLM);
  private static final Map<String, String> LOA_NAMES =
      Map.of(
          AcrRanking.LOA2, "Tillitsnivå 2",
          AcrRanking.LOA3, "Tillitsnivå 3",
          AcrRanking.LOA4, "Tillitsnivå 4");

  private final DemoProperties properties;
  private final PortvaktAccessTokens tokens;
  private final PortvaktLoginSettings login;
  private final JsonMapper json;
  private final RestClient api;

  DemoController(
      DemoProperties properties, PortvaktAccessTokens tokens, PortvaktLoginSettings login, JsonMapper json) {
    this.properties = properties;
    this.tokens = tokens;
    this.login = login;
    this.json = json.rebuild().enable(SerializationFeature.INDENT_OUTPUT).build();
    JdkClientHttpRequestFactory factory =
        new JdkClientHttpRequestFactory(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    factory.setReadTimeout(Duration.ofSeconds(10));
    this.api = RestClient.builder().requestFactory(factory).baseUrl(properties.apiUrl()).build();
  }

  @GetMapping("/healthz")
  @ResponseBody
  Map<String, String> health() {
    return Map.of("status", "ok", "app", properties.appName());
  }

  @GetMapping("/")
  String index(HttpServletRequest request, Model model) {
    page(request, model);
    return "index";
  }

  /** "Anropa API" without JavaScript: the page again, with the API's answer. */
  @GetMapping("/call-api")
  String callApiPage(HttpServletRequest request, HttpServletResponse response, Model model) {
    page(request, model);
    try {
      ApiResult result = callApi(request, response);
      model.addAttribute("apiStatus", result.status());
      model.addAttribute("apiResult", json.writeValueAsString(result.body()));
    } catch (se.portvakt.sdk.LoginRequiredException ended) {
      throw ended;
    } catch (Exception failed) {
      model.addAttribute("apiFailed", true);
    }
    return "index";
  }

  /** "Anropa API" for scripts: {@code {status, body}}. */
  @GetMapping(path = "/app/api-call", produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  ApiResult callApiJson(HttpServletRequest request, HttpServletResponse response) {
    return callApi(request, response);
  }

  /** A sensitive action: requires loa4 (a step-up when the session's acr is lower). */
  @RequireAcr(AcrRanking.LOA4)
  @GetMapping(path = "/app/sensitive", produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  Map<String, Object> sensitive() {
    return Map.of("principal", PortvaktSessionInfoFilter.describe(PortvaktSecurity.currentPrincipal().orElseThrow()));
  }

  record ApiResult(int status, Object body) {}

  private ApiResult callApi(HttpServletRequest request, HttpServletResponse response) {
    String token = tokens.getAccessToken(request, response);
    return api.get()
        .uri("/api/whoami")
        .header("Authorization", "Bearer " + token)
        .accept(MediaType.APPLICATION_JSON)
        .exchange(
            (apiRequest, apiResponse) -> {
              Object body;
              try {
                body = json.readValue(apiResponse.getBody(), Object.class);
              } catch (Exception unreadable) {
                body = null;
              }
              return new ApiResult(apiResponse.getStatusCode().value(), body);
            });
  }

  private void page(HttpServletRequest request, Model model) {
    model.addAttribute("appName", properties.appName());
    model.addAttribute("loginUrl", login.loginUrl("/"));
    model.addAttribute("logoutUrl", login.logoutPath());
    PortvaktPrincipal principal = PortvaktSecurity.currentPrincipal().orElse(null);
    if (principal == null || principal.isService()) {
      model.addAttribute("signedIn", false);
      return;
    }
    model.addAttribute("signedIn", true);
    model.addAttribute("userName", displayName(principal));
    model.addAttribute("roles", principal.roles());
    model.addAttribute("acr", principal.acr());
    model.addAttribute("acrName", LOA_NAMES.getOrDefault(principal.acr(), principal.acr()));
    model.addAttribute(
        "idpKind", principal.idpKind() == se.portvakt.sdk.IdpKind.EMPLOYEE ? "Anställd" : "Medborgare");
    model.addAttribute("authTime", TIME.format(principal.authTime()));
    PortvaktSessionState state = PortvaktSessionState.of(request.getSession(false));
    model.addAttribute("sessionExpires", TIME.format(state == null ? Instant.now() : state.expiresAt(login.idleTimeout())));
    model.addAttribute("representation", representationText(principal));
    model.addAttribute("stepUpUrl", login.stepUpUrl(properties.stepUpAcr(), "/"));
    model.addAttribute("selectRepresentationUrl", login.selectRepresentationUrl("/"));
  }

  private static String displayName(PortvaktPrincipal principal) {
    if (principal.protectedIdentity()) return "Skyddad identitet";
    return principal.name() != null ? principal.name() : "Okänt namn";
  }

  private static String representationText(PortvaktPrincipal principal) {
    Representation rep = principal.rep();
    if (rep == null) return "Dig själv";
    String kind = rep.type() == Representation.Type.ORGANISATION ? "organisation" : "person";
    return "Agerar för " + (rep.name() != null ? rep.name() : "Skyddad identitet") + " (" + kind + ")";
  }
}
