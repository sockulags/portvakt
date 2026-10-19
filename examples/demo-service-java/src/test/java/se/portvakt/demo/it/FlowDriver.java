package se.portvakt.demo.it;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Drives the browser side of a login against the real Portvakt and mock IdP, without
 * JavaScript, as the TypeScript suite's FlowDriver: follows redirects across the application,
 * Portvakt and the mock IdP, and does what the login UI, the persona page and the representation
 * chooser would. Auto-submitting SAML forms are posted like a browser would; a post to Portvakt
 * (the ACS) carries no cookies, as a cross-site POST carries no SameSite=Lax cookie.
 */
public final class FlowDriver {
  private static final JsonMapper JSON = JsonMapper.builder().build();
  private static final Pattern BOOTSTRAP =
      Pattern.compile("<script type=\"application/json\" id=\"pv-bootstrap\">([^<]*)</script>");
  private static final Pattern HIDDEN = Pattern.compile("<input type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\"\\s*/?>");
  private static final Pattern FORM_ACTION = Pattern.compile("<form method=\"post\" action=\"([^\"]+)\"");
  private static final Pattern PERSONA_ACTION = Pattern.compile("<form method=\"post\" action=\"([^\"]+)/login\">");

  /** Where a followed chain of redirects ended. */
  public sealed interface Landing {}

  /** The application (outside Portvakt and the mock IdP). */
  public record App(String url) implements Landing {}

  /** A login UI page served by Portvakt. */
  public record LoginUi(String url, int status, JsonNode bootstrap) implements Landing {}

  /** The mock IdP's persona page. */
  public record IdpPage(String url, String html) implements Landing {}

  /** Anything else. */
  public record Other(String url, int status, String body) implements Landing {}

  private final TestBrowser browser;
  private final String portvaktOrigin;
  private final String idpOrigin;
  /** Every URL requested, in order. */
  public final List<String> visited = new ArrayList<>();

  public FlowDriver(TestBrowser browser, String portvaktOrigin, String idpOrigin) {
    this.browser = browser;
    this.portvaktOrigin = portvaktOrigin;
    this.idpOrigin = idpOrigin;
  }

  public TestBrowser browser() {
    return browser;
  }

  /** Requests {@code url} (GET) and follows redirects until a page or the application. */
  public Landing follow(String url) {
    return follow("GET", url, null, null, true);
  }

  public Landing follow(String method, String url, String body, String contentType, boolean sendCookies) {
    String current = url;
    visited.add(current);
    TestBrowser.Response response =
        contentType == null
            ? browser.request(method, current, body, sendCookies)
            : browser.request(method, current, body, sendCookies, "Content-Type", contentType);
    for (int hops = 0; response.status() >= 300 && response.status() < 400; hops++) {
      if (hops >= 25) throw new AssertionError("too many redirects");
      current = response.location();
      String origin = originOf(current);
      if (!origin.equals(portvaktOrigin) && !origin.equals(idpOrigin)) return new App(current);
      visited.add(current);
      response = browser.get(current);
    }
    String page = response.body();
    String origin = originOf(current);
    if (page.contains("data-pv-autosubmit") || page.contains("data-testid=\"saml-post-form\"")) {
      Matcher action = FORM_ACTION.matcher(page);
      if (!action.find()) throw new AssertionError("auto-submit form without action");
      String target = URI.create(current).resolve(decode(action.group(1))).toString();
      return follow("POST", target, TestBrowser.formEncode(hiddenFields(page)),
          "application/x-www-form-urlencoded", !originOf(target).equals(portvaktOrigin));
    }
    if (page.contains("<title>Submitting Callback</title>")) {
      // oidc-provider's auto-submitting form (a session switch to another person).
      Matcher action = Pattern.compile("<form method=\"post\" action=\"([^\"]+)\">").matcher(page);
      if (!action.find()) throw new AssertionError("auto-submit form without action");
      String target = URI.create(current).resolve(decode(action.group(1))).toString();
      return follow("POST", target, TestBrowser.formEncode(hiddenFields(page)), "application/x-www-form-urlencoded", true);
    }
    if (origin.equals(portvaktOrigin)) {
      Matcher bootstrap = BOOTSTRAP.matcher(page);
      if (bootstrap.find()) {
        try {
          return new LoginUi(current, response.status(), JSON.readTree(decode(bootstrap.group(1))));
        } catch (Exception exception) {
          throw new AssertionError("unreadable bootstrap", exception);
        }
      }
    }
    if (origin.equals(idpOrigin) && page.contains("name=\"persona\"")) return new IdpPage(current, page);
    return new Other(current, response.status(), page);
  }

  /** Chooses a login method of the login UI by its display name and follows the flow. */
  public Landing chooseMethod(Landing landing, String displayName) {
    String interaction = interactionUrl(landing, "login");
    JsonNode details = json(browser.get(interaction + "/details", "Accept", "application/json"));
    String methodId = null;
    for (JsonNode method : details.get("methods")) {
      if (method.get("displayName").asString().equals(displayName)) methodId = method.get("id").asString();
    }
    if (methodId == null) throw new AssertionError("no login method " + displayName + " in " + details.get("methods"));
    TestBrowser.Response chosen =
        browser.postJson(
            interaction + "/login",
            "{\"loginMethodId\":\"" + methodId + "\"}",
            "X-CSRF-Token",
            details.get("csrfToken").asString());
    JsonNode body = json(chosen);
    if (chosen.status() != 200 || !body.has("redirectTo")) {
      throw new AssertionError("login choice refused: " + chosen.status() + " " + body);
    }
    return follow(URI.create(interaction).resolve(body.get("redirectTo").asString()).toString());
  }

  /** Submits a persona on the mock IdP's page and follows the flow. */
  public Landing persona(Landing landing, String personaId) {
    if (!(landing instanceof IdpPage page)) throw new AssertionError("expected the IdP page, got " + landing);
    Matcher action = PERSONA_ACTION.matcher(page.html());
    if (!action.find()) throw new AssertionError("persona page without a form");
    String target = URI.create(page.url()).resolve(decode(action.group(1)) + "/login").toString();
    return follow("POST", target, TestBrowser.formEncode(Map.of("persona", personaId)), "application/x-www-form-urlencoded", true);
  }

  /** The representation chooser's details (parties, CSRF token). */
  public JsonNode representationDetails(Landing landing) {
    return json(browser.get(interactionUrl(landing, "representation") + "/representation", "Accept", "application/json"));
  }

  /** Chooses whom to act for: {@code null} for oneself, or a party's display name. */
  public Landing chooseRepresentation(Landing landing, String partyName) {
    String interaction = interactionUrl(landing, "representation");
    JsonNode details = representationDetails(landing);
    String choice;
    if (partyName == null) {
      choice = "{\"self\":true}";
    } else {
      String partyId = null;
      for (JsonNode party : details.get("parties")) {
        if (party.get("name").asString().equals(partyName)) partyId = party.get("id").asString();
      }
      if (partyId == null) throw new AssertionError("no party " + partyName);
      choice = "{\"partyId\":\"" + partyId + "\"}";
    }
    TestBrowser.Response chosen =
        browser.postJson(interaction + "/representation", choice, "X-CSRF-Token", details.get("csrfToken").asString());
    JsonNode body = json(chosen);
    if (chosen.status() != 200 || !body.has("redirectTo")) {
      throw new AssertionError("representation choice refused: " + chosen.status() + " " + body);
    }
    return follow(URI.create(interaction).resolve(body.get("redirectTo").asString()).toString());
  }

  private String interactionUrl(Landing landing, String view) {
    if (!(landing instanceof LoginUi ui) || !view.equals(ui.bootstrap().path("view").asString())) {
      throw new AssertionError("expected the " + view + " view, got " + landing);
    }
    return portvaktOrigin + "/t/" + ui.bootstrap().get("tenant").asString() + "/interaction/" + ui.bootstrap().get("uid").asString();
  }

  public static JsonNode json(TestBrowser.Response response) {
    try {
      return JSON.readTree(response.body());
    } catch (Exception exception) {
      throw new AssertionError("not JSON (" + response.status() + "): " + response.body(), exception);
    }
  }

  private static Map<String, String> hiddenFields(String page) {
    Map<String, String> fields = new LinkedHashMap<>();
    Matcher matcher = HIDDEN.matcher(page);
    while (matcher.find()) fields.put(matcher.group(1), decode(matcher.group(2)));
    return fields;
  }

  public static String originOf(String url) {
    URI uri = URI.create(url);
    return uri.getScheme() + "://" + uri.getHost() + (uri.getPort() < 0 ? "" : ":" + uri.getPort());
  }

  private static String decode(String value) {
    return value
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&#x2F;", "/")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
  }
}
