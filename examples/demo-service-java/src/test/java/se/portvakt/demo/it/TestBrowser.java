package se.portvakt.demo.it;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringJoiner;

/**
 * A browser for integration tests without JavaScript: Java's HttpClient without automatic
 * redirects, and a cookie jar per host and port (host-only cookies, path-scoped, Max-Age and
 * Expires honoured), as the TypeScript suite's TestBrowser.
 */
public final class TestBrowser {
  /** A response: status, headers and body. */
  public record Response(int status, Map<String, List<String>> headers, String body, URI uri) {
    public String header(String name) {
      for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
        if (entry.getKey().equalsIgnoreCase(name) && !entry.getValue().isEmpty()) return entry.getValue().get(0);
      }
      return null;
    }

    /** The absolute redirect target. */
    public String location() {
      String location = header("Location");
      if (location == null) throw new AssertionError("no Location header (status " + status + ")");
      return uri.resolve(location).toString();
    }
  }

  private record Cookie(String value, String path, Instant expires) {}

  private final HttpClient client =
      HttpClient.newBuilder()
          .followRedirects(HttpClient.Redirect.NEVER)
          .connectTimeout(Duration.ofSeconds(10))
          .build();
  private final Map<String, Map<String, Cookie>> jar = new LinkedHashMap<>();

  public Response get(String url, String... headers) {
    return request("GET", url, null, true, headers);
  }

  public Response postForm(String url, Map<String, String> form, boolean sendCookies, String... headers) {
    String[] all = new String[headers.length + 2];
    System.arraycopy(headers, 0, all, 0, headers.length);
    all[headers.length] = "Content-Type";
    all[headers.length + 1] = "application/x-www-form-urlencoded";
    return request("POST", url, formEncode(form), sendCookies, all);
  }

  public Response postJson(String url, String json, String... headers) {
    String[] all = new String[headers.length + 4];
    System.arraycopy(headers, 0, all, 0, headers.length);
    all[headers.length] = "Content-Type";
    all[headers.length + 1] = "application/json";
    all[headers.length + 2] = "Accept";
    all[headers.length + 3] = "application/json";
    return request("POST", url, json, true, all);
  }

  /** A request; {@code headers} are name/value pairs. */
  public Response request(String method, String url, String body, boolean sendCookies, String... headers) {
    URI uri = URI.create(url);
    HttpRequest.Builder builder =
        HttpRequest.newBuilder(uri)
            .timeout(Duration.ofSeconds(30))
            .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
    for (int index = 0; index < headers.length; index += 2) builder.header(headers[index], headers[index + 1]);
    if (sendCookies) {
      String cookies = cookieHeader(uri);
      if (!cookies.isEmpty()) builder.header("Cookie", cookies);
    }
    HttpResponse<String> response;
    try {
      response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    } catch (IOException exception) {
      throw new AssertionError(method + " " + url + " failed: " + exception, exception);
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw new AssertionError("interrupted", exception);
    }
    for (String setCookie : response.headers().allValues("set-cookie")) store(uri, setCookie);
    return new Response(response.statusCode(), response.headers().map(), response.body(), uri);
  }

  /** The value of a cookie for an origin, or {@code null}. */
  public String cookie(String origin, String name) {
    Map<String, Cookie> cookies = jar.get(key(URI.create(origin)));
    Cookie cookie = cookies == null ? null : cookies.get(name);
    return cookie == null ? null : cookie.value();
  }

  private String cookieHeader(URI uri) {
    Map<String, Cookie> cookies = jar.get(key(uri));
    if (cookies == null) return "";
    String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
    StringJoiner joiner = new StringJoiner("; ");
    Instant now = Instant.now();
    List<String> expired = new ArrayList<>();
    cookies.forEach(
        (name, cookie) -> {
          if (cookie.expires() != null && !cookie.expires().isAfter(now)) {
            expired.add(name);
          } else if (pathMatches(path, cookie.path())) {
            joiner.add(name + "=" + cookie.value());
          }
        });
    expired.forEach(cookies::remove);
    return joiner.toString();
  }

  private static boolean pathMatches(String requestPath, String cookiePath) {
    if (requestPath.equals(cookiePath)) return true;
    if (!requestPath.startsWith(cookiePath)) return false;
    return cookiePath.endsWith("/") || requestPath.charAt(cookiePath.length()) == '/';
  }

  private void store(URI uri, String header) {
    String[] parts = header.split(";");
    int equals = parts[0].indexOf('=');
    if (equals <= 0) return;
    String name = parts[0].substring(0, equals).trim();
    String value = parts[0].substring(equals + 1).trim();
    String path = "/";
    Instant expires = null;
    for (int index = 1; index < parts.length; index++) {
      String attribute = parts[index].trim();
      int separator = attribute.indexOf('=');
      String attributeName = (separator < 0 ? attribute : attribute.substring(0, separator)).toLowerCase(Locale.ROOT);
      String attributeValue = separator < 0 ? "" : attribute.substring(separator + 1).trim();
      switch (attributeName) {
        case "path" -> path = attributeValue.isEmpty() ? "/" : attributeValue;
        case "max-age" -> {
          try {
            expires = Instant.now().plusSeconds(Long.parseLong(attributeValue));
          } catch (NumberFormatException ignored) {
            // Not a number: ignored, as browsers do.
          }
        }
        case "expires" -> {
          if (expires == null) {
            try {
              expires =
                  java.time.ZonedDateTime.parse(attributeValue, java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME)
                      .toInstant();
            } catch (RuntimeException ignored) {
              // Unparseable: a session cookie.
            }
          }
        }
        default -> {
          // Domain (host-only here), Secure, HttpOnly, SameSite: not needed by the tests.
        }
      }
    }
    Map<String, Cookie> cookies = jar.computeIfAbsent(key(uri), ignored -> new LinkedHashMap<>());
    if (expires != null && !expires.isAfter(Instant.now())) {
      cookies.remove(name);
    } else {
      cookies.put(name, new Cookie(value, path, expires));
    }
  }

  private static String key(URI uri) {
    int port = uri.getPort() >= 0 ? uri.getPort() : (uri.getScheme().equals("https") ? 443 : 80);
    return uri.getHost().toLowerCase(Locale.ROOT) + ":" + port;
  }

  static String formEncode(Map<String, String> form) {
    StringJoiner joiner = new StringJoiner("&");
    form.forEach(
        (key, value) ->
            joiner.add(
                java.net.URLEncoder.encode(key, java.nio.charset.StandardCharsets.UTF_8)
                    + "="
                    + java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8)));
    return joiner.toString();
  }
}
