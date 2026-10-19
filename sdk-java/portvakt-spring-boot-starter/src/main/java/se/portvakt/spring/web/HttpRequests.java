package se.portvakt.spring.web;

import jakarta.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Request helpers shared by the login and resource server parts (the TypeScript SDK's http.ts). */
public final class HttpRequests {
  private static final int MAX_RETURN_TO = 2048;

  private HttpRequests() {}

  /**
   * Whether the request is a top-level browser navigation (it can be redirected to Portvakt) as
   * opposed to an XHR/fetch call (it gets a JSON error). {@code Sec-Fetch-Mode} decides when the
   * browser sends it; otherwise a GET that accepts HTML and is not marked as XHR.
   */
  public static boolean isBrowserNavigation(HttpServletRequest request) {
    String mode = request.getHeader("Sec-Fetch-Mode");
    if (mode != null && !mode.isEmpty()) return mode.equals("navigate");
    String method = request.getMethod();
    if (!method.equals("GET") && !method.equals("HEAD")) return false;
    if (request.getHeader("X-Requested-With") != null) return false;
    String accept = request.getHeader("Accept");
    return accept != null && accept.contains("text/html");
  }

  /** Whether the caller asked for JSON (fetch from a script) rather than an HTML page. */
  public static boolean wantsJson(HttpServletRequest request) {
    if ("navigate".equals(request.getHeader("Sec-Fetch-Mode"))) return false;
    String accept = request.getHeader("Accept");
    return accept != null && accept.contains("application/json") && !accept.contains("text/html");
  }

  /** The path of the request below the context path. */
  public static String pathOf(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String context = request.getContextPath();
    return context != null && !context.isEmpty() && uri.startsWith(context) ? uri.substring(context.length()) : uri;
  }

  /**
   * Where to come back to after a login or step-up: the current URL of a browser navigation
   * (GET); for XHR the default (an API URL is no page to return to).
   */
  public static String returnToOf(HttpServletRequest request, String defaultReturnTo) {
    if (request.getMethod().equals("GET") && isBrowserNavigation(request)) {
      String query = request.getQueryString();
      String own = safeReturnTo(pathOf(request) + (query == null ? "" : "?" + query));
      if (own != null) return own;
    }
    return defaultReturnTo;
  }

  /**
   * A same-origin relative path to return to after a login, or {@code null}. Accepted: a path
   * that starts with a single {@code /}, without backslashes, control characters, spaces or a
   * scheme-relative ({@code //host}) start, also after percent-decoding and after resolving dot
   * segments (including {@code %2e}, which browsers read as a dot). Everything else (absolute
   * URLs, {@code //evil}, {@code /\evil}, {@code javascript:}) is refused. The result has its dot
   * segments resolved.
   */
  public static String safeReturnTo(String value) {
    if (value == null || value.isEmpty() || value.length() > MAX_RETURN_TO) return null;
    if (!value.startsWith("/") || value.startsWith("//") || value.contains("\\")) return null;
    if (hasControlCharacters(value, true)) return null;
    String decoded = percentDecode(value);
    if (decoded == null || decoded.startsWith("//") || decoded.contains("\\")) return null;
    int end = value.length();
    for (char delimiter : new char[] {'?', '#'}) {
      int index = value.indexOf(delimiter);
      if (index >= 0 && index < end) end = index;
    }
    String rest = value.substring(end);
    String path = removeDotSegments(value.substring(0, end).replaceAll("(?i)%2e", "."));
    if (!path.startsWith("/") || path.startsWith("//")) return null;
    String decodedPath = percentDecode(path);
    if (decodedPath == null || decodedPath.startsWith("//") || decodedPath.contains("\\")) return null;
    String result = path + rest;
    try {
      URI uri = new URI(result);
      if (uri.getRawAuthority() != null || uri.getScheme() != null) return null;
    } catch (URISyntaxException invalid) {
      return null;
    }
    return result;
  }

  /** RFC 3986 section 5.2.4. */
  static String removeDotSegments(String path) {
    String input = path;
    StringBuilder output = new StringBuilder();
    while (!input.isEmpty()) {
      if (input.startsWith("../")) {
        input = input.substring(3);
      } else if (input.startsWith("./")) {
        input = input.substring(2);
      } else if (input.startsWith("/./")) {
        input = "/" + input.substring(3);
      } else if (input.equals("/.")) {
        input = "/";
      } else if (input.startsWith("/../")) {
        input = "/" + input.substring(4);
        removeLastSegment(output);
      } else if (input.equals("/..")) {
        input = "/";
        removeLastSegment(output);
      } else if (input.equals(".") || input.equals("..")) {
        input = "";
      } else {
        int next = input.indexOf('/', input.startsWith("/") ? 1 : 0);
        if (next < 0) next = input.length();
        output.append(input, 0, next);
        input = input.substring(next);
      }
    }
    return output.toString();
  }

  private static void removeLastSegment(StringBuilder output) {
    int last = output.lastIndexOf("/");
    output.setLength(Math.max(last, 0));
  }

  /** Whether a string has C0 control characters or DEL (and, with {@code space}, a space). */
  public static boolean hasControlCharacters(String value, boolean space) {
    for (int index = 0; index < value.length(); index++) {
      char code = value.charAt(index);
      if (code < 0x20 || code == 0x7f || (space && code == 0x20)) return true;
    }
    return false;
  }

  /** Percent-decoding as JavaScript's decodeURIComponent: strict UTF-8, {@code +} stays. */
  static String percentDecode(String value) {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream(value.length());
    for (int index = 0; index < value.length(); index++) {
      char c = value.charAt(index);
      if (c == '%') {
        if (index + 2 >= value.length()) return null;
        int high = Character.digit(value.charAt(index + 1), 16);
        int low = Character.digit(value.charAt(index + 2), 16);
        if (high < 0 || low < 0) return null;
        bytes.write(high * 16 + low);
        index += 2;
      } else {
        byte[] encoded = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
        if (Character.isHighSurrogate(c) && index + 1 < value.length()) {
          encoded = value.substring(index, index + 2).getBytes(StandardCharsets.UTF_8);
          index++;
        }
        bytes.write(encoded, 0, encoded.length);
      }
    }
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes.toByteArray()))
          .toString();
    } catch (CharacterCodingException invalid) {
      return null;
    }
  }

  /** {@code scheme://host[:port]} of the request. */
  public static String originOf(HttpServletRequest request) {
    String scheme = request.getScheme();
    int port = request.getServerPort();
    boolean defaultPort = (scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443);
    return scheme + "://" + request.getServerName() + (defaultPort || port < 0 ? "" : ":" + port);
  }
}
