package se.portvakt.sdk;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Reading the bearer token of a request (RFC 6750 section 2.1, header only). */
public final class BearerTokens {
  /** The longest token accepted. */
  public static final int MAX_TOKEN_LENGTH = 16_384;

  private static final Pattern HEADER = Pattern.compile("^Bearer +(\\S+) *$", Pattern.CASE_INSENSITIVE);
  private static final Pattern TOKEN = Pattern.compile("^[A-Za-z0-9\\-._~+/]+=*$");

  private BearerTokens() {}

  /**
   * The token of an {@code Authorization} header value: exactly {@code Bearer <token>}.
   *
   * @return the token, or {@code null} when there is no header
   * @throws AccessTokenException 400 {@code invalid_request} for another scheme or a malformed
   *     header, 401 {@code invalid_token} for a token that cannot be one
   */
  public static String fromAuthorizationHeader(String header) {
    if (header == null || header.isEmpty()) return null;
    Matcher match = HEADER.matcher(header);
    if (!match.matches()) throw AccessTokenException.invalidRequest();
    String token = match.group(1);
    if (token.length() > MAX_TOKEN_LENGTH || !TOKEN.matcher(token).matches()) {
      throw AccessTokenException.invalidToken();
    }
    return token;
  }
}
