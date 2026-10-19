package se.portvakt.sdk;

/** RFC 6750 bearer token error codes, plus RFC 9470's {@code insufficient_user_authentication}. */
public enum BearerError {
  INVALID_REQUEST("invalid_request"),
  INVALID_TOKEN("invalid_token"),
  INSUFFICIENT_SCOPE("insufficient_scope"),
  INSUFFICIENT_USER_AUTHENTICATION("insufficient_user_authentication");

  private final String code;

  BearerError(String code) {
    this.code = code;
  }

  /** The code as sent in {@code WWW-Authenticate} and the JSON body. */
  public String code() {
    return code;
  }
}
