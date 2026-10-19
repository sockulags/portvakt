package se.portvakt.sdk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A refused bearer token (RFC 6750, RFC 9470). {@link #error()} and {@link #description()} are
 * safe to send to the caller: they never name which claim or key failed beyond the category.
 * Without an error code (no token at all) the answer is a bare 401 challenge.
 */
public class AccessTokenException extends PortvaktException {
  private static final long serialVersionUID = 1L;

  private final BearerError error;
  private final String description;
  private final String reason;
  private final String acrValues;

  public AccessTokenException(
      int status, BearerError error, String description, String reason, String acrValues) {
    super(
        error == null ? "missing_token" : error.code(),
        description == null ? "An access token is required" : description,
        status);
    this.error = error;
    this.description = description;
    this.reason = reason;
    this.acrValues = acrValues;
  }

  /** 401 without an error code: the request carried no token. */
  public static AccessTokenException missingToken() {
    return new AccessTokenException(401, null, null, null, null);
  }

  /** 401 {@code invalid_token} with the generic description. */
  public static AccessTokenException invalidToken() {
    return invalidToken("The access token is invalid");
  }

  public static AccessTokenException invalidToken(String description) {
    return new AccessTokenException(401, BearerError.INVALID_TOKEN, description, null, null);
  }

  /** 400 {@code invalid_request}: the Authorization header is malformed. */
  public static AccessTokenException invalidRequest() {
    return new AccessTokenException(
        400, BearerError.INVALID_REQUEST, "The Authorization header is malformed", null, null);
  }

  /** 403 {@code insufficient_scope} with a machine-readable reason. */
  public static AccessTokenException insufficientScope(String description, String reason) {
    return new AccessTokenException(403, BearerError.INSUFFICIENT_SCOPE, description, reason, null);
  }

  /** 401 {@code insufficient_user_authentication} (RFC 9470) asking for {@code acr}. */
  public static AccessTokenException insufficientUserAuthentication(String acr) {
    return new AccessTokenException(
        401,
        BearerError.INSUFFICIENT_USER_AUTHENTICATION,
        "A higher authentication level is required",
        "acr_not_met",
        acr);
  }

  /** The bearer error, or {@code null} when no token was presented. */
  public BearerError error() {
    return error;
  }

  public String description() {
    return description;
  }

  /** {@code missing_role}, {@code service_not_allowed}, {@code representation_not_allowed}, ... */
  public String reason() {
    return reason;
  }

  /** The required acr for {@code insufficient_user_authentication}. */
  public String acrValues() {
    return acrValues;
  }

  /** The {@code WWW-Authenticate} header value (RFC 6750 section 3). */
  public String wwwAuthenticate() {
    List<String> params = new ArrayList<>();
    params.add("realm=\"portvakt\"");
    if (error != null) {
      params.add("error=\"" + error.code() + "\"");
      if (description != null) params.add("error_description=\"" + quoteSafe(description) + "\"");
    }
    if (acrValues != null) params.add("acr_values=\"" + quoteSafe(acrValues) + "\"");
    return "Bearer " + String.join(", ", params);
  }

  /** The JSON body: {@code error}, {@code error_description}, and {@code reason}/{@code acr_values}. */
  public Map<String, Object> body() {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", error == null ? "missing_token" : error.code());
    body.put("error_description", description == null ? "An access token is required" : description);
    if (reason != null) body.put("reason", reason);
    if (acrValues != null) body.put("acr_values", acrValues);
    return body;
  }

  private static String quoteSafe(String value) {
    return value.replaceAll("[\"\\\\\\x00-\\x1f\\x7f]", "");
  }
}
