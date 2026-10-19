package se.portvakt.spring;

import se.portvakt.sdk.AccessTokenException;

/**
 * A decision of the Portvakt authorization managers, carrying why access was denied: the acr a
 * step-up must reach, or the bearer error for an access token.
 */
public class PortvaktAuthorizationDecision extends org.springframework.security.authorization.AuthorizationDecision {
  private static final long serialVersionUID = 1L;

  private final String requiredAcr;
  private final transient AccessTokenException bearerError;

  public PortvaktAuthorizationDecision(boolean granted, String requiredAcr, AccessTokenException bearerError) {
    super(granted);
    this.requiredAcr = requiredAcr;
    this.bearerError = bearerError;
  }

  public static PortvaktAuthorizationDecision granted() {
    return new PortvaktAuthorizationDecision(true, null, null);
  }

  /** The acr a step-up must reach, or {@code null}. */
  public String requiredAcr() {
    return requiredAcr;
  }

  /** The RFC 6750 error for a bearer token, or {@code null}. */
  public AccessTokenException bearerError() {
    return bearerError;
  }
}
