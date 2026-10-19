package se.portvakt.sdk;

/** The kind of login method the person signed in with ({@code idp_kind}). */
public enum IdpKind {
  EMPLOYEE("employee"),
  CITIZEN("citizen");

  private final String claimValue;

  IdpKind(String claimValue) {
    this.claimValue = claimValue;
  }

  /** The value in the token: {@code employee} or {@code citizen}. */
  public String claimValue() {
    return claimValue;
  }

  /** The kind for a claim value, or {@code null} when it is not one. */
  public static IdpKind fromClaim(Object value) {
    for (IdpKind kind : values()) {
      if (kind.claimValue.equals(value)) return kind;
    }
    return null;
  }
}
