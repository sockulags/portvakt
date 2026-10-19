package se.portvakt.sdk;

/** Cached client_credentials tokens for one target application. */
public interface ServiceTokenSource {
  /** The target application's client_id (the token's {@code aud}). */
  String audience();

  /**
   * A valid access token, fetched again shortly before the cached one expires.
   *
   * @throws PortvaktUnavailableException Portvakt is unreachable (network, timeout, 5xx)
   * @throws PortvaktException Portvakt refused the grant (the code is its OAuth error)
   */
  String getToken();

  /** Drops the cached token (for example after the target answered 401). */
  void clear();
}
