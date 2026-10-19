package se.portvakt.spring.login;

import com.nimbusds.jose.util.JSONObjectUtils;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;

/**
 * Where browser sessions' tokens live, outside the HTTP session, keyed by the session's {@code
 * grantId} ({@link PortvaktSessionState}); and the pending logins (authorization requests with
 * their PKCE verifier), taken once. {@link #update} gives exclusive access to one grant, so a
 * refresh (Portvakt rotates refresh tokens and treats a replay as theft) runs once even when
 * several requests, replicas or stale session snapshots ask at the same time.
 *
 * <p>Implementations: {@link InMemoryTokenStore} (one instance only) and {@link JdbcTokenStore}
 * ({@code portvakt.login.token-store=jdbc}).
 */
public interface PortvaktTokenStore {
  /**
   * The tokens of one grant, and the session's signed-in person as its ID token (personal data:
   * kept here, sealed, never in the HTTP session; see {@link PortvaktSecurityContextRepository}).
   *
   * @param accessToken the access token
   * @param issuedAt when it was issued
   * @param expiresAt when it expires
   * @param scopes its scopes
   * @param refreshToken the refresh token, or {@code null}
   * @param idToken the latest verified ID token of the session, or {@code null} until the login
   *     stored it
   */
  record StoredTokens(
      String accessToken, Instant issuedAt, Instant expiresAt, Set<String> scopes, String refreshToken, String idToken) {
    public StoredTokens {
      scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
    }

    public StoredTokens(String accessToken, Instant issuedAt, Instant expiresAt, Set<String> scopes, String refreshToken) {
      this(accessToken, issuedAt, expiresAt, scopes, refreshToken, null);
    }

    /** The same tokens with another ID token. */
    public StoredTokens withIdToken(String value) {
      return new StoredTokens(accessToken, issuedAt, expiresAt, scopes, refreshToken, value);
    }

    /** JSON (only ever stored sealed, or in memory). */
    public String toJson() {
      Map<String, Object> json = new LinkedHashMap<>();
      json.put("at", accessToken);
      json.put("iat", issuedAt == null ? null : issuedAt.getEpochSecond());
      json.put("exp", expiresAt == null ? null : expiresAt.getEpochSecond());
      json.put("scp", List.copyOf(scopes));
      json.put("rt", refreshToken);
      if (idToken != null) json.put("idt", idToken);
      return JSONObjectUtils.toJSONString(json);
    }

    public static StoredTokens fromJson(String text) {
      try {
        Map<String, Object> json = JSONObjectUtils.parse(text);
        Object scopes = json.get("scp");
        return new StoredTokens(
            (String) json.get("at"),
            json.get("iat") instanceof Number number ? Instant.ofEpochSecond(number.longValue()) : null,
            json.get("exp") instanceof Number number ? Instant.ofEpochSecond(number.longValue()) : null,
            scopes instanceof List<?> list ? Set.copyOf(list.stream().map(String::valueOf).toList()) : Set.of(),
            (String) json.get("rt"),
            (String) json.get("idt"));
      } catch (java.text.ParseException | ClassCastException invalid) {
        throw new IllegalStateException("unreadable stored tokens");
      }
    }

    @Override
    public String toString() {
      return "StoredTokens[expiresAt=" + expiresAt + "]";
    }
  }

  /** Stores (or replaces) a grant's tokens until {@code expiresAt}. */
  void save(String grantId, StoredTokens tokens, Instant expiresAt);

  /** The grant's tokens, or {@code null} when absent or expired. */
  StoredTokens load(String grantId);

  /**
   * Exclusive update: {@code update} sees the current tokens ({@code null} when absent) while no
   * other caller can update the same grant; what it returns is stored, unless it returns {@code
   * null} or the same instance. An exception from {@code update} leaves the grant as it was.
   *
   * @return the tokens after the update
   */
  StoredTokens update(String grantId, UnaryOperator<StoredTokens> update);

  /** Moves a grant's expiry (the session's end). */
  void expire(String grantId, Instant expiresAt);

  void delete(String grantId);

  /** Stores a pending login (a serialised authorization request) until {@code expiresAt}. */
  void savePending(String key, byte[] value, Instant expiresAt);

  /** A pending login without taking it, or {@code null}. */
  byte[] loadPending(String key);

  /** Takes a pending login: of concurrent callers, exactly one gets it. */
  byte[] takePending(String key);

  void deletePending(String key);

  /** Deletes expired grants and pending logins; returns how many. */
  int deleteExpired();
}
