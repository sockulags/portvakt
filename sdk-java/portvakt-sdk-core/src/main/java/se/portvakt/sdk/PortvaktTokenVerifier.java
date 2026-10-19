package se.portvakt.sdk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.lang.System.Logger.Level;
import java.security.Key;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Validates Portvakt's tokens with Nimbus JOSE+JWT:
 *
 * <ul>
 *   <li>signature with Portvakt's ES256 keys only (no {@code none}, no HMAC, no RSA), the key
 *       chosen by {@code kid} from {@link PortvaktJwks};
 *   <li>access tokens: header {@code typ: at+jwt} (RFC 9068); ID tokens: no {@code typ} or {@code
 *       JWT}, so an access token cannot pass as an ID token and the other way round;
 *   <li>{@code iss} exactly the configured tenant issuer. The signing keys are shared by every
 *       tenant, so a token of another tenant verifies but is refused here;
 *   <li>{@code aud}; {@code exp}, {@code nbf} and {@code iat} with the configured clock skew;
 *   <li>the claims contract, including the person/service discriminator ({@link
 *       PortvaktPrincipal#fromAccessTokenClaims}).
 * </ul>
 *
 * Thread-safe.
 */
public final class PortvaktTokenVerifier {
  private static final System.Logger LOG = System.getLogger(PortvaktTokenVerifier.class.getName());

  private static final JOSEObjectType AT_JWT = new JOSEObjectType("at+jwt");
  private static final JOSEObjectType APPLICATION_AT_JWT = new JOSEObjectType("application/at+jwt");

  private static final List<String> ACCESS_TOKEN_REQUIRED =
      List.of("iss", "aud", "exp", "iat", "sub", "client_id");
  private static final List<String> ID_TOKEN_REQUIRED = List.of("iss", "aud", "exp", "iat", "sub");

  /** A verified ID token. */
  public record VerifiedIdToken(
      String token,
      Map<String, Object> claims,
      PortvaktPrincipal principal,
      Instant sessionExp,
      Instant issuedAt,
      Instant expiresAt) {
    public VerifiedIdToken {
      claims = Map.copyOf(claims);
    }

    @Override
    public String toString() {
      return "VerifiedIdToken[" + principal + "]";
    }
  }

  private final PortvaktConfig config;
  private final DefaultJWTProcessor<SecurityContext> accessTokens;
  private final DefaultJWTProcessor<SecurityContext> idTokens;

  public PortvaktTokenVerifier(PortvaktConfig config, PortvaktJwks jwks) {
    this.config = config;
    JWSKeySelector<SecurityContext> keys = (header, context) -> select(jwks, header);
    this.accessTokens = processor(keys, new DefaultJOSEObjectTypeVerifier<>(AT_JWT, APPLICATION_AT_JWT));
    this.idTokens = processor(keys, new DefaultJOSEObjectTypeVerifier<>(JOSEObjectType.JWT, null));
  }

  private static DefaultJWTProcessor<SecurityContext> processor(
      JWSKeySelector<SecurityContext> keys, DefaultJOSEObjectTypeVerifier<SecurityContext> types) {
    DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
    processor.setJWSTypeVerifier(types);
    processor.setJWSKeySelector(keys);
    // Time and audience claims are checked below, with Portvakt's semantics.
    processor.setJWTClaimsSetVerifier((claims, context) -> {});
    return processor;
  }

  /** ES256 only, and only a published key with the token's kid. */
  private static List<Key> select(PortvaktJwks jwks, JWSHeader header) {
    if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) return List.of();
    try {
      return List.of(jwks.keyFor(header.getKeyID()).toECPublicKey());
    } catch (PortvaktJwks.UnknownKeyException | JOSEException unknown) {
      return List.of();
    }
  }

  /**
   * Validates an access token for {@code audience}.
   *
   * @throws AccessTokenException 401 {@code invalid_token} (the description says when it expired)
   * @throws PortvaktUnavailableException Portvakt's keys cannot be fetched or are too old
   */
  public PortvaktPrincipal verifyAccessToken(String token, String audience) {
    Map<String, Object> payload = verify(token, accessTokens, ACCESS_TOKEN_REQUIRED);
    if (!audienceOf(payload).contains(audience)) throw AccessTokenException.invalidToken();
    PortvaktPrincipal principal = PortvaktPrincipal.fromAccessTokenClaims(payload);
    if (principal == null) throw AccessTokenException.invalidToken();
    return principal;
  }

  /**
   * Validates an ID token issued to this application ({@code aud} contains the client_id; with
   * several audiences {@code azp} must be the client_id) and maps it to a person principal with
   * profile fields. The nonce is the caller's to check.
   *
   * @throws AccessTokenException 401 {@code invalid_token} for an invalid token or one that does
   *     not follow the claims contract
   * @throws PortvaktUnavailableException Portvakt's keys cannot be fetched or are too old
   */
  public VerifiedIdToken verifyIdToken(String token) {
    Map<String, Object> payload = verify(token, idTokens, ID_TOKEN_REQUIRED);
    List<String> audience = audienceOf(payload);
    if (!audience.contains(config.clientId())) throw AccessTokenException.invalidToken();
    if (audience.size() > 1 && !config.clientId().equals(payload.get("azp"))) {
      throw AccessTokenException.invalidToken();
    }
    PortvaktPrincipal principal;
    try {
      principal = PortvaktPrincipal.fromIdTokenClaims(payload);
    } catch (IllegalArgumentException invalid) {
      LOG.log(Level.WARNING, "ID token does not follow the claims contract: {0}", invalid.getMessage());
      throw AccessTokenException.invalidToken("The ID token does not follow the claims contract");
    }
    Object sessionExp = payload.get("session_exp");
    return new VerifiedIdToken(
        token,
        payload,
        principal,
        sessionExp instanceof Number number ? Instant.ofEpochSecond(number.longValue()) : null,
        Instant.ofEpochSecond(((Number) payload.get("iat")).longValue()),
        Instant.ofEpochSecond(((Number) payload.get("exp")).longValue()));
  }

  /**
   * Checks a verified principal against a route's requirements, with the TypeScript SDK's
   * semantics: service principals pass only when allowed (role and acr requirements apply to
   * persons only); persons may not act for a party where representation is refused, must have
   * the roles, and an acr at least the required one.
   *
   * @throws AccessTokenException 403 {@code insufficient_scope} ({@code service_not_allowed},
   *     {@code representation_not_allowed}, {@code missing_role}) or 401 {@code
   *     insufficient_user_authentication}
   */
  public void authorize(PortvaktPrincipal principal, AccessTokenRequirements requirements) {
    if (principal.isService()) {
      if (!requirements.acceptsService(principal.clientId())) {
        throw AccessTokenException.insufficientScope(
            "A person's access token is required", "service_not_allowed");
      }
      return;
    }
    if (principal.isRepresenting() && !requirements.allowRepresentation()) {
      throw AccessTokenException.insufficientScope(
          "Acting on behalf of another party is not allowed here", "representation_not_allowed");
    }
    boolean missing = requirements.roles().stream().anyMatch(role -> !principal.hasRole(role));
    boolean noneOf =
        !requirements.anyRole().isEmpty() && requirements.anyRole().stream().noneMatch(principal::hasRole);
    if (missing || noneOf) {
      throw AccessTokenException.insufficientScope("A required role is missing", "missing_role");
    }
    String acr = requirements.acr();
    if (acr != null && !config.acrRanking().atLeast(principal.acr(), acr)) {
      throw AccessTokenException.insufficientUserAuthentication(acr);
    }
  }

  // Internals ----------------------------------------------------------------------------------

  private Map<String, Object> verify(
      String token, DefaultJWTProcessor<SecurityContext> processor, List<String> required) {
    if (token == null || token.length() > BearerTokens.MAX_TOKEN_LENGTH || token.split("\\.", -1).length != 3) {
      throw AccessTokenException.invalidToken();
    }
    SignedJWT jwt;
    try {
      jwt = SignedJWT.parse(token);
      processor.process(jwt, null);
    } catch (ParseException | BadJOSEException | JOSEException | IllegalStateException refused) {
      throw AccessTokenException.invalidToken();
    }
    Map<String, Object> payload = jwt.getPayload().toJSONObject();
    if (payload == null) throw AccessTokenException.invalidToken();
    for (String claim : required) {
      if (payload.get(claim) == null) throw AccessTokenException.invalidToken();
    }
    if (!config.issuer().equals(payload.get("iss"))) throw AccessTokenException.invalidToken();
    long now = config.clock().instant().getEpochSecond();
    long skew = config.clockSkew().toSeconds();
    long exp = numericDate(payload.get("exp"));
    if (exp <= now - skew) throw AccessTokenException.invalidToken("The access token has expired");
    if (payload.containsKey("nbf") && numericDate(payload.get("nbf")) > now + skew) {
      throw AccessTokenException.invalidToken();
    }
    if (numericDate(payload.get("iat")) > now + skew) throw AccessTokenException.invalidToken();
    return payload;
  }

  /** A NumericDate claim in whole seconds; anything else refuses the token. */
  private static long numericDate(Object value) {
    if (value instanceof Long || value instanceof Integer) return ((Number) value).longValue();
    if (value instanceof Double number && Double.isFinite(number)) return (long) Math.floor(number);
    throw AccessTokenException.invalidToken();
  }

  private static List<String> audienceOf(Map<String, Object> payload) {
    Object aud = payload.get("aud");
    if (aud instanceof String single) return List.of(single);
    if (aud instanceof List<?> list && list.stream().allMatch(String.class::isInstance)) {
      return list.stream().map(String.class::cast).toList();
    }
    throw AccessTokenException.invalidToken();
  }
}
