package se.portvakt.spring.login;

import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.Collections;
import java.util.Map;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import se.portvakt.sdk.PortvaktTokenVerifier;

/** Spring representations of tokens the core verified. */
public final class IdTokens {
  private static final MappedJwtClaimSetConverter CLAIMS =
      MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());

  private IdTokens() {}

  /** A Spring {@link Jwt} of a verified token and its raw claims (times as {@code Instant}). */
  public static Jwt toJwt(String token, Map<String, Object> rawClaims) {
    Map<String, Object> headers;
    try {
      headers = SignedJWT.parse(token).getHeader().toJSONObject();
    } catch (ParseException exception) {
      throw new BadJwtException("The token is invalid", exception);
    }
    Map<String, Object> claims = CLAIMS.convert(rawClaims);
    return Jwt.withTokenValue(token).headers(h -> h.putAll(headers)).claims(c -> c.putAll(claims)).build();
  }

  /** The OIDC ID token of a verified ID token. */
  public static OidcIdToken toOidcIdToken(PortvaktTokenVerifier.VerifiedIdToken verified) {
    Jwt jwt = toJwt(verified.token(), verified.claims());
    return new OidcIdToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims());
  }
}
