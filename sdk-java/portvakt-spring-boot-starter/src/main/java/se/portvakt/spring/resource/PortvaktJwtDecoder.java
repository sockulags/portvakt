package se.portvakt.spring.resource;

import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.Map;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import se.portvakt.sdk.AccessTokenException;
import se.portvakt.sdk.PortvaktTokenVerifier;
import se.portvakt.sdk.PortvaktUnavailableException;
import se.portvakt.spring.login.IdTokens;

/**
 * The resource server's {@link JwtDecoder}, with the core's verification semantics (Nimbus):
 * ES256 with Portvakt's keys only, {@code typ: at+jwt} (a {@code JOSEObjectTypeVerifier}),
 * {@code iss} pinned exactly to the tenant issuer, {@code aud} equal to this API's audience,
 * times with the clock skew, and the person/service discriminator. Invalid tokens raise {@link
 * BadJwtException} (401 {@code invalid_token}); a Portvakt outage with no usable keys raises a
 * plain {@link JwtException} whose cause is {@link PortvaktUnavailableException} (503).
 */
public class PortvaktJwtDecoder implements JwtDecoder {
  private final PortvaktTokenVerifier verifier;
  private final String audience;

  public PortvaktJwtDecoder(PortvaktTokenVerifier verifier, String audience) {
    this.verifier = verifier;
    this.audience = audience;
  }

  /** The audience this decoder accepts. */
  public String audience() {
    return audience;
  }

  @Override
  public Jwt decode(String token) {
    try {
      verifier.verifyAccessToken(token, audience);
    } catch (AccessTokenException invalid) {
      throw new BadJwtException(invalid.description() == null ? "invalid_token" : invalid.description(), invalid);
    } catch (PortvaktUnavailableException unavailable) {
      throw new JwtException("Portvakt is unavailable", unavailable);
    }
    Map<String, Object> claims;
    try {
      claims = SignedJWT.parse(token).getPayload().toJSONObject();
    } catch (ParseException exception) {
      throw new BadJwtException("The access token is invalid", exception);
    }
    return IdTokens.toJwt(token, claims);
  }
}
