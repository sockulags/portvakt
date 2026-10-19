package se.portvakt.spring.login;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import se.portvakt.sdk.AccessTokenException;
import se.portvakt.sdk.PortvaktTokenVerifier;

/**
 * ID token validation for oauth2Login through the core verifier, consistent with access token
 * validation: ES256 with Portvakt's keys only, {@code iss} exactly the tenant issuer, {@code aud}
 * the client_id ({@code azp} with several audiences), {@code exp}/{@code iat} with the clock skew,
 * no {@code at+jwt} typ, and the claims contract. Spring checks the nonce afterwards. A Portvakt
 * outage surfaces as {@link se.portvakt.sdk.PortvaktUnavailableException}.
 */
public class PortvaktIdTokenDecoderFactory implements JwtDecoderFactory<ClientRegistration> {
  private final PortvaktTokenVerifier verifier;

  public PortvaktIdTokenDecoderFactory(PortvaktTokenVerifier verifier) {
    this.verifier = verifier;
  }

  @Override
  public JwtDecoder createDecoder(ClientRegistration registration) {
    return token -> {
      PortvaktTokenVerifier.VerifiedIdToken verified;
      try {
        verified = verifier.verifyIdToken(token);
      } catch (AccessTokenException invalid) {
        throw new BadJwtException(invalid.description() == null ? "invalid" : invalid.description(), invalid);
      }
      return IdTokens.toJwt(verified.token(), verified.claims());
    };
  }
}
