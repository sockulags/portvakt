package se.portvakt.spring.resource;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import se.portvakt.sdk.AccessTokenRequirements;
import se.portvakt.sdk.PortvaktPrincipal;
import se.portvakt.spring.PortvaktAuthorities;

/**
 * Maps a verified access token to a {@link PortvaktJwtAuthenticationToken}: the principal (person
 * or service, by the claims Portvakt issues) and its authorities ({@code PORTVAKT_ROLE_<role>},
 * {@code PORTVAKT_PERSON} or {@code PORTVAKT_SERVICE}). The resource server's defaults are
 * enforced here, also in chains the application defines itself: a service token without {@code
 * allow-service} (or outside {@code allowed-services}) and a token acting for a party without
 * {@code allow-representation} come out restricted (see the token).
 */
public class PortvaktJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
  private final AccessTokenRequirements defaults;

  public PortvaktJwtAuthenticationConverter(AccessTokenRequirements defaults) {
    this.defaults = defaults;
  }

  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    PortvaktPrincipal principal = PortvaktPrincipal.fromAccessTokenClaims(jwt.getClaims());
    if (principal == null) throw new InvalidBearerTokenException("The access token is invalid");
    String restriction = null;
    if (principal.isService() && !defaults.acceptsService(principal.clientId())) {
      restriction = "service_not_allowed";
    } else if (principal.isRepresenting() && !defaults.allowRepresentation()) {
      restriction = "representation_not_allowed";
    }
    return new PortvaktJwtAuthenticationToken(jwt, principal, PortvaktAuthorities.of(principal), restriction);
  }
}
