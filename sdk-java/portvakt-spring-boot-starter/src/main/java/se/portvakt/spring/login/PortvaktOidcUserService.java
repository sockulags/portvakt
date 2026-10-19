package se.portvakt.spring.login;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * Builds the {@link PortvaktOidcUser} from the validated ID token only. Portvakt disables the
 * userinfo endpoint (it accepts no audience-bound access token there), so it is never called.
 */
public class PortvaktOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {
  @Override
  public OidcUser loadUser(OidcUserRequest request) {
    try {
      return PortvaktOidcUser.of(request.getIdToken());
    } catch (IllegalArgumentException invalid) {
      OAuth2Error error = new OAuth2Error("invalid_id_token", "the ID token does not follow the claims contract", null);
      throw new OAuth2AuthenticationException(error, error.toString(), invalid);
    }
  }
}
