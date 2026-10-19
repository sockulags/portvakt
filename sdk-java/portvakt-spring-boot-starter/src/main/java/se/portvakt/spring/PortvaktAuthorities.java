package se.portvakt.spring;

import java.util.ArrayList;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import se.portvakt.sdk.PortvaktPrincipal;

/**
 * The authorities of a Portvakt principal: {@code PORTVAKT_ROLE_<role>} for each of the person's
 * roles in this application, plus {@code PORTVAKT_PERSON} or {@code PORTVAKT_SERVICE}.
 */
public final class PortvaktAuthorities {
  public static final String ROLE_PREFIX = "PORTVAKT_ROLE_";
  public static final String PERSON = "PORTVAKT_PERSON";
  public static final String SERVICE = "PORTVAKT_SERVICE";

  private PortvaktAuthorities() {}

  public static List<GrantedAuthority> of(PortvaktPrincipal principal) {
    List<GrantedAuthority> authorities = new ArrayList<>();
    authorities.add(new SimpleGrantedAuthority(principal.isService() ? SERVICE : PERSON));
    for (String role : principal.roles()) authorities.add(new SimpleGrantedAuthority(ROLE_PREFIX + role));
    return List.copyOf(authorities);
  }
}
