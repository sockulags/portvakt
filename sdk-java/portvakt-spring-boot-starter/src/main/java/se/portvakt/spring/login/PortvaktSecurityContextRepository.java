package se.portvakt.spring.login;

import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.text.ParseException;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Spring Security's context of a Portvakt browser session, kept out of the HTTP session: the
 * signed-in person's ID token (with their name, email, personal identity number) lives in the
 * sealed {@link PortvaktTokenStore} next to the session's tokens, under the session's grant id.
 * The HTTP session holds only {@link PortvaktSessionState} (timestamps and the grant id), so a
 * serialised session (Spring Session, a session store, a heap dump of it) carries no personal
 * data. Each request rebuilds the {@link OAuth2AuthenticationToken} with its {@link
 * PortvaktOidcUser} from the stored ID token (verified when it was stored). Any other
 * authentication (the application's own) goes to the HTTP session as usual.
 */
public class PortvaktSecurityContextRepository implements SecurityContextRepository {
  private static final Logger LOG = LoggerFactory.getLogger(PortvaktSecurityContextRepository.class);

  private final PortvaktTokenStore store;
  private final HttpSessionSecurityContextRepository sessions = new HttpSessionSecurityContextRepository();
  private final SecurityContextHolderStrategy holder = SecurityContextHolder.getContextHolderStrategy();

  public PortvaktSecurityContextRepository(PortvaktTokenStore store) {
    this.store = store;
  }

  @Override
  @SuppressWarnings("deprecation")
  public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
    return loadDeferredContext(requestResponseHolder.getRequest()).get();
  }

  @Override
  public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
    DeferredSecurityContext fallback = sessions.loadDeferredContext(request);
    Supplier<SecurityContext> portvakt = () -> portvaktContext(request);
    return new DeferredSecurityContext() {
      private SecurityContext loaded;
      private boolean generated;

      @Override
      public SecurityContext get() {
        if (loaded == null) {
          SecurityContext context = portvakt.get();
          if (context == null) {
            context = fallback.get();
            generated = fallback.isGenerated();
          }
          loaded = context;
        }
        return loaded;
      }

      @Override
      public boolean isGenerated() {
        get();
        return generated;
      }
    };
  }

  @Override
  public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
    Authentication authentication = context.getAuthentication();
    if (authentication instanceof OAuth2AuthenticationToken token && token.getPrincipal() instanceof PortvaktOidcUser user) {
      String grantId = grantIdOf(request);
      if (grantId == null) throw new IllegalStateException("a Portvakt login without a grant");
      String idToken = user.getIdToken().getTokenValue();
      store.update(grantId, current -> current == null ? null : current.withIdToken(idToken));
      // Never in the HTTP session (an earlier Spring Security version, or a context saved before).
      HttpSession session = request.getSession(false);
      if (session != null) {
        try {
          session.removeAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        } catch (IllegalStateException invalidated) {
          // Nothing to remove.
        }
      }
      return;
    }
    sessions.saveContext(context, request, response);
  }

  @Override
  public boolean containsContext(HttpServletRequest request) {
    return portvaktContext(request) != null || sessions.containsContext(request);
  }

  /** The grant of the request: the one the login callback just made, or the session's. */
  private static String grantIdOf(HttpServletRequest request) {
    if (request.getAttribute(PortvaktAuthorizedClientRepository.NEW_GRANT_ATTRIBUTE) instanceof String grantId) {
      return grantId;
    }
    PortvaktSessionState state = PortvaktSessionState.of(request.getSession(false));
    return state == null ? null : state.grantId();
  }

  /** The context of the session's stored ID token, or {@code null} when it has none. */
  private SecurityContext portvaktContext(HttpServletRequest request) {
    PortvaktSessionState state = PortvaktSessionState.of(request.getSession(false));
    if (state == null || state.grantId() == null) return null;
    PortvaktTokenStore.StoredTokens tokens = store.load(state.grantId());
    if (tokens == null || tokens.idToken() == null) return null;
    PortvaktOidcUser user = userOf(tokens.idToken());
    if (user == null) return null;
    SecurityContext context = holder.createEmptyContext();
    context.setAuthentication(
        new OAuth2AuthenticationToken(user, user.getAuthorities(), PortvaktLoginSettings.REGISTRATION_ID));
    return context;
  }

  /** The user of an ID token the login or a refresh verified (signature and claims). */
  static PortvaktOidcUser userOf(String idToken) {
    try {
      Jwt jwt = IdTokens.toJwt(idToken, SignedJWT.parse(idToken).getPayload().toJSONObject());
      return PortvaktOidcUser.of(new OidcIdToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims()));
    } catch (ParseException | RuntimeException unreadable) {
      LOG.warn("a stored ID token could not be read: {}", unreadable.getClass().getSimpleName());
      return null;
    }
  }
}
