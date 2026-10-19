package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import se.portvakt.sdk.AccessTokenException;
import se.portvakt.sdk.LoginRequiredException;
import se.portvakt.sdk.PortvaktException;
import se.portvakt.sdk.PortvaktTokenVerifier;
import se.portvakt.sdk.PortvaktUnavailableException;
import se.portvakt.spring.PortvaktAuthorities;

/**
 * The browser session's access token for the application's own API, through the {@link
 * OAuth2AuthorizedClientManager} ({@link PortvaktAuthorizedClientManager}): refreshed when it has
 * less than the minimum validity left (default: clock skew plus 30 s). Semantics as the
 * TypeScript SDK's {@code getAccessToken}:
 *
 * <ul>
 *   <li>a session refreshes once at a time: the check and the refresh run inside the token store's
 *       exclusive update, across stale session snapshots and (JDBC store) replicas;
 *   <li>using the token is activity (moves the idle timeout);
 *   <li>a refused refresh ({@code invalid_grant}: grant revoked, representation no longer valid,
 *       broker session ended) ends the session: {@link LoginRequiredException}; {@code
 *       invalid_client} (the application's own credentials) keeps it and answers 502;
 *   <li>the refreshed ID token replaces the principal and caps the session's end at the new
 *       {@code session_exp} (never later than before; a different {@code sub} ends the session);
 *   <li>Portvakt unreachable: with an outage grace of 0 the session ends; otherwise the first
 *       failure starts the outage ({@link PortvaktUnavailableException}, 503, the session
 *       continues) and the session ends only when a refresh fails after the grace has passed. A
 *       refresh that succeeded is always kept (the rotated tokens are stored), also when the new
 *       ID token cannot be checked yet.
 * </ul>
 */
public class PortvaktAccessTokens {
  private static final Logger LOG = LoggerFactory.getLogger(PortvaktAccessTokens.class);

  private final OAuth2AuthorizedClientManager manager;
  private final PortvaktTokenVerifier verifier;
  private final PortvaktSessions sessions;
  private final PortvaktLoginSettings settings;
  private final Clock clock;
  private final HttpSessionSecurityContextRepository contexts = new HttpSessionSecurityContextRepository();

  public PortvaktAccessTokens(
      OAuth2AuthorizedClientManager manager, PortvaktTokenVerifier verifier, PortvaktSessions sessions) {
    this.manager = manager;
    this.verifier = verifier;
    this.sessions = sessions;
    this.settings = sessions.settings();
    this.clock = sessions.clock();
  }

  /** A fresh access token of the request's session (see the class description). */
  public String getAccessToken(HttpServletRequest request, HttpServletResponse response) {
    return getAccessToken(request, response, null);
  }

  /**
   * A fresh access token valid at least {@code minValidity} longer.
   *
   * @throws LoginRequiredException the session ended (or never existed)
   * @throws PortvaktUnavailableException Portvakt is unreachable within the outage grace
   */
  public String getAccessToken(HttpServletRequest request, HttpServletResponse response, Duration minValidity) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (!(authentication instanceof OAuth2AuthenticationToken token)
        || !(token.getPrincipal() instanceof PortvaktOidcUser user)) {
      throw new LoginRequiredException(LoginRequiredException.Reason.NO_SESSION);
    }
    HttpSession session = request.getSession(false);
    PortvaktSessionState state = PortvaktSessionState.of(session);
    if (state == null || state.grantId() == null) {
      throw new LoginRequiredException(LoginRequiredException.Reason.NO_SESSION);
    }
    if (sessions.ended(state)) {
      sessions.end(request);
      throw new LoginRequiredException(LoginRequiredException.Reason.SESSION_EXPIRED);
    }
    PortvaktRefreshTokenProvider.ResponseHolder holder = new PortvaktRefreshTokenProvider.ResponseHolder();
    OAuth2AuthorizeRequest.Builder authorize =
        OAuth2AuthorizeRequest.withClientRegistrationId(PortvaktLoginSettings.REGISTRATION_ID)
            .principal(authentication)
            .attribute(HttpServletRequest.class.getName(), request)
            .attribute(HttpServletResponse.class.getName(), response)
            .attribute(PortvaktRefreshTokenProvider.RESPONSE_ATTRIBUTE, holder);
    if (minValidity != null) authorize.attribute(PortvaktRefreshTokenProvider.MIN_VALIDITY_ATTRIBUTE, minValidity);
    OAuth2AuthorizedClient client;
    try {
      client = manager.authorize(authorize.build());
    } catch (PortvaktUnavailableException unavailable) {
      throw outage(request, session, state, unavailable);
    } catch (ClientAuthorizationException refused) {
      String code = refused.getError() == null ? "" : refused.getError().getErrorCode();
      if (code.equals("invalid_client")) {
        // The application's own credentials are wrong: a configuration problem, not the
        // person's session. Keep the session and fail the request.
        LOG.error("Portvakt refused the refresh: invalid_client");
        throw new PortvaktException("invalid_client", "Portvakt refused the client", 502, refused);
      }
      LOG.info("Portvakt refused the refresh ({}); the session ends", code);
      sessions.end(request);
      throw new LoginRequiredException(LoginRequiredException.Reason.REFRESH_FAILED);
    }
    if (client == null) {
      sessions.end(request);
      throw new LoginRequiredException(LoginRequiredException.Reason.NO_SESSION);
    }
    state = state.withLastSeenAt(clock.instant());
    if (holder.response() != null) {
      state = state.withOutageSince(null);
      try {
        Instant before = state.endsAt();
        state = afterRefresh(request, response, state, user, token, holder);
        if (state.endsAt().isBefore(before)) sessions.store().expire(state.grantId(), state.endsAt());
      } catch (PortvaktUnavailableException unavailable) {
        // The rotated tokens are stored already; only the new ID token could not be checked.
        state.storeIn(session);
        throw outage(request, session, state, unavailable);
      }
    }
    state.storeIn(session);
    return client.getAccessToken().getTokenValue();
  }

  private PortvaktSessionState afterRefresh(
      HttpServletRequest request,
      HttpServletResponse response,
      PortvaktSessionState state,
      PortvaktOidcUser user,
      OAuth2AuthenticationToken token,
      PortvaktRefreshTokenProvider.ResponseHolder holder) {
    Instant cap = state.createdAt().plus(settings.maxAge());
    Instant endsAt = state.endsAt().isBefore(cap) ? state.endsAt() : cap;
    Object idToken = holder.response().getAdditionalParameters().get("id_token");
    if (idToken instanceof String value) {
      PortvaktTokenVerifier.VerifiedIdToken verified;
      try {
        verified = verifier.verifyIdToken(value);
      } catch (AccessTokenException invalid) {
        sessions.end(request);
        throw new LoginRequiredException(LoginRequiredException.Reason.REFRESH_FAILED);
      }
      if (!verified.principal().sub().equals(user.getPortvaktPrincipal().sub())) {
        sessions.end(request);
        throw new LoginRequiredException(LoginRequiredException.Reason.REFRESH_FAILED);
      }
      OidcIdToken oidcIdToken = IdTokens.toOidcIdToken(verified);
      PortvaktOidcUser refreshed =
          new PortvaktOidcUser(
              PortvaktAuthorities.of(verified.principal()), oidcIdToken, verified.principal(), verified.sessionExp());
      OAuth2AuthenticationToken authentication =
          new OAuth2AuthenticationToken(refreshed, refreshed.getAuthorities(), token.getAuthorizedClientRegistrationId());
      authentication.setDetails(token.getDetails());
      SecurityContext context = SecurityContextHolder.createEmptyContext();
      context.setAuthentication(authentication);
      SecurityContextHolder.setContext(context);
      contexts.saveContext(context, request, response);
      // The end only ever moves earlier: the new session_exp may shorten it; without one it stays.
      Instant sessionExp = verified.sessionExp();
      if (sessionExp != null && sessionExp.isBefore(endsAt)) endsAt = sessionExp;
    }
    if (!clock.instant().isBefore(endsAt)) {
      sessions.end(request);
      throw new LoginRequiredException(LoginRequiredException.Reason.SESSION_EXPIRED);
    }
    return state.withEndsAt(endsAt);
  }

  private RuntimeException outage(
      HttpServletRequest request, HttpSession session, PortvaktSessionState state, PortvaktUnavailableException error) {
    Instant now = clock.instant();
    LOG.warn("Portvakt unreachable during refresh");
    Instant since = state.outageSince() == null ? now : state.outageSince();
    Duration grace = settings.outageGrace();
    if (grace.isZero() || Duration.between(since, now).compareTo(grace) > 0) {
      sessions.end(request);
      return new LoginRequiredException(LoginRequiredException.Reason.OUTAGE_GRACE_EXCEEDED);
    }
    if (state.outageSince() == null) state.withOutageSince(now).storeIn(session);
    return new PortvaktUnavailableException("Portvakt is unavailable; the session continues", error);
  }
}
