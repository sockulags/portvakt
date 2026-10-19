package se.portvakt.spring.login;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.time.Clock;
import java.time.Duration;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * Pending logins, single use: the authorization request (with its PKCE verifier and nonce) lives
 * in the {@link PortvaktTokenStore} and the HTTP session holds only a pointer (a random key and
 * the state), which binds the login to the browser. Removing it at the callback is an atomic take
 * from the store, so of two concurrent callbacks with the same state only one gets the login and
 * redeems the code (a second redemption would make Portvakt revoke the grant). A login started
 * later in the same browser replaces the pending one.
 */
public class PortvaktAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
  /** The session attribute pointing at the pending login. */
  public static final String ATTRIBUTE = PortvaktAuthorizationRequestRepository.class.getName();

  /** How long a started login may take. */
  public static final Duration LOGIN_TIMEOUT = Duration.ofMinutes(10);

  private record Pointer(String key, String state) implements Serializable {}

  private final PortvaktTokenStore store;
  private final Clock clock;

  public PortvaktAuthorizationRequestRepository(PortvaktTokenStore store, Clock clock) {
    this.store = store;
    this.clock = clock;
  }

  @Override
  public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
    Pointer pointer = pointer(request);
    if (pointer == null) return null;
    byte[] value = store.loadPending(pointer.key);
    return value == null ? null : deserialize(value);
  }

  @Override
  public void saveAuthorizationRequest(
      OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
    HttpSession session = request.getSession();
    if (session.getAttribute(ATTRIBUTE) instanceof Pointer previous) store.deletePending(previous.key);
    if (authorizationRequest == null) {
      session.removeAttribute(ATTRIBUTE);
      return;
    }
    String key = PortvaktAuthorizedClientRepository.newGrantId();
    store.savePending(key, serialize(authorizationRequest), clock.instant().plus(LOGIN_TIMEOUT));
    session.setAttribute(ATTRIBUTE, new Pointer(key, authorizationRequest.getState()));
  }

  @Override
  public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
    Pointer pointer = pointer(request);
    if (pointer == null) return null;
    byte[] value = store.takePending(pointer.key);
    HttpSession session = request.getSession(false);
    if (session != null) {
      try {
        session.removeAttribute(ATTRIBUTE);
      } catch (IllegalStateException invalidated) {
        // Nothing to remove.
      }
    }
    return value == null ? null : deserialize(value);
  }

  /** The session's pointer, when the request's state parameter is the pending login's. */
  private static Pointer pointer(HttpServletRequest request) {
    String state = request.getParameter("state");
    HttpSession session = request.getSession(false);
    if (state == null || session == null) return null;
    Object value;
    try {
      value = session.getAttribute(ATTRIBUTE);
    } catch (IllegalStateException invalidated) {
      return null;
    }
    if (!(value instanceof Pointer pointer)) return null;
    return java.security.MessageDigest.isEqual(
            pointer.state.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            state.getBytes(java.nio.charset.StandardCharsets.UTF_8))
        ? pointer
        : null;
  }

  private static byte[] serialize(OAuth2AuthorizationRequest request) {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
      out.writeObject(request);
    } catch (IOException exception) {
      throw new IllegalStateException("cannot store the pending login", exception);
    }
    return bytes.toByteArray();
  }

  /** Only what an authorization request is made of (the store's contents are sealed anyway). */
  private static final ObjectInputFilter FILTER =
      ObjectInputFilter.Config.createFilter(
          "maxdepth=20;maxrefs=10000;maxbytes=262144;"
              + "org.springframework.security.oauth2.core.**;java.lang.*;java.util.*;java.time.*;!*");

  private static OAuth2AuthorizationRequest deserialize(byte[] value) {
    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(value))) {
      in.setObjectInputFilter(FILTER);
      return in.readObject() instanceof OAuth2AuthorizationRequest request ? request : null;
    } catch (IOException | ClassNotFoundException exception) {
      return null;
    }
  }
}
