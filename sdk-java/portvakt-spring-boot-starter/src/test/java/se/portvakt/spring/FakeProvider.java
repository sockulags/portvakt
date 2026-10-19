package se.portvakt.spring;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A fake tenant issuer on 127.0.0.1 for the starter's tests: discovery, JWKS and a token endpoint
 * (authorization_code and refresh_token, rotating refresh tokens, ID tokens signed with {@link
 * #key}).
 */
final class FakeProvider implements AutoCloseable {
  static final String CLIENT_ID = "case-service";
  static final String SUB = "3f2b8c4e-91d7-4a3e-8b6f-2d4c9e1a7b55";

  final HttpServer server;
  final String issuer;
  final ECKey key;
  volatile boolean down;
  /** Only the JWKS is unreachable. */
  volatile boolean jwksDown;
  final AtomicInteger codeGrants = new AtomicInteger();
  final AtomicInteger refreshGrants = new AtomicInteger();
  /** The nonce the next code grant's ID token carries. */
  volatile String nonce;
  /** The token endpoint answers with this status and OAuth error instead (for example 401). */
  volatile int tokenErrorStatus;
  volatile String tokenError;
  /** With {@link #tokenErrorStatus}: a Retry-After header, or {@code null}. */
  volatile String tokenRetryAfter;
  /** Further claims of the ID tokens (for example pin and email). */
  volatile Map<String, Object> extraClaims = Map.of();
  /** Delay of the token endpoint, to make concurrent requests overlap. */
  volatile long tokenDelayMillis;
  /** session_exp of the ID tokens (epoch seconds), or {@code null} for none. */
  volatile Long sessionExp = Instant.now().getEpochSecond() + 3600;
  /** Whether a refresh answers with an ID token. */
  volatile boolean refreshIdToken = true;
  volatile String acr = "http://id.elegnamnden.se/loa/1.0/loa3";
  /** The refresh token that is currently valid; others (replays) are refused. */
  volatile String currentRefreshToken;
  volatile long accessTokenLifetime = 300;
  /** The token endpoint answers its headers at once and then trickles the body. */
  volatile boolean trickleToken;

  FakeProvider() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    issuer = "http://127.0.0.1:" + server.getAddress().getPort() + "/t/fake";
    key = new ECKeyGenerator(Curve.P_256).keyID("key-1").generate();
    server.createContext("/", this::handle);
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
  }

  @Override
  public void close() {
    server.stop(0);
  }

  /** ID token claims as Portvakt issues them. */
  Map<String, Object> idTokenClaims(String withNonce) {
    long now = Instant.now().getEpochSecond();
    Map<String, Object> claims = new HashMap<>();
    claims.put("iss", issuer);
    claims.put("aud", CLIENT_ID);
    claims.put("sub", SUB);
    claims.put("tid", "fake");
    claims.put("idp", "0f1976f6-7f6c-4baf-a88c-2bc6f2e68ce7");
    claims.put("idp_kind", "citizen");
    claims.put("acr", acr);
    claims.put("auth_time", now);
    if (sessionExp != null) claims.put("session_exp", sessionExp);
    claims.put("roles", List.of("handlaggare"));
    claims.put("attrs", Map.of());
    claims.put("name", "Sven Medborgare");
    if (withNonce != null) claims.put("nonce", withNonce);
    claims.putAll(extraClaims);
    claims.put("iat", now);
    claims.put("exp", now + 300);
    return claims;
  }

  String sign(Map<String, Object> claims, JOSEObjectType type) throws Exception {
    JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID());
    if (type != null) header.type(type);
    SignedJWT jwt = new SignedJWT(header.build(), JWTClaimsSet.parse(claims));
    jwt.sign(new ECDSASigner(key));
    return jwt.serialize();
  }

  private void handle(HttpExchange exchange) throws IOException {
    try (exchange) {
      if (down) return;
      String path = exchange.getRequestURI().getPath();
      switch (path) {
        case "/t/fake/.well-known/openid-configuration" ->
            send(
                exchange,
                200,
                "{\"issuer\":\"" + issuer + "\",\"authorization_endpoint\":\"" + issuer + "/auth\",\"token_endpoint\":\""
                    + issuer + "/token\",\"jwks_uri\":\"" + issuer + "/jwks\",\"end_session_endpoint\":\"" + issuer
                    + "/session/end\"}");
        case "/t/fake/jwks" -> {
          if (jwksDown) {
            send(exchange, 503, "{}");
            return;
          }
          send(exchange, 200, new JWKSet(key.toPublicJWK()).toString(true));
        }
        case "/t/fake/token" -> token(exchange);
        default -> exchange.sendResponseHeaders(404, -1);
      }
    } catch (IOException exception) {
      throw exception;
    } catch (Exception exception) {
      throw new IOException(exception);
    }
  }

  private void token(HttpExchange exchange) throws Exception {
    Map<String, String> form = new LinkedHashMap<>();
    for (String pair : new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).split("&")) {
      String[] parts = pair.split("=", 2);
      form.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8), parts.length > 1 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "");
    }
    if (tokenDelayMillis > 0) Thread.sleep(tokenDelayMillis);
    if (trickleToken) {
      exchange.getResponseHeaders().set("Content-Type", "application/json");
      exchange.sendResponseHeaders(200, 100_000);
      for (int index = 0; index < 100 && trickleToken; index++) {
        exchange.getResponseBody().write(' ');
        exchange.getResponseBody().flush();
        Thread.sleep(200);
      }
      return;
    }
    if (tokenErrorStatus != 0) {
      if (tokenRetryAfter != null) exchange.getResponseHeaders().set("Retry-After", tokenRetryAfter);
      send(exchange, tokenErrorStatus, "{\"error\":\"" + tokenError + "\"}");
      return;
    }
    String grant = form.get("grant_type");
    Map<String, Object> body = new LinkedHashMap<>();
    if ("authorization_code".equals(grant)) {
      int count = codeGrants.incrementAndGet();
      if (count > 1 && "used-code".equals(form.get("code"))) {
        send(exchange, 400, "{\"error\":\"invalid_grant\"}");
        return;
      }
      body.put("id_token", sign(idTokenClaims(nonce), null));
    } else if ("refresh_token".equals(grant)) {
      refreshGrants.incrementAndGet();
      if (currentRefreshToken != null && !currentRefreshToken.equals(form.get("refresh_token"))) {
        send(exchange, 400, "{\"error\":\"invalid_grant\"}");
        return;
      }
      if (refreshIdToken) body.put("id_token", sign(idTokenClaims(null), null));
    } else {
      send(exchange, 400, "{\"error\":\"unsupported_grant_type\"}");
      return;
    }
    String refreshToken = "refresh-" + java.util.UUID.randomUUID();
    currentRefreshToken = refreshToken;
    body.put("access_token", "access-" + java.util.UUID.randomUUID());
    body.put("token_type", "Bearer");
    body.put("expires_in", accessTokenLifetime);
    body.put("refresh_token", refreshToken);
    body.put("scope", "openid profile email");
    send(exchange, 200, JSONObjectUtils.toJSONString(body));
  }

  private static void send(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, bytes.length);
    exchange.getResponseBody().write(bytes);
  }
}
