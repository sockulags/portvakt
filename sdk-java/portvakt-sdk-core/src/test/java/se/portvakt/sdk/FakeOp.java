package se.portvakt.sdk;

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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A minimal OP for unit tests: discovery, JWKS and a token endpoint (client_credentials) on an
 * ephemeral port of 127.0.0.1. {@code down} closes connections without an answer (a network
 * error); {@code serverError} answers every request with that status.
 */
final class FakeOp implements AutoCloseable {
  static final String CLIENT_ID = "fake-app";
  static final String CLIENT_SECRET = "fake-app-secret-0123456789abcdef";

  final HttpServer server;
  final String baseUrl;
  final String issuer;
  final List<ECKey> keys = new CopyOnWriteArrayList<>();
  final AtomicInteger jwksRequests = new AtomicInteger();
  final AtomicInteger discoveryRequests = new AtomicInteger();
  final AtomicInteger tokenRequests = new AtomicInteger();
  final AtomicInteger failedRequests = new AtomicInteger();
  final List<Map<String, String>> tokenForms = new CopyOnWriteArrayList<>();
  final List<String> tokenAuthorizations = new CopyOnWriteArrayList<>();
  volatile boolean down;
  volatile Integer serverError;
  /** An error status for the JWKS only, or for discovery only. */
  volatile Integer jwksError;
  volatile Integer discoveryError;
  /** The JWKS answers its headers at once and then trickles the body, a byte every 200 ms. */
  volatile boolean trickleJwks;
  volatile long tokenLifetime = 300;
  volatile String tokenError;

  FakeOp() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    issuer = baseUrl + "/t/fake";
    keys.add(new ECKeyGenerator(Curve.P_256).keyID("key-1").generate());
    server.createContext("/", this::handle);
    server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
    server.start();
  }

  @Override
  public void close() {
    server.stop(0);
  }

  ECKey signingKey() {
    return keys.get(0);
  }

  /** Adds a published key (a rotation) and returns its kid. */
  String addKey() throws Exception {
    String kid = "key-" + (keys.size() + 1);
    keys.add(new ECKeyGenerator(Curve.P_256).keyID(kid).generate());
    return kid;
  }

  /** A key that is not published. */
  static ECKey foreignKey() throws Exception {
    return new ECKeyGenerator(Curve.P_256).keyID("foreign-" + UUID.randomUUID()).generate();
  }

  String sign(Map<String, Object> claims) throws Exception {
    return sign(claims, signingKey(), new JOSEObjectType("at+jwt"));
  }

  String sign(Map<String, Object> claims, ECKey key, JOSEObjectType type) throws Exception {
    JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID());
    if (type != null) header.type(type);
    SignedJWT jwt = new SignedJWT(header.build(), JWTClaimsSet.parse(claims));
    jwt.sign(new ECDSASigner(key));
    return jwt.serialize();
  }

  PortvaktConfig.Builder config() {
    return PortvaktConfig.builder()
        .issuer(issuer)
        .clientId(CLIENT_ID)
        .clientAuth(ClientAuth.clientSecretBasic(CLIENT_SECRET))
        .allowInsecureRequests(true);
  }

  private void handle(HttpExchange exchange) throws IOException {
    try (exchange) {
      if (down) {
        failedRequests.incrementAndGet();
        // No answer at all: the client sees a closed connection.
        return;
      }
      if (serverError != null) {
        failedRequests.incrementAndGet();
        send(exchange, serverError, "<html>error</html>", "text/html");
        return;
      }
      String path = exchange.getRequestURI().getPath();
      switch (path) {
        case "/t/fake/.well-known/openid-configuration" -> {
          discoveryRequests.incrementAndGet();
          if (discoveryError != null) {
            failedRequests.incrementAndGet();
            send(exchange, discoveryError, "<html>error</html>", "text/html");
            return;
          }
          Map<String, Object> metadata = new LinkedHashMap<>();
          metadata.put("issuer", issuer);
          metadata.put("authorization_endpoint", issuer + "/auth");
          metadata.put("token_endpoint", issuer + "/token");
          metadata.put("jwks_uri", issuer + "/jwks");
          metadata.put("end_session_endpoint", issuer + "/session/end");
          send(exchange, 200, JSONObjectUtils.toJSONString(metadata), "application/json");
        }
        case "/t/fake/jwks" -> {
          jwksRequests.incrementAndGet();
          if (jwksError != null) {
            failedRequests.incrementAndGet();
            send(exchange, jwksError, "<html>error</html>", "text/html");
            return;
          }
          if (trickleJwks) {
            exchange.sendResponseHeaders(200, 100_000);
            for (int index = 0; index < 100 && trickleJwks; index++) {
              exchange.getResponseBody().write(' ');
              exchange.getResponseBody().flush();
              Thread.sleep(200);
            }
            return;
          }
          List<com.nimbusds.jose.jwk.JWK> published = new ArrayList<>();
          for (ECKey key : keys) published.add(key.toPublicJWK());
          send(exchange, 200, new JWKSet(published).toString(true), "application/json");
        }
        case "/t/fake/token" -> {
          tokenRequests.incrementAndGet();
          String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
          Map<String, String> form = new LinkedHashMap<>();
          for (String pair : body.split("&")) {
            String[] parts = pair.split("=", 2);
            form.put(
                java.net.URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
                parts.length > 1 ? java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "");
          }
          tokenForms.add(form);
          String authorization = exchange.getRequestHeaders().getFirst("Authorization");
          if (authorization != null) tokenAuthorizations.add(authorization);
          if (tokenError != null) {
            send(exchange, 400, "{\"error\":\"" + tokenError + "\"}", "application/json");
            return;
          }
          String token = "token-" + tokenRequests.get();
          send(
              exchange,
              200,
              "{\"access_token\":\"" + token + "\",\"token_type\":\"Bearer\",\"expires_in\":" + tokenLifetime + "}",
              "application/json");
        }
        default -> send(exchange, 404, "{}", "application/json");
      }
    } catch (Exception exception) {
      throw new IOException(exception);
    }
  }

  private static void send(HttpExchange exchange, int status, String body, String type) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", type);
    exchange.sendResponseHeaders(status, bytes.length);
    exchange.getResponseBody().write(bytes);
  }
}
