package se.portvakt.sdk;

import java.net.URI;
import java.util.Map;

/**
 * Portvakt's discovery metadata for the tenant ({@code /.well-known/openid-configuration}).
 *
 * @param issuer the issuer, equal to the configured one
 * @param authorizationEndpoint the authorization endpoint
 * @param tokenEndpoint the token endpoint
 * @param jwksUri the JWKS
 * @param endSessionEndpoint RP-initiated logout, or {@code null}
 * @param raw every metadata value as published
 */
public record ProviderMetadata(
    String issuer,
    URI authorizationEndpoint,
    URI tokenEndpoint,
    URI jwksUri,
    URI endSessionEndpoint,
    Map<String, Object> raw) {
  public ProviderMetadata {
    raw = Map.copyOf(raw);
  }
}
