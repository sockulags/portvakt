package se.portvakt.sdk;

import com.nimbusds.jose.jwk.JWK;
import java.text.ParseException;
import java.util.Objects;

/** How the application authenticates at Portvakt's token endpoint. */
public sealed interface ClientAuth {
  /** {@code client_secret_basic}, {@code client_secret_post} or {@code private_key_jwt}. */
  String method();

  /** {@code client_secret_basic}: HTTP Basic with the form-encoded client_id and secret. */
  static ClientAuth clientSecretBasic(String clientSecret) {
    return new ClientSecret("client_secret_basic", clientSecret);
  }

  /** {@code client_secret_post}: client_id and client_secret in the form body. */
  static ClientAuth clientSecretPost(String clientSecret) {
    return new ClientSecret("client_secret_post", clientSecret);
  }

  /**
   * {@code private_key_jwt} with a private JWK (EC P-256 signs ES256, RSA signs RS256 unless the
   * JWK names its {@code alg}). Its public part must be registered with the application in
   * Portvakt, under the same {@code kid}.
   */
  static ClientAuth privateKeyJwt(JWK privateJwk) {
    return new PrivateKeyJwt(privateJwk);
  }

  /** {@link #privateKeyJwt(JWK)} from the JWK's JSON. */
  static ClientAuth privateKeyJwt(String privateJwkJson) {
    try {
      return new PrivateKeyJwt(JWK.parse(privateJwkJson));
    } catch (ParseException | RuntimeException exception) {
      throw new PortvaktConfigException(
          java.util.List.of("clientAuth.privateJwk: not a valid JWK"));
    }
  }

  /** A client secret, sent with Basic authentication or in the form body. */
  record ClientSecret(String method, String clientSecret) implements ClientAuth {
    public ClientSecret {
      Objects.requireNonNull(method, "method");
    }

    @Override
    public String toString() {
      return "ClientSecret[method=" + method + "]";
    }
  }

  /** A signed client assertion (RFC 7523) with the application's private key. */
  record PrivateKeyJwt(JWK privateJwk) implements ClientAuth {
    @Override
    public String method() {
      return "private_key_jwt";
    }

    @Override
    public String toString() {
      return "PrivateKeyJwt[kid=" + (privateJwk == null ? null : privateJwk.getKeyID()) + "]";
    }
  }
}
