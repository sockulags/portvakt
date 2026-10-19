package se.portvakt.spring.login;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import se.portvakt.sdk.PortvaktConfigException;

/**
 * AES-256-GCM for token store contents. The first key seals, every key opens (rotation: put the
 * new key first, remove the old one after the longest session has ended). The row's key (the
 * grant id) is the additional authenticated data, so sealed contents cannot be moved to another
 * row. Format: version (1), nonce (12 bytes), ciphertext and tag.
 */
public final class TokenSealer {
  private static final byte VERSION = 1;
  private static final int NONCE_BYTES = 12;
  private static final int TAG_BITS = 128;
  private static final SecureRandom RANDOM = new SecureRandom();

  private final List<SecretKey> keys;

  /** @param base64Keys 32 random bytes each, base64 */
  public TokenSealer(List<String> base64Keys) {
    List<String> issues = new ArrayList<>();
    List<SecretKey> parsed = new ArrayList<>();
    if (base64Keys == null || base64Keys.isEmpty()) {
      issues.add("portvakt.login.token-encryption-key: required for the jdbc token store (32 random bytes, base64)");
    } else {
      for (String value : base64Keys) {
        byte[] bytes;
        try {
          bytes = Base64.getDecoder().decode(value.trim());
        } catch (IllegalArgumentException invalid) {
          bytes = new byte[0];
        }
        if (bytes.length != 32) {
          issues.add("portvakt.login.token-encryption-key: each key must be 32 bytes, base64");
          break;
        }
        parsed.add(new SecretKeySpec(bytes, "AES"));
      }
    }
    if (!issues.isEmpty()) throw new PortvaktConfigException(issues);
    this.keys = List.copyOf(parsed);
  }

  public byte[] seal(byte[] plaintext, String rowKey) {
    byte[] nonce = new byte[NONCE_BYTES];
    RANDOM.nextBytes(nonce);
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, keys.get(0), new GCMParameterSpec(TAG_BITS, nonce));
      cipher.updateAAD(rowKey.getBytes(StandardCharsets.UTF_8));
      byte[] sealed = cipher.doFinal(plaintext);
      return ByteBuffer.allocate(1 + NONCE_BYTES + sealed.length).put(VERSION).put(nonce).put(sealed).array();
    } catch (GeneralSecurityException exception) {
      throw new IllegalStateException("sealing failed", exception);
    }
  }

  /** The plaintext, or {@code null} when no key opens it (or it belongs to another row). */
  public byte[] open(byte[] sealed, String rowKey) {
    if (sealed == null || sealed.length < 1 + NONCE_BYTES + TAG_BITS / 8 || sealed[0] != VERSION) return null;
    for (SecretKey key : keys) {
      try {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, sealed, 1, NONCE_BYTES));
        cipher.updateAAD(rowKey.getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(sealed, 1 + NONCE_BYTES, sealed.length - 1 - NONCE_BYTES);
      } catch (GeneralSecurityException wrongKey) {
        // Try the next key.
      }
    }
    return null;
  }
}
