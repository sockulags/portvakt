package se.portvakt.sdk.internal;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Strict readers for the claims contract (docs/claims.md), mirroring the TypeScript SDK's zod
 * schemas: an optional claim may be absent, but a present claim (also JSON {@code null}) must
 * have the right type and size. Every reader throws {@link Invalid} instead of returning a
 * half-valid value. Internal API.
 */
public final class Claims {
  /** A claim does not follow the contract. Never carries a claim value. */
  public static final class Invalid extends Exception {
    private static final long serialVersionUID = 1L;

    public Invalid(String claim) {
      super("invalid claim: " + claim);
    }
  }

  private static final long MAX_SAFE_INTEGER = 9_007_199_254_740_991L;

  private final Map<String, Object> claims;

  public Claims(Map<String, Object> claims) {
    this.claims = claims;
  }

  public boolean has(String name) {
    return claims.containsKey(name);
  }

  /** A required string of 1 to 512 characters. */
  public String shortString(String name) throws Invalid {
    Object value = claims.get(name);
    if (!(value instanceof String text) || text.isEmpty() || text.length() > 512) {
      throw new Invalid(name);
    }
    return text;
  }

  /** An optional string of at most {@code max} characters; {@code null} when absent. */
  public String optionalString(String name, int max) throws Invalid {
    if (!claims.containsKey(name)) return null;
    Object value = claims.get(name);
    if (!(value instanceof String text) || text.length() > max) throw new Invalid(name);
    return text;
  }

  /** A required non-negative integer (epoch seconds). */
  public long nonNegativeInteger(String name) throws Invalid {
    long value = integer(name, claims.get(name));
    if (value < 0) throw new Invalid(name);
    return value;
  }

  /** An optional positive integer; {@code null} when absent. */
  public Long optionalPositiveInteger(String name) throws Invalid {
    if (!claims.containsKey(name)) return null;
    long value = integer(name, claims.get(name));
    if (value <= 0) throw new Invalid(name);
    return value;
  }

  /** Roles: absent means none; at most 1000 strings of at most 255 characters. */
  public List<String> roles() throws Invalid {
    if (!claims.containsKey("roles")) return List.of();
    return stringList("roles", claims.get("roles"), 1000, 255);
  }

  /** Attributes: absent means none; string keys (at most 255) to strings (at most 4000). */
  public Map<String, String> attrs() throws Invalid {
    if (!claims.containsKey("attrs")) return Map.of();
    if (!(claims.get("attrs") instanceof Map<?, ?> map)) throw new Invalid("attrs");
    Map<String, String> result = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : map.entrySet()) {
      if (!(entry.getKey() instanceof String key) || key.length() > 255) throw new Invalid("attrs");
      if (!(entry.getValue() instanceof String value) || value.length() > 4000) {
        throw new Invalid("attrs");
      }
      result.put(key, value);
    }
    return result;
  }

  /** An optional list of at most {@code maxItems} strings of at most {@code maxLength}. */
  public List<String> optionalStringList(String name, int maxItems, int maxLength) throws Invalid {
    if (!claims.containsKey(name)) return null;
    return stringList(name, claims.get(name), maxItems, maxLength);
  }

  /** {@code aud}: one short string or a list of them. */
  public List<String> audience() throws Invalid {
    Object value = claims.get("aud");
    if (value instanceof String) return List.of(shortString("aud"));
    if (!(value instanceof List<?> list)) throw new Invalid("aud");
    List<String> result = new ArrayList<>();
    for (Object item : list) {
      if (!(item instanceof String text) || text.isEmpty() || text.length() > 512) {
        throw new Invalid("aud");
      }
      result.add(text);
    }
    return List.copyOf(result);
  }

  /** An optional object claim; {@code null} when absent. */
  public Claims optionalObject(String name) throws Invalid {
    if (!claims.containsKey(name)) return null;
    if (!(claims.get(name) instanceof Map<?, ?> map)) throw new Invalid(name);
    Map<String, Object> copy = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : map.entrySet()) {
      if (!(entry.getKey() instanceof String key)) throw new Invalid(name);
      copy.put(key, entry.getValue());
    }
    return new Claims(copy);
  }

  /** The raw value (for enum claims). */
  public Object raw(String name) {
    return claims.get(name);
  }

  private static long integer(String name, Object value) throws Invalid {
    if (value instanceof Long || value instanceof Integer || value instanceof Short) {
      long number = ((Number) value).longValue();
      if (Math.abs(number) > MAX_SAFE_INTEGER) throw new Invalid(name);
      return number;
    }
    if (value instanceof Double || value instanceof Float) {
      double number = ((Number) value).doubleValue();
      if (!Double.isFinite(number) || number != Math.rint(number)) throw new Invalid(name);
      if (Math.abs(number) > MAX_SAFE_INTEGER) throw new Invalid(name);
      return (long) number;
    }
    if (value instanceof java.math.BigInteger || value instanceof java.math.BigDecimal) {
      try {
        long number = ((Number) value) instanceof java.math.BigDecimal decimal
            ? decimal.longValueExact()
            : ((java.math.BigInteger) value).longValueExact();
        if (Math.abs(number) > MAX_SAFE_INTEGER) throw new Invalid(name);
        return number;
      } catch (ArithmeticException exception) {
        throw new Invalid(name);
      }
    }
    throw new Invalid(name);
  }

  private static List<String> stringList(String name, Object value, int maxItems, int maxLength)
      throws Invalid {
    if (!(value instanceof List<?> list) || list.size() > maxItems) throw new Invalid(name);
    List<String> result = new ArrayList<>(list.size());
    for (Object item : list) {
      if (!(item instanceof String text) || text.length() > maxLength) throw new Invalid(name);
      result.add(text);
    }
    return List.copyOf(result);
  }
}
