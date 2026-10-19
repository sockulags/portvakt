package se.portvakt.sdk;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * Assurance level ordering, lowest first, with Portvakt's semantics: equal values always match;
 * otherwise both values must be ranked and the given one must rank at least as high. Values
 * outside the ranking only ever match themselves. Must match Portvakt's {@code ACR_RANKING}.
 */
public final class AcrRanking implements Serializable {
  private static final long serialVersionUID = 1L;

  public static final String LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2";
  public static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";
  public static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

  /** The Swedish eID Framework levels loa2 &lt; loa3 &lt; loa4, Portvakt's default. */
  public static final AcrRanking DEFAULT = new AcrRanking(List.of(LOA2, LOA3, LOA4));

  private final List<String> levels;

  private AcrRanking(List<String> levels) {
    this.levels = List.copyOf(levels);
  }

  /** A ranking, lowest first. */
  public static AcrRanking of(List<String> levels) {
    Objects.requireNonNull(levels, "levels");
    return new AcrRanking(levels);
  }

  public List<String> levels() {
    return levels;
  }

  /** Whether {@code acr} meets {@code required}. A {@code null} acr never does. */
  public boolean atLeast(String acr, String required) {
    if (acr == null || required == null) return false;
    if (acr.equals(required)) return true;
    int have = levels.indexOf(acr);
    int need = levels.indexOf(required);
    return have >= 0 && need >= 0 && have >= need;
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof AcrRanking ranking && ranking.levels.equals(levels);
  }

  @Override
  public int hashCode() {
    return levels.hashCode();
  }

  @Override
  public String toString() {
    return "AcrRanking" + levels;
  }
}
