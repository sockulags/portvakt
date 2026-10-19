package se.portvakt.sdk;

import java.io.Serializable;
import java.util.Objects;

/**
 * The party a person acts for (representation, ombud): {@code rep} in the tokens.
 *
 * <p>{@code sub} is the party's id in Portvakt's party register (never a personal identity or
 * organisation number). {@code name} is only known from the ID token (browser sessions) and never
 * for a person party with a protected identity. <b>Applications must authorise every action on
 * behalf of {@code sub} with their own rules</b>: Portvakt only attests that the signed-in person
 * holds a representation right for the party in this application.
 *
 * @param sub the party's UUID
 * @param type person or organisation
 * @param name display name, or {@code null}
 */
public record Representation(String sub, Type type, String name) implements Serializable {
  /** The kind of party. */
  public enum Type {
    PERSON("person"),
    ORGANISATION("organisation");

    private final String claimValue;

    Type(String claimValue) {
      this.claimValue = claimValue;
    }

    public String claimValue() {
      return claimValue;
    }

    static Type fromClaim(Object value) {
      for (Type type : values()) {
        if (type.claimValue.equals(value)) return type;
      }
      return null;
    }
  }

  public Representation {
    Objects.requireNonNull(sub, "sub");
    Objects.requireNonNull(type, "type");
  }

  @Override
  public String toString() {
    // The name is personal data when the party is a person: never in logs.
    return "Representation[sub=" + sub + ", type=" + type.claimValue + "]";
  }
}
