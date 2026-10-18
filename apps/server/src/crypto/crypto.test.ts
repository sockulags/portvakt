import { createHmac, createPublicKey, createSign, createVerify, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { BlindIndex } from "./blind-index.js";
import { EnvelopeError, masterKeyId, SecretBox } from "./envelope.js";
import { ecThumbprint, generateSigningKey, publicJwkSchema } from "./jwk.js";
import { constantTimeEqual, generateClientSecret, MIN_CLIENT_SECRET_LENGTH } from "./secrets.js";

const keyA = randomBytes(32);
const keyB = randomBytes(32);
const context = "login_method:5f1c4b8e-0000-4000-8000-000000000001:client_secret";

/** Flips one bit in segment `index` of an envelope. */
function tamper(envelope: string, index: number): string {
  const parts = envelope.split(".");
  const bytes = Buffer.from(parts[index] ?? "", "base64url");
  bytes[0] = (bytes[0] ?? 0) ^ 0x01;
  parts[index] = bytes.toString("base64url");
  return parts.join(".");
}

function expectEnvelopeError(fn: () => unknown, code: EnvelopeError["code"]): void {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(EnvelopeError);
    expect((error as EnvelopeError).code).toBe(code);
    return;
  }
  expect.fail("expected an EnvelopeError");
}

describe("SecretBox", () => {
  const box = SecretBox.fromMasterKeys({ current: keyA, previous: [] });

  it("round-trips strings and bytes", () => {
    const envelope = box.encrypt("upstream-secret ÅÄÖ", context);
    expect(box.decryptString(envelope, context)).toBe("upstream-secret ÅÄÖ");
    const bytes = randomBytes(100);
    expect(box.decrypt(box.encrypt(bytes, context), context).equals(bytes)).toBe(true);
    expect(box.decryptString(box.encrypt("", context), context)).toBe("");
  });

  it("produces a versioned format carrying the master key id, never the plaintext", () => {
    const envelope = box.encrypt("plain-text-secret", context);
    const parts = envelope.split(".");
    expect(parts).toHaveLength(6);
    expect(parts[0]).toBe("pv1");
    expect(parts[1]).toBe(masterKeyId(keyA));
    expect(box.keyIdOf(envelope)).toBe(box.currentKeyId);
    expect(envelope).not.toContain("plain-text-secret");
    expect(Buffer.from(envelope).toString("base64")).not.toContain(
      Buffer.from("plain-text-secret").toString("base64"),
    );
  });

  it("uses a fresh data key and IV for every encryption", () => {
    const first = box.encrypt("same", context);
    const second = box.encrypt("same", context);
    expect(first).not.toBe(second);
    expect(first.split(".")[3]).not.toBe(second.split(".")[3]);
    expect(first.split(".")[4]).not.toBe(second.split(".")[4]);
  });

  it("detects tampering in every segment", () => {
    const envelope = box.encrypt("secret", context);
    for (const index of [2, 3, 4, 5]) {
      expectEnvelopeError(
        () => box.decrypt(tamper(envelope, index), context),
        "authentication_failed",
      );
    }
  });

  it("detects truncation and a changed key id", () => {
    const envelope = box.encrypt("secret", context);
    const parts = envelope.split(".");
    const truncated = [...parts.slice(0, 5), (parts[5] ?? "").slice(0, 10)].join(".");
    expectEnvelopeError(() => box.decrypt(truncated, context), "malformed");
    const otherKid = [parts[0], masterKeyId(keyB), ...parts.slice(2)].join(".");
    expectEnvelopeError(() => box.decrypt(otherKid, context), "unknown_key");
  });

  it("binds the ciphertext to its context", () => {
    const envelope = box.encrypt("secret", context);
    expectEnvelopeError(
      () => box.decrypt(envelope, "login_method:other:client_secret"),
      "authentication_failed",
    );
    expect(() => box.encrypt("secret", "")).toThrow(TypeError);
  });

  it("rejects malformed and unsupported envelopes", () => {
    for (const value of [
      "",
      "pv1",
      "pv2.a.b.c.d.e",
      "pv1.a.b.c.d",
      "pv1.a.b.c.d.e!",
      "pv1.....x",
    ]) {
      expectEnvelopeError(() => box.decrypt(value, context), "malformed");
    }
  });

  it("refuses master keys of the wrong length", () => {
    expect(() => SecretBox.fromMasterKeys({ current: randomBytes(16), previous: [] })).toThrow(
      TypeError,
    );
  });

  describe("master key rotation", () => {
    const oldBox = SecretBox.fromMasterKeys({ current: keyA, previous: [] });
    const rotated = SecretBox.fromMasterKeys({ current: keyB, previous: [keyA] });
    const newOnly = SecretBox.fromMasterKeys({ current: keyB, previous: [] });

    it("decrypts values wrapped by a previous key and flags them for re-wrapping", () => {
      const envelope = oldBox.encrypt("secret", context);
      expect(rotated.decryptString(envelope, context)).toBe("secret");
      expect(rotated.needsRewrap(envelope)).toBe(true);
      expect(rotated.needsRewrap(rotated.encrypt("secret", context))).toBe(false);
      expectEnvelopeError(() => newOnly.decrypt(envelope, context), "unknown_key");
    });

    it("re-wraps under the current key, keeping the data ciphertext", () => {
      const envelope = oldBox.encrypt("secret", context);
      const rewrapped = rotated.rewrap(envelope, context);
      expect(rotated.keyIdOf(rewrapped)).toBe(masterKeyId(keyB));
      expect(rewrapped.split(".").slice(4)).toEqual(envelope.split(".").slice(4));
      // After rotation the old key can be dropped.
      expect(newOnly.decryptString(rewrapped, context)).toBe("secret");
      expectEnvelopeError(() => oldBox.decrypt(rewrapped, context), "unknown_key");
    });

    it("refuses to re-wrap a tampered value or one under the wrong context", () => {
      const envelope = oldBox.encrypt("secret", context);
      expectEnvelopeError(
        () => rotated.rewrap(tamper(envelope, 5), context),
        "authentication_failed",
      );
      expectEnvelopeError(() => rotated.rewrap(envelope, "other"), "authentication_failed");
    });
  });
});

describe("client secrets", () => {
  it("generates 256-bit secrets", () => {
    const secret = generateClientSecret();
    expect(Buffer.from(secret, "base64url")).toHaveLength(32);
    expect(secret.length).toBeGreaterThanOrEqual(MIN_CLIENT_SECRET_LENGTH);
    expect(generateClientSecret()).not.toBe(secret);
  });
});

describe("BlindIndex", () => {
  const index = BlindIndex.fromMasterKeys({ current: keyA, previous: [] });

  it("is deterministic per purpose and value, and reveals neither", () => {
    const first = index.compute("pin", "191212121212");
    expect(index.compute("pin", "191212121212")).toEqual(first);
    expect(first.keyId).toBe(masterKeyId(keyA));
    expect(first.index).not.toContain("191212121212");
    expect(index.compute("orgnr", "191212121212").index).not.toBe(first.index);
    expect(index.compute("pin", "191212121213").index).not.toBe(first.index);
  });

  it("differs per master key and finds old indexes through candidates after rotation", () => {
    const rotated = BlindIndex.fromMasterKeys({ current: keyB, previous: [keyA] });
    const old = index.compute("pin", "191212121212");
    const current = rotated.compute("pin", "191212121212");
    expect(current.index).not.toBe(old.index);
    expect(current.keyId).toBe(masterKeyId(keyB));
    expect(rotated.candidates("pin", "191212121212")).toEqual([current.index, old.index]);
  });

  it("uses a key independent from the envelope key", () => {
    const value = "191212121212";
    const plainHmac = createHmac("sha256", keyA).update(`pin:${value}`).digest("base64url");
    expect(index.compute("pin", value).index).not.toBe(plainHmac);
  });
});

describe("constantTimeEqual", () => {
  it("compares values of any length", () => {
    expect(constantTimeEqual("abc", "abc")).toBe(true);
    expect(constantTimeEqual("abc", "abd")).toBe(false);
    expect(constantTimeEqual("abc", "abcd")).toBe(false);
    expect(constantTimeEqual(Buffer.from("x"), "x")).toBe(true);
    expect(constantTimeEqual("", "")).toBe(true);
  });
});

describe("generateSigningKey", () => {
  it("creates an ES256 key whose kid is its thumbprint and whose public JWK verifies", () => {
    const key = generateSigningKey();
    expect(key.alg).toBe("ES256");
    expect(key.kid).toBe(ecThumbprint(key.publicJwk));
    expect(publicJwkSchema.parse(key.publicJwk)).toEqual(key.publicJwk);
    expect("d" in key.publicJwk).toBe(false);
    expect(() => publicJwkSchema.parse(key.privateJwk)).toThrow();

    const signature = createSign("SHA256")
      .update("payload")
      .sign({ key: { ...key.privateJwk }, format: "jwk", dsaEncoding: "ieee-p1363" });
    const publicKey = createPublicKey({ key: { ...key.publicJwk }, format: "jwk" });
    expect(
      createVerify("SHA256")
        .update("payload")
        .verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, signature),
    ).toBe(true);
    expect(generateSigningKey().kid).not.toBe(key.kid);
  });
});
