import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Constant-time comparison of two secrets. Both sides are hashed first, so neither the content
 * nor the length of the expected value leaks through timing.
 */
export function constantTimeEqual(a: string | Uint8Array, b: string | Uint8Array): boolean {
  const digestA = createHash("sha256").update(a).digest();
  const digestB = createHash("sha256").update(b).digest();
  return timingSafeEqual(digestA, digestB);
}

const CLIENT_SECRET_BYTES = 32;
/**
 * Minimum length of a downstream client secret. Secrets are machine generated (see
 * {@link generateClientSecret}); the minimum keeps human-chosen passwords out.
 */
export const MIN_CLIENT_SECRET_LENGTH = 32;

/** Generates a downstream client secret (256 bits, base64url). Shown to the admin once. */
export function generateClientSecret(): string {
  return randomBytes(CLIENT_SECRET_BYTES).toString("base64url");
}
