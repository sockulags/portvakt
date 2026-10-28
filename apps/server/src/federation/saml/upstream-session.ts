import { z } from "zod";
import type { KeyRing } from "../../crypto/keyring.js";
import type { UpstreamSession } from "../../repositories/federation-states.js";
import type { LogoutSubject } from "./protocol.js";

/**
 * The upstream SAML session of a login at rest: the NameID and SessionIndex are never stored in
 * the clear. They are sealed (SecretBox) for the SP-initiated LogoutRequest, and indexed with
 * the blind-index key (HMAC, per login method) so an IdP-initiated LogoutRequest finds the
 * sessions. Lookups use the indexes under every configured master key.
 */

const sealedSchema = z
  .object({
    nameId: z.string().min(1).max(1024),
    nameIdFormat: z.string().min(1).max(255).optional(),
    nameQualifier: z.string().min(1).max(1024).optional(),
    spNameQualifier: z.string().min(1).max(1024).optional(),
    sessionIndex: z.string().min(1).max(1024).optional(),
  })
  .strict();

const context = (loginMethodId: string): string => `saml_upstream_session:${loginMethodId}`;
const nameIdValue = (loginMethodId: string, nameId: string): string =>
  `${loginMethodId}:nameid:${nameId}`;
const sessionIndexValue = (loginMethodId: string, sessionIndex: string): string =>
  `${loginMethodId}:session:${sessionIndex}`;

export function sealUpstreamSession(
  keys: KeyRing,
  loginMethodId: string,
  subject: LogoutSubject,
): UpstreamSession {
  const sealed = sealedSchema.parse({
    nameId: subject.nameId,
    ...(subject.nameIdFormat === undefined ? {} : { nameIdFormat: subject.nameIdFormat }),
    ...(subject.nameQualifier === undefined ? {} : { nameQualifier: subject.nameQualifier }),
    ...(subject.spNameQualifier === undefined ? {} : { spNameQualifier: subject.spNameQualifier }),
    ...(subject.sessionIndex === undefined ? {} : { sessionIndex: subject.sessionIndex }),
  });
  return {
    protocol: "saml",
    nameIdIndex: keys.index.compute("saml", nameIdValue(loginMethodId, subject.nameId)).index,
    ...(subject.sessionIndex === undefined
      ? {}
      : {
          sessionIndexIndex: keys.index.compute(
            "saml",
            sessionIndexValue(loginMethodId, subject.sessionIndex),
          ).index,
        }),
    sealed: keys.secrets.encrypt(JSON.stringify(sealed), context(loginMethodId)),
  };
}

export function unsealUpstreamSession(
  keys: KeyRing,
  loginMethodId: string,
  session: UpstreamSession,
): LogoutSubject {
  const data = sealedSchema.parse(
    JSON.parse(keys.secrets.decryptString(session.sealed, context(loginMethodId))),
  );
  return {
    nameId: data.nameId,
    nameIdFormat: data.nameIdFormat,
    nameQualifier: data.nameQualifier,
    spNameQualifier: data.spNameQualifier,
    sessionIndex: data.sessionIndex,
  };
}

/**
 * The same upstream session under the current master key (master key rotation): the sealed
 * values re-wrapped (the data ciphertext kept) and both blind indexes computed again with the
 * current index key. Throws when no configured key opens the sealed values.
 */
export function reindexUpstreamSession(
  keys: KeyRing,
  loginMethodId: string,
  session: UpstreamSession,
): UpstreamSession {
  const subject = unsealUpstreamSession(keys, loginMethodId, session);
  return {
    protocol: "saml",
    nameIdIndex: keys.index.compute("saml", nameIdValue(loginMethodId, subject.nameId)).index,
    ...(subject.sessionIndex === undefined
      ? {}
      : {
          sessionIndexIndex: keys.index.compute(
            "saml",
            sessionIndexValue(loginMethodId, subject.sessionIndex),
          ).index,
        }),
    sealed: keys.secrets.rewrap(session.sealed, context(loginMethodId)),
  };
}

/** The NameID's index under every configured master key (current first). */
export const nameIdIndexCandidates = (
  keys: KeyRing,
  loginMethodId: string,
  nameId: string,
): string[] => keys.index.candidates("saml", nameIdValue(loginMethodId, nameId));

export const sessionIndexCandidates = (
  keys: KeyRing,
  loginMethodId: string,
  sessionIndex: string,
): string[] => keys.index.candidates("saml", sessionIndexValue(loginMethodId, sessionIndex));
