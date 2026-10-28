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

/** An optional value of the assertion; an empty attribute (`SPNameQualifier=""`) is absent. */
const present = (value: string | undefined): string | undefined =>
  value === undefined || value === "" ? undefined : value;

export function sealUpstreamSession(
  keys: KeyRing,
  loginMethodId: string,
  subject: LogoutSubject,
): UpstreamSession {
  const nameIdFormat = present(subject.nameIdFormat);
  const nameQualifier = present(subject.nameQualifier);
  const spNameQualifier = present(subject.spNameQualifier);
  const sessionIndex = present(subject.sessionIndex);
  const sealed = sealedSchema.parse({
    nameId: subject.nameId,
    ...(nameIdFormat === undefined ? {} : { nameIdFormat }),
    ...(nameQualifier === undefined ? {} : { nameQualifier }),
    ...(spNameQualifier === undefined ? {} : { spNameQualifier }),
    ...(sessionIndex === undefined ? {} : { sessionIndex }),
  });
  return {
    protocol: "saml",
    nameIdIndex: keys.index.compute("saml", nameIdValue(loginMethodId, subject.nameId)).index,
    ...(sessionIndex === undefined
      ? {}
      : {
          sessionIndexIndex: keys.index.compute(
            "saml",
            sessionIndexValue(loginMethodId, sessionIndex),
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
