import { randomUUID } from "node:crypto";
import type { KeyRing } from "../crypto/keyring.js";
import type { Db } from "../db/database.js";
import { personnummerSchema } from "../domain/personnummer.js";
import {
  type Identity,
  type IdentityAttributes,
  identityAttributesSchema,
  jitLoginInputSchema,
  PIN_INDEX_SUBJECT_PREFIX,
  type JitLoginInput,
  type JitLoginResult,
  type Person,
} from "../domain/person.js";
import {
  InvalidReferenceError,
  mapDbErrors,
  NotFoundError,
  parseInput,
  requireUuids,
} from "./errors.js";
import { resolvePending } from "./pending.js";
import { requireRow } from "./sql.js";

interface PersonRow {
  id: string;
  tenant_id: string;
  created_at: Date;
  updated_at: Date;
  last_login_at: Date | null;
  protected_identity: boolean;
}

interface IdentityRow {
  id: string;
  tenant_id: string;
  person_id: string;
  login_method_id: string;
  subject: string;
  attributes: unknown;
  pin_index: string | null;
  created_at: Date;
  updated_at: Date;
  last_login_at: Date;
}

const PERSON_COLUMNS = "id, tenant_id, created_at, updated_at, last_login_at, protected_identity";
const IDENTITY_COLUMNS =
  "id, tenant_id, person_id, login_method_id, subject, attributes, pin_index, created_at, updated_at, last_login_at";

interface PersonSummaryRow {
  id: string;
  created_at: Date;
  last_login_at: Date | null;
  protected_identity: boolean;
  name: string | null;
  email: string | null;
}

/** A person as the admin search lists it: the latest name and email of any identity. */
export interface PersonSummary {
  readonly id: string;
  readonly createdAt: Date;
  readonly lastLoginAt: Date | null;
  readonly protectedIdentity: boolean;
  /** `null` for a protected identity (no name is stored) or when no upstream sent one. */
  readonly displayName: string | null;
  readonly email: string | null;
}

const SELECT_SUMMARY = `
  SELECT p.id, p.created_at, p.last_login_at, p.protected_identity, latest.name, latest.email
    FROM persons p
    LEFT JOIN LATERAL (
      SELECT i.attributes ->> 'name' AS name, i.attributes ->> 'email' AS email
        FROM identities i
       WHERE i.tenant_id = p.tenant_id AND i.person_id = p.id
         AND (i.attributes ? 'name' OR i.attributes ? 'email')
       ORDER BY i.last_login_at DESC, i.id
       LIMIT 1
    ) latest ON true`;

const toSummary = (row: PersonSummaryRow): PersonSummary => ({
  id: row.id,
  createdAt: row.created_at,
  lastLoginAt: row.last_login_at,
  protectedIdentity: row.protected_identity,
  displayName: row.protected_identity ? null : row.name,
  email: row.protected_identity ? null : row.email,
});

/** AAD context binding an encrypted personal identity number to its identity. */
export const identityPinContext = (identityId: string): string => `identity:${identityId}:pin`;

function toPerson(row: PersonRow): Person {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastLoginAt: row.last_login_at,
    protectedIdentity: row.protected_identity,
  };
}

function toIdentity(row: IdentityRow): Identity {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    personId: row.person_id,
    loginMethodId: row.login_method_id,
    subject: row.subject,
    attributes: identityAttributesSchema.parse(row.attributes),
    pinIndex: row.pin_index,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastLoginAt: row.last_login_at,
  };
}

/** A flagged identity keeps no name or email (and its person becomes protected). */
function storableAttributes(attributes: IdentityAttributes): IdentityAttributes {
  if (!attributes.protectedIdentity) return attributes;
  return {
    groups: attributes.groups,
    protectedIdentity: true,
    ...(attributes.upstreamAcr === undefined ? {} : { upstreamAcr: attributes.upstreamAcr }),
    ...(attributes.hsaId === undefined ? {} : { hsaId: attributes.hsaId }),
    ...(attributes.orgAffiliation === undefined
      ? {}
      : { orgAffiliation: attributes.orgAffiliation }),
  };
}

export class PersonRepository {
  readonly #db: Db;
  readonly #keys: KeyRing;

  constructor(db: Db, keys: KeyRing) {
    this.#db = db;
    this.#keys = keys;
  }

  async findById(tenantId: string, id: string): Promise<Person | null> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<PersonRow>(
      `SELECT ${PERSON_COLUMNS} FROM persons WHERE tenant_id = $1 AND id = $2`,
      [tenantId, id],
    );
    return row === undefined ? null : toPerson(row);
  }

  async listIdentities(tenantId: string, personId: string): Promise<Identity[]> {
    requireUuids({ tenantId, personId });
    const rows = await this.#db.query<IdentityRow>(
      `SELECT ${IDENTITY_COLUMNS} FROM identities
        WHERE tenant_id = $1 AND person_id = $2 ORDER BY created_at, id`,
      [tenantId, personId],
    );
    return rows.map(toIdentity);
  }

  async findIdentity(
    tenantId: string,
    loginMethodId: string,
    subject: string,
  ): Promise<Identity | null> {
    requireUuids({ tenantId, loginMethodId });
    const [row] = await this.#db.query<IdentityRow>(
      `SELECT ${IDENTITY_COLUMNS} FROM identities
        WHERE tenant_id = $1 AND login_method_id = $2 AND subject = $3`,
      [tenantId, loginMethodId, subject],
    );
    return row === undefined ? null : toIdentity(row);
  }

  /** Decrypted personal identity number of an identity (for the `pin` claim). Never log it. */
  async getPin(tenantId: string, identityId: string): Promise<string | null> {
    requireUuids({ tenantId, identityId });
    const [row] = await this.#db.query<{ pin_encrypted: string | null }>(
      "SELECT pin_encrypted FROM identities WHERE tenant_id = $1 AND id = $2",
      [tenantId, identityId],
    );
    if (row === undefined) throw new NotFoundError("Identity");
    if (row.pin_encrypted === null) return null;
    return this.#keys.secrets.decryptString(row.pin_encrypted, identityPinContext(identityId));
  }

  /**
   * Blind indexes of the person's personal identity numbers (from every identity that carries
   * one) under every configured master key, current first and without duplicates. Pass them to
   * the representation grant lookups: a stored index only matches indexes computed under the same
   * master key, so comparing against the identity's stored `pinIndex` alone would miss grants
   * indexed before (or after) a master key rotation until `rewrap-secrets` has run. Empty when
   * no identity has a personal identity number. Never log the result.
   */
  async pinIndexCandidates(tenantId: string, personId: string): Promise<string[]> {
    requireUuids({ tenantId, personId });
    const rows = await this.#db.query<{ id: string; pin_encrypted: string }>(
      `SELECT id, pin_encrypted FROM identities
        WHERE tenant_id = $1 AND person_id = $2 AND pin_encrypted IS NOT NULL
        ORDER BY created_at, id`,
      [tenantId, personId],
    );
    const candidates = new Set<string>();
    for (const row of rows) {
      const pin = this.#keys.secrets.decryptString(row.pin_encrypted, identityPinContext(row.id));
      for (const index of this.#keys.index.candidates("pin", pin)) candidates.add(index);
    }
    return [...candidates];
  }

  /**
   * Blind indexes (under every master key) of the personal identity number of the person's
   * identity through one login method, as {@link pinIndexCandidates} for a single identity:
   * representation by pin counts only the number the current login asserted. Empty when that
   * identity has no number. Never log the result.
   */
  async pinIndexCandidatesOfIdentity(
    tenantId: string,
    personId: string,
    loginMethodId: string,
  ): Promise<string[]> {
    requireUuids({ tenantId, personId, loginMethodId });
    const [row] = await this.#db.query<{ id: string; pin_encrypted: string }>(
      `SELECT id, pin_encrypted FROM identities
        WHERE tenant_id = $1 AND person_id = $2 AND login_method_id = $3
          AND pin_encrypted IS NOT NULL`,
      [tenantId, personId, loginMethodId],
    );
    if (row === undefined) return [];
    const pin = this.#keys.secrets.decryptString(row.pin_encrypted, identityPinContext(row.id));
    return this.#keys.index.candidates("pin", pin);
  }

  /**
   * The personal identity numbers (canonical) of the given set that belong to a protected person
   * of the tenant, in one query (each number looked up under every master key's blind index).
   */
  async protectedPins(tenantId: string, pins: readonly string[]): Promise<Set<string>> {
    requireUuids({ tenantId });
    if (pins.length === 0) return new Set();
    const byIndex = new Map<string, string>();
    for (const pin of new Set(pins)) {
      for (const index of this.#keys.index.candidates("pin", pin)) byIndex.set(index, pin);
    }
    const rows = await this.#db.query<{ pin_index: string }>(
      `SELECT DISTINCT i.pin_index FROM identities i
         JOIN persons p ON p.tenant_id = i.tenant_id AND p.id = i.person_id
        WHERE i.tenant_id = $1 AND i.pin_index = ANY ($2::text[]) AND p.protected_identity`,
      [tenantId, [...byIndex.keys()]],
    );
    return new Set(rows.map((row) => byIndex.get(row.pin_index)!));
  }

  /**
   * The personal identity number of the person's most recently used identity that carries one
   * (step-up of a known person: SAML PrincipalSelection, an OIDC pin `login_hint`); `null` when
   * no identity has one. Personal data: never log it.
   */
  async latestPin(tenantId: string, personId: string): Promise<string | null> {
    requireUuids({ tenantId, personId });
    const [row] = await this.#db.query<{ id: string; pin_encrypted: string }>(
      `SELECT id, pin_encrypted FROM identities
        WHERE tenant_id = $1 AND person_id = $2 AND pin_encrypted IS NOT NULL
        ORDER BY last_login_at DESC, id
        LIMIT 1`,
      [tenantId, personId],
    );
    if (row === undefined) return null;
    return this.#keys.secrets.decryptString(row.pin_encrypted, identityPinContext(row.id));
  }

  /**
   * Whether a person of the tenant with a protected identity has an identity with this personal
   * identity number (looked up under every master key's blind index). A represented person party
   * is then treated as protected too.
   */
  async isProtectedByPin(tenantId: string, pin: string): Promise<boolean> {
    requireUuids({ tenantId });
    const [row] = await this.#db.query<{ found: boolean }>(
      `SELECT EXISTS (
         SELECT 1 FROM identities i
           JOIN persons p ON p.tenant_id = i.tenant_id AND p.id = i.person_id
          WHERE i.tenant_id = $1 AND i.pin_index = ANY ($2::text[]) AND p.protected_identity
       ) AS found`,
      [tenantId, this.#keys.index.candidates("pin", pin)],
    );
    return row?.found === true;
  }

  /**
   * Just-in-time provisioning at login, in one transaction: finds the identity for (login
   * method, upstream subject) and refreshes its attributes, or creates the identity. A new
   * identity joins an existing person when the login method links by pin, the login reached the
   * method's asserted acr, and another linking login method of the tenant already has an identity
   * with the same personal identity number; otherwise a new person is created.
   *
   * Safe under concurrent first logins of the same subject (exactly one identity and person are
   * created) and of the same pin through different linking methods (serialised by an advisory
   * lock on the pin index).
   */
  async upsertFromLogin(tenantId: string, input: JitLoginInput): Promise<JitLoginResult> {
    requireUuids({ tenantId });
    const data = parseInput(jitLoginInputSchema, input);
    const attributes = JSON.stringify(storableAttributes(data.attributes));
    const pin =
      data.pin === undefined
        ? null
        : {
            value: data.pin,
            stored: this.#keys.index.compute("pin", data.pin),
            candidates: this.#keys.index.candidates("pin", data.pin),
          };

    // A subject that is the personal identity number is stored as its blind index (current
    // master key) and looked up under every configured key, like any other pin lookup.
    const subject =
      data.subjectFromPin && pin !== null
        ? `${PIN_INDEX_SUBJECT_PREFIX}${pin.stored.index}`
        : data.subject;
    const subjectCandidates =
      data.subjectFromPin && pin !== null
        ? pin.candidates.map((index) => `${PIN_INDEX_SUBJECT_PREFIX}${index}`)
        : [data.subject];

    return this.#db.transaction(async (tx) => {
      const [method] = await tx.query<{
        link_by_pin: boolean;
        asserted_acr: string;
        trust_pin_for_representation: boolean;
      }>(
        `SELECT link_by_pin, asserted_acr, trust_pin_for_representation
           FROM login_methods WHERE tenant_id = $1 AND id = $2`,
        [tenantId, data.loginMethodId],
      );
      if (method === undefined) throw new InvalidReferenceError("Login method not in tenant");

      const refresh = async (): Promise<IdentityRow | undefined> => {
        const [existing] = await tx.query<{ id: string }>(
          `SELECT id FROM identities
            WHERE tenant_id = $1 AND login_method_id = $2 AND subject = ANY ($3::text[])
            ORDER BY subject = $4 DESC
            LIMIT 1 FOR UPDATE`,
          [tenantId, data.loginMethodId, subjectCandidates, subject],
        );
        if (existing === undefined) return undefined;
        const [row] = await tx.query<IdentityRow>(
          `UPDATE identities
              SET attributes = $2::jsonb, pin_encrypted = $3, pin_index = $4, pin_index_key = $5,
                  subject = $6, last_login_at = now()
            WHERE id = $1
          RETURNING ${IDENTITY_COLUMNS}`,
          [existing.id, attributes, ...this.#pinColumns(existing.id, pin), subject],
        );
        return row;
      };

      let identity = await refresh();
      let created = false;
      let linked = false;
      if (identity === undefined) {
        let personId: string | undefined;
        if (pin !== null && method.link_by_pin && data.acr === method.asserted_acr) {
          await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
            `portvakt:pin-link:${tenantId}:${pin.stored.index}`,
          ]);
          const [match] = await tx.query<{ person_id: string }>(
            `SELECT i.person_id
               FROM identities i
               JOIN login_methods lm ON lm.tenant_id = i.tenant_id AND lm.id = i.login_method_id
              WHERE i.tenant_id = $1 AND i.pin_index = ANY ($2::text[])
                AND i.login_method_id <> $3 AND lm.link_by_pin
              ORDER BY i.created_at, i.id
              LIMIT 1`,
            [tenantId, pin.candidates, data.loginMethodId],
          );
          personId = match?.person_id;
          linked = personId !== undefined;
        }
        let newPersonId: string | undefined;
        if (personId === undefined) {
          newPersonId = requireRow(
            await mapDbErrors(() =>
              tx.query<{ id: string }>(
                "INSERT INTO persons (tenant_id, last_login_at) VALUES ($1, now()) RETURNING id",
                [tenantId],
              ),
            ),
          ).id;
          personId = newPersonId;
        }

        // ON CONFLICT waits for a concurrent insert of the same subject to commit; if that one
        // wins, our new person is discarded and the winner's identity is refreshed instead.
        const identityId = randomUUID();
        const [inserted] = await mapDbErrors(() =>
          tx.query<IdentityRow>(
            `INSERT INTO identities
               (id, tenant_id, person_id, login_method_id, subject, attributes,
                pin_encrypted, pin_index, pin_index_key)
             VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)
             ON CONFLICT (login_method_id, subject) DO NOTHING
             RETURNING ${IDENTITY_COLUMNS}`,
            [
              identityId,
              tenantId,
              personId,
              data.loginMethodId,
              subject,
              attributes,
              ...this.#pinColumns(identityId, pin),
            ],
          ),
        );
        if (inserted === undefined) {
          if (newPersonId !== undefined) {
            await tx.query("DELETE FROM persons WHERE tenant_id = $1 AND id = $2", [
              tenantId,
              newPersonId,
            ]);
          }
          linked = false;
          identity = await refresh();
          if (identity === undefined) throw new Error("Identity conflict could not be resolved");
        } else {
          identity = inserted;
          created = newPersonId !== undefined;
        }
      }

      // Protected identity is sticky on the person: once any linked identity was flagged, no
      // identity of the person keeps a name or email, whichever method signs in.
      const personRow = requireRow(
        await tx.query<PersonRow>(
          `UPDATE persons
              SET last_login_at = now(), protected_identity = protected_identity OR $3
            WHERE tenant_id = $1 AND id = $2
           RETURNING ${PERSON_COLUMNS}`,
          [tenantId, identity.person_id, data.attributes.protectedIdentity],
        ),
      );
      if (personRow.protected_identity) {
        await tx.query(
          `UPDATE identities SET attributes = attributes - 'name' - 'email'
            WHERE tenant_id = $1 AND person_id = $2 AND (attributes ? 'name' OR attributes ? 'email')`,
          [tenantId, personRow.id],
        );
        identity = requireRow(
          await tx.query<IdentityRow>(`SELECT ${IDENTITY_COLUMNS} FROM identities WHERE id = $1`, [
            identity.id,
          ]),
        );
      }
      // Assignments made before this person signed in (admin API) become theirs now.
      const resolved = await resolvePending(tx, tenantId, {
        personId: personRow.id,
        loginMethodId: data.loginMethodId,
        subjects: subjectCandidates,
        trustedPinIndexes:
          pin !== null && method.trust_pin_for_representation ? pin.candidates : [],
      });
      return {
        person: toPerson(personRow),
        identity: toIdentity(identity),
        created,
        linked,
        resolved,
      };
    });
  }

  /**
   * Administration: persons of the tenant whose latest known name or email (of any identity)
   * starts with `query`, or has a word starting with it, case-insensitively. Protected persons
   * keep no name or email, so they are only found by personal identity number
   * ({@link findByPin}). Personal data: never log the query or the result.
   */
  async search(tenantId: string, query: string, limit = 25): Promise<PersonSummary[]> {
    requireUuids({ tenantId });
    const needle = query
      .trim()
      .toLowerCase()
      .replace(/[!%_]/g, (char) => `!${char}`);
    if (needle.length === 0) return [];
    const rows = await this.#db.query<PersonSummaryRow>(
      `${SELECT_SUMMARY}
        WHERE p.tenant_id = $1 AND p.id IN (
          SELECT i.person_id FROM identities i
           WHERE i.tenant_id = $1
             AND (lower(i.attributes ->> 'name') LIKE $2 || '%' ESCAPE '!'
                  OR lower(i.attributes ->> 'email') LIKE $2 || '%' ESCAPE '!'
                  OR lower(i.attributes ->> 'name') LIKE '% ' || $2 || '%' ESCAPE '!'))
        ORDER BY latest.name NULLS LAST, p.id
        LIMIT $3`,
      [tenantId, needle, Math.min(Math.max(limit, 1), 100)],
    );
    return rows.map(toSummary);
  }

  /**
   * Administration: the persons of the tenant with an identity carrying this personal identity
   * number (blind index under every master key). Never log the number.
   */
  async findByPin(tenantId: string, pin: string): Promise<PersonSummary[]> {
    requireUuids({ tenantId });
    const canonical = personnummerSchema.safeParse(pin);
    if (!canonical.success) return [];
    const rows = await this.#db.query<PersonSummaryRow>(
      `${SELECT_SUMMARY}
        WHERE p.tenant_id = $1 AND p.id IN (
          SELECT i.person_id FROM identities i
           WHERE i.tenant_id = $1 AND i.pin_index = ANY ($2::text[]))
        ORDER BY p.created_at, p.id`,
      [tenantId, this.#keys.index.candidates("pin", canonical.data)],
    );
    return rows.map(toSummary);
  }

  /** Administration: the summary (latest name and email) of one person. */
  async summary(tenantId: string, personId: string): Promise<PersonSummary | null> {
    requireUuids({ tenantId, personId });
    const [row] = await this.#db.query<PersonSummaryRow>(
      `${SELECT_SUMMARY} WHERE p.tenant_id = $1 AND p.id = $2`,
      [tenantId, personId],
    );
    return row === undefined ? null : toSummary(row);
  }

  /**
   * The persons of the tenant with an identity for (login method, upstream subject), or whose
   * identity through a method trusted for personal identity numbers carries this number: who a
   * new pending assignment would resolve to right away.
   */
  async matchPendingTarget(
    tenantId: string,
    target: { readonly loginMethodId: string; readonly subject: string } | { readonly pin: string },
  ): Promise<string[]> {
    requireUuids({ tenantId });
    if ("pin" in target) {
      const rows = await this.#db.query<{ person_id: string }>(
        `SELECT DISTINCT i.person_id FROM identities i
           JOIN login_methods lm ON lm.tenant_id = i.tenant_id AND lm.id = i.login_method_id
          WHERE i.tenant_id = $1 AND i.pin_index = ANY ($2::text[])
            AND lm.trust_pin_for_representation
          ORDER BY i.person_id`,
        [tenantId, this.#keys.index.candidates("pin", target.pin)],
      );
      return rows.map((row) => row.person_id);
    }
    requireUuids({ loginMethodId: target.loginMethodId });
    const rows = await this.#db.query<{ person_id: string }>(
      `SELECT person_id FROM identities
        WHERE tenant_id = $1 AND login_method_id = $2 AND subject = $3`,
      [tenantId, target.loginMethodId, target.subject],
    );
    return rows.map((row) => row.person_id);
  }

  /**
   * Clears a person's protected identity (an administrator's decision, M6 admin API). Nothing
   * clears it automatically; a later flagged login sets it again. Returns false for an unknown
   * person.
   */
  async clearProtectedIdentity(tenantId: string, personId: string): Promise<boolean> {
    requireUuids({ tenantId, personId });
    const rows = await this.#db.query(
      `UPDATE persons SET protected_identity = false WHERE tenant_id = $1 AND id = $2 RETURNING id`,
      [tenantId, personId],
    );
    return rows.length > 0;
  }

  /**
   * Administration: removes one identity of a person (the person keeps their other identities,
   * assignments and grants). Returns false when the person has no such identity.
   */
  async deleteIdentity(tenantId: string, personId: string, identityId: string): Promise<boolean> {
    requireUuids({ tenantId, personId, identityId });
    const rows = await this.#db.query(
      "DELETE FROM identities WHERE tenant_id = $1 AND person_id = $2 AND id = $3 RETURNING id",
      [tenantId, personId, identityId],
    );
    return rows.length > 0;
  }

  /**
   * Administration: deletes a person with their identities, role and attribute assignments and
   * the representation grants made out to them (cascades). Returns false for an unknown person.
   */
  async delete(tenantId: string, personId: string): Promise<boolean> {
    requireUuids({ tenantId, personId });
    const rows = await this.#db.query(
      "DELETE FROM persons WHERE tenant_id = $1 AND id = $2 RETURNING id",
      [tenantId, personId],
    );
    return rows.length > 0;
  }

  #pinColumns(
    identityId: string,
    pin: { value: string; stored: { index: string; keyId: string } } | null,
  ): [string | null, string | null, string | null] {
    if (pin === null) return [null, null, null];
    return [
      this.#keys.secrets.encrypt(pin.value, identityPinContext(identityId)),
      pin.stored.index,
      pin.stored.keyId,
    ];
  }
}
