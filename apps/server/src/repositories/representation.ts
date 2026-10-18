import { randomUUID } from "node:crypto";
import type { BlindIndexPurpose } from "../crypto/blind-index.js";
import type { KeyRing } from "../crypto/keyring.js";
import type { Db } from "../db/database.js";
import { parseOrganisationsnummer, parsePersonnummer } from "../domain/personnummer.js";
import {
  createGrantInputSchema,
  type CreateGrantInput,
  createPartyInputSchema,
  type CreatePartyInput,
  type GrantAgent,
  type Party,
  type PartyType,
  type RepresentationGrant,
} from "../domain/representation.js";
import { displayNameSchema } from "../domain/schemas.js";
import { ConflictError, mapDbErrors, NotFoundError, parseInput, requireUuids } from "./errors.js";

interface PartyRow {
  id: string;
  tenant_id: string;
  type: PartyType;
  identifier_encrypted: string;
  display_name: string;
  created_at: Date;
  updated_at: Date;
}

interface GrantRow {
  id: string;
  tenant_id: string;
  agent_person_id: string | null;
  agent_identifier_index: string | null;
  all_applications: boolean;
  valid_from: Date;
  valid_to: Date | null;
  revoked_at: Date | null;
  revoked_by: string | null;
  created_by: string | null;
  created_at: Date;
  application_ids: string[];
  party_id: string;
  party_type: PartyType;
  party_identifier_encrypted: string;
  party_display_name: string;
  party_created_at: Date;
  party_updated_at: Date;
}

const PARTY_COLUMNS =
  "id, tenant_id, type, identifier_encrypted, display_name, created_at, updated_at";

const SELECT_GRANT = `
  SELECT g.id, g.tenant_id, g.agent_person_id, g.agent_identifier_index, g.all_applications,
         g.valid_from, g.valid_to, g.revoked_at, g.revoked_by, g.created_by, g.created_at,
         ARRAY(SELECT ga.application_id::text FROM representation_grant_applications ga
                WHERE ga.tenant_id = g.tenant_id AND ga.grant_id = g.id
                ORDER BY ga.application_id) AS application_ids,
         p.id AS party_id, p.type AS party_type,
         p.identifier_encrypted AS party_identifier_encrypted,
         p.display_name AS party_display_name, p.created_at AS party_created_at,
         p.updated_at AS party_updated_at
    FROM representation_grants g
    JOIN parties p ON p.tenant_id = g.tenant_id AND p.id = g.party_id`;

/**
 * SQL condition: grant `g` is made out to the agent with person id `person`, or to a personal
 * identity number whose blind index is in the text array `pins`.
 */
const madeOutTo = (person: string, pins: string): string => `
      (g.agent_person_id = ${person} OR g.agent_identifier_index = ANY (${pins}::text[]))`;

/**
 * SQL condition: grant `g` can be used at time `at` for application `app` by the agent (see
 * {@link madeOutTo}). Valid means: not revoked, `at` in [valid_from, valid_to), the application
 * enabled for the tenant, and either `all_applications` or a row for the application. A limited
 * grant whose last application was removed matches nothing.
 */
const usableBy = (person: string, pins: string, app: string, at: string): string => `
  ${madeOutTo(person, pins)}
  AND g.revoked_at IS NULL
  AND g.valid_from <= ${at}
  AND (g.valid_to IS NULL OR g.valid_to > ${at})
  AND EXISTS (SELECT 1 FROM tenant_applications ta
               WHERE ta.tenant_id = g.tenant_id AND ta.application_id = ${app} AND ta.enabled)
  AND (g.all_applications
       OR EXISTS (SELECT 1 FROM representation_grant_applications ga
                   WHERE ga.tenant_id = g.tenant_id AND ga.grant_id = g.id
                     AND ga.application_id = ${app}))`;

const partyIdentifierContext = (partyId: string): string => `party:${partyId}:identifier`;
const grantAgentContext = (grantId: string): string =>
  `representation_grant:${grantId}:agent_identifier`;

const purposeOf = (type: PartyType): BlindIndexPurpose => (type === "person" ? "pin" : "orgnr");

function canonicalIdentifier(type: PartyType, identifier: string): string | null {
  return type === "person"
    ? (parsePersonnummer(identifier)?.canonical ?? null)
    : parseOrganisationsnummer(identifier);
}

export class PartyRepository {
  readonly #db: Db;
  readonly #keys: KeyRing;

  constructor(db: Db, keys: KeyRing) {
    this.#db = db;
    this.#keys = keys;
  }

  /**
   * Creates a party. The identifier is validated (personnummer for persons, organisationsnummer
   * for organisations), stored encrypted, and unique per tenant and type through its blind index.
   */
  async create(tenantId: string, input: CreatePartyInput): Promise<Party> {
    requireUuids({ tenantId });
    const data = parseInput(createPartyInputSchema, input);
    if ((await this.findByIdentifier(tenantId, data.type, data.identifier)) !== null) {
      throw new ConflictError("A party with this identifier already exists", "parties_identifier");
    }
    const id = randomUUID();
    const index = this.#keys.index.compute(purposeOf(data.type), data.identifier);
    const [row] = await mapDbErrors(() =>
      this.#db.query<PartyRow>(
        `INSERT INTO parties
           (id, tenant_id, type, identifier_encrypted, identifier_index, identifier_index_key,
            display_name)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING ${PARTY_COLUMNS}`,
        [
          id,
          tenantId,
          data.type,
          this.#keys.secrets.encrypt(data.identifier, partyIdentifierContext(id)),
          index.index,
          index.keyId,
          data.displayName,
        ],
      ),
    );
    if (row === undefined) throw new Error("Statement returned no row");
    return this.#toParty(row);
  }

  async findById(tenantId: string, id: string): Promise<Party | null> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<PartyRow>(
      `SELECT ${PARTY_COLUMNS} FROM parties WHERE tenant_id = $1 AND id = $2`,
      [tenantId, id],
    );
    return row === undefined ? null : this.#toParty(row);
  }

  /** Lookup through the blind index; `identifier` may be in any accepted format. */
  async findByIdentifier(
    tenantId: string,
    type: PartyType,
    identifier: string,
  ): Promise<Party | null> {
    requireUuids({ tenantId });
    const canonical = canonicalIdentifier(type, identifier);
    if (canonical === null) return null;
    const [row] = await this.#db.query<PartyRow>(
      `SELECT ${PARTY_COLUMNS} FROM parties
        WHERE tenant_id = $1 AND type = $2 AND identifier_index = ANY ($3::text[])`,
      [tenantId, type, this.#keys.index.candidates(purposeOf(type), canonical)],
    );
    return row === undefined ? null : this.#toParty(row);
  }

  async list(tenantId: string): Promise<Party[]> {
    requireUuids({ tenantId });
    const rows = await this.#db.query<PartyRow>(
      `SELECT ${PARTY_COLUMNS} FROM parties WHERE tenant_id = $1 ORDER BY display_name, id`,
      [tenantId],
    );
    return rows.map((row) => this.#toParty(row));
  }

  async rename(tenantId: string, id: string, displayName: string): Promise<Party> {
    requireUuids({ tenantId, id });
    const name = parseInput(displayNameSchema, displayName);
    const [row] = await mapDbErrors(() =>
      this.#db.query<PartyRow>(
        `UPDATE parties SET display_name = $3 WHERE tenant_id = $1 AND id = $2
         RETURNING ${PARTY_COLUMNS}`,
        [tenantId, id, name],
      ),
    );
    if (row === undefined) throw new NotFoundError("Party");
    return this.#toParty(row);
  }

  /** Deletes the party and every grant to act for it. */
  async delete(tenantId: string, id: string): Promise<boolean> {
    requireUuids({ tenantId, id });
    const rows = await this.#db.query(
      "DELETE FROM parties WHERE tenant_id = $1 AND id = $2 RETURNING id",
      [tenantId, id],
    );
    return rows.length > 0;
  }

  #toParty(row: PartyRow): Party {
    return {
      id: row.id,
      tenantId: row.tenant_id,
      type: row.type,
      identifier: this.#keys.secrets.decryptString(
        row.identifier_encrypted,
        partyIdentifierContext(row.id),
      ),
      displayName: row.display_name,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}

export class RepresentationGrantRepository {
  readonly #db: Db;
  readonly #keys: KeyRing;

  constructor(db: Db, keys: KeyRing) {
    this.#db = db;
    this.#keys = keys;
  }

  /**
   * Creates a grant for a known person or for a personal identity number (someone who has not
   * signed in yet). The agent, the party and every listed application must belong to the tenant
   * (composite foreign keys), otherwise {@link InvalidReferenceError} is raised.
   */
  async create(tenantId: string, input: CreateGrantInput): Promise<RepresentationGrant> {
    requireUuids({ tenantId });
    const data = parseInput(createGrantInputSchema, input);
    const id = randomUUID();
    const agentPersonId = "personId" in data.agent ? data.agent.personId : null;
    const agentPin =
      "pin" in data.agent
        ? {
            encrypted: this.#keys.secrets.encrypt(data.agent.pin, grantAgentContext(id)),
            ...this.#keys.index.compute("pin", data.agent.pin),
          }
        : null;

    await this.#db.transaction(async (tx) => {
      await mapDbErrors(() =>
        tx.query(
          `INSERT INTO representation_grants
             (id, tenant_id, agent_person_id, agent_identifier_encrypted, agent_identifier_index,
              agent_identifier_index_key, party_id, all_applications, valid_from, valid_to,
              created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, now()), $10, $11)`,
          [
            id,
            tenantId,
            agentPersonId,
            agentPin?.encrypted ?? null,
            agentPin?.index ?? null,
            agentPin?.keyId ?? null,
            data.partyId,
            data.allApplications,
            data.validFrom ?? null,
            data.validTo,
            data.createdBy,
          ],
        ),
      );
      if (data.applicationIds.length > 0) {
        await mapDbErrors(() =>
          tx.query(
            `INSERT INTO representation_grant_applications (tenant_id, grant_id, application_id)
             SELECT $1, $2, unnest($3::uuid[])`,
            [tenantId, id, data.applicationIds],
          ),
        );
      }
    });
    return this.#require(tenantId, id);
  }

  async findById(tenantId: string, id: string): Promise<RepresentationGrant | null> {
    requireUuids({ tenantId, id });
    const [row] = await this.#db.query<GrantRow>(
      `${SELECT_GRANT} WHERE g.tenant_id = $1 AND g.id = $2`,
      [tenantId, id],
    );
    return row === undefined ? null : this.#toGrant(row);
  }

  /**
   * Every grant of an agent (by person id, or by pin index for grants created before the first
   * sign-in), including expired and revoked ones (administration).
   *
   * `pinIndexes` are the agent's pin blind indexes under every configured master key, from
   * `PersonRepository.pinIndexCandidates`: a grant indexed before a master key rotation still
   * matches an identity indexed after it, and the other way round. Empty when the agent has no
   * personal identity number.
   */
  async listForAgent(
    tenantId: string,
    personId: string,
    pinIndexes: readonly string[],
  ): Promise<RepresentationGrant[]> {
    requireUuids({ tenantId, personId });
    const rows = await this.#db.query<GrantRow>(
      `${SELECT_GRANT}
        WHERE g.tenant_id = $1 AND ${madeOutTo("$2", "$3")}
        ORDER BY g.created_at, g.id`,
      [tenantId, personId, [...pinIndexes]],
    );
    return rows.map((row) => this.#toGrant(row));
  }

  async listForParty(tenantId: string, partyId: string): Promise<RepresentationGrant[]> {
    requireUuids({ tenantId, partyId });
    const rows = await this.#db.query<GrantRow>(
      `${SELECT_GRANT} WHERE g.tenant_id = $1 AND g.party_id = $2 ORDER BY g.created_at, g.id`,
      [tenantId, partyId],
    );
    return rows.map((row) => this.#toGrant(row));
  }

  /**
   * Grants the signed-in person can use now (or at `at`) for this application: what the
   * representation chooser offers. `pinIndexes` as for {@link listForAgent}: they match grants
   * made out to the personal identity number before the person existed.
   */
  async listValidForAgent(
    tenantId: string,
    personId: string,
    pinIndexes: readonly string[],
    applicationId: string,
    at?: Date,
  ): Promise<RepresentationGrant[]> {
    requireUuids({ tenantId, personId, applicationId });
    const rows = await this.#db.query<GrantRow>(
      `${SELECT_GRANT}
        WHERE g.tenant_id = $1
          AND ${usableBy("$2", "$3", "$4", "COALESCE($5::timestamptz, now())")}
        ORDER BY p.display_name, g.id`,
      [tenantId, personId, [...pinIndexes], applicationId, at ?? null],
    );
    return rows.map((row) => this.#toGrant(row));
  }

  /**
   * The grant if it is still usable by this agent for this application (checked at refresh).
   * `pinIndexes` as for {@link listForAgent}.
   */
  async findValid(
    tenantId: string,
    grantId: string,
    personId: string,
    pinIndexes: readonly string[],
    applicationId: string,
    at?: Date,
  ): Promise<RepresentationGrant | null> {
    requireUuids({ tenantId, grantId, personId, applicationId });
    const [row] = await this.#db.query<GrantRow>(
      `${SELECT_GRANT}
        WHERE g.tenant_id = $1 AND g.id = $6
          AND ${usableBy("$2", "$3", "$4", "COALESCE($5::timestamptz, now())")}`,
      [tenantId, personId, [...pinIndexes], applicationId, at ?? null, grantId],
    );
    return row === undefined ? null : this.#toGrant(row);
  }

  /**
   * Revokes the grant. Revoking an already revoked grant keeps the original revocation.
   * `revokedBy` is the acting admin's person id, if any.
   */
  async revoke(
    tenantId: string,
    grantId: string,
    revokedBy: string | null,
  ): Promise<RepresentationGrant> {
    requireUuids({ tenantId, grantId, revokedBy });
    const rows = await this.#db.query(
      `UPDATE representation_grants
          SET revoked_at = COALESCE(revoked_at, now()),
              revoked_by = CASE WHEN revoked_at IS NULL THEN $3::uuid ELSE revoked_by END
        WHERE tenant_id = $1 AND id = $2
        RETURNING id`,
      [tenantId, grantId, revokedBy],
    );
    if (rows.length === 0) throw new NotFoundError("Representation grant");
    return this.#require(tenantId, grantId);
  }

  async #require(tenantId: string, id: string): Promise<RepresentationGrant> {
    const grant = await this.findById(tenantId, id);
    if (grant === null) throw new NotFoundError("Representation grant");
    return grant;
  }

  #toGrant(row: GrantRow): RepresentationGrant {
    let agent: GrantAgent;
    if (row.agent_person_id !== null) {
      agent = { type: "person", personId: row.agent_person_id };
    } else if (row.agent_identifier_index !== null) {
      agent = { type: "pin", pinIndex: row.agent_identifier_index };
    } else {
      throw new Error("Representation grant without an agent");
    }
    return {
      id: row.id,
      tenantId: row.tenant_id,
      agent,
      party: {
        id: row.party_id,
        tenantId: row.tenant_id,
        type: row.party_type,
        identifier: this.#keys.secrets.decryptString(
          row.party_identifier_encrypted,
          partyIdentifierContext(row.party_id),
        ),
        displayName: row.party_display_name,
        createdAt: row.party_created_at,
        updatedAt: row.party_updated_at,
      },
      allApplications: row.all_applications,
      applicationIds: row.application_ids,
      validFrom: row.valid_from,
      validTo: row.valid_to,
      revokedAt: row.revoked_at,
      revokedBy: row.revoked_by,
      createdBy: row.created_by,
      createdAt: row.created_at,
    };
  }
}

export { grantAgentContext, partyIdentifierContext };
