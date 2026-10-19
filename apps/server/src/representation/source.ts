import type { Party, RepresentationSourceId } from "../domain/representation.js";
import type { RepresentationGrantRepository } from "../repositories/representation.js";

/** Who asks, for which application, and when (validity windows are checked at `at`). */
export interface RepresentationQuery {
  readonly tenantId: string;
  /** The signed-in person (the agent). */
  readonly personId: string;
  /**
   * Blind indexes (under every configured master key) of the personal identity number the
   * current login asserted, for rights made out to a number (possibly before the person first
   * signed in). Only a login through a method trusted for it (`trustPinForRepresentation`)
   * contributes one; otherwise empty, and only rights made out to the person id count. Never
   * log them.
   */
  readonly pinIndexes: readonly string[];
  readonly applicationId: string;
  readonly at: Date;
  /**
   * Only rights for this party (re-checking one stored choice). A source may ignore it; the
   * registry filters again.
   */
  readonly partyId?: string | undefined;
}

/** A party the person may act for, as one source attests it. */
export interface RepresentationCandidate {
  /**
   * The party in Portvakt's party register (`rep.sub` is its id). A source that finds parties
   * elsewhere (Bolagsverket, Mina ombud) registers them as parties first, so every party has a
   * stable Portvakt UUID.
   */
  readonly party: Party;
  readonly source: RepresentationSourceId;
  /** The source's own reference for the right (internal: the grant id). Never shown. */
  readonly reference: string;
  /** End of the right's validity, if it has one. */
  readonly validTo: Date | null;
}

/**
 * A source of representation rights. A source answers for one (tenant, person, application)
 * at a time, with only the rights that are valid at `query.at`: not revoked, inside their
 * validity window, and covering the application. It must fail (throw) rather than answer
 * partially; the registry then treats the source as having no rights for this query (fail
 * closed) and logs it.
 */
export interface RepresentationSource {
  readonly id: RepresentationSourceId;
  candidates(query: RepresentationQuery): Promise<RepresentationCandidate[]>;
}

/**
 * The internal register (v1): representation grants made out to the person (by person id) or to
 * their personal identity number (by blind index, before the first sign-in), limited to the
 * application or valid for all applications of the tenant.
 */
export class InternalRepresentationSource implements RepresentationSource {
  readonly id = "internal" as const;
  readonly #grants: RepresentationGrantRepository;

  constructor(grants: RepresentationGrantRepository) {
    this.#grants = grants;
  }

  async candidates(query: RepresentationQuery): Promise<RepresentationCandidate[]> {
    const grants = await this.#grants.listValidForAgent(
      query.tenantId,
      query.personId,
      query.pinIndexes,
      query.applicationId,
      query.at,
      query.partyId,
    );
    return grants.map((grant) => ({
      party: grant.party,
      source: this.id,
      reference: grant.id,
      validTo: grant.validTo,
    }));
  }
}
