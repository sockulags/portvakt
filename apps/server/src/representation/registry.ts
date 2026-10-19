import type { Application, RepresentationMode } from "../domain/application.js";
import type {
  Party,
  PartyType,
  RepresentationChoice,
  RepresentationSourceId,
} from "../domain/representation.js";
import type { Tenant } from "../domain/tenant.js";
import type { Logger } from "../logging/logger.js";
import type { LoginMethodRepository } from "../repositories/login-methods.js";
import type { PersonRepository } from "../repositories/persons.js";
import type { RepresentationCandidate, RepresentationSource } from "./source.js";

/** Where a right came from (one entry per source and reference). */
export interface RepresentationProvenance {
  readonly source: RepresentationSourceId;
  readonly reference: string;
  readonly validTo: Date | null;
}

/** A party the person may act for, merged over every enabled source. */
export interface RepresentationOption {
  readonly party: Party;
  /**
   * The party is a person with a protected identity: marked so in the register, or a protected
   * person of the tenant has an identity with its personal identity number. Its name is then
   * never issued (`rep` in ID tokens) and the chooser shows no identifier.
   */
  readonly protectedIdentity: boolean;
  readonly provenance: readonly RepresentationProvenance[];
}

export interface RepresentationRegistryOptions {
  readonly sources: readonly RepresentationSource[];
  readonly persons: PersonRepository;
  readonly loginMethods: LoginMethodRepository;
  readonly logger: Logger;
}

/**
 * Who acts: the signed-in person and the login method of the current login (the grant login's
 * method at a refresh). Rights made out to the person id always count; rights made out to a
 * personal identity number count only for the number this login asserted, and only when the
 * method is trusted for it (`trustPinForRepresentation`). A pin another identity of the person
 * carries (another method, identity linking) never does.
 */
export interface RepresentationAgent {
  readonly personId: string;
  readonly loginMethodId: string | undefined;
}

const collator = new Intl.Collator("sv", { sensitivity: "base" });

/**
 * Merges the representation sources a tenant has enabled (`tenant.representationSources`, v1:
 * the internal register) into one list of parties: de-duplicated by party id with the
 * provenance of every source and right that attests it, ordered by name. A source that fails
 * contributes nothing (fail closed) and is logged without any personal data.
 */
export class RepresentationRegistry {
  readonly #sources: ReadonlyMap<RepresentationSourceId, RepresentationSource>;
  readonly #persons: PersonRepository;
  readonly #loginMethods: LoginMethodRepository;
  readonly #log: Logger;

  constructor(options: RepresentationRegistryOptions) {
    this.#sources = new Map(options.sources.map((source) => [source.id, source]));
    this.#persons = options.persons;
    this.#loginMethods = options.loginMethods;
    this.#log = options.logger.child({ component: "representation" });
  }

  /** Every party the agent may act for in `applicationId` at `at`. */
  async options(
    tenant: Tenant,
    agent: RepresentationAgent,
    applicationId: string,
    at: Date = new Date(),
  ): Promise<RepresentationOption[]> {
    return this.#options(tenant, agent, applicationId, at, undefined);
  }

  /** The option for `partyId` if the agent may (still) act for it, else `null`. */
  async find(
    tenant: Tenant,
    agent: RepresentationAgent,
    applicationId: string,
    partyId: string,
    at: Date = new Date(),
  ): Promise<RepresentationOption | null> {
    const [option] = await this.#options(tenant, agent, applicationId, at, partyId);
    return option ?? null;
  }

  /** The pin indexes the agent's current login may use (see {@link RepresentationAgent}). */
  async #pinIndexes(tenant: Tenant, agent: RepresentationAgent): Promise<string[]> {
    if (agent.loginMethodId === undefined) return [];
    const method = await this.#loginMethods.findById(tenant.id, agent.loginMethodId);
    if (method?.trustPinForRepresentation !== true) return [];
    return this.#persons.pinIndexCandidatesOfIdentity(tenant.id, agent.personId, method.id);
  }

  async #options(
    tenant: Tenant,
    agent: RepresentationAgent,
    applicationId: string,
    at: Date,
    partyId: string | undefined,
  ): Promise<RepresentationOption[]> {
    const enabledIds = tenant.representationSources.filter((id) => this.#sources.has(id));
    if (enabledIds.length === 0) return [];
    const { personId } = agent;
    const pinIndexes = await this.#pinIndexes(tenant, agent);
    const query = { tenantId: tenant.id, personId, pinIndexes, applicationId, at, partyId };
    const enabled = tenant.representationSources
      .map((id) => this.#sources.get(id))
      .filter((source): source is RepresentationSource => source !== undefined);
    const answers = await Promise.all(
      enabled.map(async (source): Promise<RepresentationCandidate[]> => {
        try {
          return await source.candidates(query);
        } catch (error) {
          this.#log.warn({ err: error, source: source.id }, "representation source failed");
          return [];
        }
      }),
    );
    const merged = new Map<string, { party: Party; provenance: RepresentationProvenance[] }>();
    for (const candidate of answers.flat()) {
      if (partyId !== undefined && candidate.party.id !== partyId) continue;
      const entry = merged.get(candidate.party.id) ?? { party: candidate.party, provenance: [] };
      entry.provenance.push({
        source: candidate.source,
        reference: candidate.reference,
        validTo: candidate.validTo,
      });
      merged.set(candidate.party.id, entry);
    }
    const entries = [...merged.values()];
    // One query for every person party: never one per party.
    const protectedPins = await this.#persons.protectedPins(
      tenant.id,
      entries.filter(({ party }) => party.type === "person").map(({ party }) => party.identifier),
    );
    const options = entries.map(({ party, provenance }) => ({
      party,
      provenance,
      protectedIdentity:
        party.protectedIdentity || (party.type === "person" && protectedPins.has(party.identifier)),
    }));
    return options.sort(
      (a, b) =>
        collator.compare(a.party.displayName, b.party.displayName) ||
        a.party.id.localeCompare(b.party.id),
    );
  }
}

/** The stored choice for acting for `option`'s party. */
export function choiceFor(option: RepresentationOption): RepresentationChoice {
  return {
    type: "party",
    partyId: option.party.id,
    partyType: option.party.type,
    sources: [...new Set(option.provenance.map((entry) => entry.source))],
  };
}

/** Whether the representation mode lets the person act for themselves. */
export const allowsSelf = (mode: RepresentationMode): boolean => mode === "optional";

/**
 * Whether a stored choice is still valid for `application` now; returns the refreshed choice
 * (current sources) or `null`. Self is valid only while the application's mode is `optional`.
 */
export async function revalidateChoice(
  registry: RepresentationRegistry,
  tenant: Tenant,
  agent: RepresentationAgent,
  application: Application,
  choice: RepresentationChoice,
  at: Date = new Date(),
): Promise<RepresentationChoice | null> {
  if (application.representationMode === "none") return null;
  if (choice.type === "self") return allowsSelf(application.representationMode) ? choice : null;
  const option = await registry.find(tenant, agent, application.id, choice.partyId, at);
  return option === null ? null : choiceFor(option);
}

/** How the chooser shows a party's identifier; never the full personal identity number. */
export type PartyIdentifierView =
  | { readonly kind: "organisation_number"; readonly value: string }
  /** The date part (`YYYYMMDD`) of a personal identity or coordination number. */
  | { readonly kind: "birth_date"; readonly value: string };

export interface PartyOptionView {
  readonly id: string;
  readonly type: PartyType;
  readonly name: string;
  /** `null` for a person with a protected identity. */
  readonly identifier: PartyIdentifierView | null;
}

/** The chooser's view of an option: name, type and a masked identifier. */
export function partyOptionView(option: RepresentationOption): PartyOptionView {
  const { party } = option;
  let identifier: PartyIdentifierView | null;
  if (party.type === "organisation") {
    identifier = { kind: "organisation_number", value: party.identifier };
  } else if (option.protectedIdentity) {
    identifier = null;
  } else {
    identifier = { kind: "birth_date", value: party.identifier.slice(0, 8) };
  }
  return { id: party.id, type: party.type, name: party.displayName, identifier };
}
