import { Badge, Button, Card } from "@portvakt/design-system/components";
import { Icon } from "@portvakt/design-system/patterns";
import type { PartyIdentifier, PartyOption, RepresentationChoice } from "../api";
import { format, useI18n, type Messages } from "../i18n";

/**
 * How an identifier is shown: an organisation number as `NNNNNN-NNNN`, a person only by the
 * date part of the personal identity number with the last four digits masked
 * (`YYYYMMDD-XXXX`). The server never sends the full number; this only formats.
 */
export function formatIdentifier(
  identifier: PartyIdentifier,
  t: Messages["representation"],
): string {
  if (identifier.kind === "organisation_number") {
    const value = `${identifier.value.slice(0, 6)}-${identifier.value.slice(6)}`;
    return format(t.organisationNumber, { value });
  }
  return format(t.personalNumber, { value: `${identifier.value.slice(0, 8)}-XXXX` });
}

interface PartyListProps {
  readonly parties: readonly PartyOption[];
  /** Offer "Myself" first (the application's representation mode is optional). */
  readonly allowSelf: boolean;
  readonly onChoose: (choice: RepresentationChoice) => void;
  readonly disabled?: boolean;
}

/**
 * The representation choices: "Myself" (when allowed) and one card per party with its type,
 * name and masked identifier (none for a protected identity). Every choice is a button, so it
 * is reachable with Tab and chosen with Enter or Space; the list is labelled for screen readers.
 */
export function PartyList({ parties, allowSelf, onChoose, disabled = false }: PartyListProps) {
  const { t } = useI18n();
  const r = t.representation;
  return (
    <ul className="pv-parties" aria-label={r.listLabel} data-testid="party-list">
      {allowSelf && (
        <li>
          <Card className="pv-party" data-testid="party-self">
            <span className="pv-party-icon" aria-hidden="true">
              <Icon name="home" size={20} />
            </span>
            <span className="pv-party-text">
              <span className="pv-party-name">{r.self}</span>
              <span className="pv-party-meta">{r.selfDetail}</span>
            </span>
            <Button
              variant="secondary"
              disabled={disabled}
              data-testid="representation-option-self"
              onClick={() => onChoose({ self: true })}
            >
              {r.chooseSelf}
            </Button>
          </Card>
        </li>
      )}
      {parties.map((party) => (
        <li key={party.id}>
          <Card className="pv-party" data-testid={`party-${party.id}`}>
            <span className="pv-party-icon" aria-hidden="true">
              <Icon name={party.type === "organisation" ? "users" : "home"} size={20} />
            </span>
            <span className="pv-party-text">
              <span className="pv-party-name">{party.name}</span>
              <span className="pv-party-meta">
                <Badge>{r.types[party.type]}</Badge>
                {party.identifier !== null && (
                  <span data-testid="party-identifier">
                    {formatIdentifier(party.identifier, r)}
                  </span>
                )}
              </span>
            </span>
            <Button
              variant="primary"
              disabled={disabled}
              data-testid={`representation-option-${party.id}`}
              onClick={() => onChoose({ partyId: party.id })}
            >
              {format(r.choose, { name: party.name })}
            </Button>
          </Card>
        </li>
      ))}
    </ul>
  );
}
