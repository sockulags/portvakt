import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { PartyOption } from "../api";
import { MESSAGES } from "../i18n";
import { formatIdentifier, PartyList } from "./PartyList";

const parties: PartyOption[] = [
  {
    id: "org-1",
    type: "organisation",
    name: "Bygg AB",
    identifier: { kind: "organisation_number", value: "5566778899" },
  },
  {
    id: "person-1",
    type: "person",
    name: "Sven Medborgare",
    identifier: { kind: "birth_date", value: "19121212" },
  },
  { id: "person-2", type: "person", name: "Skyddad Person", identifier: null },
];

describe("formatIdentifier", () => {
  const t = MESSAGES.sv.representation;

  it("formats organisation numbers and masks personal identity numbers", () => {
    expect(formatIdentifier({ kind: "organisation_number", value: "5566778899" }, t)).toBe(
      "Organisationsnummer 556677-8899",
    );
    expect(formatIdentifier({ kind: "birth_date", value: "19121212" }, t)).toBe(
      "Personnummer 19121212-XXXX",
    );
    // Even if a server sent more than the date part, only the date part is shown.
    expect(formatIdentifier({ kind: "birth_date", value: "191212121212" }, t)).toBe(
      "Personnummer 19121212-XXXX",
    );
  });
});

describe("PartyList", () => {
  it("shows myself first, then each party with its type and masked identifier", () => {
    render(<PartyList parties={parties} allowSelf onChoose={() => undefined} />);
    const list = screen.getByRole("list", { name: "Vem du kan företräda" });
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(4);
    expect(items[0]!.textContent).toContain("Mig själv");
    expect(within(items[1]!).getByTestId("party-identifier").textContent).toBe(
      "Organisationsnummer 556677-8899",
    );
    expect(items[1]!.textContent).toContain("Organisation");
    expect(within(items[2]!).getByTestId("party-identifier").textContent).toBe(
      "Personnummer 19121212-XXXX",
    );
    expect(items[2]!.textContent).not.toContain("1212121212");
    // A protected identity: name and type only.
    expect(within(items[3]!).queryByTestId("party-identifier")).toBeNull();
    expect(items[3]!.textContent).toContain("Privatperson");
  });

  it("offers no self choice when the application requires representation", () => {
    render(<PartyList parties={parties} allowSelf={false} onChoose={() => undefined} />);
    expect(screen.queryByTestId("representation-option-self")).toBeNull();
    expect(screen.getAllByRole("button")).toHaveLength(3);
  });

  it("chooses by click and by keyboard, with descriptive button names", async () => {
    const onChoose = vi.fn();
    const user = userEvent.setup();
    render(<PartyList parties={parties} allowSelf onChoose={onChoose} />);
    expect(screen.getByRole("button", { name: "Företräd Bygg AB" })).toBeDefined();
    await user.click(screen.getByTestId("representation-option-org-1"));
    expect(onChoose).toHaveBeenLastCalledWith({ partyId: "org-1" });

    await user.tab();
    expect(document.activeElement).toBe(screen.getByTestId("representation-option-person-1"));
    await user.keyboard("{Enter}");
    expect(onChoose).toHaveBeenLastCalledWith({ partyId: "person-1" });
    await user.tab({ shift: true });
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(screen.getByTestId("representation-option-self"));
    await user.keyboard(" ");
    expect(onChoose).toHaveBeenLastCalledWith({ self: true });
  });
});
