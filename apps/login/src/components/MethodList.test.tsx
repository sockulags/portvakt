import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { LoginMethodView } from "../api";
import { groupMethods, MethodList } from "./MethodList";

const methods: LoginMethodView[] = [
  { id: "bankid", displayName: "BankID", kind: "citizen" },
  { id: "entra", displayName: "Kommunens konto", kind: "employee" },
  { id: "freja", displayName: "Freja eID", kind: "citizen" },
];

describe("groupMethods", () => {
  it("puts employees first and keeps the order within a group", () => {
    expect(groupMethods(methods)).toEqual([
      { kind: "employee", methods: [methods[1]] },
      { kind: "citizen", methods: [methods[0], methods[2]] },
    ]);
    expect(groupMethods([])).toEqual([]);
  });
});

describe("MethodList", () => {
  it("labels the groups when both kinds are offered", () => {
    render(<MethodList methods={methods} onChoose={() => undefined} />);
    const employees = screen.getByRole("region", { name: "Logga in som medarbetare" });
    expect(
      within(employees)
        .getAllByRole("button")
        .map((b) => b.textContent),
    ).toEqual(["Logga in med Kommunens konto"]);
    const citizens = screen.getByRole("region", { name: "Logga in som privatperson" });
    expect(within(citizens).getAllByRole("listitem")).toHaveLength(2);
  });

  it("shows no group headings for a single kind", () => {
    render(
      <MethodList
        methods={methods.filter((m) => m.kind === "citizen")}
        onChoose={() => undefined}
      />,
    );
    expect(screen.queryByRole("heading")).toBeNull();
    expect(screen.getAllByRole("button")).toHaveLength(2);
  });

  it("chooses a method by click and by keyboard", async () => {
    const onChoose = vi.fn();
    const user = userEvent.setup();
    render(<MethodList methods={methods} onChoose={onChoose} />);
    await user.click(screen.getByTestId("method-bankid"));
    expect(onChoose).toHaveBeenLastCalledWith(methods[0]);
    await user.tab();
    expect(document.activeElement).toBe(screen.getByTestId("method-freja"));
    await user.keyboard("{Enter}");
    expect(onChoose).toHaveBeenLastCalledWith(methods[2]);
  });
});
