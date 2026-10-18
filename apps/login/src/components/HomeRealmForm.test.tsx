import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { HomeRealmForm, isEmail, type HomeRealmOutcome } from "./HomeRealmForm";

describe("isEmail", () => {
  it("accepts addresses and refuses the rest", () => {
    expect(isEmail(" anna@kommun.example ")).toBe(true);
    expect(isEmail("anna@kommun")).toBe(false);
    expect(isEmail("anna kommun.example")).toBe(false);
    expect(isEmail("")).toBe(false);
  });
});

describe("HomeRealmForm", () => {
  it("validates the address before looking it up", async () => {
    const onSubmit = vi.fn((): Promise<HomeRealmOutcome> => Promise.resolve("redirecting"));
    const user = userEvent.setup();
    render(<HomeRealmForm onSubmit={onSubmit} />);
    const field = screen.getByLabelText(/E-postadress/);
    await user.type(field, "not-an-address{Enter}");
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByTestId("hrd-error").textContent).toBe("Ange en giltig e-postadress.");
    expect(field.getAttribute("aria-invalid")).toBe("true");
  });

  it("describes the field by its hint and error, with one live error region", async () => {
    const user = userEvent.setup();
    render(<HomeRealmForm onSubmit={() => Promise.resolve("not_found")} />);
    const field = screen.getByRole("textbox", { name: "E-postadress" });
    const described = () =>
      (field.getAttribute("aria-describedby") ?? "")
        .split(" ")
        .map((id) => document.getElementById(id)?.textContent);
    expect(described()).toEqual(["Vi skickar dig vidare till din organisations inloggning."]);
    await user.type(field, "x{Enter}");
    expect(described()).toEqual([
      "Vi skickar dig vidare till din organisations inloggning.",
      "Ange en giltig e-postadress.",
    ]);
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(screen.getAllByText("Ange en giltig e-postadress.")).toHaveLength(1);
  });

  it("submits the trimmed address and explains an unknown domain", async () => {
    const onSubmit = vi.fn((): Promise<HomeRealmOutcome> => Promise.resolve("not_found"));
    const user = userEvent.setup();
    render(<HomeRealmForm initialEmail="anna@kommun.example" onSubmit={onSubmit} />);
    const field = screen.getByLabelText(/E-postadress/);
    expect((field as HTMLInputElement).value).toBe("anna@kommun.example");
    await user.clear(field);
    await user.type(field, "  erik@elsewhere.example ");
    await user.click(screen.getByTestId("hrd-submit"));
    expect(onSubmit).toHaveBeenCalledWith("erik@elsewhere.example");
    expect((await screen.findByTestId("hrd-error")).textContent).toMatch(/ingen inloggning/);
    expect(screen.getByTestId<HTMLButtonElement>("hrd-submit").disabled).toBe(false);
  });

  it("stays busy while the browser leaves for the login method", async () => {
    const user = userEvent.setup();
    render(<HomeRealmForm onSubmit={() => Promise.resolve("redirecting")} />);
    await user.type(screen.getByLabelText(/E-postadress/), "anna@kommun.example{Enter}");
    expect(screen.getByTestId("hrd-submit").getAttribute("aria-busy")).toBe("true");
  });
});
