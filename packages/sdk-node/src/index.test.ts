import { describe, expect, it } from "vitest";
import { SDK_NAME } from "./index.js";

describe("sdk-node", () => {
  it("exports its name", () => {
    expect(SDK_NAME).toBe("@portvakt/sdk-node");
  });
});
