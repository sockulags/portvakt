import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Testing Library unmounts after each test only with globals; Vitest runs without them here.
afterEach(() => {
  cleanup();
});
