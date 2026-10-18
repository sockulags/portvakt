import { afterEach, describe, expect, it, vi } from "vitest";
import { createLogger } from "../logging/logger.js";
import { PeriodicTask } from "./periodic.js";

const logger = createLogger({ level: "silent" });

describe("PeriodicTask", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("runs on its interval, never overlapping itself, and keeps going after a failure", async () => {
    vi.useFakeTimers();
    let runs = 0;
    let active = 0;
    let maxActive = 0;
    const task = new PeriodicTask({
      name: "test",
      intervalSeconds: 10,
      logger,
      run: async () => {
        runs += 1;
        active += 1;
        maxActive = Math.max(maxActive, active);
        await new Promise((resolve) => setTimeout(resolve, 15_000));
        active -= 1;
        if (runs === 1) throw new Error("first run fails");
      },
    });
    task.start();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(runs).toBe(1);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(runs).toBe(1); // the next run is scheduled only after the previous one finished
    await vi.advanceTimersByTimeAsync(20_000);
    expect(runs).toBe(2);
    expect(maxActive).toBe(1);
    const stopping = task.stop();
    await vi.advanceTimersByTimeAsync(15_000);
    await stopping;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(runs).toBe(2);
  });

  it("runs immediately when asked and waits for a run in progress on stop", async () => {
    let finished = false;
    const task = new PeriodicTask({
      name: "now",
      intervalSeconds: 3600,
      logger,
      runImmediately: true,
      run: async () => {
        await new Promise((resolve) => setTimeout(resolve, 20));
        finished = true;
      },
    });
    task.start();
    await task.stop();
    expect(finished).toBe(true);
  });
});
