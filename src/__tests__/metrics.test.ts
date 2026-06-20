import { describe, expect, it } from "vitest";
import { emptyMetrics, measure, measureAverage } from "../crypto/metrics";

describe("metrics", () => {
  it("emptyMetrics starts at zero", () => {
    expect(emptyMetrics()).toEqual({
      keygenTimeMs: 0,
      publicKeySizeBytes: 0,
      privateKeySizeBytes: 0,
      ciphertextSizeBytes: 0,
      encryptTimeMs: 0,
      decryptTimeMs: 0,
    });
  });

  it("measure returns the result and a non-negative time", async () => {
    const { result, timeMs } = await measure(async () => 42);
    expect(result).toBe(42);
    expect(timeMs).toBeGreaterThanOrEqual(0);
  });

  it("measureAverage runs fn exactly N times and returns the last result", async () => {
    let calls = 0;
    const { result, timeMs, iterations } = await measureAverage(async () => ++calls, 10);
    expect(calls).toBe(10);
    expect(result).toBe(10);
    expect(iterations).toBe(10);
    expect(timeMs).toBeGreaterThanOrEqual(0);
  });

  it("measureAverage reports per-call (averaged) time, not total", async () => {
    // Each call burns a small, roughly fixed amount of work. The averaged
    // time for many iterations must not exceed the total elapsed for few.
    const busy = async () => {
      let x = 0;
      for (let i = 0; i < 5000; i++) x += i;
      return x;
    };
    const few = await measureAverage(busy, 1);
    const many = await measureAverage(busy, 50);
    // Averaged per-call time should be within an order of magnitude, never 50x.
    expect(many.timeMs).toBeLessThan(few.timeMs * 5 + 5);
  });

  it("measureAverage rejects iteration counts below 1", async () => {
    await expect(measureAverage(async () => 1, 0)).rejects.toThrow(/iterations/);
  });
});
