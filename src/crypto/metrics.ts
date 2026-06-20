// ── Metrics Engine ───────────────────────────────────────────────────

export interface Metrics {
  keygenTimeMs: number;
  publicKeySizeBytes: number;
  privateKeySizeBytes: number;
  ciphertextSizeBytes: number;
  encryptTimeMs: number;
  decryptTimeMs: number;
}

export function emptyMetrics(): Metrics {
  return {
    keygenTimeMs: 0,
    publicKeySizeBytes: 0,
    privateKeySizeBytes: 0,
    ciphertextSizeBytes: 0,
    encryptTimeMs: 0,
    decryptTimeMs: 0,
  };
}

export async function measure<T>(fn: () => Promise<T>): Promise<{ result: T; timeMs: number }> {
  const start = performance.now();
  const result = await fn();
  const timeMs = performance.now() - start;
  return { result, timeMs };
}

/**
 * Run `fn` `iterations` times and report the mean wall-clock time per call.
 * Single performance.now() samples are noisy; averaging gives a stable,
 * trustworthy number for the side-by-side comparison.
 */
export async function measureAverage<T>(
  fn: () => Promise<T>,
  iterations: number
): Promise<{ result: T; timeMs: number; iterations: number }> {
  if (iterations < 1) throw new Error("iterations must be >= 1");
  let result!: T;
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    result = await fn();
  }
  const timeMs = (performance.now() - start) / iterations;
  return { result, timeMs, iterations };
}
