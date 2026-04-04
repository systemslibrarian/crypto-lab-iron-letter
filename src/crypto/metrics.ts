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
