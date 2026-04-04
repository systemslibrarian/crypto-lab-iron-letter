// ── Key URL System ───────────────────────────────────────────────────
// Encodes public keys into shareable URLs and decodes them back.

export type AlgoId = "ecies" | "rsa2048" | "rsa4096";

export function buildShareUrl(publicKeyB64: string, algo: AlgoId): string {
  const base = `${window.location.origin}${window.location.pathname}`;
  const params = new URLSearchParams({ pk: publicKeyB64, algo });
  return `${base}?${params.toString()}`;
}

export function parseShareUrl(url: string): { pk: string; algo: AlgoId } | null {
  try {
    const u = new URL(url);
    const pk = u.searchParams.get("pk");
    const algo = u.searchParams.get("algo") as AlgoId | null;
    if (!pk || !algo) return null;
    if (!["ecies", "rsa2048", "rsa4096"].includes(algo)) return null;
    return { pk, algo };
  } catch {
    return null;
  }
}

export function parseCurrentUrl(): { pk: string; algo: AlgoId } | null {
  return parseShareUrl(window.location.href);
}
