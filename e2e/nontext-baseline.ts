/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element, whose ratio
 * is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  "control-boundary|button#btn-mitm-auth.min-h-[44px].px-4.py-2.rounded-lg.bg-emerald-600.text-zinc-950.font-medium.text-sm.hover:bg-emerald-500.transition-colors.focus:outline-2.focus:outline-emerald-400.focus:outline-offset-2": { ratio: 2.25, required: 3.0, unverified: false },
  "control-boundary|button#btn-open.min-h-[44px].px-4.py-2.rounded-lg.bg-violet-500.text-zinc-950.font-medium.text-sm.hover:bg-violet-400.transition-colors.focus:outline-2.focus:outline-violet-400.focus:outline-offset-2": { ratio: 2.59, required: 3.0, unverified: false },
  "control-boundary|button#btn-seal.min-h-[44px].px-4.py-2.rounded-lg.bg-emerald-600.text-zinc-950.font-medium.text-sm.hover:bg-emerald-500.transition-colors.focus:outline-2.focus:outline-emerald-400.focus:outline-offset-2": { ratio: 2.25, required: 3.0, unverified: false }
};
