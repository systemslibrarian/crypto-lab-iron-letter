import { test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  driveDeepLink,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * Every state the lab can render is driven the way a visitor reaches it: all
 * four tabs, the How It Works modal, the seal-with-nothing-entered error, three
 * rounds of keygen (ECIES, RSA-2048 and RSA-4096, whose key material is the
 * only thing that overflows the capped panes), the private-key disclosure, the
 * QR panel opened and closed again, a real seal, a real open, Eve's key being
 * rejected for real, all three MITM outcomes, the Compare tab before and after
 * the benchmark, and the share-URL landing page. Every one of those is scanned,
 * in both themes, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel and no
 * `<details>` is ever force-revealed, why each scan asserts its content first,
 * and why `violations` is not the whole oracle.
 */

/**
 * Why the staleness ratchet runs in the LIGHT configurations only.
 *
 * `expectBaselineNotStale` fails on any baselined finding that never appeared,
 * which is what forces a fixed entry out of `nontext-baseline.ts` instead of
 * letting it linger as a permanent exemption. `nonTextSeen` is module state and
 * `fullyParallel` gives every test its own worker, so the check sees exactly
 * the states ITS OWN test drove — it can only be sound in a configuration that
 * reaches every baselined selector.
 *
 * Here the WHOLE baseline is light-theme-only. All three entries are filled
 * buttons — `#btn-seal` and `#btn-mitm-auth` on `bg-emerald-600`, `#btn-open`
 * on `bg-violet-500` — and a filled control's boundary is its fill against the
 * surrounding surface. Those fills clear 3:1 against the dark `zinc-950` page
 * and land at 2.25:1 and 2.59:1 against the light one. Wiring the ratchet into
 * all four configurations failed both dark runs naming all three entries and
 * passed both light ones, which was measured rather than assumed. So the
 * entries are not rotted, they are invisible from dark, and light is the only
 * place the rule is sound.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    await driveDeepLink(page, theme);
    if (theme === 'light') expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    await driveDeepLink(page, `${theme} @380px`);
    if (theme === 'light') expectBaselineNotStale();
    reportCollected();
  });
}
