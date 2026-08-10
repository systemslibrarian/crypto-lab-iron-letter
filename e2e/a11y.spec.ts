import { test } from '@playwright/test';
import { boot, driveAllStates, driveDeepLink, NARROW, reportCollected } from './gate';

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

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
    await driveDeepLink(page, theme);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    await driveDeepLink(page, `${theme} @380px`);
    reportCollected();
  });
}
