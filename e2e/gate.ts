import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Collection mode: run every configuration to the end and report everything at
 * once, instead of stopping at the first finding in the first state.
 *
 * A gate that fails fast is right for CI and wrong for a remediation pass —
 * fixing one finding per full run wastes a run each time, and each run here is
 * four RSA-4096 keygens long. `A11Y_COLLECT=1` turns the oracles' assertions
 * into recordings.
 *
 * It cannot be mistaken for a passing gate. `reportCollected()` runs at the end
 * of every test in both modes and FAILS if anything was recorded, so a
 * collecting run that found something is still a red run; and with the variable
 * unset — which is how CI and every commit-time run behave — each oracle
 * asserts immediately, exactly as if this switch did not exist.
 */
const COLLECT = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

/**
 * Assert a finding list is empty, or record it in collection mode.
 * `null` and `[]` both mean "nothing found"; anything else is a finding.
 */
function softExpect(value: unknown[] | Record<string, unknown> | null, message: string): void {
  const clean = value === null || (Array.isArray(value) && value.length === 0);
  if (clean) return;
  if (COLLECT) {
    collected.push(`${message}\n${JSON.stringify(value, null, 2)}`);
    return;
  }
  expect(value, message).toEqual(Array.isArray(value) ? [] : null);
}

/** Fail the test if a collection run recorded anything. Call once, at the end. */
export function reportCollected(): void {
  expect(
    collected,
    'findings recorded in collection mode — a collecting run that finds anything is still a failing run'
  ).toEqual([]);
}

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaces
 *     called `neutralizeMotion()` — `animation: none !important; transition:
 *     none !important` on every element and pseudo-element — before every scan,
 *     which makes the suite structurally unable to see a motion defect, and
 *     BYPASSES this lab's own `@media (prefers-reduced-motion: reduce)` block
 *     instead of exercising it. It then called `revealInline()`, which stripped
 *     `.hidden` off every element and force-opened every `<details>`. On this
 *     lab that fabricates a page no visitor can reach: `#open-result` is hidden
 *     until a decrypt produces text, and `#qr-container` is hidden until the QR
 *     button renders an SVG into it, so un-hiding them scans two empty divs
 *     dressed as populated ones — and never scans the populated versions,
 *     because the old drive never opened them for real.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing. At first paint this lab has no keys, no ciphertext, no ECDH
 *     panel, no byte-layout strip and no MITM transcript: the headline claim —
 *     that Eve can sit on the wire and read everything unless the key she hands
 *     over is signed — is five interactions deep.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 *
 * This lab has a genuinely infinite animation — `.ecdh-arrow` pulses forever —
 * so quiescence is only reachable because reduced motion is really in effect
 * and the stylesheet's own block collapses it to 0.01ms. If that emulation ever
 * silently stopped working, this would hang rather than pass, which is the
 * right way round.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab
 * has two candidates: `.ecdh-secret` fades in from `opacity: .25`, and
 * `.ecdh-arrow` pulses between `.65` and `1`.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  softExpect(invisible, `no visible text may render at opacity 0 in state: ${label}`);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * THE DEFAULTS ARE ASSERTED, NOT ASSUMED. The tab that opens, the MITM
 * tamper switch that decides which of two very different transcripts renders,
 * and the empty seal field that produces the error state are all read back
 * here, because a drive that starts from the wrong assumption about them
 * silently scans one half of the lab twice and the other half never.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The whole page is rendered from main.ts into an empty `#app`, so a
  // navigation that resolves proves nothing. Require the tablist and the first
  // exhibit's controls.
  await expect(page.locator('[role="tab"]')).toHaveCount(4);
  await expect(page.locator('#btn-keygen')).toBeVisible();
  // The startup self-check re-renders the whole app when it finishes, which
  // detaches anything a click is mid-flight on. Wait for the finished state,
  // and require it to be the PASSED one — a failed self-check renders a
  // different banner and would leave the rest of this drive measuring an app
  // that had already given up.
  await expect(page.locator('[role="status"]')).toHaveText('WebCrypto self-check passed');

  // Defaults, asserted.
  await expect(page.locator('#tab-ecies')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#seal-message')).toHaveValue('');
  await expect(page.locator('#mitm-tamper')).not.toBeChecked();
  await expect(page.locator('#open-result')).toBeHidden();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints base64url public keys, private keys and
 * ciphertexts as unbroken tokens, lays the envelope out as a flex strip of
 * proportionally-sized segments, and puts a three-column comparison table on
 * the Compare tab.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    // `body { overflow-x: hidden }` propagates to the viewport when `html`
    // leaves `overflow` at `visible`, so `scrollWidth` stays equal to
    // `clientWidth` even when content is CUT OFF — a worse 1.4.10 outcome than
    // a scrollbar, and invisible to the standard check. Detect the clipping
    // directly rather than trusting the scroll geometry.
    const clippedByViewport = ['hidden', 'clip'].includes(
      getComputedStyle(document.body).overflowX,
    );
    if (!clippedByViewport && doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      // Stop BEFORE <body>. When `body { overflow-x: hidden }` propagates to the
      // viewport, body itself answers "hidden" to this walk — so every element
      // on the page reads as clipped, `escaping` is always empty, and the oracle
      // reports nothing at all. A viewport-level clip is the DEFECT, not a
      // legitimate scroller.
      while (n && n !== doc && n !== document.body) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const escaping = over.filter((x) => !clipped(x.el));
    if (!escaping.length) return null;
    const widest = escaping[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  softExpect(overflow, `page must not scroll horizontally in state: ${label}`);
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll. This lab caps the key and ciphertext
 * panes at `max-h-24` / `max-h-32` with `overflow-y: auto`, and an RSA-4096
 * private key overflows those by a long way.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  softExpect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  );
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 *
 * WCAG 1.4.11 (non-text contrast) has no oracle here and is not claimed by this
 * gate: the focus rings, the byte-layout strip, the key-size bars and the
 * control borders were measured by hand off screenshots at both widths in both
 * themes, and the findings fixed in the stylesheet.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`);

  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/** Switch tabs through the real control and wait for the re-render. */
async function openTab(page: Page, tab: 'ecies' | 'rsa2048' | 'rsa4096' | 'compare'): Promise<void> {
  await page.locator(`#tab-${tab}`).click();
  await expect(page.locator(`#tab-${tab}`)).toHaveAttribute('aria-selected', 'true');
}

/**
 * Generate keys in the current tab and wait for the real completion signal.
 *
 * RSA-4096 keygen is genuinely slow and highly variable — a fixed wait either
 * flakes or wastes minutes — so this waits on the button leaving its `aria-busy`
 * state and on the key material actually appearing.
 */
async function keygen(page: Page): Promise<void> {
  await page.locator('#btn-keygen').click();
  await expect(page.locator('#btn-keygen')).toBeEnabled({ timeout: 180_000 });
  await expect(page.locator('#seal-recipient-pk')).not.toHaveValue('', { timeout: 180_000 });
  await expect(page.locator('#open-privkey')).not.toHaveValue('');
}

/**
 * Drive one algorithm tab end to end: the empty-field error, keygen, the
 * private-key disclosure, the QR panel both ways, a real seal, a real open, and
 * the wrong-key rejection. Scanned after every step.
 */
async function driveAlgo(
  page: Page,
  theme: string,
  tab: 'ecies' | 'rsa2048' | 'rsa4096'
): Promise<void> {
  await openTab(page, tab);
  await scan(page, `${theme} / ${tab} / no keys yet`);

  // The error branch, reached the way a visitor reaches it: press Seal with an
  // empty message. This is a `role="alert"` node in red on the dark card and it
  // is one of only two error styles in the lab.
  await page.locator('#btn-seal').click();
  await expect(page.locator('[role="alert"]')).toHaveText(
    'Enter a recipient public key and a message to seal.'
  );
  await scan(page, `${theme} / ${tab} / seal refused, nothing entered`);

  await keygen(page);
  await scan(page, `${theme} / ${tab} / keys generated`);

  // The private key lives behind a <details>. Click the summary — never set
  // `open` from script, which is the thing that made the old gate's reveal of
  // this panel meaningless.
  const disclosure = page.locator('details').first();
  await disclosure.locator('summary').click();
  await expect(disclosure).toHaveAttribute('open', '');
  await scan(page, `${theme} / ${tab} / private key revealed`);

  // The QR panel. RSA-4096's public key does not fit in a QR code at all — 550
  // bytes of SPKI is ~734 base64url characters against this encoder's 669-byte
  // ceiling — so that tab renders an explanation instead of a code. Both are
  // real states with real content, and both are asserted rather than assumed:
  // asserting only the `<svg>` is how the throw that used to happen here went
  // unnoticed, and asserting only "not empty" would let it come back.
  await page.locator('#btn-qr').click();
  if (tab === 'rsa4096') {
    await expect(page.locator('#qr-container')).toContainText('too large to fit in a QR code');
  } else {
    await expect(page.locator('#qr-container svg')).toBeVisible();
  }
  await scan(page, `${theme} / ${tab} / QR panel shown`);
  await page.locator('#btn-qr').click();
  await expect(page.locator('#qr-container')).toBeHidden();
  await scan(page, `${theme} / ${tab} / QR panel hidden again`);

  await page.locator('#seal-message').fill('Meet at the docks at midnight.');
  await page.locator('#btn-seal').click();
  await expect(page.locator('.byte-strip')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#open-ciphertext')).not.toHaveValue('');
  await scan(page, `${theme} / ${tab} / letter sealed, envelope laid out byte by byte`);

  await page.locator('#btn-open').click();
  await expect(page.locator('#open-result')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#open-plaintext')).toHaveText('Meet at the docks at midnight.');
  await scan(page, `${theme} / ${tab} / opened with the right key`);

  await page.locator('#btn-open-wrong').click();
  await expect(page.locator('#open-plaintext')).toContainText('Rejected.', { timeout: 60_000 });
  await scan(page, `${theme} / ${tab} / Eve's key rejected`);
}

/**
 * Drive the lab through every state that renders content, scanning each.
 *
 * All four tabs, both error styles, both disclosure states, both QR states,
 * both MITM outcomes (Eve reads everything / Alice aborts on the signature),
 * and the Compare tab before and after the benchmark. RSA-4096 is included
 * rather than assumed to inherit RSA-2048's result: it is the only tab whose
 * key material overflows the `max-h-24` panes, which is a different oracle's
 * problem entirely.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint`);

  await page.locator('a.cl-skip-link').focus();
  await scan(page, `${theme} / skip link focused`);

  // The modal covers the page with its own backdrop, so it cannot be scanned
  // alongside anything else.
  await page.locator('#btn-how').click();
  await expect(page.locator('#modal-how')).toBeVisible();
  await scan(page, `${theme} / How It Works modal open`);
  await page.locator('#btn-close-modal').click();
  await expect(page.locator('#modal-how')).toBeHidden();
  await scan(page, `${theme} / modal closed, focus returned`);

  // Compare, with nothing measured yet — its own empty state, and the only
  // place the lab says "run the benchmark" rather than showing a table.
  await openTab(page, 'compare');
  await expect(page.locator('#tabpanel')).toContainText('Run the benchmark above');
  await scan(page, `${theme} / compare, nothing measured yet`);

  await driveAlgo(page, theme, 'ecies');

  // ── The MITM exhibit: both outcomes, and the tamper switch both ways ──
  // Eve always substitutes her key; the variable is whether Alice checks the
  // signature. Unauthenticated first, with the switch at its shipped default.
  await page.locator('#btn-mitm-unauth').click();
  await expect(page.locator('#mitm-verdict')).toContainText('Secrets DIFFER', { timeout: 60_000 });
  await expect(page.locator('#mitm-bob-read')).toBeVisible();
  await scan(page, `${theme} / MITM, unauthenticated, letter relayed verbatim`);

  // …then with Eve rewriting the letter, which is a different transcript: Bob
  // reads text Alice never wrote, and that row turns red.
  await page.locator('#mitm-tamper').check();
  await page.locator('#btn-mitm-unauth').click();
  await expect(page.locator('#mitm-bob-read.mitm-bad')).toBeVisible({ timeout: 60_000 });
  await scan(page, `${theme} / MITM, unauthenticated, letter rewritten by Eve`);

  // …and the abort branch, which renders an entirely different subtree: no
  // secrets, no plaintexts, just the failed verification.
  await page.locator('#btn-mitm-auth').click();
  await expect(page.locator('#mitm-verdict')).toContainText('Attack defeated', { timeout: 60_000 });
  await scan(page, `${theme} / MITM, signed key checked, attack defeated`);

  await driveAlgo(page, theme, 'rsa2048');
  await driveAlgo(page, theme, 'rsa4096');

  // Compare again, now that all three tabs hold real measurements: the table
  // and the key-size bar chart only exist in this state.
  await openTab(page, 'compare');
  await expect(page.locator('table')).toBeVisible();
  await scan(page, `${theme} / compare, table and key-size bars populated`);

  await page.locator('#btn-benchmark').click();
  await expect(page.locator('#btn-benchmark')).toBeEnabled({ timeout: 300_000 });
  await expect(page.locator('table')).toBeVisible();
  await scan(page, `${theme} / compare, after the benchmark`);
}

/**
 * The share-URL landing state: a visitor arrives with someone else's public key
 * in the query string, and the lab opens the named tab with that key pre-filled.
 * It is a first paint the drive above can never produce, because it is decided
 * before any script of the lab's own runs.
 */
export async function driveDeepLink(page: Page, theme: string): Promise<void> {
  await openTab(page, 'ecies');
  const pk = await page.evaluate(
    () => (document.getElementById('seal-recipient-pk') as HTMLInputElement).value
  );
  expect(pk, 'a public key must exist before it can be deep-linked').not.toBe('');
  await page.goto(`?pk=${encodeURIComponent(pk)}&algo=ecies`);
  await expect(page.locator('#tab-ecies')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#seal-recipient-pk')).toHaveValue(pk);
  await scan(page, `${theme} / arrived from a share URL`);
}
