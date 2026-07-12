import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

/**
 * WCAG regression gate. Deploys are already gated on the crypto self-tests;
 * this gates them on accessibility the same way.
 *
 * The page has four tabs (ECIES / RSA-2048 / RSA-4096 / Compare), native
 * <details> (private-key reveal), and class-toggled (`.hidden`) inline regions
 * (#qr-container, #open-result) plus a full-screen "How It Works" modal
 * (#modal-how) opened by #btn-how. We scan every tab in both themes with the
 * <details> expanded and the inline `.hidden` regions revealed, then scan the
 * modal separately (its backdrop covers the page, so it can't be scanned
 * alongside the base view). Animations/transitions are neutralized so nothing
 * is scanned mid-transition.
 */

const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];
const TABS = ["ecies", "rsa2048", "rsa4096", "compare"];

async function waitForBoot(page: Page): Promise<void> {
  // The startup WebCrypto self-test finishes asynchronously and re-renders the
  // whole app (replacing the tabs, panels, etc.). Wait for it to settle so
  // interactions don't race a re-render that detaches an element mid-click.
  await expect(
    page.getByText("Running WebCrypto self-check..."),
  ).toHaveCount(0);
}

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content:
      "*, *::before, *::after { animation: none !important; transition: none !important; }",
  });
}

async function revealInline(page: Page): Promise<void> {
  // Expand every <details> and reveal class-toggled inline regions, but leave
  // the full-screen modal hidden — it's scanned separately.
  await page.evaluate(() => {
    for (const details of document.querySelectorAll("details")) {
      (details as HTMLDetailsElement).open = true;
    }
    for (const el of document.querySelectorAll<HTMLElement>(".hidden")) {
      if (el.id === "modal-how") continue;
      el.classList.remove("hidden");
    }
    for (const el of document.querySelectorAll<HTMLElement>("*")) {
      if (el.id === "modal-how") continue;
      if (el.style && el.style.display === "none") el.style.display = "";
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(" ")).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

// Drive the ECIES workbench through a full seal so the teaching panels that
// only exist after a keypair/ciphertext — the ECDH convergence panel, the
// color-coded byte-layout strip, and the "wrong key" (Eve) button — are present
// and get scanned for contrast/labels in both themes.
async function prepareEcies(page: Page): Promise<void> {
  await page.locator("#tab-ecies").click();
  await expect(page.locator("#tab-ecies")).toHaveAttribute("aria-selected", "true");
  await page.locator("#btn-keygen").click();
  // Bob's public key populates the seal field once the three keypairs exist.
  await expect(page.locator("#seal-recipient-pk")).not.toHaveValue("");
  await page.locator("#seal-message").fill("Meet at the docks at midnight.");
  await page.locator("#btn-seal").click();
  // The sealed-envelope byte strip and ECDH panel appear after a successful seal.
  await expect(page.locator(".byte-strip")).toBeVisible();
  await expect(page.locator("#btn-open-wrong")).toBeVisible();
}

async function runSuite(page: Page): Promise<void> {
  await prepareEcies(page);
  await neutralizeMotion(page);
  for (const tab of TABS) {
    await page.locator(`#tab-${tab}`).click();
    await expect(page.locator(`#tab-${tab}`)).toHaveAttribute(
      "aria-selected",
      "true",
    );
    await neutralizeMotion(page);
    await revealInline(page);
    await scan(page);
  }

  // "How It Works" modal — its backdrop covers the page.
  await page.locator("#btn-how").click();
  const modal = page.locator("#modal-how");
  await expect(modal).toBeVisible();
  await neutralizeMotion(page);
  await scan(page);
  await page.locator("#btn-close-modal").click();
  await expect(modal).toBeHidden();
}

test("no WCAG A/AA violations in dark theme", async ({ page }) => {
  await page.goto(".");
  await waitForBoot(page);
  await runSuite(page);
});

test("no WCAG A/AA violations in light theme", async ({ page }) => {
  await page.goto(".");
  await waitForBoot(page);
  await page.locator("#cl-theme-toggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await runSuite(page);
});
