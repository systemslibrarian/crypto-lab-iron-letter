import { expect, test, type Page } from "@playwright/test";

/**
 * Browser gate for the man-in-the-middle exhibit.
 *
 * These assertions are on values the page COMPUTED in that run — the two ECDH
 * secrets as hex, the plaintext Eve's private key actually recovered, the text
 * Bob actually decrypted, and the real ECDSA verification result — not on
 * static copy. The authenticated variant must be shown to defeat the same
 * attack, or the exhibit teaches nothing.
 */

const ALICE_MESSAGE = "Meet me at the north gate at eight. — Alice";
const HEX32 = /^[0-9a-f]{64}$/;

async function boot(page: Page): Promise<void> {
  await page.goto(".");
  await expect(page.getByText("Running WebCrypto self-check...")).toHaveCount(0);
  await page.locator("#tab-ecies").click();
  await expect(page.locator("#mitm-message")).toBeVisible();
  await page.locator("#mitm-message").fill(ALICE_MESSAGE);
}

test("unauthenticated: Eve substitutes her key, reads the letter, and the two sides derive different secrets", async ({
  page,
}) => {
  await boot(page);
  await page.locator("#btn-mitm-unauth").click();

  // The verdict is derived from a byte comparison of this run's two secrets.
  await expect(page.locator("#mitm-verdict")).toContainText("Secrets DIFFER");

  const alice = (await page.locator("#mitm-alice-secret").innerText()).trim();
  const bob = (await page.locator("#mitm-bob-secret").innerText()).trim();
  expect(alice).toMatch(HEX32);
  expect(bob).toMatch(HEX32);
  expect(alice).not.toBe(bob);

  // Eve's decrypt is a real AES-GCM open with her own private key.
  await expect(page.locator("#mitm-eve-read")).toHaveText(ALICE_MESSAGE);
  // ...and Bob's side of the wire looks entirely normal.
  await expect(page.locator("#mitm-bob-read")).toHaveText(ALICE_MESSAGE);

  // The check Alice skipped is computed anyway, and it would have failed.
  await expect(page.locator("#mitm-result")).toContainText("the key was accepted on sight");
  await expect(page.locator("#mitm-result")).toContainText("INVALID");
  // Control: the same verification passes over Bob's genuine signed key, so
  // "INVALID" above means "Eve's key", not "verification is broken".
  await expect(page.getByText("Control: same check over Bob's genuine signed key")).toBeVisible();
});

test("unauthenticated: Eve can replace Alice's words and Bob's decryption still succeeds", async ({
  page,
}) => {
  await boot(page);
  await page.locator("#mitm-tamper").check();
  await page.locator("#btn-mitm-unauth").click();

  await expect(page.locator("#mitm-eve-read")).toHaveText(ALICE_MESSAGE);
  const bobRead = (await page.locator("#mitm-bob-read").innerText()).trim();
  expect(bobRead).not.toBe(ALICE_MESSAGE);
  expect(bobRead).toContain("account 4471");
});

test("authenticated: the signature check defeats the identical attack", async ({ page }) => {
  await boot(page);
  await page.locator("#mitm-tamper").check();
  await page.locator("#btn-mitm-auth").click();

  await expect(page.locator("#mitm-verdict")).toContainText("Attack defeated");
  await expect(page.locator("#mitm-result")).toContainText("Yes — signed-key channel");
  await expect(page.locator("#mitm-result")).toContainText("returned false");

  // Nothing to read and nothing to forge: the seal never happened.
  await expect(page.locator("#mitm-eve-read")).toHaveCount(0);
  await expect(page.locator("#mitm-alice-secret")).toHaveCount(0);
  await expect(page.locator("#mitm-result")).toContainText("Eve recovered:");
  await expect(page.locator("#mitm-result")).toContainText("nothing");
});

test("both variants run back to back from the same key substitution", async ({ page }) => {
  await boot(page);
  await page.locator("#btn-mitm-unauth").click();
  await expect(page.locator("#mitm-verdict")).toContainText("Secrets DIFFER");
  await expect(page.locator("#mitm-result")).toContainText("SUBSTITUTED by Eve");

  await page.locator("#btn-mitm-auth").click();
  await expect(page.locator("#mitm-verdict")).toContainText("Attack defeated");
  // Same substitution on the wire — only the check changed.
  await expect(page.locator("#mitm-result")).toContainText("SUBSTITUTED by Eve");
});
