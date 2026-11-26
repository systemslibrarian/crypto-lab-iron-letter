import { expect, test } from "@playwright/test";

for (const tab of ["ecies", "rsa2048", "rsa4096"]) {
  test(`${tab} opens the exact text Alice sealed for Bob`, async ({ page }) => {
    await page.goto(".");
    await expect(page.getByText("WebCrypto self-check passed")).toBeVisible();
    await page.locator(`[data-tab="${tab}"]`).click();
    await page.locator("#btn-keygen").click();
    const recipient = page.locator("#seal-recipient-pk");
    await expect(recipient).not.toHaveValue("");
    const message = "\uFEFF  Hello, Bob!\n  📚  ";
    await page.locator("#seal-message").fill(message);
    await page.locator("#btn-seal").click();
    await expect(page.locator("#open-ciphertext")).not.toHaveValue("");
    await page.locator("#btn-open").click();
    const plaintext = page.locator("#open-plaintext");
    await expect(plaintext).toBeVisible();
    expect(await plaintext.textContent()).toBe(message);
    await expect(plaintext).toHaveCSS("white-space", "pre-wrap");
  });
}
