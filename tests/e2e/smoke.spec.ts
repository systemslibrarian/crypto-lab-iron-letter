import { expect, test } from "@playwright/test";

test.describe("Iron Letter smoke", () => {
  test("loads, self-checks, and completes an ECIES round trip", async ({ page }) => {
    await page.goto("/");

    await expect(page.getByRole("heading", { name: "Iron Letter" })).toBeVisible();
    await expect(page.getByText("WebCrypto self-check passed")).toBeVisible();

    await page.getByRole("button", { name: /Generate ECIES P-256 Keypair/i }).click();
    await expect(page.getByText(/Public Key \(65 bytes\)/)).toBeVisible();

    const recipientPublicKey = await page.locator("#seal-recipient-pk").inputValue();
    await expect(recipientPublicKey.length).toBeGreaterThan(0);

    await page.locator("#seal-message").fill("Browser smoke test message");
    await page.getByRole("button", { name: "Seal Letter" }).click();
    await expect(page.getByText(/Ciphertext \(/)).toBeVisible();

    await page.getByRole("button", { name: "Open Letter" }).click();
    await expect(page.locator("#open-plaintext")).toHaveText("Browser smoke test message");
  });

  test("supports deep-linked public keys", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText("WebCrypto self-check passed")).toBeVisible();
    await page.getByRole("tab", { name: "RSA-2048" }).click();
    await page.getByRole("button", { name: /Generate RSA-2048 Keypair/i }).click();
    await expect(page.locator("#seal-recipient-pk")).not.toHaveValue("");

    const publicKey = await page.locator("#seal-recipient-pk").inputValue();
    const shareUrl = new URL("http://127.0.0.1:4173/crypto-lab-iron-letter/");
    shareUrl.searchParams.set("algo", "rsa2048");
    shareUrl.searchParams.set("pk", publicKey);

    await page.goto(shareUrl.toString());
    await expect(page.locator("#seal-recipient-pk")).toHaveValue(publicKey);
  });
});
