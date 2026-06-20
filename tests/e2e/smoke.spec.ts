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

  test("shows a seal error in the Seal panel when inputs are missing", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText("WebCrypto self-check passed")).toBeVisible();

    await page.getByRole("button", { name: /Generate ECIES P-256 Keypair/i }).click();
    await expect(page.getByText(/Public Key \(65 bytes\)/)).toBeVisible();

    // Recipient key auto-fills, but the message is empty: sealing must surface
    // an inline error (not silently no-op, and not buried in the Open panel).
    await page.getByRole("button", { name: "Seal Letter" }).click();
    await expect(page.getByRole("alert")).toContainText(/recipient public key and a message/i);
  });

  test("Run Benchmark populates the comparison table in one click", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText("WebCrypto self-check passed")).toBeVisible();

    await page.getByRole("tab", { name: "Compare" }).click();
    await page.getByRole("button", { name: /Run Benchmark/i }).click();

    // Security-level row is static; metric rows fill in as the benchmark runs.
    await expect(page.getByRole("cell", { name: "~128-bit" })).toBeVisible();
    await expect(page.getByRole("cell", { name: "65 B" })).toBeVisible({ timeout: 30000 });
    await expect(page.getByRole("button", { name: /Run Benchmark/i })).toBeEnabled({ timeout: 30000 });
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
