import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("5G identity exhibit creates fresh Profile A outputs and shows null and tamper limits", async ({ page }) => {
  await page.goto("./");
  await page.getByRole("tab", { name: "5G identity" }).click();
  await page.getByRole("button", { name: "Generate and send" }).click();
  await expect(page.locator("#suci-last-run")).toContainText("Home network recovered MSIN: 001002086");
  const first = await page.locator(".suci-fields dd").last().innerText();
  await page.getByRole("button", { name: "Generate and send" }).click();
  const second = await page.locator(".suci-fields dd").last().innerText();
  expect(second).not.toBe(first);

  await page.getByRole("checkbox", { name: /Change one encrypted bit/ }).check();
  await page.getByRole("button", { name: "Generate and send" }).click();
  await expect(page.getByText(/MAC check failed; altered output rejected/)).toBeVisible();

  await page.getByLabel("Situation").selectOption("null");
  await page.getByRole("button", { name: "Generate and send" }).click();
  await expect(page.getByText(/A nearby observer can read the subscriber digits/)).toBeVisible();
  await expect(page.locator(".suci-fields dd").last()).toHaveText("00012080f6");
  await page.getByLabel("Situation").selectOption("emergency");
  await expect(page.getByText(/when the phone receives an Identity Request/)).toBeVisible();
  await expect(page.getByRole("link", { name: /ETSI TS 133 501 V19.7.0/ })).toHaveAttribute("href", /ts_133501v190700p\.pdf$/);
});

test("5G identity exhibit remains accessible at narrow width", async ({ page }) => {
  await page.setViewportSize({ width: 380, height: 812 });
  await page.goto("./");
  await page.getByRole("tab", { name: "5G identity" }).click();
  await page.getByRole("button", { name: "Generate and send" }).click();
  await expect(page.locator("#suci-last-run")).toContainText("Home network recovered MSIN: 001002086");
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(results.violations).toEqual([]);
  const horizontalOverflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
  expect(horizontalOverflow).toBe(false);
});
