import { expect, test } from "@playwright/test";

test("every section opens without errors", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  for (const [path, heading] of [["/", "Network overview"], ["/alerts", "Alerts"], ["/tls", "TLS clients"], ["/rules", "Detection rules"], ["/analyze", "Analyse a capture"], ["/detection", "Detection coverage"]]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
  }
  expect(errors).toEqual([]);
});

test("a launched attack is detected and explained", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Sensor online")).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "DNS tunnelling" }).click();
  const alert = page.getByRole("button", { name: /Possible DNS tunnelling/ });
  await expect(alert).toBeVisible({ timeout: 30_000 });
  await alert.click();
  await expect(page.getByRole("dialog")).toContainText("T1071.004");
  await expect(page.getByRole("dialog")).toContainText("Recommended response");
});

test("the sample capture is analysed in the browser", async ({ page }) => {
  await page.goto("/analyze");
  await page.getByRole("button", { name: "Analyse the sample capture" }).click();
  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible({ timeout: 60_000 });
  for (const finding of [/Port scan/, /SYN flood/, /DNS tunnelling/, /Rare TLS client/, /Beaconing/]) await expect(page.getByText(finding).first()).toBeVisible();
});

test("a broken rule is rejected with its line number", async ({ page }) => {
  await page.goto("/rules");
  const box = page.getByLabel("Rules");
  await expect(box).not.toHaveValue("");
  await box.fill('alert tcp any any -> any 22 (msg:"missing semicolon" sid:9)');
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByText(/line 1:/)).toBeVisible();
});
