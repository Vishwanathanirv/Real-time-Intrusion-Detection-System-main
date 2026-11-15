import { expect, test } from "@playwright/test";

test("every tool opens over the map without errors", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await expect(page.getByRole("img", { name: /Network map: \d+ hosts/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "The network right now" })).toBeVisible();
  for (const [path, heading] of [["/alerts", "Alerts"], ["/tls", "TLS clients"], ["/rules", "Detection rules"], ["/analyze", "Analyse a capture"], ["/detection", "Detection coverage"]]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
  }
  expect(errors).toEqual([]);
});

test("a launched attack is detected, shown on the map and explained", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Live", { exact: true })).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Attack to simulate").selectOption("dns_tunnel");
  await page.getByRole("button", { name: "Launch" }).click();
  const alert = page.getByRole("button", { name: /Possible DNS tunnelling/ }).first();
  await expect(alert).toBeVisible({ timeout: 30_000 });
  await alert.click();
  const inspector = page.getByRole("complementary", { name: "Inspector" });
  await expect(inspector).toContainText("T1071.004");
  await expect(inspector).toContainText("What to do");
  await inspector.getByRole("button", { name: "Acknowledge" }).click();
  await expect(inspector).toContainText("Status: acknowledged");
});

test("clicking a host on the map shows who it talks to", async ({ page }) => {
  await page.goto("/");
  const server = page.getByRole("button", { name: /^File server/ });
  await expect(server).toBeVisible({ timeout: 30_000 });
  await server.dispatchEvent("pointerup");
  const inspector = page.getByRole("complementary", { name: "Inspector" });
  await expect(inspector).toContainText("Talking to");
  await expect(inspector).toContainText("10.0.0.20");
});

test("the sample capture is analysed in the browser", async ({ page }) => {
  await page.goto("/analyze");
  await page.getByRole("button", { name: "Analyse the sample capture" }).click();
  await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible({ timeout: 60_000 });
  const sheet = page.getByRole("region", { name: "Analyse a pcap" });
  for (const finding of [/Port scan/, /SYN flood/, /DNS tunnelling/, /Rare TLS client/, /Beaconing/]) await expect(sheet.getByText(finding).first()).toBeVisible();
});

test("a broken rule is rejected with its line number", async ({ page }) => {
  await page.goto("/rules");
  const box = page.getByLabel("Rules", { exact: true }).and(page.locator("textarea"));
  await expect(box).not.toHaveValue("");
  await box.fill('alert tcp any any -> any 22 (msg:"missing semicolon" sid:9)');
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByText(/line 1:/)).toBeVisible();
});
