import { expect, test } from "@playwright/test";

test("every tool opens without errors", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await expect(page.getByRole("img", { name: /Network map: \d+ hosts/ })).toBeVisible();
  await expect(page.getByRole("heading", { name: "The network right now" })).toBeVisible();
  for (const [path, heading] of [
    ["/alerts", "Alerts"],
    ["/tls", "TLS clients"],
    ["/rules", "Detection rules"],
    ["/analyze", "Analyse a capture"],
    ["/detection", "Detection coverage"],
  ]) {
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

test("opening an alert from the alert list selects it on the overview", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Live", { exact: true })).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Attack to simulate").selectOption("port_scan");
  await page.getByRole("button", { name: "Launch" }).click();
  await page.keyboard.press("2");
  await expect(page.getByRole("heading", { level: 1, name: "Alerts" })).toBeVisible();
  const row = page
    .getByRole("list", { name: "open alerts" })
    .getByRole("button", { name: /Port scan/ })
    .first();
  await expect(row).toBeVisible({ timeout: 30_000 });
  await expect(row).toContainText("T1046");
  await row.click();
  await expect(page).toHaveURL(/\/$/);
  const inspector = page.getByRole("complementary", { name: "Inspector" });
  await expect(inspector).toContainText("T1046");
  await expect(inspector).toContainText("What to do");
});

test("coverage shows the public NSL-KDD benchmark per class", async ({ page }) => {
  await page.goto("/detection");
  const panel = page.getByRole("region", { name: "Coverage" });
  await expect(panel.getByText("Public dataset: NSL-KDD, held-out test set")).toBeVisible();
  for (const c of ["Normal", "DoS", "Probe", "Remote to local", "User to root"]) await expect(panel.getByRole("cell", { name: c, exact: true })).toBeVisible();
});

test.describe("with reduced motion", () => {
  test.use({ reducedMotion: "reduce" });
  test("moving traffic lines stand still", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("img", { name: /Network map/ })).toBeVisible();
    await expect(page.locator(".flow").first()).toBeAttached({ timeout: 30_000 });
    expect(await page.locator(".flow").first().evaluate((el) => getComputedStyle(el).animationName)).toBe("none");
  });
});

test("the overview works on a phone without horizontal scrolling", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByRole("img", { name: /Network map/ })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Tools" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("Rewind replays an incident on the map and returns to live", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Live", { exact: true })).toBeVisible({ timeout: 30_000 });
  // The demo starts with a port scan already recorded; replay it from its row.
  const row = page.getByRole("button", { name: /Port scan/ }).first();
  await expect(row).toBeVisible({ timeout: 30_000 });
  await row.click();
  const inspector = page.getByRole("complementary", { name: "Inspector" });
  await inspector.getByRole("button", { name: "Replay this incident" }).click();
  const tape = page.getByRole("slider", { name: "Replay position" });
  await expect(tape).toBeVisible();
  await expect(page.getByText(/^REPLAY · /)).toBeVisible();
  const before = Number(await tape.getAttribute("aria-valuenow"));
  await expect.poll(async () => Number(await tape.getAttribute("aria-valuenow")), { timeout: 10_000 }).toBeGreaterThan(before);
  // Scrub with the keyboard, then go back to live.
  await page.getByRole("button", { name: "Pause the replay" }).click();
  await tape.focus();
  const at = Number(await tape.getAttribute("aria-valuenow"));
  await page.keyboard.press("Shift+ArrowLeft");
  await expect(tape).toHaveAttribute("aria-valuenow", String(Math.max(0, at - 10)));
  await page.getByRole("button", { name: "Back to live" }).click();
  await expect(tape).toBeHidden();
  // R rewinds the last minute from anywhere.
  await page.keyboard.press("r");
  await expect(tape).toBeVisible();
  await page.keyboard.press("l");
  await expect(tape).toBeHidden();
});

test("the what-if lab shows a slowed-down attack slipping through, then runs it live", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: "What if…?" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "What-if lab" })).toBeVisible();
  await page.getByRole("radio", { name: /SYN flood/ }).click();
  await expect(page.getByText(/^Caught in /)).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Attacker patience: how many times slower").fill("12");
  await expect(page.getByText("Slipped through")).toBeVisible({ timeout: 30_000 });
  // Lower the threshold until the patient flood is caught again.
  await page.getByLabel(/^Threshold: SYN packets per second/).fill("20");
  await expect(page.getByText(/^Caught in /)).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Run it on the live network" }).click();
  await expect(page.getByText(/launched on the live network, 12× slower/)).toBeVisible();
});

test("explain-like-I'm-new mode adds plain words everywhere and is remembered", async ({ page }) => {
  await page.goto("/");
  const toggle = page.getByRole("button", { name: "Explain like I'm new" });
  await expect(toggle).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByText(/Each dot is a computer and each line/)).toHaveCount(0);
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByText(/Each dot is a computer and each line/)).toBeVisible();
  await expect(page.getByText("Workstations: people's computers")).toBeVisible();
  const row = page.getByRole("button", { name: /Port scan/ }).first();
  await expect(row).toBeVisible({ timeout: 30_000 });
  await row.click();
  await expect(page.getByRole("complementary", { name: "Inspector" })).toContainText("Someone is trying every door handle");
  await page.reload();
  await expect(page.getByRole("button", { name: "Explain like I'm new" })).toHaveAttribute("aria-pressed", "true");
  await page.keyboard.press("e");
  await expect(page.getByText(/Each dot is a computer and each line/)).toHaveCount(0);
});

test("an alert becomes a shareable report link that opens on its own", async ({ page }) => {
  await page.goto("/");
  const row = page.getByRole("button", { name: /Port scan/ }).first();
  await expect(row).toBeVisible({ timeout: 30_000 });
  await row.click();
  const inspector = page.getByRole("complementary", { name: "Inspector" });
  const title = (await inspector.getByRole("heading", { level: 2 }).first().textContent()) ?? "";
  await inspector.getByRole("button", { name: "Share report" }).click();
  const href = await inspector.getByRole("link", { name: "Open the report" }).getAttribute("href");
  expect(href).toMatch(/\/report#[A-Za-z0-9_-]{50,}$/);
  await page.goto(href!);
  await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
  await expect(page.getByText("T1046").first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Recommended response" })).toBeVisible();
  await expect(page.getByRole("img", { name: /The incident on the network map, frame \d+ of [1-9]\d*/ })).toBeVisible();
  // A damaged link says so instead of breaking.
  await page.goto("/report#broken");
  await expect(page.getByRole("heading", { name: "No report here" })).toBeVisible();
});

test("the command menu runs any action by name, and the alert sound chimes for new alerts", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Live", { exact: true })).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Alert sound" }).click();
  await expect(page.getByRole("button", { name: "Alert sound" })).toHaveAttribute("aria-pressed", "true");
  await page.keyboard.press("Control+k");
  const console = page.getByRole("dialog", { name: "Command menu" });
  await expect(console).toBeVisible();
  await page.getByRole("combobox", { name: "Command" }).fill("launch dns");
  await expect(console.getByRole("option", { name: "Launch: DNS tunnelling" })).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("Enter");
  await expect(console).toBeHidden();
  // The overview follows the launched attack, and its alert chimes.
  await expect(page.getByRole("complementary", { name: "Inspector" })).toContainText("T1071.004", { timeout: 30_000 });
  await expect.poll(() => page.evaluate(() => Number(document.documentElement.dataset.chimes ?? 0))).toBeGreaterThan(0);
  await page.keyboard.press("/");
  await page.getByRole("combobox", { name: "Command" }).fill("explain");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: "Explain like I'm new" })).toHaveAttribute("aria-pressed", "true");
  await page.keyboard.press("/");
  await page.getByRole("combobox", { name: "Command" }).fill("nothing like this");
  await expect(page.getByText(/No command matches/)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(console).toBeHidden();
});
