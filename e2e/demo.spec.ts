import { expect, test } from "@playwright/test";

// Returning visitors skip the first-screen briefing; one test below checks it as a first-timer.
test.beforeEach(async ({ page }, info) => {
  if (!info.title.startsWith("first screen")) await page.addInitScript(() => localStorage.setItem("packeteye-briefed", "1"));
});

test("every tool opens over the map without errors", async ({ page }) => {
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

test("picking a strip on the alert board locks the scope onto that alert", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Live", { exact: true })).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("Attack to simulate").selectOption("port_scan");
  await page.getByRole("button", { name: "Launch" }).click();
  await page.keyboard.press("2");
  await expect(page.getByRole("heading", { level: 1, name: "Alerts" })).toBeVisible();
  const strip = page
    .getByRole("list", { name: "open alerts" })
    .getByRole("button", { name: /Port scan/ })
    .first();
  await expect(strip).toBeVisible({ timeout: 30_000 });
  await expect(strip).toContainText("T1046");
  await strip.click();
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
  test("the sonar sweep is switched off", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("img", { name: /Network map/ })).toBeVisible();
    await expect(page.locator(".sweep")).toBeHidden();
  });
});

test("the scope works on a phone without horizontal scrolling", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByRole("img", { name: /Network map/ })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Tools" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("Rewind replays an incident on the scope and returns to live", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Live", { exact: true })).toBeVisible({ timeout: 30_000 });
  // The demo starts with a port scan already recorded; replay it from its strip.
  const strip = page.getByRole("button", { name: /Port scan/ }).first();
  await expect(strip).toBeVisible({ timeout: 30_000 });
  await strip.click();
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
  // R rewinds the last minute from anywhere on the scope.
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
  await page.getByRole("button", { name: "Run it on the live scope" }).click();
  await expect(page.getByText(/launched on the live scope, 12× slower/)).toBeVisible();
});

test("explain-like-I'm-new mode adds plain words everywhere and is remembered", async ({ page }) => {
  await page.goto("/");
  const toggle = page.getByRole("button", { name: "Explain like I'm new" });
  await expect(toggle).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByText(/This is a sonar screen for a network/)).toHaveCount(0);
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByText(/This is a sonar screen for a network/)).toBeVisible();
  await expect(page.getByText("OFFICE · people's computers")).toBeVisible();
  const strip = page.getByRole("button", { name: /Port scan/ }).first();
  await expect(strip).toBeVisible({ timeout: 30_000 });
  await strip.click();
  await expect(page.getByRole("complementary", { name: "Inspector" })).toContainText("Someone is trying every door handle");
  await page.reload();
  await expect(page.getByRole("button", { name: "Explain like I'm new" })).toHaveAttribute("aria-pressed", "true");
  await page.keyboard.press("e");
  await expect(page.getByText(/This is a sonar screen for a network/)).toHaveCount(0);
});

test("an alert becomes a shareable report link that opens on its own", async ({ page }) => {
  await page.goto("/");
  const strip = page.getByRole("button", { name: /Port scan/ }).first();
  await expect(strip).toBeVisible({ timeout: 30_000 });
  await strip.click();
  const inspector = page.getByRole("complementary", { name: "Inspector" });
  const title = (await inspector.getByRole("heading", { level: 2 }).first().textContent()) ?? "";
  await inspector.getByRole("button", { name: "Share report" }).click();
  const href = await inspector.getByRole("link", { name: "Open the report" }).getAttribute("href");
  expect(href).toMatch(/\/report#[A-Za-z0-9_-]{50,}$/);
  await page.goto(href!);
  await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
  await expect(page.getByText("T1046").first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Recommended response" })).toBeVisible();
  await expect(page.getByRole("img", { name: /The incident on the scope, frame \d+ of [1-9]\d*/ })).toBeVisible();
  // A damaged link says so instead of breaking.
  await page.goto("/report#broken");
  await expect(page.getByRole("heading", { name: "No report here" })).toBeVisible();
});

test("how it works follows one real packet from the wire to the alert board", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: "How it works" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Capture" })).toBeVisible();
  await expect(page.getByText(/PacketEye never reads what.s inside a message/)).toBeVisible();
  await expect(page.getByLabel(/^The first 96 of \d+ bytes of the frame/)).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Next stage" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Decode" })).toBeVisible();
  await expect(page.getByText(/^t13i\d+_/)).toBeVisible();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("heading", { level: 1, name: "Flow" })).toBeVisible();
  await expect(page.getByText("log_bytes")).toBeVisible();
  // Each ring on the scope is a stage you can jump to (here with the keyboard).
  await page.getByRole("button", { name: "Stage 4: Detect" }).press("Enter");
  await expect(page.getByRole("heading", { level: 1, name: "Detect" })).toBeVisible();
  await expect(page.getByText("Fired", { exact: true })).toBeVisible();
  await expect(page.getByText("Matched", { exact: true })).toBeVisible();
  await expect(page.getByRole("meter", { name: "Anomaly score" })).toBeVisible();
  await page.keyboard.press("5");
  await expect(page.getByRole("button", { name: /Rare TLS client/ })).toBeVisible();
  await page.getByRole("button", { name: "Launch this implant on the live scope" }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("img", { name: /Network map/ })).toBeVisible();
});

test("first screen: a first-time visitor gets the idea, then watches an attack get caught", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1, name: "See attacks the way radar sees aircraft." })).toBeVisible();
  for (const t of ["The problem", "The idea", "Why it's different"]) await expect(page.getByText(t, { exact: true })).toBeVisible();
  await expect(page.getByRole("img", { name: /Network map/ })).toBeVisible();
  await page.getByRole("button", { name: "Watch an attack get caught →" }).click();
  await expect(page.getByRole("heading", { name: "See attacks the way radar sees aircraft." })).toHaveCount(0);
  // The scope locks onto the attack's alert by itself.
  const inspector = page.getByRole("complementary", { name: "Inspector" });
  await expect(inspector).toContainText("T1046", { timeout: 30_000 });
  // It does not come back on the next visit, but the logo brings it back.
  await page.reload();
  await expect(page.getByRole("heading", { name: "See attacks the way radar sees aircraft." })).toHaveCount(0);
  await page.getByRole("button", { name: "PacketEye" }).click();
  await expect(page.getByRole("heading", { name: "See attacks the way radar sees aircraft." })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("heading", { name: "See attacks the way radar sees aircraft." })).toHaveCount(0);
});

test("the command console runs any action by name, and sonar pings sound for new alerts", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Live", { exact: true })).toBeVisible({ timeout: 30_000 });
  await page.getByRole("button", { name: "Sonar pings" }).click();
  await expect(page.getByRole("button", { name: "Sonar pings" })).toHaveAttribute("aria-pressed", "true");
  await page.keyboard.press("Control+k");
  const console = page.getByRole("dialog", { name: "Command console" });
  await expect(console).toBeVisible();
  await page.getByRole("combobox", { name: "Command" }).fill("launch dns");
  await expect(console.getByRole("option", { name: "Launch: DNS tunnelling" })).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("Enter");
  await expect(console).toBeHidden();
  // The scope follows the launched attack, and its alert pings.
  await expect(page.getByRole("complementary", { name: "Inspector" })).toContainText("T1071.004", { timeout: 30_000 });
  await expect.poll(() => page.evaluate(() => Number(document.documentElement.dataset.pings ?? 0))).toBeGreaterThan(0);
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
