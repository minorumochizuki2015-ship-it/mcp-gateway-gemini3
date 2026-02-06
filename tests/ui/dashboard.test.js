const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { parseHTML } = require("linkedom");

const root = path.resolve(__dirname, "../..");

function loadPage(summary) {
  const filePath = path.join(root, "docs/ui_poc/dashboard.html");
  const html = fs.readFileSync(filePath, "utf-8");
  const { window, document } = parseHTML(html);
  const context = { window, document, console };
  context.window.apiClient = {
    fetchDashboardSummary: async () => summary,
  };
  context.fetch = () => Promise.resolve({ ok: false });
  vm.createContext(context);
  const scripts = Array.from(document.querySelectorAll("script"))
    .filter((s) => !s.getAttribute("src"))
    .map((s) => s.textContent || "");
  for (const code of scripts) {
    vm.runInContext(code, context);
  }
  return { document, window };
}

function tick() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function testDashboardRender() {
  const summary = {
    allowlist: { total: 4, active: 3, deny: 0, quarantine: 1 },
    scans: {
      total: 12,
      latest_status: "warn",
      latest_ts: "2025-12-10T14:30:00Z",
      severity_counts: { critical: 1, high: 3, medium: 4, low: 2 },
      owasp_counts: { LLM01: 2 },
    },
    council: { total: 4, latest_decision: "allow", latest_ts: "2025-12-10T14:35:00Z" },
    shadow_audit: { chain_ok: true, policy_bundle_hash_ok: false },
  };
  const { document } = loadPage(summary);
  await tick();
  assert.strictEqual(document.getElementById("allowTotal").textContent, "4");
  assert.ok(document.getElementById("allowBadges").textContent.includes("active 3"));
  assert.strictEqual(document.getElementById("scanTotal").textContent, "12");
  assert.ok(document.getElementById("scanLatest").textContent.includes("warn"));
  assert.strictEqual(document.getElementById("councilTotal").textContent, "4");
  assert.ok(document.getElementById("shadowStatus").textContent.includes("chain OK"));
  // New severity grid uses .severity-item instead of #severityList li
  const severityItems = document.querySelectorAll(".severity-item");
  assert.ok(severityItems.length >= 4, "at least 4 severity items");
  assert.ok(document.getElementById("criticalCount"), "criticalCount element exists");
  assert.ok(document.getElementById("highCount"), "highCount element exists");
}

async function testDashboardUnavailable() {
  const { document } = loadPage(null);
  await tick();
  assert.strictEqual(document.getElementById("errorBox").style.display, "block");
}

async function testNavbarLinks() {
  const { document } = loadPage({});
  await tick();
  
  const navLinks = document.querySelectorAll(".nav-link");
  assert.ok(navLinks.length >= 5, "at least 5 nav links exist");
  
  const hrefs = Array.from(navLinks).map(l => l.getAttribute("href"));
  assert.ok(hrefs.includes("settings_environments.html"), "environments link exists");
  assert.ok(hrefs.includes("dashboard.html"), "dashboard link exists");
  assert.ok(hrefs.includes("scans.html"), "scans link exists");
  assert.ok(hrefs.includes("allowlist.html"), "allowlist link exists");
  assert.ok(hrefs.includes("audit_log.html"), "audit log link exists");
}

async function testLangToggle() {
  const { document } = loadPage({});
  await tick();
  
  const langJa = document.getElementById("langJa");
  const langEn = document.getElementById("langEn");
  assert.ok(langJa, "JA language button exists");
  assert.ok(langEn, "EN language button exists");
}

(async () => {
  await testDashboardRender();
  await testDashboardUnavailable();
  await testNavbarLinks();
  await testLangToggle();
  console.log("dashboard tests: ok");
})();
