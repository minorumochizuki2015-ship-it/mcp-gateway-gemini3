const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { parseHTML } = require("linkedom");

const root = path.resolve(__dirname, "../..");

function loadPage(filePath, { allowlistData, allowlistStatus, statusError = false }) {
  const html = fs.readFileSync(filePath, "utf-8");
  const { window, document } = parseHTML(html);
  window.location = new URL(`http://localhost/${path.basename(filePath)}`);
  const context = { window, document, console };
  context.fetch = () => Promise.resolve({ ok: false });
  context.apiClient = {
    fetchAllowlist: async () => allowlistData,
    fetchAllowlistStatus: async () => {
      if (statusError) return null;
      return allowlistStatus;
    },
  };
  context.window.apiClient = context.apiClient;
  vm.createContext(context);
  const scripts = Array.from(document.querySelectorAll("script"))
    .filter((s) => !s.getAttribute("src"))
    .map((s) => s.textContent || "");
  for (const code of scripts) {
    vm.runInContext(code, context);
  }
  return { document };
}

function tick() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function testAllowlistPage() {
  const mock = [
    {
      id: 1,
      server_id: 1,
      name: "gateway-lab",
      base_url: "http://gateway.lab",
      status: "active",
      registered_at: "2025-12-10T10:00:00Z",
      last_scan_ts: "2025-12-10T11:00:00Z",
    },
    {
      id: 2,
      server_id: 2,
      name: "gateway-prod",
      base_url: "http://gateway.prod",
      status: "proposed",
      registered_at: "2025-12-09T10:00:00Z",
      last_scan_ts: "",
    },
  ];
  const status = {
    total: 2,
    allow: 1,
    deny: 1,
    quarantine: 0,
    last_scan_ts: "2025-12-10T12:00:00Z",
    last_decision_ts: "2025-12-10T13:00:00Z",
    shadow_audit_chain_ok: true,
    policy_bundle_present_ok: true,
    policy_bundle_signature_status: "verified",
    policy_bundle_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    policy_bundle_hash_ok: true, // legacy fallback
  };
  const { document } = loadPage(path.join(root, "docs/ui_poc/allowlist.html"), {
    allowlistData: mock,
    allowlistStatus: status,
  });
  await tick();
  const rows = document.querySelectorAll("tbody#allowRows tr");
  assert.strictEqual(rows.length, 2, "renders allowlist rows");
  assert.ok(rows[0].textContent.includes("gateway-lab"));
  const statusBadge = rows[0].querySelector(".status");
  assert.ok(statusBadge.textContent.includes("active"));
  assert.strictEqual(document.getElementById("statusTotal").textContent, "2");
  assert.strictEqual(document.getElementById("statusAllow").textContent, "1");
  assert.strictEqual(document.getElementById("statusDeny").textContent, "1");
  assert.strictEqual(document.getElementById("statusQuarantine").textContent, "0");
  assert.ok(document.getElementById("statusTimestamps").textContent.includes("last_scan"));
  assert.strictEqual(document.getElementById("shadowBadge").className.includes("ok"), true);
  assert.strictEqual(document.getElementById("bundlePresentBadge").className.includes("ok"), true);
  assert.strictEqual(document.getElementById("bundleSignatureBadge").className.includes("ok"), true);
  assert.ok(document.getElementById("bundleShaBadge").textContent.includes("sha:"), "sha badge rendered");
}

async function testAllowlistStatusUnavailable() {
  const { document } = loadPage(path.join(root, "docs/ui_poc/allowlist.html"), {
    allowlistData: [],
    allowlistStatus: null,
    statusError: true,
  });
  await tick();
  const unavailable = document.getElementById("statusUnavailable");
  assert.strictEqual(unavailable.hidden, false, "shows unavailable message on failure");
}

(async () => {
  await testAllowlistPage();
  await testAllowlistStatusUnavailable();
  console.log("allowlist tests: ok");
})();
