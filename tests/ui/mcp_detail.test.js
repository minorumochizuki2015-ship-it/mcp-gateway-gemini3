const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { parseHTML } = require("linkedom");
const { URLSearchParams } = require("url");

const root = path.resolve(__dirname, "../..");

function loadPage(filePath, detail, history) {
  const html = fs.readFileSync(filePath, "utf-8");
  const { window, document } = parseHTML(html);
  window.location = new URL(`http://localhost/${path.basename(filePath)}?server_id=1`);
  const context = { window, document, console, URLSearchParams };
  context.fetch = () => Promise.resolve({ ok: false });
  context.apiClient = {
    fetchMcpDetail: async () => detail,
    fetchMcpHistory: async () => history || null,
  };
  context.window.URLSearchParams = URLSearchParams;
  context.window.apiClient = context.apiClient;
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

async function testMcpDetail() {
  const detail = {
    server: { name: "gateway-lab", base_url: "http://gateway.lab", status: "approved" },
    allowlist: { status: "active", risk_level: "high", capabilities: ["sampling", "network_write"] },
    scan: { run_id: "run-1", status: "warn", last_scan_ts: "2025-12-11T10:00:00Z", severity_counts: { critical: 0, high: 1, medium: 2, low: 0 } },
    council: { run_id: "council-1", decision: "quarantine", rationale: "test reason", ts: "2025-12-11T11:00:00Z" },
    evidence: { scan_run_id: "run-1", council_run_id: "council-1" },
  };
  const history = {
    server_id: 1,
    history: [
      { type: "council_decision", ts: "2025-12-10T14:35:00Z", decision: "allow", rationale: "ok", evaluator_count: 3 },
      { type: "scan", run_id: "run-2", ts: "2025-12-10T14:30:00Z", status: "pass", severity_counts: { critical: 0, high: 1, medium: 0, low: 0 }, owasp_counts: { LLM01: 1 } }
    ],
    total: 2,
    limit: 20,
    offset: 0
  };
  const { document, window } = loadPage(path.join(root, "docs/ui_poc/mcp_detail.html"), detail, history);
  await tick();
  if (window.loadHistory) {
    await window.loadHistory();
    await tick();
    if (window.applyHistoryFilter) {
      window.applyHistoryFilter();
      await tick();
    }
    if (window.renderHistory && window.historyData) {
      window.renderHistory(window.historyData.history);
      await tick();
    }
  }
  assert.strictEqual(document.getElementById("srvName").textContent, "gateway-lab");
  assert.strictEqual(document.getElementById("allowRisk").textContent, "high");
  assert.ok(document.getElementById("allowCaps").textContent.includes("sampling"));
  assert.ok(document.getElementById("scanSev").textContent.includes("H:1"));
  assert.strictEqual(document.getElementById("councilDecision").textContent, "quarantine");
  assert.strictEqual(document.getElementById("evScan").textContent, "run-1");

  // switch to history tab and verify list
  document.getElementById("tabHistory").click();
  await tick();
  await tick();
  const historyList = document.getElementById("historyList");
  assert.ok(historyList.querySelector('[data-type="council_decision"]'));
  const typeSelect = document.getElementById("historyType");
  typeSelect.value = "scan";
  typeSelect.dispatchEvent(new document.defaultView.Event("change"));
  await tick();
  if (window.applyHistoryFilter) {
    window.applyHistoryFilter();
    await tick();
  }
  const items = Array.from(historyList.querySelectorAll("li"));
  assert.ok(items.length > 0);
  assert.ok(items.some((el) => (el.getAttribute("data-type") || "").includes("scan") || el.textContent.includes("Scan")));
}

async function testMcpDetailUnavailable() {
  const { document } = loadPage(path.join(root, "docs/ui_poc/mcp_detail.html"), null);
  await tick();
  const errorCard = document.getElementById("errorCard");
  assert.strictEqual(errorCard.style.display, "block");
}

(async () => {
  await testMcpDetail();
  await testMcpDetailUnavailable();
  console.log("mcp detail tests: ok");
})();
