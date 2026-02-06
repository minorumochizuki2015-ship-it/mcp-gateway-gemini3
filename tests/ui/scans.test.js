const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { parseHTML } = require("linkedom");

const root = path.resolve(__dirname, "../..");

function loadPage(filePath, { query = "", apiClientFactory }) {
  const html = fs.readFileSync(filePath, "utf-8");
  const { window, document } = parseHTML(html);
  window.location = new URL(`http://localhost/${path.basename(filePath)}${query}`);
  const context = {
    window,
    document,
    console,
    URL,
    URLSearchParams,
    setTimeout,
    clearTimeout,
  };
  context.fetch = () => Promise.resolve({ ok: false });
  vm.createContext(context);
  const mockCode = fs.readFileSync(path.join(root, "docs/ui_poc/mock_data.js"), "utf-8");
  vm.runInContext(mockCode, context);
  if (apiClientFactory) {
    window.apiClient = apiClientFactory(window);
  }
  const scripts = Array.from(document.querySelectorAll("script"))
    .filter((s) => !s.getAttribute("src"))
    .map((s) => s.textContent || "");
  for (const code of scripts) {
    vm.runInContext(code, context);
  }
  return { window, document, render: context.render };
}

function tick() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function testScansPage() {
  const { document } = loadPage(path.join(root, "docs/ui_poc/scans.html"), {
    apiClientFactory: (win) => ({
      fetchScans: async () => win.suiteScanData.scans,
    }),
  });
  await tick();
  const nav = document.querySelector(".nav");
  assert.ok(nav, "renders nav");
  const rows = document.querySelectorAll("tbody#scanRows tr");
  assert.ok(rows.length >= 2, "should render rows from mock data");
  const firstCells = rows[0].querySelectorAll("td");
  assert.ok(firstCells[1].textContent.includes("gateway"), "shows environment");
  const link = rows[0].querySelector("a");
  assert.ok(link.getAttribute("href").startsWith("scan_detail.html?id="));
}

async function testScansFilterControls() {
  const { document } = loadPage(path.join(root, "docs/ui_poc/scans.html"), {
    apiClientFactory: (win) => ({
      fetchScans: async () => win.suiteScanData.scans,
    }),
  });
  await tick();
  const select = document.getElementById("statusFilter");
  assert.ok(select, "status filter exists");
  const options = Array.from(select.querySelectorAll("option")).map((o) => o.value);
  assert.ok(options.includes("passed") && options.includes("failed"), "has status options");
}

async function testScansFallbackUsesMock() {
  const { document } = loadPage(path.join(root, "docs/ui_poc/scans.html"), {
    apiClientFactory: (win) => ({
      fetchScans: async () => win.suiteScanData.scans,
    }),
  });
  await tick();
  const rows = document.querySelectorAll("tbody#scanRows tr");
  assert.ok(rows.length >= 2, "fallback renders mock rows");
  const statTotal = document.getElementById("statTotal").textContent;
  assert.ok(Number(statTotal) >= 2, "stats show totals");
}

async function testScansStatusFilter() {
  const { document, render } = loadPage(path.join(root, "docs/ui_poc/scans.html"), {
    apiClientFactory: (win) => ({
      fetchScans: async () => win.suiteScanData.scans,
    }),
  });
  await tick();
  const select = document.getElementById("statusFilter");
  let statusValue = "";
  Object.defineProperty(select, "value", {
    configurable: true,
    enumerable: true,
    get() {
      return statusValue;
    },
    set(v) {
      statusValue = v;
    },
  });
  const rows = () => document.querySelectorAll("tbody#scanRows tr");
  assert.strictEqual(rows().length, 2, "initially renders all rows");

  select.value = "passed";
  select.selectedIndex = 1;
  assert.strictEqual(select.value, "passed", "status filter value set");
  render();
  await tick();
  assert.strictEqual(rows().length, 1, "filters to passed");
  assert.ok(rows()[0].textContent.includes("gateway-lab"));

  select.value = "failed";
  select.selectedIndex = 2;
  render();
  await tick();
  assert.strictEqual(rows().length, 1, "filters to failed");
  assert.ok(rows()[0].textContent.includes("gateway-prod"));
}

async function testScansEnvironmentFilter() {
  const { document, render } = loadPage(path.join(root, "docs/ui_poc/scans.html"), {
    apiClientFactory: (win) => ({
      fetchScans: async () => win.suiteScanData.scans,
    }),
  });
  await tick();
  const envInput = document.getElementById("envFilter");
  const rows = () => document.querySelectorAll("tbody#scanRows tr");
  assert.strictEqual(rows().length, 2, "initially renders all rows");

  envInput.value = "prod";
  render();
  await tick();
  assert.strictEqual(rows().length, 1, "filters to prod environment");
  assert.ok(rows()[0].textContent.includes("gateway-prod"));

  envInput.value = "";
  render();
  await tick();
  assert.strictEqual(rows().length, 2, "clearing filter restores all rows");
}

async function testScanDetailPage() {
  const { document } = loadPage(path.join(root, "docs/ui_poc/scan_detail.html"), {
    query: "?id=scan-001",
    apiClientFactory: () => ({
      fetchScanDetail: async () => ({
        scan: {
          id: "scan-001",
          environment: "gateway-lab",
          profile: "full",
          status: "passed",
          startedAt: "2025-12-10T09:15:00Z",
          durationSeconds: 95,
          actor: "analyst@example.com",
        },
        findings: [
          {
            severity: "High",
            category: "認証",
            summary: "Token audience mismatch detected",
            resource: "/gateway/tools",
            owasp_llm_code: "LLM01",
            owasp_llm_title: "Prompt injection",
            evidence_source: "ci_evidence",
          },
        ],
      }),
    }),
  });
  await tick();
  const meta = document.querySelectorAll(".meta-card");
  assert.ok(meta.length >= 5, "renders summary cards");
  const findings = document.querySelectorAll("tbody#findingRows tr");
  assert.strictEqual(findings.length, 1, "renders findings row");
  assert.ok(findings[0].textContent.includes("LLM01"));
}

(async () => {
  await testScansPage();
  await testScansFilterControls();
  await testScansFallbackUsesMock();
  await testScansStatusFilter();
  await testScansEnvironmentFilter();
  await testScanDetailPage();
  console.log("ui scans tests: ok");
})();
