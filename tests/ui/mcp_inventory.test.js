const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { parseHTML } = require("linkedom");

const root = path.resolve(__dirname, "../..");

function loadPage(filePath, { apiFactory } = {}) {
  const html = fs.readFileSync(filePath, "utf-8");
  const { window, document } = parseHTML(html);
  window.location = new URL(`http://localhost/${path.basename(filePath)}`);
  const context = {
    window,
    document,
    console,
    URL,
    URLSearchParams,
    setTimeout,
    clearTimeout,
    fetch: () => Promise.resolve({ ok: false }),
  };
  window.apiClient = { isMockEnabled: () => true };
  vm.createContext(context);

  // Load mock data
  const mockCode = fs.readFileSync(path.join(root, "docs/ui_poc/mcp_inventory_mock.js"), "utf-8");
  vm.runInContext(mockCode, context);

  // Override fetch if apiFactory provided
  if (apiFactory) {
    context.fetch = apiFactory(window);
  }

  // Fix select elements' value property for linkedom
  const selects = document.querySelectorAll("select");
  for (const sel of selects) {
    if (sel.value === undefined) {
      Object.defineProperty(sel, "value", {
        get() { return this.options[this.selectedIndex]?.value || ""; },
        set(v) {
          for (let i = 0; i < this.options.length; i++) {
            if (this.options[i].value === v) { this.selectedIndex = i; break; }
          }
        },
        configurable: true
      });
    }
  }

  // Fix input elements' value property for linkedom
  const inputs = document.querySelectorAll("input");
  for (const inp of inputs) {
    if (!inp.hasOwnProperty("_value")) {
      inp._value = inp.getAttribute("value") || "";
      Object.defineProperty(inp, "value", {
        get() { return this._value; },
        set(v) { this._value = v; },
        configurable: true
      });
    }
  }

  // Run inline scripts
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

async function testMcpInventoryPage() {
  const { document } = loadPage(path.join(root, "docs/ui_poc/mcp_inventory.html"));
  await tick();

  // Check nav exists
  const nav = document.querySelector(".nav");
  assert.ok(nav, "renders nav");

  // Check nav brand
  const navBrand = document.querySelector(".nav-brand");
  assert.ok(navBrand.textContent.includes("MCP Gateway Suite"), "nav brand shows title");

  // Check page title
  const pageTitle = document.querySelector(".page-title");
  assert.ok(pageTitle.textContent.includes("MCP Inventory"), "page title is correct");

  // Check stats cards exist
  assert.ok(document.getElementById("statTotal"), "statTotal exists");
  assert.ok(document.getElementById("statAllow"), "statAllow exists");
  assert.ok(document.getElementById("statQuarantine"), "statQuarantine exists");
  assert.ok(document.getElementById("statDeny"), "statDeny exists");
  assert.ok(document.getElementById("statHighRisk"), "statHighRisk exists");
}

async function testMcpInventoryTableRenders() {
  const { document } = loadPage(path.join(root, "docs/ui_poc/mcp_inventory.html"));
  await tick();

  const rows = document.querySelectorAll("tbody#mcpRows tr");
  assert.ok(rows.length >= 5, "should render rows from mock data");

  // Check first row contains expected data
  const firstRow = rows[0];
  assert.ok(firstRow.textContent.includes("code-assistant-mcp"), "first row shows server name");
}

async function testMcpInventoryStatsUpdate() {
  const { document } = loadPage(path.join(root, "docs/ui_poc/mcp_inventory.html"));
  await tick();

  const statTotal = document.getElementById("statTotal").textContent;
  assert.strictEqual(statTotal, "5", "total servers is 5");

  const statAllow = document.getElementById("statAllow").textContent;
  assert.strictEqual(statAllow, "2", "allowed servers is 2");

  const statQuarantine = document.getElementById("statQuarantine").textContent;
  assert.strictEqual(statQuarantine, "2", "quarantined servers is 2");

  const statDeny = document.getElementById("statDeny").textContent;
  assert.strictEqual(statDeny, "1", "denied servers is 1");
}

async function testMcpInventoryFilters() {
  const { document, render } = loadPage(path.join(root, "docs/ui_poc/mcp_inventory.html"));
  await tick();

  // Check filter elements exist
  const statusFilter = document.getElementById("statusFilter");
  const riskFilter = document.getElementById("riskFilter");
  const searchFilter = document.getElementById("searchFilter");

  assert.ok(statusFilter, "status filter exists");
  assert.ok(riskFilter, "risk filter exists");
  assert.ok(searchFilter, "search filter exists");

  // Test status filter options
  const statusOptions = Array.from(statusFilter.querySelectorAll("option")).map((o) => o.value);
  assert.ok(statusOptions.includes("active"), "has active option");
  assert.ok(statusOptions.includes("quarantine"), "has quarantine option");
  assert.ok(statusOptions.includes("deny"), "has deny option");
}

async function testMcpInventoryRiskBadges() {
  const { document } = loadPage(path.join(root, "docs/ui_poc/mcp_inventory.html"));
  await tick();

  const rows = document.querySelectorAll("tbody#mcpRows tr");

  // Find row with critical risk
  let hasCritical = false;
  let hasHigh = false;
  let hasLow = false;
  for (const row of rows) {
    const text = row.innerHTML;
    if (text.includes("risk-critical")) hasCritical = true;
    if (text.includes("risk-high")) hasHigh = true;
    if (text.includes("risk-low")) hasLow = true;
  }

  assert.ok(hasCritical, "shows critical risk badge");
  assert.ok(hasHigh, "shows high risk badge");
  assert.ok(hasLow, "shows low risk badge");
}

async function testMcpInventoryDetailLinks() {
  const { document } = loadPage(path.join(root, "docs/ui_poc/mcp_inventory.html"));
  await tick();

  const links = document.querySelectorAll("tbody#mcpRows a.action-link");
  assert.ok(links.length >= 5, "detail links exist for all rows");

  const firstLink = links[0];
  assert.ok(firstLink.getAttribute("href").startsWith("mcp_detail.html?id="), "link points to mcp_detail page");
}

async function testMcpInventoryDangerousCaps() {
  const { document } = loadPage(path.join(root, "docs/ui_poc/mcp_inventory.html"));
  await tick();

  const dangerousTags = document.querySelectorAll(".cap-tag.dangerous");
  assert.ok(dangerousTags.length > 0, "dangerous capabilities are highlighted");
}

(async () => {
  await testMcpInventoryPage();
  await testMcpInventoryTableRenders();
  await testMcpInventoryStatsUpdate();
  await testMcpInventoryFilters();
  await testMcpInventoryRiskBadges();
  await testMcpInventoryDetailLinks();
  await testMcpInventoryDangerousCaps();
  console.log("mcp_inventory tests: ok");
})();
