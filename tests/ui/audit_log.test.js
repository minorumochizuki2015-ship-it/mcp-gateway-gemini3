const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { parseHTML } = require("linkedom");

const root = path.resolve(__dirname, "../..");

function loadPage() {
  const filePath = path.join(root, "docs/ui_poc/audit_log.html");
  const html = fs.readFileSync(filePath, "utf-8");
  const { window, document } = parseHTML(html);
  window.location = new URL(`http://localhost/${path.basename(filePath)}`);
  const context = { window, document, console, URL, URLSearchParams, setTimeout, clearTimeout };
  vm.createContext(context);

  context.window.apiClient = {
    fetchControlAudit: async () => ({
      ok: true,
      data: [
        {
          ts: "2025-01-01T00:00:00Z",
          type: "control_upstream_updated",
          actor: "ui",
          summary: "event control_upstream_updated",
          source: "ui",
        },
        {
          ts: "2025-01-02T00:00:00Z",
          type: "token_issued",
          actor: "ui",
          summary: "event token_issued",
          source: "ui",
        },
        {
          ts: "2025-01-03T00:00:00Z",
          type: "openai_proxy_block",
          actor: "gateway",
          summary: "blocked (openai_proxy_block)",
          source: "proxy",
        },
      ],
    }),
  };

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

async function testAuditLogRenders() {
  const { document } = loadPage();
  await tick();
  const nav = document.querySelector(".nav");
  assert.ok(nav, "renders nav");
  const rows = document.querySelectorAll("tbody#auditRows tr");
  assert.ok(rows.length >= 3, "renders audit rows from api client");
  const typeSelect = document.getElementById("typeFilter");
  assert.ok(typeSelect, "type filter exists");
  assert.ok(!document.getElementById("adminToken"), "admin token input removed");
}

(async () => {
  await testAuditLogRenders();
  console.log("audit log tests: ok");
})();
