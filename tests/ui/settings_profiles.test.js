const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { parseHTML } = require("linkedom");

const root = path.resolve(__dirname, "../..");

function loadPage() {
  const filePath = path.join(root, "docs/ui_poc/settings_profiles.html");
  const html = fs.readFileSync(filePath, "utf-8");
  const { window, document } = parseHTML(html);

  // Mock fetch and apiClient for testing
  const mockApiClient = {
    fetchPolicyProfilePresets: async () => ({
      ok: true,
      data: {
        presets: [
          {
            name: "standard",
            description: "標準セキュリティ（推奨）",
            restricted_sinks: ["shell", "filesystem"],
            allow_untrusted_with_approvals: true,
          },
          {
            name: "strict",
            description: "厳格モード",
            restricted_sinks: ["shell", "filesystem", "network"],
            allow_untrusted_with_approvals: false,
          },
          {
            name: "development",
            description: "開発テスト用（緩和）",
            restricted_sinks: [],
            allow_untrusted_with_approvals: true,
          },
        ],
        core_rules: {
          restricted_sinks: ["shell", "filesystem"],
          description: "コア不変ルール（無効化不可）",
        },
      },
    }),
    previewPolicyProfile: async (payload) => ({
      ok: true,
      data: {
        current: { profile_name: "standard", restricted_sinks: ["shell", "filesystem"] },
        proposed: { profile_name: payload.profile_name, restricted_sinks: ["shell", "filesystem", ...payload.restricted_sinks_additions] },
        changes: payload.restricted_sinks_additions.length > 0 ? [{ field: "restricted_sinks", added: payload.restricted_sinks_additions, removed: [] }] : [],
        has_changes: payload.restricted_sinks_additions.length > 0,
      },
    }),
    saveControlPolicyProfile: async (payload) => ({
      ok: true,
      data: { evidence_id: "ev-test-12345" },
    }),
  };

  window.apiClient = mockApiClient;
  window.getLanguage = () => "ja";

  const context = { window, document, console, setTimeout, Promise };
  vm.createContext(context);

  const scripts = Array.from(document.querySelectorAll("script"))
    .filter((s) => !s.getAttribute("src"))
    .map((s) => s.textContent || "");
  for (const code of scripts) {
    try {
      vm.runInContext(code, context);
    } catch (e) {
      // Ignore errors from scripts that depend on browser APIs
    }
  }
  return { document, window: context.window };
}

function tick(ms = 50) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function testProfilesPageRenders() {
  const { document } = loadPage();
  await tick(100);

  // Check page title
  const pageTitle = document.querySelector(".page-title");
  assert.ok(pageTitle, "page title exists");
  assert.ok(pageTitle.textContent.includes("Policy Profiles"), "page title contains Policy Profiles");

  // Check profile select exists
  const profileSelect = document.querySelector('[data-testid="profile-select"]');
  assert.ok(profileSelect, "profile select exists");

  // Check preview button exists
  const previewBtn = document.querySelector('[data-testid="preview-btn"]');
  assert.ok(previewBtn, "preview button exists");

  // Check save button exists
  const saveBtn = document.querySelector('[data-testid="save-btn"]');
  assert.ok(saveBtn, "save button exists");

  console.log("  ✓ Page renders correctly");
}

async function testDataTestIds() {
  const { document } = loadPage();
  await tick(100);

  const requiredTestIds = [
    "profile-select",
    "additional-sinks",
    "allow-untrusted",
    "change-reason",
    "preview-btn",
    "save-btn",
    "evidence-id",
    "preview-panel",
    "result-panel",
  ];

  for (const testId of requiredTestIds) {
    const el = document.querySelector(`[data-testid="${testId}"]`);
    assert.ok(el, `data-testid="${testId}" exists`);
  }

  console.log("  ✓ All required data-testid attributes present");
}

async function testI18nDictionaryExists() {
  const { document } = loadPage();
  await tick(100);

  // Check that i18n dictionary is defined in script
  const scripts = Array.from(document.querySelectorAll("script"))
    .filter((s) => !s.getAttribute("src"))
    .map((s) => s.textContent || "")
    .join("");

  assert.ok(scripts.includes("ProfilesI18N"), "ProfilesI18N dictionary exists");
  assert.ok(scripts.includes("function t(key)"), "t() translation function exists");
  assert.ok(scripts.includes("pageTitle"), "i18n key pageTitle exists");
  assert.ok(scripts.includes("saveSuccess"), "i18n key saveSuccess exists");
  assert.ok(scripts.includes("presetUntrustedAllowed"), "i18n key presetUntrustedAllowed exists");

  console.log("  ✓ i18n dictionary and function present");
}

async function testPresetApprovalsDisplay() {
  const { document } = loadPage();
  await tick(100);

  // Check that preset-approvals CSS class exists
  const styles = Array.from(document.querySelectorAll("style"))
    .map((s) => s.textContent || "")
    .join("");

  assert.ok(styles.includes(".preset-approvals"), "preset-approvals CSS class exists");
  assert.ok(styles.includes(".preset-approvals.allowed"), "preset-approvals.allowed CSS class exists");
  assert.ok(styles.includes(".preset-approvals.denied"), "preset-approvals.denied CSS class exists");

  console.log("  ✓ Preset approvals display styles present");
}

async function testCoreRulesSection() {
  const { document } = loadPage();
  await tick(100);

  // Check core rules section exists
  const coreRulesSection = document.querySelector(".core-rules");
  assert.ok(coreRulesSection, "core rules section exists");

  // Check warning title (contains warning emoji)
  const warningTitle = document.querySelector(".core-rules-title");
  assert.ok(warningTitle, "core rules warning title exists");
  assert.ok(warningTitle.textContent.includes("⚠️") || warningTitle.textContent.includes("コア"), "core rules title contains warning indicator");

  console.log("  ✓ Core rules section present with warning title");
}

(async () => {
  console.log("settings_profiles tests:");
  try {
    await testProfilesPageRenders();
    await testDataTestIds();
    await testI18nDictionaryExists();
    await testPresetApprovalsDisplay();
    await testCoreRulesSection();
    console.log("settings_profiles tests: ok");
  } catch (e) {
    console.error("settings_profiles tests: FAILED");
    console.error(e);
    process.exit(1);
  }
})();
