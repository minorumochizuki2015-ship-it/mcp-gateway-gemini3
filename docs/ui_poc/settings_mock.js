// Settings PoC 用のモックデータ。
window.SUITE_SETTINGS_ENVIRONMENTS = [
  { name: "gateway-lab", endpoint: "https://lab.gateway.internal/api", status: "active", note: "staging / smoke" },
  { name: "gateway-prod", endpoint: "https://gateway.internal/api", status: "active", note: "primary" },
  { name: "gateway-dr", endpoint: "https://dr.gateway.internal/api", status: "standby", note: "DR / cold" }
];

window.SUITE_SETTINGS_PROFILES = [
  { name: "quick", mode: "quick", ttl_days: 7, description: "短時間のスモーク用（軽量）" },
  { name: "full", mode: "full", ttl_days: 14, description: "標準の包括スキャン（推奨）" },
  { name: "strict", mode: "custom", ttl_days: 3, description: "高頻度・高リスク向け（厳格）" }
];

window.SUITE_SETTINGS_UPSTREAM = {
  base_url: "https://generativelanguage.googleapis.com/v1beta/openai",
  provider: "gemini_openai",
  models_allowlist: ["models/gemini-3-flash-preview", "models/gemini-2.5-flash"],
  api_key: "{REDACTED}",
  status: "active",
  last_tested: "2026-02-08T14:00:00Z"
};

window.SUITE_SETTINGS_POLICY_PROFILE = {
  profile_name: "standard",
  restricted_sinks: ["network_write", "file_write"],
  restricted_sinks_additions: [],
  allow_untrusted_with_approvals: false
};

window.SUITE_SETTINGS_TOKENS = [
  { id: "tok-001", name: "gateway-lab-client", issued_at: "2026-02-07T14:00:00Z", expires_at: "2026-03-07T14:00:00Z", status: "active" },
  { id: "tok-002", name: "ci-scanner", issued_at: "2026-02-08T09:00:00Z", expires_at: "2026-02-15T09:00:00Z", status: "active" }
];
