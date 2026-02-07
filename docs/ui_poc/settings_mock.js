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
