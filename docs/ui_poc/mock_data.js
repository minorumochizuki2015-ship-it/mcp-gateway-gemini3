// Suite Scan UI PoC 用のモックデータ（read-only 表示向け）。
window.suiteScanData = {
  scans: [
    { id: "scan-001", startedAt: "2025-12-10T09:15:00Z", actor: "analyst@example.com", environment: "gateway-lab", profile: "full", status: "passed", durationSeconds: 95, severity_counts: { critical: 0, high: 1, medium: 2, low: 1 }, owasp_counts: { LLM01: 1, LLM04: 1 } },
    { id: "scan-002", startedAt: "2025-12-10T11:40:00Z", actor: "ops@example.com", environment: "gateway-prod", profile: "quick", status: "failed", durationSeconds: 62, severity_counts: { critical: 1, high: 1, medium: 1, low: 0 }, owasp_counts: { LLM02: 1, LLM05: 1 } }
  ],
  findings: {
    "scan-001": [
      { severity: "High", category: "認証", summary: "Token audience mismatch detected", resource: "/gateway/tools", owasp_llm_code: "LLM01", owasp_llm_title: "Prompt injection", evidence_source: "ci_evidence" },
      { severity: "Medium", category: "権限", summary: "Tool exposure missing owner tag", resource: "/registry/tools_exposed", owasp_llm_code: "LLM04", owasp_llm_title: "Excessive agency", evidence_source: "ci_evidence" }
    ],
    "scan-002": [
      { severity: "Critical", category: "ログ", summary: "Unmasked secret in gateway response", resource: "/gateway/run", owasp_llm_code: "LLM05", owasp_llm_title: "Sensitive information disclosure", evidence_source: "acl_proxy_evidence" },
      { severity: "High", category: "データ", summary: "AllowList missing sampling guard", resource: "/allowlist/tools_exposed", owasp_llm_code: "LLM02", owasp_llm_title: "Insecure output handling", evidence_source: "ci_evidence" }
    ]
  },
  audit_log: [
    { ts: "2025-12-10T14:30:00Z", type: "scan_run", actor: "analyst@example.com", summary: "scan started: gateway-lab (profile=full)", source: "ui" },
    { ts: "2025-12-10T14:35:00Z", type: "council_decision", actor: "council@example.com", summary: "decision=allow (server_id=1)", source: "govern" },
    { ts: "2025-12-11T10:00:00Z", type: "shadow_audit_verify", actor: "system", summary: "verify_chain=pass", source: "shadow_audit" },
    { ts: "2025-12-11T11:00:00Z", type: "gateway_update", actor: "ops@example.com", summary: "allowlist snapshot applied", source: "gateway" }
  ],
  history: {
    "1": {
      server_id: 1,
      name: "code-assistant-mcp",
      history: [
        {
          type: "council_decision",
          ts: "2025-12-10T14:35:00Z",
          decision: "allow",
          rationale: "Low risk, no dangerous capabilities detected.",
          evaluator_count: 3
        },
        {
          type: "scan",
          run_id: "scan-007",
          ts: "2025-12-10T14:30:00Z",
          status: "pass",
          severity_counts: { critical: 0, high: 1, medium: 2, low: 0 },
          owasp_counts: { LLM01: 1, LLM04: 1 }
        },
        {
          type: "scan",
          run_id: "scan-006",
          ts: "2025-12-05T10:00:00Z",
          status: "warn",
          severity_counts: { critical: 0, high: 2, medium: 3, low: 1 },
          owasp_counts: { LLM02: 2, LLM05: 1 }
        }
      ],
      total: 3,
      limit: 20,
      offset: 0
    }
  },
  dashboard_summary: {
    allowlist: { total: 4, active: 3, deny: 0, quarantine: 1 },
    scans: {
      total: 12,
      latest_status: "warn",
      latest_ts: "2025-12-10T14:30:00Z",
      severity_counts: { critical: 1, high: 3, medium: 4, low: 2 },
      owasp_counts: { LLM01: 2, LLM04: 1, LLM05: 1 }
    },
    council: { total: 4, latest_decision: "allow", latest_ts: "2025-12-10T14:35:00Z" },
    shadow_audit: { chain_ok: true, policy_bundle_hash_ok: false }
  }
};
