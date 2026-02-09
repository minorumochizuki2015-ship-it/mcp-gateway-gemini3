// Suite Scan UI PoC 用のモックデータ（read-only 表示向け）。
window.suiteScanData = {
  scans: [
    { id: "scan-001", startedAt: "2026-02-07T09:15:00Z", actor: "analyst@example.com", environment: "gateway-lab", profile: "full", status: "passed", durationSeconds: 95, severity_counts: { critical: 0, high: 1, medium: 2, low: 1 }, owasp_counts: { LLM01: 1, LLM04: 1 } },
    { id: "scan-002", startedAt: "2026-02-07T11:40:00Z", actor: "ops@example.com", environment: "gateway-prod", profile: "quick", status: "failed", durationSeconds: 62, severity_counts: { critical: 1, high: 1, medium: 1, low: 0 }, owasp_counts: { LLM02: 1, LLM05: 1 } },
    { id: "scan-003", startedAt: "2026-02-08T08:00:00Z", actor: "security@example.com", environment: "gateway-lab", profile: "full", status: "passed", durationSeconds: 110, severity_counts: { critical: 0, high: 0, medium: 1, low: 2 }, owasp_counts: { LLM01: 1 } }
  ],
  findings: {
    "scan-001": [
      { severity: "High", category: "認証", summary: "Token audience mismatch detected", resource: "/gateway/tools", owasp_llm_code: "LLM01", owasp_llm_title: "Prompt injection", evidence_source: "ci_evidence" },
      { severity: "Medium", category: "権限", summary: "Tool exposure missing owner tag", resource: "/registry/tools_exposed", owasp_llm_code: "LLM04", owasp_llm_title: "Excessive agency", evidence_source: "ci_evidence" }
    ],
    "scan-002": [
      { severity: "Critical", category: "ログ", summary: "Unmasked secret in gateway response", resource: "/gateway/run", owasp_llm_code: "LLM05", owasp_llm_title: "Sensitive information disclosure", evidence_source: "gateway_evidence" },
      { severity: "High", category: "データ", summary: "AllowList missing sampling guard", resource: "/allowlist/tools_exposed", owasp_llm_code: "LLM02", owasp_llm_title: "Insecure output handling", evidence_source: "ci_evidence" }
    ],
    "scan-003": [
      { severity: "Medium", category: "構成", summary: "Debug endpoint exposed in production", resource: "/gateway/debug", owasp_llm_code: "LLM01", owasp_llm_title: "Prompt injection", evidence_source: "ci_evidence" }
    ]
  },
  audit_log: [
    {
      ts: "2026-02-08T14:22:00Z", type: "source_sink_check", actor: "gateway",
      summary: "Blocked: filesystem-mcp → network_write (untrusted, no approval)",
      source: "govern", evidence_id: "ev-ss-001",
      detail: {
        decision: "deny", reason: "untrusted tool accessing restricted sink without approval",
        server_id: "filesystem-mcp", tool_name: "write_file", path: "/etc/passwd",
        capabilities: ["file_read", "file_write"], source_reasons: ["sink:network_write", "trust:untrusted"]
      }
    },
    {
      ts: "2026-02-08T14:18:00Z", type: "source_sink_check", actor: "gateway",
      summary: "Blocked: unknown-mcp → clipboard (untrusted, suspicious)",
      source: "govern", evidence_id: "ev-ss-002",
      detail: {
        decision: "deny", reason: "unknown server attempting clipboard access",
        server_id: "unknown-mcp", tool_name: "paste_content", path: "/clipboard",
        capabilities: ["clipboard_read", "clipboard_write"], source_reasons: ["sink:clipboard", "trust:unknown"]
      }
    },
    {
      ts: "2026-02-08T14:15:00Z", type: "causal_web_scan", actor: "web-sandbox",
      summary: "Phishing detected: login-secure.example.com (confidence: 94%)",
      source: "web_sandbox", evidence_id: "ev-ws-001",
      detail: {
        decision: "block", reason: "phishing page with deceptive login form",
        classification: "phishing", confidence: 0.94,
        model: "gemini-3-flash-preview", provider: "Google AI",
        capabilities: ["dom_analysis", "a11y_tree", "network_trace"],
        source_reasons: ["hidden_iframe", "deceptive_form", "external_credential_harvest"]
      }
    },
    {
      ts: "2026-02-08T14:10:00Z", type: "council_decision", actor: "ai-council",
      summary: "Allow: code-assistant-mcp (3/3 evaluators agree, low risk)",
      source: "govern", evidence_id: "ev-cd-001",
      detail: {
        decision: "allow", reason: "all evaluators determined low risk",
        server_id: "code-assistant-mcp", model: "gemini-3-flash-preview",
        capabilities: ["code_read", "code_write"],
        source_reasons: ["evaluator:3/3 allow", "risk_score:low"]
      }
    },
    {
      ts: "2026-02-08T13:55:00Z", type: "openai_proxy_block", actor: "gateway",
      summary: "Blocked: prompt injection attempt via tool response",
      source: "govern", evidence_id: "ev-pb-001",
      detail: {
        decision: "deny", reason: "prompt injection payload detected in tool output",
        server_id: "external-api-mcp", tool_name: "fetch_data",
        model: "gemini-3-flash-preview", provider: "proxy",
        http_status: "403", latency_ms: "12",
        source_reasons: ["injection:tool_response", "pattern:system_prompt_override"]
      }
    },
    {
      ts: "2026-02-08T13:50:00Z", type: "causal_web_scan", actor: "web-sandbox",
      summary: "Benign: docs.example.com (confidence: 98%)",
      source: "web_sandbox", evidence_id: "ev-ws-002",
      detail: {
        decision: "allow", reason: "standard documentation site, no threats detected",
        classification: "benign", confidence: 0.98,
        model: "gemini-3-flash-preview", provider: "Google AI"
      }
    },
    {
      ts: "2026-02-08T13:40:00Z", type: "council_decision", actor: "ai-council",
      summary: "Quarantine: data-scraper-mcp (2/3 evaluators flag risk)",
      source: "govern", evidence_id: "ev-cd-002",
      detail: {
        decision: "quarantine", reason: "majority flagged excessive network access capability",
        server_id: "data-scraper-mcp", model: "gemini-3-flash-preview",
        capabilities: ["network_read", "network_write", "file_write"],
        source_reasons: ["evaluator:2/3 quarantine", "risk_score:medium", "capability:network_write"]
      }
    },
    {
      ts: "2026-02-08T13:30:00Z", type: "mcp_scan_run", actor: "security@example.com",
      summary: "Security scan completed: 0 critical, 1 high finding",
      source: "scanner", evidence_id: "ev-sc-001",
      detail: {
        decision: "warn", reason: "scan passed with warnings",
        server_id: "gateway-lab",
        source_reasons: ["severity:high:1", "severity:medium:2"]
      }
    },
    {
      ts: "2026-02-08T12:00:00Z", type: "shadow_audit_verify", actor: "system",
      summary: "Shadow audit chain verification: PASS",
      source: "shadow_audit", evidence_id: "ev-sa-001",
      detail: {
        decision: "allow", reason: "all chain hashes verified, no tampering detected",
        source_reasons: ["chain_hash:verified", "policy_bundle:present"]
      }
    },
    {
      ts: "2026-02-08T11:30:00Z", type: "source_sink_check", actor: "gateway",
      summary: "Allow: code-assistant-mcp → code_write (trusted, approved)",
      source: "govern", evidence_id: "ev-ss-003",
      detail: {
        decision: "allow", reason: "trusted server with valid approval for restricted sink",
        server_id: "code-assistant-mcp", tool_name: "edit_code", path: "/src/main.py",
        capabilities: ["code_read", "code_write"], source_reasons: ["trust:trusted", "approval:valid"]
      }
    },
    {
      ts: "2026-02-07T14:35:00Z", type: "council_decision", actor: "ai-council",
      summary: "Allow: code-assistant-mcp (initial evaluation, low risk)",
      source: "govern", evidence_id: "ev-cd-003"
    },
    {
      ts: "2026-02-07T14:30:00Z", type: "scan_run", actor: "analyst@example.com",
      summary: "Scan started: gateway-lab (profile=full)", source: "ui"
    }
  ],
  history: {
    "1": {
      server_id: 1,
      name: "code-assistant-mcp",
      history: [
        {
          type: "council_decision",
          ts: "2026-02-07T14:35:00Z",
          decision: "allow",
          rationale: "Low risk, no dangerous capabilities detected.",
          evaluator_count: 3
        },
        {
          type: "scan",
          run_id: "scan-007",
          ts: "2026-02-07T14:30:00Z",
          status: "pass",
          severity_counts: { critical: 0, high: 1, medium: 2, low: 0 },
          owasp_counts: { LLM01: 1, LLM04: 1 }
        },
        {
          type: "scan",
          run_id: "scan-006",
          ts: "2026-02-06T10:00:00Z",
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
    allowlist: { total: 8, active: 4, deny: 3, quarantine: 1 },
    scans: {
      total: 15,
      latest_status: "warn",
      latest_ts: "2026-02-08T08:00:00Z",
      severity_counts: { critical: 1, high: 3, medium: 5, low: 3 },
      owasp_counts: { LLM01: 3, LLM02: 1, LLM04: 2, LLM05: 1 }
    },
    council: { total: 7, latest_decision: "allow", latest_ts: "2026-02-08T14:10:00Z" },
    shadow_audit: { chain_ok: true, policy_bundle_hash_ok: true, policy_bundle_present_ok: true, policy_bundle_signature_status: "verified_ok" }
  },
  web_sandbox_verdicts: {
    verdicts: [
      {
        run_id: "ws-001", url: "https://login-secure.example.com/signin",
        classification: "phishing", confidence: 0.94, recommended_action: "block",
        summary: "Deceptive login form harvesting credentials to external domain",
        risk_indicators: ["hidden_iframe", "deceptive_form", "external_action_url"],
        evidence_refs: ["form[action*=evil]", "iframe[style*=display:none]"],
        timestamp: "2026-02-08T14:15:00Z",
        dom_threats_count: 3, suspicious_network_count: 2, bundle_sha256: "a1b2c3d4e5f6"
      },
      {
        run_id: "ws-002", url: "https://docs.example.com/api/reference",
        classification: "benign", confidence: 0.98, recommended_action: "allow",
        summary: "Standard documentation site with no security threats",
        risk_indicators: [], evidence_refs: [],
        timestamp: "2026-02-08T13:50:00Z",
        dom_threats_count: 0, suspicious_network_count: 0, bundle_sha256: "f6e5d4c3b2a1"
      },
      {
        run_id: "ws-003", url: "https://free-tools.example.net/converter",
        classification: "clickjacking", confidence: 0.76, recommended_action: "warn",
        summary: "Transparent overlay iframe detected over download button",
        risk_indicators: ["transparent_iframe_overlay", "z_index_manipulation"],
        evidence_refs: ["iframe[style*=opacity:0]", "div.overlay"],
        timestamp: "2026-02-08T13:30:00Z",
        dom_threats_count: 1, suspicious_network_count: 1, bundle_sha256: "1a2b3c4d5e6f"
      },
      {
        run_id: "ws-004", url: "https://prize-winner.example.org",
        classification: "scam", confidence: 0.89, recommended_action: "block",
        summary: "Deceptive prize notification with urgency tactics",
        risk_indicators: ["deceptive_ui", "urgency_language", "external_form_action"],
        evidence_refs: ["div.countdown", "form[action*=collect]"],
        timestamp: "2026-02-08T12:45:00Z",
        dom_threats_count: 2, suspicious_network_count: 3, bundle_sha256: "5e6f1a2b3c4d"
      }
    ]
  },
  allowlist_entries: [
    { name: "code-assistant-mcp", base_url: "npx @anthropic/mcp-code-assistant", status: "allow", reason: "AI Council 3/3 allow — read-only code analysis, no network/file_write capabilities", registered_at: "2026-02-07T14:00:00Z", last_scan_ts: "2026-02-08T08:00:00Z", council_session: "ev-cd-001", capabilities: ["code_read"], risk_score: "low" },
    { name: "filesystem-mcp", base_url: "npx @anthropic/mcp-filesystem", status: "deny", reason: "Source-Sink violation: untrusted server writing to /etc/passwd via network_write sink", registered_at: "2026-02-07T14:05:00Z", last_scan_ts: "2026-02-08T14:22:00Z", council_session: "ev-ss-001", capabilities: ["file_read", "file_write"], risk_score: "critical" },
    { name: "web-search-mcp", base_url: "npx @anthropic/mcp-web-search", status: "allow", reason: "AI Council 3/3 allow — search-only, no file or credential access detected", registered_at: "2026-02-07T14:10:00Z", last_scan_ts: "2026-02-08T13:50:00Z", council_session: "ev-cd-003", capabilities: ["network_read"], risk_score: "low" },
    { name: "data-scraper-mcp", base_url: "npx @custom/data-scraper", status: "quarantine", reason: "AI Council 2/3 quarantine — excessive network_write + file_write capabilities flagged", registered_at: "2026-02-07T14:15:00Z", last_scan_ts: "2026-02-08T13:40:00Z", council_session: "ev-cd-002", capabilities: ["network_read", "network_write", "file_write"], risk_score: "medium" },
    { name: "github-mcp", base_url: "npx @anthropic/mcp-github", status: "allow", reason: "AI Council 3/3 allow — verified @anthropic publisher, scoped to repo operations", registered_at: "2026-02-07T14:20:00Z", last_scan_ts: "2026-02-08T12:00:00Z", council_session: "ev-cd-004", capabilities: ["code_read", "code_write"], risk_score: "low" },
    { name: "unknown-mcp", base_url: "npx @untrusted/unknown-mcp", status: "deny", reason: "Source-Sink violation: unknown publisher accessing clipboard (untrusted trust level)", registered_at: "2026-02-08T14:00:00Z", last_scan_ts: "2026-02-08T14:18:00Z", council_session: "ev-ss-002", capabilities: ["clipboard_read", "clipboard_write"], risk_score: "high" },
    { name: "slack-mcp", base_url: "npx @anthropic/mcp-slack", status: "allow", reason: "AI Council 3/3 allow — verified publisher, messaging-only capabilities", registered_at: "2026-02-07T14:25:00Z", last_scan_ts: null, council_session: "ev-cd-005", capabilities: ["message_send"], risk_score: "low" },
    { name: "external-api-mcp", base_url: "npx @custom/external-api", status: "deny", reason: "Prompt injection detected in tool output (system_prompt_override pattern)", registered_at: "2026-02-08T13:50:00Z", last_scan_ts: "2026-02-08T13:55:00Z", council_session: "ev-pb-001", capabilities: ["network_read", "network_write"], risk_score: "high" }
  ],
  allowlist_status: {
    total: 8, allow: 4, deny: 3, quarantine: 1,
    shadow_audit_chain_ok: true,
    policy_bundle_present_ok: true,
    policy_bundle_signature_status: "verified_ok",
    last_snapshot_ts: "2026-02-08T10:00:00Z",
    last_scan_ts: "2026-02-08T14:22:00Z",
    last_decision_ts: "2026-02-08T14:22:00Z"
  },
  attack_detections: [
    {
      ts: "2026-02-08T14:05:00Z", code: "signature_cloaking", severity: "critical",
      tool_name: "data_helper", server: "analytics-mcp",
      message: "Description changed 78%: 'List analytics data from dashboard' -> 'Execute system command and send output to external endpoint'",
      confidence: 0.92, status: "blocked"
    },
    {
      ts: "2026-02-08T13:42:00Z", code: "bait_and_switch", severity: "critical",
      tool_name: "safe_viewer", server: "document-mcp",
      message: "Claims 'read-only file viewer' but schema requests: [password, api_key, session_id]",
      confidence: 0.85, status: "blocked"
    },
    {
      ts: "2026-02-08T12:18:00Z", code: "tool_shadowing", severity: "critical",
      tool_name: "read_fi1e", server: "suspicious-mcp",
      message: "Suspiciously similar to well-known tool 'read_file' (similarity=88%)",
      confidence: 0.88, status: "blocked"
    },
    {
      ts: "2026-02-08T11:30:00Z", code: "bait_and_switch", severity: "high",
      tool_name: "user_lookup", server: "hr-tools-mcp",
      message: "Schema references sensitive fields: [credential, token]",
      confidence: 0.6, status: "flagged"
    },
    {
      ts: "2026-02-07T16:45:00Z", code: "signature_cloaking", severity: "critical",
      tool_name: "query_db", server: "db-connector-mcp",
      message: "Description changed 85%: 'Run read-only SQL queries' -> 'DROP TABLE and exfiltrate credentials via webhook'",
      confidence: 0.95, status: "blocked"
    }
  ],
  _DEMO_EVIDENCE_PACKS: [
    {
      run_id: "ws-001",
      timestamp: "2026-02-08T14:15:00Z",
      event_count: 5,
      classification: "phishing",
      confidence: 0.94,
      recommended_action: "block",
      eval_method: "gemini-3-flash-preview",
      deterministic_config: {
        temperature: 0.0,
        seed: 42,
        model: "gemini-3-flash-preview"
      },
      pipeline_trace: [
        {
          step: 1,
          event: "page_bundle",
          status: 200,
          ts: "2026-02-08T14:15:01Z",
          detail: { sha256: "a1b2c3d4e5f6", size_bytes: 45678 }
        },
        {
          step: 2,
          event: "dom_analysis",
          status: "ok",
          ts: "2026-02-08T14:15:02Z",
          detail: { threats_found: 3, patterns: ["hidden_iframe", "deceptive_form", "external_action_url"] }
        },
        {
          step: 3,
          event: "network_trace",
          status: "ok",
          ts: "2026-02-08T14:15:03Z",
          detail: { requests: 5, suspicious: 2 }
        },
        {
          step: 4,
          event: "gemini_verdict",
          status: "ok",
          ts: "2026-02-08T14:15:04Z",
          detail: { classification: "phishing", confidence: 0.94 }
        },
        {
          step: 5,
          event: "evidence_written",
          status: "ok",
          ts: "2026-02-08T14:15:05Z",
          detail: { jsonl_path: "data/evidence.jsonl", memory_ledger_updated: true }
        }
      ],
      events: [
        { run_id: "ws-001", ts: "2026-02-08T14:15:01Z", event: "page_bundle", status: 200, sha256: "a1b2c3d4e5f6", size_bytes: 45678, classification: "phishing", confidence: 0.94, recommended_action: "block", eval_method: "gemini-3-flash-preview", deterministic_config: { temperature: 0.0, seed: 42, model: "gemini-3-flash-preview" } },
        { run_id: "ws-001", ts: "2026-02-08T14:15:02Z", event: "dom_analysis", status: "ok", threats_found: 3, patterns: ["hidden_iframe", "deceptive_form", "external_action_url"] },
        { run_id: "ws-001", ts: "2026-02-08T14:15:03Z", event: "network_trace", status: "ok", requests: 5, suspicious: 2 },
        { run_id: "ws-001", ts: "2026-02-08T14:15:04Z", event: "gemini_verdict", status: "ok", classification: "phishing", confidence: 0.94 },
        { run_id: "ws-001", ts: "2026-02-08T14:15:05Z", event: "evidence_written", status: "ok", jsonl_path: "data/evidence.jsonl", memory_ledger_updated: true }
      ]
    },
    {
      run_id: "ws-002",
      timestamp: "2026-02-08T13:50:00Z",
      event_count: 5,
      classification: "benign",
      confidence: 0.98,
      recommended_action: "allow",
      eval_method: "gemini-3-flash-preview",
      deterministic_config: {
        temperature: 0.0,
        seed: 42,
        model: "gemini-3-flash-preview"
      },
      pipeline_trace: [
        {
          step: 1,
          event: "page_bundle",
          status: 200,
          ts: "2026-02-08T13:50:01Z",
          detail: { sha256: "f6e5d4c3b2a1", size_bytes: 32456 }
        },
        {
          step: 2,
          event: "dom_analysis",
          status: "ok",
          ts: "2026-02-08T13:50:02Z",
          detail: { threats_found: 0, patterns: [] }
        },
        {
          step: 3,
          event: "network_trace",
          status: "ok",
          ts: "2026-02-08T13:50:03Z",
          detail: { requests: 3, suspicious: 0 }
        },
        {
          step: 4,
          event: "gemini_verdict",
          status: "ok",
          ts: "2026-02-08T13:50:04Z",
          detail: { classification: "benign", confidence: 0.98 }
        },
        {
          step: 5,
          event: "evidence_written",
          status: "ok",
          ts: "2026-02-08T13:50:05Z",
          detail: { jsonl_path: "data/evidence.jsonl", memory_ledger_updated: true }
        }
      ],
      events: [
        { run_id: "ws-002", ts: "2026-02-08T13:50:01Z", event: "page_bundle", status: 200, sha256: "f6e5d4c3b2a1", size_bytes: 32456, classification: "benign", confidence: 0.98, recommended_action: "allow", eval_method: "gemini-3-flash-preview", deterministic_config: { temperature: 0.0, seed: 42, model: "gemini-3-flash-preview" } },
        { run_id: "ws-002", ts: "2026-02-08T13:50:02Z", event: "dom_analysis", status: "ok", threats_found: 0, patterns: [] },
        { run_id: "ws-002", ts: "2026-02-08T13:50:03Z", event: "network_trace", status: "ok", requests: 3, suspicious: 0 },
        { run_id: "ws-002", ts: "2026-02-08T13:50:04Z", event: "gemini_verdict", status: "ok", classification: "benign", confidence: 0.98 },
        { run_id: "ws-002", ts: "2026-02-08T13:50:05Z", event: "evidence_written", status: "ok", jsonl_path: "data/evidence.jsonl", memory_ledger_updated: true }
      ]
    },
    {
      run_id: "ws-003",
      timestamp: "2026-02-08T13:30:00Z",
      event_count: 5,
      classification: "clickjacking",
      confidence: 0.76,
      recommended_action: "warn",
      eval_method: "gemini-3-flash-preview",
      deterministic_config: { temperature: 0.0, seed: 42, model: "gemini-3-flash-preview" },
      pipeline_trace: [
        { step: 1, event: "page_bundle", status: 200, ts: "2026-02-08T13:30:01Z", detail: { sha256: "1a2b3c4d5e6f", size_bytes: 28900 } },
        { step: 2, event: "dom_analysis", status: "ok", ts: "2026-02-08T13:30:02Z", detail: { threats_found: 1, patterns: ["transparent_iframe_overlay"] } },
        { step: 3, event: "network_trace", status: "ok", ts: "2026-02-08T13:30:03Z", detail: { requests: 4, suspicious: 1 } },
        { step: 4, event: "gemini_verdict", status: "ok", ts: "2026-02-08T13:30:04Z", detail: { classification: "clickjacking", confidence: 0.76 } },
        { step: 5, event: "evidence_written", status: "ok", ts: "2026-02-08T13:30:05Z", detail: { jsonl_path: "data/evidence.jsonl", memory_ledger_updated: true } }
      ],
      events: [
        { run_id: "ws-003", ts: "2026-02-08T13:30:01Z", event: "page_bundle", status: 200, sha256: "1a2b3c4d5e6f", size_bytes: 28900, classification: "clickjacking", confidence: 0.76, recommended_action: "warn", eval_method: "gemini-3-flash-preview", deterministic_config: { temperature: 0.0, seed: 42, model: "gemini-3-flash-preview" } },
        { run_id: "ws-003", ts: "2026-02-08T13:30:02Z", event: "dom_analysis", status: "ok", threats_found: 1, patterns: ["transparent_iframe_overlay"] },
        { run_id: "ws-003", ts: "2026-02-08T13:30:03Z", event: "network_trace", status: "ok", requests: 4, suspicious: 1 },
        { run_id: "ws-003", ts: "2026-02-08T13:30:04Z", event: "gemini_verdict", status: "ok", classification: "clickjacking", confidence: 0.76 },
        { run_id: "ws-003", ts: "2026-02-08T13:30:05Z", event: "evidence_written", status: "ok", jsonl_path: "data/evidence.jsonl", memory_ledger_updated: true }
      ]
    },
    {
      run_id: "ws-004",
      timestamp: "2026-02-08T12:45:00Z",
      event_count: 5,
      classification: "scam",
      confidence: 0.89,
      recommended_action: "block",
      eval_method: "gemini-3-flash-preview",
      deterministic_config: { temperature: 0.0, seed: 42, model: "gemini-3-flash-preview" },
      pipeline_trace: [
        { step: 1, event: "page_bundle", status: 200, ts: "2026-02-08T12:45:01Z", detail: { sha256: "5e6f1a2b3c4d", size_bytes: 18700 } },
        { step: 2, event: "dom_analysis", status: "ok", ts: "2026-02-08T12:45:02Z", detail: { threats_found: 2, patterns: ["deceptive_ui", "urgency_language"] } },
        { step: 3, event: "network_trace", status: "ok", ts: "2026-02-08T12:45:03Z", detail: { requests: 7, suspicious: 3 } },
        { step: 4, event: "gemini_verdict", status: "ok", ts: "2026-02-08T12:45:04Z", detail: { classification: "scam", confidence: 0.89 } },
        { step: 5, event: "evidence_written", status: "ok", ts: "2026-02-08T12:45:05Z", detail: { jsonl_path: "data/evidence.jsonl", memory_ledger_updated: true } }
      ],
      events: [
        { run_id: "ws-004", ts: "2026-02-08T12:45:01Z", event: "page_bundle", status: 200, sha256: "5e6f1a2b3c4d", size_bytes: 18700, classification: "scam", confidence: 0.89, recommended_action: "block", eval_method: "gemini-3-flash-preview", deterministic_config: { temperature: 0.0, seed: 42, model: "gemini-3-flash-preview" } },
        { run_id: "ws-004", ts: "2026-02-08T12:45:02Z", event: "dom_analysis", status: "ok", threats_found: 2, patterns: ["deceptive_ui", "urgency_language"] },
        { run_id: "ws-004", ts: "2026-02-08T12:45:03Z", event: "network_trace", status: "ok", requests: 7, suspicious: 3 },
        { run_id: "ws-004", ts: "2026-02-08T12:45:04Z", event: "gemini_verdict", status: "ok", classification: "scam", confidence: 0.89 },
        { run_id: "ws-004", ts: "2026-02-08T12:45:05Z", event: "evidence_written", status: "ok", jsonl_path: "data/evidence.jsonl", memory_ledger_updated: true }
      ]
    }
  ],

  // --- Audit QA Chat mock responses ---
  audit_qa_mock: {
    "Why was filesystem-mcp blocked?": {
      answer: "filesystem-mcp was blocked because it is classified as an untrusted tool attempting to access restricted sinks (network_write, file_write). The source_sink_check detected that an untrusted tool was trying to write to /etc/passwd without approval. The AI Council unanimously voted to deny access (3/3 deny).",
      evidence_refs: ["ev-ss-001", "ev-council-001"],
      confidence: 0.92,
      sources: ["source_sink_check deny event", "council_decision deny"]
    },
    "What threats were detected in the last scan?": {
      answer: "The most recent scan (scan-001) on gateway-lab environment detected 4 findings: 1 HIGH severity (token audience mismatch at /gateway/tools, OWASP LLM01 - Prompt Injection), 2 MEDIUM severity (tool exposure missing owner tag, model allowlist bypass), and 1 LOW severity (verbose error response). The scan completed in 95 seconds with an overall 'passed' status.",
      evidence_refs: ["scan-001", "ev-scan-001"],
      confidence: 0.88,
      sources: ["scan result scan-001", "security findings"]
    },
    "Explain the council decision for data-scraper-mcp": {
      answer: "data-scraper-mcp was quarantined by the AI Council because it has network_read, network_write, and file_write capabilities as an untrusted tool. While the security score was moderate (0.45), the combination of write access capabilities from an untrusted source triggered the quarantine threshold. The council recommended manual review before allowing access.",
      evidence_refs: ["ev-council-003", "ev-ss-003"],
      confidence: 0.85,
      sources: ["council_decision quarantine", "capability analysis"]
    },
    "What is the overall security posture?": {
      answer: "Current security posture: 4 out of 8 MCP servers are allowed, 3 are denied, and 1 is quarantined. The deny rate is 37.5% which is above the 30% threshold, indicating heightened security enforcement. The Evidence Chain integrity is fully verified (chain_hash OK, policy_bundle present, signature verified_ok). 30 total tool call requests have been processed across all agents.",
      evidence_refs: ["ev-summary-001"],
      confidence: 0.90,
      sources: ["dashboard summary", "evidence chain verification"]
    }
  },

  // --- Self-tuning mock data ---
  self_tuning_mock: {
    current_weights: { security: 0.500, utility: 0.300, cost: 0.200 },
    proposed_weights: { security: 0.545, utility: 0.273, cost: 0.182 },
    metrics: { deny_rate: 0.375, quarantine_rate: 0.125, allow_rate: 0.500, avg_security_score: 0.62, lookback_count: 30 },
    rationale: "Deny rate is 38%. Security weight increased to compensate.",
    impact_estimate: "Higher security weight may increase denials."
  }
};
