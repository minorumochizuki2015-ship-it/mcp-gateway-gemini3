// Mock MCP server inventory data for the Suite UI PoC.
// Aligned with mock_data.js allowlist_entries for cross-page consistency.
window.mcpInventoryMock = {
  servers: [
    {
      server_id: 1,
      name: "code-assistant-mcp",
      base_url: "npx @anthropic/mcp-code-assistant",
      status: "allow",
      risk_level: "low",
      capabilities: ["code_read"],
      last_scan_ts: "2026-02-08T08:00:00Z",
      last_decision_ts: "2026-02-08T08:05:00Z"
    },
    {
      server_id: 2,
      name: "filesystem-mcp",
      base_url: "npx @anthropic/mcp-filesystem",
      status: "deny",
      risk_level: "critical",
      capabilities: ["file_read", "file_write"],
      last_scan_ts: "2026-02-08T14:22:00Z",
      last_decision_ts: "2026-02-08T14:22:00Z"
    },
    {
      server_id: 3,
      name: "web-search-mcp",
      base_url: "npx @anthropic/mcp-web-search",
      status: "allow",
      risk_level: "low",
      capabilities: ["network_read"],
      last_scan_ts: "2026-02-08T13:50:00Z",
      last_decision_ts: "2026-02-08T13:55:00Z"
    },
    {
      server_id: 4,
      name: "data-scraper-mcp",
      base_url: "npx @custom/data-scraper",
      status: "quarantine",
      risk_level: "medium",
      capabilities: ["network_read", "network_write", "file_write"],
      last_scan_ts: "2026-02-08T13:40:00Z",
      last_decision_ts: "2026-02-08T13:40:00Z"
    },
    {
      server_id: 5,
      name: "github-mcp",
      base_url: "npx @anthropic/mcp-github",
      status: "allow",
      risk_level: "low",
      capabilities: ["code_read", "code_write"],
      last_scan_ts: "2026-02-08T12:00:00Z",
      last_decision_ts: "2026-02-08T12:05:00Z"
    },
    {
      server_id: 6,
      name: "unknown-mcp",
      base_url: "npx @untrusted/unknown-mcp",
      status: "deny",
      risk_level: "high",
      capabilities: ["clipboard_read", "clipboard_write"],
      last_scan_ts: "2026-02-08T14:18:00Z",
      last_decision_ts: "2026-02-08T14:18:00Z"
    },
    {
      server_id: 7,
      name: "slack-mcp",
      base_url: "npx @anthropic/mcp-slack",
      status: "allow",
      risk_level: "low",
      capabilities: ["message_send"],
      last_scan_ts: null,
      last_decision_ts: "2026-02-07T14:25:00Z"
    },
    {
      server_id: 8,
      name: "external-api-mcp",
      base_url: "npx @custom/external-api",
      status: "deny",
      risk_level: "high",
      capabilities: ["network_read", "network_write"],
      last_scan_ts: "2026-02-08T13:55:00Z",
      last_decision_ts: "2026-02-08T13:55:00Z"
    }
  ]
};
