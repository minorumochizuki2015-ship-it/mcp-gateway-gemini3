// Mock MCP server inventory data for the Suite UI PoC.
window.mcpInventoryMock = {
  servers: [
    {
      server_id: 1,
      name: "code-assistant-mcp",
      base_url: "http://localhost:5001/mcp",
      status: "active",
      risk_level: "low",
      capabilities: ["read", "code_execution"],
      last_scan_ts: "2025-12-10T14:30:00Z",
      last_decision_ts: "2025-12-10T14:35:00Z"
    },
    {
      server_id: 2,
      name: "file-manager-mcp",
      base_url: "http://localhost:5002/mcp",
      status: "quarantine",
      risk_level: "high",
      capabilities: ["file_write", "file_read"],
      last_scan_ts: "2025-12-09T10:00:00Z",
      last_decision_ts: "2025-12-09T10:15:00Z"
    },
    {
      server_id: 3,
      name: "network-tools-mcp",
      base_url: "http://localhost:5003/mcp",
      status: "deny",
      risk_level: "critical",
      capabilities: ["network_write", "network_read"],
      last_scan_ts: "2025-12-08T08:00:00Z",
      last_decision_ts: "2025-12-08T08:30:00Z"
    },
    {
      server_id: 4,
      name: "docs-search-mcp",
      base_url: "http://localhost:5004/mcp",
      status: "active",
      risk_level: "low",
      capabilities: ["read"],
      last_scan_ts: "2025-12-11T09:00:00Z",
      last_decision_ts: "2025-12-11T09:05:00Z"
    },
    {
      server_id: 5,
      name: "sampling-agent-mcp",
      base_url: "http://localhost:5005/mcp",
      status: "quarantine",
      risk_level: "medium",
      capabilities: ["sampling", "read"],
      last_scan_ts: "2025-12-10T16:00:00Z",
      last_decision_ts: "2025-12-10T16:20:00Z"
    }
  ]
};
