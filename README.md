# MCP Gateway - AI-Powered Security Gateway for MCP

**Gemini 3 Hackathon Submission** | [Live Demo UI](#dashboard-ui) | [Quick Start](#quick-start) | [Architecture](#architecture)

## The Problem

The MCP (Model Context Protocol) ecosystem has grown to **13,000+ servers**, but security tooling hasn't kept pace. AI agents connect to MCP servers that can:
- Exfiltrate credentials via hidden tool parameters
- Inject prompts through deceptive tool descriptions
- Redirect data to malicious endpoints disguised as legitimate APIs

There is no standard way to **inspect, evaluate, and enforce security** at the MCP connection layer.

## What MCP Gateway Does

MCP Gateway is a **security-first proxy** that sits between AI clients (ChatGPT, Claude, Gemini CLI) and MCP servers. Every tool call passes through a multi-layer inspection pipeline powered by **Gemini 3 structured output**:

```
AI Client ──► MCP Gateway ──► MCP Servers
               │
               ├── Scan (static + semantic)
               ├── AI Council verdict
               ├── Source/Sink policy check
               ├── Prompt sanitization
               └── Evidence trail (every decision logged)
```

**Key insight**: Instead of binary allow/deny, the gateway produces **structured evidence** — the _why_ behind every decision — making security auditable and explainable.

## 5 Gemini 3 Integration Points

Every AI-powered component uses `response_mime_type="application/json"` with Pydantic schemas for type-safe, deterministic outputs. Rule-based fallback activates automatically when the API is unavailable.

| # | Component | Gemini Schema | What It Does |
|---|-----------|--------------|--------------|
| 1 | **AI Council** | `CouncilVerdict` | Multi-criteria security evaluation → allow / deny / quarantine with confidence scores and per-finding analysis |
| 2 | **Semantic Scanner** | `SemanticScanResult` | Deep analysis of tool descriptions for hidden threats (data exfiltration, prompt injection, deceptive naming) that regex cannot detect |
| 3 | **RedTeam Generator** | `RedTeamGeneration` | Dynamic attack scenario generation tailored to each tool's capabilities |
| 4 | **RedTeam Evaluator** | `PayloadSafetyVerdict` | AI-powered safety assessment of tool responses against generated attack scenarios |
| 5 | **Causal Web Sandbox** | `WebSecurityVerdict` | Evidence-based web page threat classification with DOM analysis, network tracing, and a11y deceptive-label detection |

## Dashboard UI

A full-featured management UI with **bilingual support (English / Japanese)** for real-time monitoring and investigation.

### Pages

| Page | Purpose | Key Features |
|------|---------|-------------|
| **Dashboard** | Decision-centric overview | KPI cards (requests, block rate, AI Council status), Gateway Flow diagram, Recent Decisions table with confidence bars and evidence links |
| **Environments** | Gateway configuration | Setup wizard (admin token → upstream LLM → policy profile), system diagnostics, environment registration |
| **Scans** | Security scan history | Severity breakdown (Critical/High/Medium/Low), OWASP LLM mapping, filter by status/environment |
| **AllowList** | Approved MCP servers | Registration status, last scan timestamp, endpoint verification |
| **Web Sandbox** | Live URL security analysis | SSRF-protected fetch → DOM threat detection → a11y deceptive label check → network trace → Gemini verdict with expandable evidence details |
| **Audit Log** | Decision evidence trail | Expandable detail rows showing decision/reason/capabilities/source_reasons, evidence ID linking, type/actor filtering |
| **Billing** | Usage tracking | Token consumption, API call counts, cost estimation |
| **Settings** | Policy profiles | OWASP LLM top-10 rule configuration, custom restricted sinks, severity thresholds |

### How Decisions Are Shown

Every security decision in the UI includes:
- **Decision** — ALLOW / DENY / QUARANTINE pill with color coding
- **Confidence** — Percentage with visual bar (e.g., 95%)
- **Finding** — What was detected (e.g., "untrusted source to restricted sink")
- **Evidence** — Clickable link to the full audit trail entry with expandable details

This makes the gateway's behavior **transparent and auditable** — not a black box.

## Architecture

```
                    +------------------+
                    |   AI Clients     |
                    | (ChatGPT/Claude  |
                    |  /Gemini CLI)    |
                    +--------+---------+
                             |
                    +--------v---------+
                    |   ACL Proxy      |  ← Rust ACL-aware proxy
                    |   (acl-proxy/)   |    URL policy + HTTPS MITM
                    +--------+---------+
                             |
                    +--------v---------+
                    |   MCP Gateway    |  ← Python FastAPI
                    |  + Dashboard UI  |    Security pipeline
                    +--+--+--+--+-----+
                       |  |  |  |
          +------------+  |  |  +------------+
          |               |  |               |
   +------v------+ +-----v------+ +----v-----+ +------v------+
   | AI Council  | | Semantic   | | RedTeam  | | Causal Web  |
   | (Gemini 3)  | | Scanner    | | Gen+Eval | | Sandbox     |
   |             | | (Gemini 3) | |(Gemini 3)| | (Gemini 3)  |
   +------+------+ +-----+------+ +----+-----+ +------+------+
          |               |             |              |
          +-------+-------+------+------+------+-------+
                  |              |              |
         +--------v-------+ +---v--------------v---+
         | Evidence Trail  | | Memory Ledger (SSOT) |
         | (JSONL)         | | Hash-based dedup     |
         +-----------------+ +---------------------+
```

### Security Layers

| Layer | Mechanism | Description |
|-------|-----------|-------------|
| **L1: Source/Sink Policy** | Deterministic | Untrusted sources cannot access restricted sinks (filesystem, network, credentials) |
| **L2: Static Scan** | Pattern matching | Known vulnerability patterns, OWASP LLM Top 10 mapping |
| **L3: Semantic Scan** | Gemini 3 | Deep analysis of tool descriptions for hidden intent |
| **L4: AI Council** | Gemini 3 | Multi-criteria evaluation with confidence scoring |
| **L5: Prompt Sanitization** | Multi-level | MINIMAL / STANDARD / STRICT / PARANOID modes with regex + Unicode defense |
| **L6: Web Sandbox** | Gemini 3 + DOM analysis | Evidence-based classification of web content (phishing, malware, clickjacking, scam) |

### Causal Web Sandbox Security

The Web Sandbox implements three P0 security controls:

| Threat | Control | Implementation |
|--------|---------|---------------|
| **SSRF** | IP validation | Blocks private networks (RFC 1918), metadata endpoints (169.254.x.x), dangerous ports |
| **Prompt Injection** | Content isolation | Strips hidden elements, zero-width Unicode, applies `<analysis_boundary>` envelope |
| **Resource Exhaustion** | Hard limits | 2MB HTML, 15s timeout, 3 redirects, 50K DOM elements, 256 depth |

## Quick Start

```bash
# Clone and setup
git clone <repo-url> && cd mcp-gateway
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Set Gemini API key (required for AI features)
export GOOGLE_API_KEY="your-api-key"

# Start the gateway
python -m uvicorn src.mcp_gateway.gateway:app --host 127.0.0.1 --port 4100 --reload

# Open Dashboard UI
# http://127.0.0.1:4100/docs/ui_poc/dashboard.html
```

### UI Quick Start (Static Serve)

```bash
# Serve UI pages with a simple HTTP server
./scripts/serve_suite_ui.sh
# → http://127.0.0.1:3000/dashboard.html
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `GOOGLE_API_KEY` | Gemini API key | Required for AI features |
| `GEMINI_MODEL` | Gemini model name | `gemini-3-flash-preview` |
| `MCP_GATEWAY_ADMIN_TOKEN` | Admin authentication token | Required |
| `MCP_GATEWAY_UPSTREAM_API_KEY` | Upstream LLM API key | Required for proxy |
| `LEDGER_PATH` | Memory Ledger JSONL path | Optional (enables SSOT) |
| `LEDGER_ERROR_POLICY` | Ledger error handling | `closed` (fail-closed) |

## Test Suite

```bash
# Run all tests (241 tests)
python -m pytest tests/ -v

# Gemini integration tests
python -m pytest tests/test_council.py tests/test_scanner.py tests/test_redteam.py tests/test_causal_sandbox.py -v

# UI DOM tests (linkedom)
npm test
```

## Key Files

```
src/mcp_gateway/
  gateway.py          # FastAPI gateway (3800+ lines) - routing, policy, control plane
  ai_council.py       # Gemini 3 structured output → CouncilVerdict
  scanner.py          # Static + Semantic + Advanced Attack Detection (Gemini 3)
  redteam.py          # Dynamic attack generation + safety evaluation
  causal_sandbox.py   # Evidence-based web security analysis (Gemini 3)
  sanitizer.py        # Multi-level prompt injection defense
  evidence.py         # JSONL evidence trail + Memory Ledger dual-write
  ssot/               # Memory Ledger (persistent SSOT) + Durable Streams
  registry.py         # MCP server registration and management

docs/ui_poc/          # Dashboard UI (9 pages, bilingual EN/JA)
  dashboard.html      # Decision-centric KPI + flow + decisions table
  settings_environments.html  # Setup wizard + diagnostics + env registration
  web_sandbox.html    # Live URL security scanner with evidence details
  audit_log.html      # Expandable decision evidence trail
  scans.html          # Security scan results with severity/OWASP
  allowlist.html      # Approved MCP server list
  api_client.js       # Shared API client (auto admin-token, auth retry)
  ...

acl-proxy/            # Rust ACL-aware HTTP/HTTPS proxy
docker-compose.yml    # One-command full stack deployment
```

## Evidence Trail + Memory Ledger

Every decision is recorded as JSONL evidence. When `LEDGER_PATH` is set, events are dual-written to a Memory Ledger (SSOT) with hash-based deduplication:

```json
{"event": "source_sink_check", "decision": "deny", "server_id": "evil-mcp", "reason": "untrusted_to_restricted_sink", ...}
{"event": "council_decision", "eval_method": "gemini", "verdict_confidence": 0.95, ...}
{"event": "causal_web_scan", "classification": "phishing", "confidence": 0.92, "recommended_action": "block", ...}
{"event": "redteam_gemini", "scenarios_tested": 5, "failures": 0, ...}
```

## Advanced Attack Detection

Beyond standard static and semantic scanning, the gateway includes three novel attack detectors targeting supply-chain threats specific to the MCP ecosystem:

| Detector | Attack | Detection Method |
|----------|--------|-----------------|
| **Signature Cloaking** | Tool description changes post-registration | Jaccard word-set similarity (<40% = cloaking) |
| **Bait-and-Switch** | Benign description + malicious schema | Schema field names vs description claim analysis |
| **Tool Shadowing** | Names mimicking trusted tools (`read_fi1e`) | Character-level similarity vs 20 well-known MCP tools |

All detectors run automatically during `POST /api/scans` and produce structured evidence events. Combined with the existing tool-manifest hash pinning (SHA256 drift detection), this provides defense-in-depth against MCP tool supply-chain attacks.

## Full Stack Deployment (Docker)

```bash
mkdir -p .local
echo "your-admin-token" > .local/admin_token.txt
echo "your-upstream-key" > .local/upstream_api_key.txt
echo "your-google-api-key" > .local/google_api_key.txt

docker compose up --build
```

## Security Notice

This gateway is designed for **local / internal network use**. Do not expose it directly to the public internet. Always place an authenticating proxy (e.g., `acl-proxy/`) in front, and keep the gateway bound to `127.0.0.1`.

## License

MIT
