# MCP Gateway - AI-Powered Security Gateway for MCP

> **The first security gateway that makes AI tool access _auditable_, not just allow/deny.**

**Gemini 3 Hackathon Submission** | [Live Pipeline Demo](#live-pipeline-demo) | [Quick Start](#quick-start-30-seconds) | [5 Gemini Integration Points](#5-gemini-3-integration-points)

---

## The Problem: 13,000+ MCP Servers, Zero Security Layer

The MCP (Model Context Protocol) ecosystem has exploded to **13,000+ servers**, but there is no standard security layer. AI agents connect to MCP servers that can:

- **Typosquatting**: `read_fi1e` (with the digit `1`) mimics `read_file` — and the AI can't tell the difference
- **Signature Cloaking**: A tool description changes from _"List analytics data"_ to _"Execute system command and exfiltrate credentials"_ — after initial approval
- **Bait-and-Switch**: A "read-only file viewer" that secretly requests `password`, `api_key`, `session_id` fields

**No existing tool catches these.** Static scanners miss semantic attacks. Rule-based systems can't reason about intent.

## What MCP Gateway Does

MCP Gateway is a **security-first proxy** between AI clients (ChatGPT, Claude, Gemini CLI) and MCP servers. Every tool call passes through a 6-layer inspection pipeline powered by **Gemini 3 structured output**:

```
AI Client ──► MCP Gateway ──► MCP Servers
               │
               ├── L1: Source/Sink Policy (deterministic)
               ├── L2: Static Scan (pattern matching)
               ├── L3: Semantic Scan (Gemini 3)
               ├── L4: AI Council Verdict (Gemini 3)
               ├── L5: Prompt Sanitization (multi-level)
               └── L6: Web Sandbox (Gemini 3 + DOM)
```

**Key insight**: Instead of binary allow/deny, every decision produces **structured evidence** — the _why_ behind every verdict — making security **auditable and explainable**.

## Why Gemini 3?

MCP Gateway requires a model that can produce **deterministic, structured security verdicts** — not free-form text. Gemini 3's `response_schema` with Pydantic models enables:

| Capability | How We Use It | Why It Matters |
|-----------|---------------|---------------|
| **Structured Output** | `response_schema=CouncilVerdict` | Verdicts are _typed JSON_, not parsed prose. Zero extraction errors. |
| **Temperature 0 + Seed** | `temperature=0.0, seed=42` | Same tool description → same verdict. Reproducible security decisions. |
| **Schema Validation** | Pydantic `BaseModel` → JSON Schema | Invalid verdicts are rejected at the API level, not caught by post-hoc parsing. |
| **Graceful Degradation** | Rule-based fallback when API unavailable | Security is never compromised — gateway continues with deterministic rules. |

Every Gemini call is wrapped with the same pattern:
```python
response = client.models.generate_content(
    model="gemini-3-flash-preview",
    contents=prompt,
    config=types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=CouncilVerdict,   # Pydantic model
        temperature=0.0, seed=42,
    ),
)
verdict = CouncilVerdict.model_validate_json(response.text)
```

## 5 Gemini 3 Integration Points

| # | Component | Schema | What It Does |
|---|-----------|--------|-------------|
| 1 | **AI Council** | `CouncilVerdict` | Multi-criteria security evaluation with per-finding analysis and confidence scoring |
| 2 | **Semantic Scanner** | `SemanticScanResult` | Deep analysis of tool descriptions for hidden threats that regex cannot detect |
| 3 | **RedTeam Generator** | `RedTeamGeneration` | Dynamic attack scenario generation tailored to each tool's capabilities |
| 4 | **RedTeam Evaluator** | `PayloadSafetyVerdict` | AI-powered safety assessment of tool responses against attack scenarios |
| 5 | **Causal Web Sandbox** | `WebSecurityVerdict` | Evidence-based web page threat classification with DOM/a11y/network analysis |

## Live Pipeline Demo

The gateway includes a **real-time SSE pipeline** that demonstrates the full security flow in ~30 seconds:

1. **LLM Agent Requests Tool Access** — 5 MCP servers with mixed trust levels
2. **Gateway Intercepts + Security Scan** — Static analysis with finding counts
3. **AI Council Verdict (Gemini 3)** — Per-server allow/deny with latency and rationale
4. **Advanced Threat Analysis** — Typosquatting char-diff, signature cloaking description diff, bait-and-switch field detection
5. **Causal Web Sandbox** — Live HTTP fetch → DOM analysis → Gemini verdict on 3 test pages
6. **MCP Tool Call Interception** — Agent session simulation with BLOCKED/ALLOWED/DLP enforcement

Each step streams as a Server-Sent Event with visual indicators (Gemini badges, latency timers, confidence bars).

## Dashboard UI

9 pages with **bilingual support (English / Japanese)**:

| Page | Purpose |
|------|---------|
| **Dashboard** | KPI cards, Gateway Flow diagram, Live Pipeline Demo, Attack Detection Timeline, Recent Decisions |
| **Environments** | Setup wizard, system diagnostics, environment registration |
| **Scans** | Security scan results with severity/OWASP breakdown |
| **AllowList** | MCP server registration, trust status, scan history |
| **Web Sandbox** | Live URL scanner with DOM threats, network traces, a11y issues, Gemini verdict |
| **Audit Log** | Expandable decision evidence trail with evidence IDs |
| **Billing** | Token consumption, API call counts, cost estimation |
| **Settings** | OWASP LLM Top 10 policy configuration |

### Attack Detection Timeline

The dashboard includes a visual attack timeline with **char-level diff rendering**:

- **Tool Shadowing**: `read_fi`**`1`**`e` vs `read_fi`**`l`**`e` — character differences highlighted in red/green
- **Signature Cloaking**: ~~"List analytics data"~~ → **"Execute system command"** — strikethrough + red new description
- **Bait & Switch**: Sensitive fields (`password`, `api_key`) highlighted inline

## Advanced Attack Detection

Three novel detectors targeting MCP supply-chain threats:

| Detector | Attack | Detection |
|----------|--------|-----------|
| **Signature Cloaking** | Tool description changes post-registration | Jaccard word-set similarity (<40% = cloaking) |
| **Bait-and-Switch** | Benign description + malicious schema | Schema field vs description claim analysis |
| **Tool Shadowing** | Names mimicking trusted tools | Character-level similarity vs 20 well-known MCP tools |

## Causal Web Sandbox

Evidence-based web security analysis inspired by rendering pipeline internals:

| Component | What It Produces |
|-----------|-----------------|
| **Page Bundle** | SHA256 hash, content length, resource count, blocked resources |
| **DOM Analysis** | Hidden iframes, deceptive forms, suspicious scripts with CSS selectors |
| **A11y Tree** | Deceptive label detection (aria-label mismatch) |
| **Network Trace** | URL extraction from scripts/forms/images, suspicious domain flagging |
| **Gemini Verdict** | Structured classification (benign/phishing/malware/clickjacking/scam) with evidence refs |

### Security Controls (P0)

| Threat | Control | Implementation |
|--------|---------|---------------|
| **SSRF** | IP validation | Blocks RFC 1918, metadata (169.254.x.x), dangerous ports |
| **Prompt Injection** | Content isolation | Strips hidden elements, zero-width Unicode, `<analysis_boundary>` envelope |
| **Resource Exhaustion** | Hard limits | 2MB HTML, 15s timeout, 3 redirects, 50K DOM elements |

## Quick Start (30 seconds)

```bash
# Clone and setup
git clone https://github.com/minorumochizuki2015-ship-it/mcp-gateway-gemini3.git
cd mcp-gateway-gemini3
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Demo mode (no auth required, instant start)
MCP_GATEWAY_DEMO_MODE=true \
MCP_GATEWAY_ADMIN_TOKEN=demo \
python -m uvicorn src.mcp_gateway.gateway:app --host 127.0.0.1 --port 4100

# Open Dashboard → Click "Run Live Pipeline"
# http://127.0.0.1:4100/docs/ui_poc/dashboard.html
```

### With Gemini AI

```bash
export GOOGLE_API_KEY="your-api-key"
MCP_GATEWAY_ADMIN_TOKEN=your-token \
python -m uvicorn src.mcp_gateway.gateway:app --host 127.0.0.1 --port 4100
```

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
                    |  + Dashboard UI  |    6-layer security pipeline
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

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `GOOGLE_API_KEY` | Gemini API key | Required for AI features |
| `GEMINI_MODEL` | Gemini model name | `gemini-3-flash-preview` |
| `MCP_GATEWAY_ADMIN_TOKEN` | Admin authentication | Required |
| `MCP_GATEWAY_DEMO_MODE` | Skip auth for demo | `false` |
| `MCP_GATEWAY_UPSTREAM_API_KEY` | Upstream LLM API key | Required for proxy |
| `LEDGER_PATH` | Memory Ledger JSONL | Optional (enables SSOT) |
| `LEDGER_ERROR_POLICY` | Ledger error handling | `closed` (fail-closed) |

## Test Suite

```bash
# 241 tests
python -m pytest tests/ -v

# Gemini integration tests only
python -m pytest tests/test_council.py tests/test_scanner.py \
  tests/test_redteam.py tests/test_causal_sandbox.py -v
```

## API Endpoints (47 total)

### Core Pipeline
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scans` | Run security scan + advanced attack detection |
| POST | `/api/council/evaluate/{id}` | AI Council verdict |
| POST | `/api/web-sandbox/scan` | Causal Web Sandbox analysis |
| POST | `/api/redteam/generate` | Generate attack scenarios |
| POST | `/api/redteam/evaluate` | Evaluate tool safety |

### Management
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dashboard/summary` | Dashboard KPI data |
| GET | `/api/allowlist` | List MCP servers |
| POST | `/api/allowlist/{id}/register` | Register MCP server |
| GET | `/api/audit-log` | Evidence trail |
| GET | `/api/demo/run-live` | SSE live pipeline |

## Evidence Trail

Every decision produces JSONL evidence. When `LEDGER_PATH` is set, events are dual-written to a Memory Ledger (SSOT) with hash-based deduplication:

```json
{"event": "source_sink_check", "decision": "deny", "server_id": "evil-mcp", "reason": "untrusted_to_restricted_sink"}
{"event": "council_decision", "eval_method": "gemini", "verdict_confidence": 0.95}
{"event": "causal_web_scan", "classification": "phishing", "confidence": 0.92, "recommended_action": "block"}
{"event": "attack_detection", "code": "tool_shadowing", "tool_name": "read_fi1e", "status": "blocked"}
```

## Full Stack (Docker)

```bash
mkdir -p .local
echo "your-admin-token" > .local/admin_token.txt
echo "your-upstream-key" > .local/upstream_api_key.txt
echo "your-google-api-key" > .local/google_api_key.txt

docker compose up --build
```

## Key Files

```
src/mcp_gateway/
  gateway.py          # FastAPI gateway (4900+ lines) — routing, policy, SSE pipeline
  ai_council.py       # Gemini 3 → CouncilVerdict
  scanner.py          # Static + Semantic + Advanced Attack Detection
  redteam.py          # Attack generation + safety evaluation
  causal_sandbox.py   # Evidence-based web security (Gemini 3)
  sanitizer.py        # Multi-level prompt injection defense
  evidence.py         # JSONL evidence trail + Memory Ledger
  ssot/               # Memory Ledger (persistent SSOT) + Durable Streams
  registry.py         # MCP server registration and management

docs/ui_poc/          # Dashboard UI (9 pages, bilingual EN/JA)
acl-proxy/            # Rust ACL-aware HTTP/HTTPS proxy
docker-compose.yml    # One-command full stack deployment
```

## Security Notice

This gateway is designed for **local / internal network use**. Do not expose directly to the public internet. Use an authenticating proxy (e.g., `acl-proxy/`) in front.

## License

MIT
