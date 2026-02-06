# MCP Gateway + Gemini 3

**Gemini 3 Hackathon Submission** - An AI-powered MCP (Model Context Protocol) security gateway that uses Gemini 3 structured output for intelligent threat detection, semantic analysis, and dynamic red-teaming.

## What it does

MCP Gateway sits between AI clients (ChatGPT, Claude, Gemini CLI) and MCP servers, providing a security layer that:

1. **AI Council** - Uses Gemini 3 structured output to evaluate scan results and make allow/deny/quarantine decisions with confidence scores and per-finding analysis
2. **Semantic Scanner** - Gemini 3 analyzes tool descriptions for hidden threats (data exfiltration, prompt injection, deceptive naming) that regex-based scanning would miss
3. **Dynamic Red Team** - Gemini 3 generates attack scenarios, tests them against the gateway's defenses, and evaluates response safety
4. **Context Sanitizer** - Multi-level prompt injection defense (MINIMAL/STANDARD/STRICT/PARANOID) with regex pattern matching and redaction

## Gemini 3 Integration Points

| Component | Gemini Feature | Purpose |
|-----------|---------------|---------|
| AI Council (`ai_council.py`) | Structured Output (`CouncilVerdict`) | Security evaluation with typed decisions |
| Semantic Scanner (`scanner.py`) | Structured Output (`SemanticScanResult`) | Deep analysis of tool descriptions |
| RedTeam Generator (`redteam.py`) | Structured Output (`RedTeamGeneration`) | Dynamic attack scenario creation |
| RedTeam Evaluator (`redteam.py`) | Structured Output (`PayloadSafetyVerdict`) | AI-powered response safety assessment |

All integrations use `response_mime_type="application/json"` with Pydantic schema for type-safe, deterministic outputs. Rule-based fallback is provided when the API is unavailable.

## Architecture

```
                    +------------------+
                    |   AI Clients     |
                    | (ChatGPT/Claude) |
                    +--------+---------+
                             |
                    +--------v---------+
                    |   ACL Proxy      |  <-- Rust ACL-aware proxy
                    |   (acl-proxy/)   |      URL policy + HTTPS MITM
                    +--------+---------+
                             |
                    +--------v---------+
                    |   MCP Gateway    |  <-- Python FastAPI
                    |   + Dashboard UI |      Security evaluation
                    +--+----+----+-----+
                       |    |    |
          +------------+    |    +------------+
          |                 |                 |
+---------v---+   +---------v---+   +---------v---+
| AI Council  |   |  Scanner    |   |  RedTeam    |
| (Gemini 3)  |   | (Gemini 3)  |   | (Gemini 3)  |
+------+------+   +------+------+   +------+------+
       |                 |                 |
       +--------+--------+---------+-------+
                |                  |
       +--------v--------+ +------v--------+
       | Evidence Trail  | | Memory Ledger |
       | (JSONL)         | | (SSOT)        |
       +-----------------+ +---------------+
         Dual-write with hash-based dedup
```

## Quick Start

```bash
# Install dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Set Gemini API key
export GOOGLE_API_KEY="your-api-key"

# Run tests
python -m pytest tests/ -v

# Start the gateway
python -m uvicorn src.mcp_gateway.gateway:app --reload
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `GOOGLE_API_KEY` | Gemini API key | Required for AI features |
| `GEMINI_MODEL` | Gemini model name | `gemini-2.0-flash` |
| `MCP_GATEWAY_ADMIN_TOKEN` | Admin authentication token | Required |
| `MCP_GATEWAY_UPSTREAM_API_KEY` | Upstream LLM API key | Required for chat |
| `LEDGER_PATH` | Memory Ledger JSONL path | Optional (enables persistent SSOT) |
| `LEDGER_ERROR_POLICY` | Ledger error handling (`open`/`closed`) | `open` (fail-open) |

## Key Files

```
src/mcp_gateway/
  gateway.py       # Main FastAPI gateway with sanitizer integration
  ai_council.py    # Gemini 3 structured output for security decisions
  scanner.py       # Static + semantic (Gemini 3) vulnerability scanning
  redteam.py       # Dynamic attack generation + safety evaluation
  sanitizer.py     # Multi-level prompt injection defense
  evidence.py      # JSONL evidence trail with Memory Ledger dual-write
  ssot/            # Memory Ledger (persistent SSOT) + Durable Streams
  registry.py      # MCP server registration and management

acl-proxy/           # Rust ACL-aware HTTP/HTTPS proxy
  src/               # Policy engine, MITM, loop protection
  tests/             # Integration tests
  Cargo.toml         # Rust dependencies

docker/              # Dockerfiles for gateway + proxy
docker-compose.yml   # One-command full stack deployment

tests/ui/            # Playwright UI tests for dashboard
```

## Full Stack Deployment (Docker)

```bash
# Create secrets
mkdir -p .local
echo "your-admin-token" > .local/admin_token.txt
echo "your-upstream-key" > .local/upstream_api_key.txt
echo "your-google-api-key" > .local/google_api_key.txt

# Start all services
docker compose up --build
```

## Test Suite

```bash
# Run all tests (194 tests)
python -m pytest tests/ -v

# Run Gemini-specific tests
python -m pytest tests/test_council.py tests/test_scanner.py tests/test_redteam.py tests/test_sanitizer.py -v
```

## Evidence Trail + Memory Ledger

Every decision is recorded as JSONL evidence for auditability. When `LEDGER_PATH` is set, events are also dual-written to a Memory Ledger (SSOT) with hash-based deduplication and monotonic sequence tracking:

```json
{"event": "council_decision", "eval_method": "gemini", "verdict_confidence": 0.95, ...}
{"event": "mcp_scan_run", "scan_type": "semantic", "gemini_model": "gemini-2.0-flash", ...}
{"event": "redteam_gemini", "scenarios_tested": 5, "failures": 0, ...}
```

```bash
# Enable persistent Memory Ledger
export LEDGER_PATH="./observability/memory_ledger.jsonl"
```

## License

MIT
