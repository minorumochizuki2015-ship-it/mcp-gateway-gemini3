# Devpost Submission Text (~200 words)

## Project Description

**MCP Gateway** is a security-first proxy that sits between AI clients (ChatGPT, Claude, Gemini) and the 13,000+ MCP servers in the ecosystem. Every tool call passes through a 6-layer inspection pipeline with **7 Gemini 3 integration points**.

### Gemini 3 Features Used (All Central to the Application)

1. **Thinking Levels** (`high`/`low`): Deep reasoning for threat analysis, fast triage for safe content. Used across all 7 components.

2. **Structured Output** (typed JSON schemas): Every Gemini call returns a typed verdict (`CouncilVerdict`, `WebSecurityVerdict`, `AgentScanResult`) - not free-form text. This makes security decisions machine-parseable and auditable.

3. **URL Context**: The Causal Web Sandbox has Gemini 3 visit suspicious URLs directly, performing multimodal page analysis without a separate renderer.

4. **Google Search Grounding**: Real-time threat intelligence - "Has this domain been reported as malicious?" - integrated into AI Council, Scanner, Sandbox, and Agent Scan.

5. **Function Calling** (multi-turn): The Agent Scan component operates as an autonomous security agent, deciding which tools to invoke based on the threat surface - not a fixed pipeline.

6. **Audit QA Chat**: Gemini 3 explains its own security decisions by reasoning over the evidence trail. Users ask "Why was this blocked?" and get structured answers with confidence scores and evidence references.

**Key differentiator**: Not just allow/deny. Every decision produces structured evidence - the *why* behind every verdict. **Audit QA Chat** lets users interrogate those decisions in natural language. Self-Tuning UI proposes AI Council weight adjustments based on historical metrics. 414 tests passing. Open source.

### What's Next

- **OAuth2 PAR (RFC 9126) + DPoP (RFC 9449)**: Enterprise-grade token security replacing static Bearer tokens. Server-side request storage + client-bound proof-of-possession tokens. Planned Q2-Q4 2026.
