# Devpost Submission Text (~200 words)

## Project Description

**MCP Gateway** is a security-first proxy that sits between AI clients (ChatGPT, Claude, Gemini) and the 13,000+ MCP servers in the ecosystem. Every tool call passes through a 6-layer inspection pipeline with **6 Gemini 3 integration points**.

### Gemini 3 Features Used (All Central to the Application)

1. **Thinking Levels** (`high`/`low`): Deep reasoning for threat analysis, fast triage for safe content. Used across all 6 components.

2. **Structured Output** (typed JSON schemas): Every Gemini call returns a typed verdict (`CouncilVerdict`, `WebSecurityVerdict`, `AgentScanResult`) - not free-form text. This makes security decisions machine-parseable and auditable.

3. **URL Context**: The Causal Web Sandbox has Gemini 3 visit suspicious URLs directly, performing multimodal page analysis without a separate renderer.

4. **Google Search Grounding**: Real-time threat intelligence - "Has this domain been reported as malicious?" - integrated into AI Council, Scanner, Sandbox, and Agent Scan.

5. **Function Calling** (multi-turn): The Agent Scan component operates as an autonomous security agent, deciding which tools to invoke based on the threat surface - not a fixed pipeline.

**Key differentiator**: Not just allow/deny. Every decision produces structured evidence - the *why* behind every verdict. 401 tests passing. Open source.
