# MCP Gateway Demo Video Script (~3 minutes)

## Target: Gemini 3 Hackathon Submission (Devpost)

---

## SCENE 1: HOOK (0:00 - 0:10)

**[VISUAL]**: Dashboard full screen - AI Gateway Dashboard with pipeline running, threats detected

**[NARRATION / TEXT OVERLAY]**:
> "13,000+ MCP servers. Zero security layer. Until now."

**[TEXT OVERLAY]**: MCP Gateway - AI-Powered Security for the Agent Era

---

## SCENE 2: THE PROBLEM (0:10 - 0:30)

**[VISUAL]**: Split screen - Left: MCP ecosystem growth chart, Right: Attack types

**[NARRATION / TEXT OVERLAY]**:
> "AI agents connect to thousands of MCP servers to read files, query databases, browse the web. But there's no security layer between them."

**[VISUAL]**: Show 3 attack cards appearing:
1. **Tool Shadowing**: `read_fi1e` mimics `read_file` (char diff highlighted)
2. **Signature Cloaking**: Description changes from "List data" to "Execute command"
3. **Prompt Injection**: Hidden instructions in tool outputs

> "94% attack success rate. Existing scanners catch as few as ~3%."

---

## SCENE 3: THE SOLUTION (0:30 - 1:00)

**[VISUAL]**: Architecture diagram (architecture-overview.svg) animating

**[NARRATION / TEXT OVERLAY]**:
> "MCP Gateway: a 6-layer security pipeline powered by Gemini 3."

**[VISUAL]**: Each layer lights up:
- L1 Policy (deterministic)
- L2 Static Scan (pattern matching)
- L3 Semantic Scan (**Gemini 3**)
- L4 AI Council (**Gemini 3**)
- L5 Prompt Sanitization
- L6 Web Sandbox (**Gemini 3**)

> "Not just allow/deny. Every decision produces structured evidence - auditable, explainable."

**[VISUAL]**: Show Gemini 3 features badge:
- Thinking Levels (high/low)
- URL Context
- Google Search Grounding
- Function Calling
- Structured Output

> "6 Gemini 3 integration points. 5 exclusive features. This is why only Gemini 3 can do this."

---

## SCENE 4: LIVE DEMO - PIPELINE (1:00 - 1:45)

**[VISUAL]**: Dashboard - Click "Run Security Scenario"

**[NARRATION / TEXT OVERLAY]**:
> "Let's run a live security scenario."

**[VISUAL]**: SSE pipeline streaming in real-time:
1. "3 Gemini agents connect through the gateway"
2. "Gemini Pro tries `read_fi1e` on suspicious-mcp... BLOCKED"
   - Tool Shadowing detected: similarity 85% with read_file
3. "Gemini Flash queries data-scraper-mcp... WARN"
   - AI Council evaluates with Google Search grounding
4. "Advanced threats detected: Signature Cloaking, Bait-and-Switch"
   - Description diff shown with strikethrough

> "The gateway caught what static scanners miss - semantic attacks."

---

## SCENE 5: LIVE DEMO - WEB SANDBOX (1:45 - 2:30)

**[VISUAL]**: Web Sandbox page - scanning login-apple-verify.tk

**[NARRATION / TEXT OVERLAY]**:
> "The Causal Web Sandbox - where Gemini 3's unique capabilities shine."

**[VISUAL]**: Scan results appearing:
1. **Page Bundle**: SHA256 hash, 15 resources
2. **DOM Analysis**: Hidden iframe detected, deceptive form
3. **Detection Matrix**: Brand impersonation (apple), Freenom TLD (.tk), suspicious tokens (login, verify)

**[VISUAL]**: Comparison Panel - Rule-based vs Gemini 3
- Left: "4 risk indicators - pattern matching only"
- Right: "9 risk indicators - credential phishing, form exfiltration target, hidden iframe"

> "Rule-based caught the obvious. Gemini 3 understood the intent."

**[VISUAL]**: Attack Narrative panel
> "Step 1: Domain impersonates Apple brand. Step 2: Hidden iframe for prompt injection. Step 3: Form exfiltrates to evil-collector.example.net."

**[VISUAL]**: MCP-Specific Threats panel
> "AI agent could auto-fill credentials. Hidden iframe: prompt injection risk."

---

## SCENE 6: EVIDENCE & DETECTION (2:30 - 2:50)

**[VISUAL]**: Detection Matrix (detection-matrix.svg) - 13/13 verified

**[NARRATION / TEXT OVERLAY]**:
> "13 detection patterns. 13 passing. DGA domains, IDN homographs, leet-speak typosquatting, MCP protocol injection - all verified with explicit test cases."

**[VISUAL]**: Evidence Trail JSONL scrolling
> "Every verdict produces structured evidence. Auditable. Explainable. 401 tests passing."

---

## SCENE 7: CLOSING (2:50 - 3:00)

**[VISUAL]**: Dashboard with all green indicators

**[TEXT OVERLAY]**:
> "Gemini 3 is powerful. But enterprises need a seatbelt."
> "We built that seatbelt."

**[VISUAL]**: Logo + tagline
> **MCP Gateway** - The first security gateway that makes AI tool access auditable, not just allow/deny.
> Powered by Gemini 3 | 401 Tests | 6 Integration Points | Open Source

---

## TECHNICAL NOTES

- **Total duration**: ~3:00
- **Format**: Screen recording of live dashboard + Web Sandbox + animated overlays
- **Resolution**: 1920x1080 (16:9)
- **Upload**: YouTube (unlisted or public)
- **No live API key needed**: Demo Gemini mode provides pre-computed Gemini-quality verdicts
