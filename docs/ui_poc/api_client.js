// Lightweight API client with opt-in mock fallback for the Suite Scan UI PoC.

// Global HTML escape utility for safe innerHTML rendering of API data.
window.escapeHtml = function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
};

(function () {
  const params = new URLSearchParams(window.location.search);
  const BASE =
    params.get("api_base") ||
    window.SUITE_API_BASE ||
    "/api";
  const CONTROL_BASE =
    params.get("control_base") ||
    window.SUITE_CONTROL_BASE ||
    BASE;
  const LEGACY_ADMIN_TOKEN_KEY = "suite_admin_token";
  const DANGER_ADMIN_STATE_KEY = "suite_admin_danger";
  const ONBOARDING_COLLAPSED_KEY = "suite_onboarding_collapsed";
  const ONBOARDING_COMPLETED_KEY = "suite_onboarding_completed";
  const UPSTREAM_TTL_MS = 3600 * 1000;
  const IS_FILE_PROTOCOL =
    typeof window !== "undefined" &&
    window.location &&
    window.location.protocol === "file:";
  const DISABLE_MOCK_PARAM =
    params.get("disable_mock") === "1" || window.SUITE_DISABLE_MOCK === true;
  const ENABLE_MOCK_PARAM =
    params.get("enable_mock") === "1" || window.SUITE_ENABLE_MOCK === true;
  const ENABLE_MOCK =
    !DISABLE_MOCK_PARAM && (ENABLE_MOCK_PARAM || IS_FILE_PROTOCOL);
  const DISABLE_MOCK = !ENABLE_MOCK;

  // SaaS mode: hide admin token input UI
  const SAAS_MODE =
    params.get("saas") === "1" || window.SUITE_SAAS_MODE === true;

  function getStorage() {
    try {
      return window.localStorage;
    } catch (e) {
      return null;
    }
  }

  function getSessionStorage() {
    try {
      return window.sessionStorage;
    } catch (e) {
      return null;
    }
  }

  (function purgeLegacyAdminToken() {
    const storage = getStorage();
    if (!storage) return;
    try {
      storage.removeItem(LEGACY_ADMIN_TOKEN_KEY);
    } catch (e) {}
  })();

  function parseDangerState(raw) {
    if (!raw) return null;
    try {
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object") return null;
      const token = String(parsed.token || "").trim();
      if (!token) return null;
      const expiresAt =
        parsed.expiresAt === null || parsed.expiresAt === undefined
          ? null
          : Number(parsed.expiresAt);
      const createdAt = Number(parsed.createdAt || Date.now());
      if (expiresAt !== null && !Number.isFinite(expiresAt)) return null;
      if (!Number.isFinite(createdAt)) return null;
      return { token, expiresAt, createdAt };
    } catch (e) {
      return null;
    }
  }

  function clearDangerState() {
    const storage = getStorage();
    const session = getSessionStorage();
    try {
      if (storage) storage.removeItem(DANGER_ADMIN_STATE_KEY);
    } catch (e) {}
    try {
      if (session) session.removeItem(DANGER_ADMIN_STATE_KEY);
    } catch (e) {}
  }

  function getDangerModeState() {
    const storage = getStorage();
    const session = getSessionStorage();
    let raw = null;
    let storageType = null;
    try {
      raw = session ? session.getItem(DANGER_ADMIN_STATE_KEY) : null;
      if (raw) storageType = "session";
    } catch (e) {}
    if (!raw) {
      try {
        raw = storage ? storage.getItem(DANGER_ADMIN_STATE_KEY) : null;
        if (raw) storageType = "local";
      } catch (e) {}
    }
    const state = parseDangerState(raw);
    if (!state) return null;
    if (state.expiresAt !== null && Date.now() > state.expiresAt) {
      clearDangerState();
      return null;
    }
    return { ...state, storageType };
  }

  function setDangerModeState({ token, expiresAt, storageType }) {
    const storage = getStorage();
    const session = getSessionStorage();
    const target = storageType === "local" ? storage : session;
    const other = storageType === "local" ? session : storage;
    if (!target) return false;
    const payload = JSON.stringify({
      token: String(token || "").trim(),
      expiresAt: expiresAt === undefined ? null : expiresAt,
      createdAt: Date.now(),
    });
    try {
      target.setItem(DANGER_ADMIN_STATE_KEY, payload);
    } catch (e) {
      return false;
    }
    try {
      if (other) other.removeItem(DANGER_ADMIN_STATE_KEY);
    } catch (e) {}
    return true;
  }

  function getAdminToken() {
    return (
      params.get("admin_token") ||
      window.SUITE_ADMIN_TOKEN ||
      ""
    );
  }

  function setAdminToken(token) {
    const trimmed = String(token || "").trim();
    window.SUITE_ADMIN_TOKEN = trimmed;
  }

  let sessionRefreshPromise = null;
  let adminSessionRequired = false;
  let gatewayOffline = IS_FILE_PROTOCOL;
  let gatewayOfflineReason = IS_FILE_PROTOCOL ? "file" : null;

  function setGatewayOnline() {
    if (!gatewayOffline) return;
    gatewayOffline = false;
    gatewayOfflineReason = null;
    updateGatewayOfflineBanner();
  }

  function setGatewayOffline(reason) {
    const next = reason || "network";
    if (gatewayOffline && gatewayOfflineReason === next) return;
    gatewayOffline = true;
    gatewayOfflineReason = next;
    updateGatewayOfflineBanner();
  }

  async function createControlSession(token, { timeoutMs = 4000 } = {}) {
    const trimmed = String(token || "").trim();
    if (!trimmed) return { ok: false, status: 0, data: null, errorType: "auth" };
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
    try {
      const res = await fetch(`${CONTROL_BASE}/control/session`, {
        method: "POST",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${trimmed}`,
        },
        mode: "cors",
        credentials: "include",
        signal: controller ? controller.signal : undefined,
      });
      if (!res.ok) {
        const errorType =
          res.status >= 500
            ? "server"
            : res.status === 401 || res.status === 403
              ? "auth"
              : "other";
        return { ok: false, status: res.status, data: null, errorType };
      }
      const data = await res.json().catch(() => null);
      if (window.SUITE_ADMIN_TOKEN) window.SUITE_ADMIN_TOKEN = "";
      adminSessionRequired = false;
      updateAdminSessionBanner();
      return { ok: true, status: res.status, data, errorType: null };
    } catch (e) {
      const isAbort = e && e.name === "AbortError";
      return { ok: false, status: 0, data: null, errorType: isAbort ? "timeout" : "network" };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async function ensureControlSession() {
    if (sessionRefreshPromise) return sessionRefreshPromise;
    const state = getDangerModeState();
    const candidate = getAdminToken() || (state ? state.token : "");
    if (!candidate) return Promise.resolve(false);
    sessionRefreshPromise = (async () => {
      const res = await createControlSession(candidate);
      return res.ok;
    })();
    try {
      return await sessionRefreshPromise;
    } finally {
      sessionRefreshPromise = null;
    }
  }

  async function enableDangerMode(token, { durationMs, storageType = "session" } = {}) {
    const trimmed = String(token || "").trim();
    if (!trimmed) return { ok: false, reason: "missing_token" };
    const sessionRes = await createControlSession(trimmed);
    if (!sessionRes.ok) return { ok: false, reason: "session_failed", sessionRes };
    const expiresAt =
      durationMs === null || durationMs === undefined ? null : Date.now() + Number(durationMs);
    const stored = setDangerModeState({
      token: trimmed,
      expiresAt,
      storageType: storageType === "local" ? "local" : "session",
    });
    if (!stored) return { ok: false, reason: "storage_failed" };
    return { ok: true, expiresAt };
  }

  function disableDangerMode() {
    clearDangerState();
  }

  function formatTimeRemaining(ms) {
    if (!Number.isFinite(ms) || ms < 0) return "";
    const totalSeconds = Math.floor(ms / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    if (hours > 0) return `${hours}h ${String(minutes).padStart(2, "0")}m`;
    if (minutes > 0) return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
    return `${seconds}s`;
  }

  async function requestJson(path, { method = "GET", body = null, auth = false } = {}) {
    const res = await requestJsonWithStatus(path, { method, body, auth });
    return res.ok ? res.data : null;
  }

  async function requestJsonWithStatus(
    path,
    { method = "GET", body = null, auth = false, timeoutMs = 4000 } = {}
  ) {
    const headers = { Accept: "application/json" };
    if (body) headers["Content-Type"] = "application/json";
    try {
      const attempt = async () => {
        const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
        const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
        try {
          return await fetch(path, {
          method,
          headers,
          mode: "cors",
          credentials: "include",
          body: body ? JSON.stringify(body) : null,
          signal: controller ? controller.signal : undefined,
        });
        } finally {
          if (timer) clearTimeout(timer);
        }
      };
      let res = await attempt();
      setGatewayOnline();
      if (auth && (res.status === 401 || res.status === 403)) {
        const refreshed = await ensureControlSession();
        if (refreshed) {
          res = await attempt();
        }
      }
      if (!res.ok) {
        if (auth && (res.status === 401 || res.status === 403)) {
          adminSessionRequired = true;
          updateAdminSessionBanner();
        }
        const errorType =
          res.status >= 500
            ? "server"
            : res.status === 401 || res.status === 403
              ? "auth"
            : "other";
        return { ok: false, status: res.status, data: null, errorType };
      }
      const data = await res.json();
      if (auth) {
        adminSessionRequired = false;
        updateAdminSessionBanner();
      }
      return { ok: true, status: res.status, data, errorType: null };
    } catch (e) {
      const isAbort = e && e.name === "AbortError";
      setGatewayOffline(IS_FILE_PROTOCOL ? "file" : isAbort ? "timeout" : "network");
      return { ok: false, status: 0, data: null, errorType: isAbort ? "timeout" : "network" };
    }
  }

  async function fetchJson(path) {
    return requestJson(path);
  }

  async function fetchScans() {
    const data = await fetchJson(`${BASE}/scans`);
    if (data && Array.isArray(data) && data.length > 0) return data;
    // Fallback to mock when API returns empty or fails
    if (DISABLE_MOCK) return data || [];
    return (window.suiteScanData && window.suiteScanData.scans) || data || [];
  }

  async function fetchScanDetail(id) {
    const data = await fetchJson(`${BASE}/scans/${encodeURIComponent(id)}`);
    if (data) return data;
    if (DISABLE_MOCK) return { scan: null, findings: [] };
    const fallback =
      (window.suiteScanData &&
        window.suiteScanData.findings &&
        window.suiteScanData.findings[id]) ||
      [];
    const scan =
      (window.suiteScanData &&
        window.suiteScanData.scans &&
        window.suiteScanData.scans.find((s) => s.id === id)) ||
      null;
    return { scan, findings: fallback };
  }

  async function fetchAllowlist() {
    const data = await fetchJson(`${BASE}/allowlist`);
    if (data && Array.isArray(data) && data.length > 0) return data;
    // Fallback to mock allowlist entries when API returns empty
    if (!DISABLE_MOCK && window.suiteScanData && window.suiteScanData.allowlist_entries) {
      return window.suiteScanData.allowlist_entries;
    }
    return data || [];
  }

  async function fetchAllowlistStatus() {
    const data = await fetchJson(`${BASE}/allowlist/status`);
    if (data && typeof data === "object") return data;
    if (DISABLE_MOCK) return null;
    return (window.suiteScanData && window.suiteScanData.allowlist_status) || null;
  }

  async function fetchMcpDetail(serverId) {
    if (!serverId && serverId !== 0) return null;
    const data = await fetchJson(`${BASE}/mcp/${encodeURIComponent(serverId)}`);
    if (data && typeof data === "object") return data;
    if (DISABLE_MOCK) return null;
    return (window.suiteScanData && window.suiteScanData.mcp_detail) || null;
  }

  async function fetchMcpHistory(serverId) {
    if (!serverId && serverId !== 0) return null;
    const data = await fetchJson(`${BASE}/mcp/${encodeURIComponent(serverId)}/history`);
    if (data && typeof data === "object" && Array.isArray(data.history)) return data;
    if (DISABLE_MOCK) return null;
    const fallback =
      window.suiteScanData &&
      window.suiteScanData.history &&
      window.suiteScanData.history[String(serverId || 0)];
    return fallback || null;
  }

  async function fetchDashboardSummary() {
    const data = await fetchJson(`${BASE}/dashboard/summary`);
    if (data && typeof data === "object") {
      // If live data has meaningful content, use it; otherwise supplement with mock
      const al = data.allowlist || {};
      const hasLiveData = (al.total || 0) > 0 || (data.scans && data.scans.total > 0) || (data.council && data.council.total > 0);
      if (hasLiveData) return data;
      // Live data is empty - merge with mock for demo richness
      if (!DISABLE_MOCK && window.suiteScanData && window.suiteScanData.dashboard_summary) {
        return window.suiteScanData.dashboard_summary;
      }
      return data;
    }
    if (DISABLE_MOCK) return null;
    return (window.suiteScanData && window.suiteScanData.dashboard_summary) || null;
  }

  function getOnboardingCompleted() {
    const storage = getStorage();
    if (!storage) return false;
    return storage.getItem(ONBOARDING_COMPLETED_KEY) === "1";
  }

  function setOnboardingCompleted(val) {
    const storage = getStorage();
    if (!storage) return;
    if (val) {
      storage.setItem(ONBOARDING_COMPLETED_KEY, "1");
    } else {
      storage.removeItem(ONBOARDING_COMPLETED_KEY);
    }
  }

  function isFreshTimestamp(ts, ttlMs) {
    if (!ts) return false;
    const parsed = Date.parse(ts);
    if (!Number.isFinite(parsed)) return false;
    return Date.now() - parsed <= ttlMs;
  }

  function evaluateUpstreamStatus(upstream) {
    if (!upstream || typeof upstream !== "object") return false;
    const baseUrl = String(upstream.base_url || "").trim();
    if (!baseUrl) return false;
    if (upstream.status !== "ok") return false;
    return isFreshTimestamp(upstream.last_tested, UPSTREAM_TTL_MS);
  }

  function evaluateTokens(tokens) {
    if (!Array.isArray(tokens)) return false;
    return tokens.some((token) => token && token.status === "active");
  }

  async function getSetupCompletion() {
    const upstreamRes = await requestJsonWithStatus(`${CONTROL_BASE}/control/upstream`, { auth: true });
    const tokensRes = await requestJsonWithStatus(`${CONTROL_BASE}/control/tokens`, { auth: true });
    const errors = [upstreamRes, tokensRes].filter((res) => !res.ok);

    if (errors.some((res) => res.errorType === "auth")) {
      return { complete: false, source: "auth" };
    }
    if (errors.some((res) => res.errorType === "server" || res.errorType === "timeout" || res.errorType === "network")) {
      return { complete: getOnboardingCompleted(), source: "fallback" };
    }
    if (errors.length > 0) {
      return { complete: false, source: "error" };
    }

    const upstreamOk = evaluateUpstreamStatus(upstreamRes.data);
    const tokensOk = evaluateTokens(tokensRes.data);
    const complete = upstreamOk && tokensOk;
    setOnboardingCompleted(complete);
    return { complete, source: "server" };
  }

  async function applyNavOrder() {
    if (typeof document === "undefined") return;
    const navLinks = document.querySelector(".nav-links");
    if (!navLinks) return;
    const links = Array.from(navLinks.querySelectorAll("a.nav-link"));
    if (!links.length) return;
    const hrefs = links.map((link) => link.getAttribute("href"));
    const required = [
      "settings_environments.html",
      "dashboard.html",
      "scans.html",
      "allowlist.html",
      "web_sandbox.html",
      "audit_log.html",
    ];
    const hasAllRequired = required.every((href) => hrefs.includes(href));
    if (!hasAllRequired) return;

    const orderFor = (complete) =>
      complete
        ? ["dashboard.html", "scans.html", "settings_environments.html", "allowlist.html", "web_sandbox.html", "audit_log.html"]
        : ["settings_environments.html", "dashboard.html", "scans.html", "allowlist.html", "web_sandbox.html", "audit_log.html"];

    const reorderLinks = (order) => {
      const linkMap = new Map();
      links.forEach((link) => linkMap.set(link.getAttribute("href"), link));
      const ordered = [];
      order.forEach((href) => {
        const link = linkMap.get(href);
        if (link) {
          ordered.push(link);
          linkMap.delete(href);
        }
      });
      links.forEach((link) => {
        if (linkMap.has(link.getAttribute("href"))) ordered.push(link);
      });
      ordered.forEach((link) => navLinks.appendChild(link));
    };

    const localComplete = getOnboardingCompleted();
    reorderLinks(orderFor(localComplete));

    const result = await getSetupCompletion();
    if (result && result.source === "server" && result.complete !== localComplete) {
      reorderLinks(orderFor(result.complete));
    }
  }

  async function fetchSettingsEnvironments() {
    const data = await fetchJson(`${BASE}/settings/environments`);
    if (data && Array.isArray(data)) return data;
    return [];
  }

  async function saveSettingsEnvironment(payload) {
    return requestJson(`${BASE}/settings/environments`, { method: "POST", body: payload });
  }

  async function fetchControlUpstream() {
    return requestJsonWithStatus(`${CONTROL_BASE}/control/upstream`, { auth: true });
  }

  async function saveControlUpstream(payload) {
    return requestJsonWithStatus(`${CONTROL_BASE}/control/upstream`, {
      method: "PUT",
      body: payload,
      auth: true,
    });
  }

  async function testControlUpstream() {
    return requestJsonWithStatus(`${CONTROL_BASE}/control/upstream/test`, {
      method: "POST",
      auth: true,
    });
  }

  async function fetchControlPolicyProfile() {
    return requestJsonWithStatus(`${CONTROL_BASE}/control/policy-profile`, { auth: true });
  }

  async function saveControlPolicyProfile(payload) {
    return requestJsonWithStatus(`${CONTROL_BASE}/control/policy-profile`, {
      method: "PUT",
      body: payload,
      auth: true,
    });
  }

  async function fetchPolicyProfilePresets() {
    return requestJsonWithStatus(`${CONTROL_BASE}/control/policy-profile/presets`, { auth: true });
  }

  async function previewPolicyProfile(payload) {
    return requestJsonWithStatus(`${CONTROL_BASE}/control/policy-profile/preview`, {
      method: "POST",
      body: payload,
      auth: true,
    });
  }

  async function issueControlToken(payload) {
    return requestJsonWithStatus(`${CONTROL_BASE}/control/tokens`, {
      method: "POST",
      body: payload,
      auth: true,
    });
  }

  async function listControlTokens() {
    return requestJsonWithStatus(`${CONTROL_BASE}/control/tokens`, { auth: true });
  }

  async function revokeControlToken(tokenId) {
    if (tokenId === undefined || tokenId === null) return null;
    return requestJsonWithStatus(`${CONTROL_BASE}/control/tokens/${encodeURIComponent(tokenId)}/revoke`, {
      method: "POST",
      auth: true,
    });
  }

  async function fetchControlAudit(limit) {
    const query = limit ? `?limit=${encodeURIComponent(limit)}` : "";
    const res = await requestJsonWithStatus(`${CONTROL_BASE}/control/audit${query}`, { auth: true });
    if (res && res.ok && Array.isArray(res.data) && res.data.length > 0) return res;
    // Mock fallback: return audit_log from mock_data.js when API fails or returns empty
    if (!DISABLE_MOCK && window.suiteScanData && Array.isArray(window.suiteScanData.audit_log)) {
      const mockData = limit ? window.suiteScanData.audit_log.slice(0, limit) : window.suiteScanData.audit_log;
      return { ok: true, data: mockData, status: 200 };
    }
    return res;
  }

  async function fetchControlDiagnostics() {
    return requestJsonWithStatus(`${CONTROL_BASE}/control/diagnostics`, { auth: true, timeoutMs: 8000 });
  }

  // --- Billing API (P2) ---

  async function fetchBillingTenant() {
    return requestJsonWithStatus(`${CONTROL_BASE}/billing/tenant`, { auth: true });
  }

  async function createBillingTenant(payload) {
    return requestJsonWithStatus(`${CONTROL_BASE}/billing/tenant`, {
      method: "POST",
      body: payload,
      auth: true,
    });
  }

  async function fetchBillingSubscription() {
    return requestJsonWithStatus(`${CONTROL_BASE}/billing/subscription`, { auth: true });
  }

  async function createCheckoutSession(payload) {
    return requestJsonWithStatus(`${CONTROL_BASE}/stripe/create-checkout-session`, {
      method: "POST",
      body: payload,
      auth: true,
    });
  }

  // --- Web Sandbox API ---

  async function scanWebSandbox(url) {
    const res = await requestJsonWithStatus(`${BASE}/web-sandbox/scan`, {
      method: "POST",
      body: { url },
    });
    if (res.ok) return res.data;
    throw new Error(
      res.status === 0
        ? "Gateway unreachable"
        : `Scan failed (HTTP ${res.status})`
    );
  }

  async function fetchWebSandboxArtifact(bundleId) {
    return fetchJson(`${BASE}/web-sandbox/artifacts/${encodeURIComponent(bundleId)}`);
  }

  async function fetchWebSandboxVerdicts() {
    const data = await fetchJson(`${BASE}/web-sandbox/verdicts`);
    const liveVerdicts = (data && typeof data === "object" && Array.isArray(data.verdicts)) ? data.verdicts : [];
    // Merge live verdicts with mock verdicts for demo richness
    if (!DISABLE_MOCK && window.suiteScanData && window.suiteScanData.web_sandbox_verdicts) {
      const mockVerdicts = window.suiteScanData.web_sandbox_verdicts.verdicts || [];
      // Combine: live first, then mock (avoid duplicates by run_id)
      const seenIds = new Set(liveVerdicts.map(v => v.run_id));
      const merged = [...liveVerdicts, ...mockVerdicts.filter(v => !seenIds.has(v.run_id))];
      return { verdicts: merged };
    }
    return { verdicts: liveVerdicts };
  }

  function isMockEnabled() {
    return ENABLE_MOCK;
  }

  function isSaasMode() {
    return SAAS_MODE;
  }

  window.apiClient = {
    fetchScans,
    fetchScanDetail,
    fetchAllowlist,
    fetchAllowlistStatus,
    fetchMcpDetail,
    fetchMcpHistory,
    fetchDashboardSummary,
    fetchSettingsEnvironments,
    saveSettingsEnvironment,
    fetchControlUpstream,
    saveControlUpstream,
    testControlUpstream,
    fetchControlPolicyProfile,
    saveControlPolicyProfile,
    fetchPolicyProfilePresets,
    previewPolicyProfile,
    issueControlToken,
    listControlTokens,
    revokeControlToken,
    fetchControlAudit,
    fetchControlDiagnostics,
    createControlSession,
    enableDangerMode,
    disableDangerMode,
    getDangerModeState,
    getAdminToken,
    setAdminToken,
    isMockEnabled,
    isSaasMode,
    // Billing API (P2)
    fetchBillingTenant,
    createBillingTenant,
    fetchBillingSubscription,
    createCheckoutSession,
    // Web Sandbox API
    scanWebSandbox,
    fetchWebSandboxArtifact,
    fetchWebSandboxVerdicts,
  };

  function injectOnboardingCard() {
    if (typeof document === "undefined") return;
    if (document.getElementById("onboarding-card")) return;
    const onboardingRoot = document.querySelector('[data-onboarding-root="true"]');
    if (!onboardingRoot) return;
    const container = onboardingRoot;
    if (!container) return;
    const anchor =
      container.querySelector(".page-header") ||
      container.querySelector(".header") ||
      container.querySelector("h1");
    const card = document.createElement("section");
    const storage = getStorage();
    const isCollapsed = storage ? storage.getItem(ONBOARDING_COLLAPSED_KEY) === "1" : false;
    const currentLang = (function () {
      try { return storage ? storage.getItem('suite_language') || 'en' : 'en'; } catch (e) { return 'en'; }
    })();
    const I18N = window.I18N || {};
    const dict = I18N[currentLang] || I18N.ja || {};
    const onb = dict.onboarding || {};
    card.id = "onboarding-card";
    card.className = "onboarding-card";
    card.innerHTML = `
      <button class="onboarding-tab" type="button" aria-expanded="${!isCollapsed}" aria-controls="onboarding-content" data-i18n="onboarding.toggleShow">
        ${isCollapsed ? (onb.toggleShow || "Show Guide") : (onb.toggleHide || "Hide Guide")}
      </button>
      <div class="onboarding-content" id="onboarding-content">
        <div class="onboarding-head">
          <div>
            <div class="onboarding-title" data-i18n="onboarding.title">Getting Started Guide</div>
            <div class="onboarding-subtitle" data-i18n="onboarding.subtitle">
              MCP Gateway is an LLM hub. Clients only use the Gateway URL; upstream LLM switching and policies are centrally managed here.
            </div>
          </div>
          <div class="onboarding-badge" data-i18n="onboarding.badge">Initial Setup</div>
        </div>
        <ol class="onboarding-steps">
          <li class="onboarding-step">
            <span class="onboarding-step-index">1</span>
            <span data-i18n="onboarding.step1">Receive Admin Token from administrator and verify setup permissions.</span>
          </li>
          <li class="onboarding-step">
            <span class="onboarding-step-index">2</span>
            <span data-i18n="onboarding.step2">Save upstream LLM Base URL and API Key in Environments, then verify with Save &amp; Test.</span>
          </li>
          <li class="onboarding-step">
            <span class="onboarding-step-index">3</span>
            <span data-i18n="onboarding.step3">Issue a token in the Gateway Connection Wizard and paste the displayed settings into your client.</span>
          </li>
        </ol>
        <div class="onboarding-actions">
          <a class="onboarding-link" href="settings_environments.html" data-i18n="onboarding.linkEnv">Environments</a>
          <a class="onboarding-link" href="dashboard.html" data-i18n="onboarding.linkDashboard">Dashboard</a>
          <a class="onboarding-link" href="audit_log.html" data-i18n="onboarding.linkAudit">Audit Log</a>
        </div>
        <div class="onboarding-note" data-i18n="onboarding.note">Tip: Even when switching upstream LLMs, clients keep the same URL and tokens.</div>
      </div>
    `;
    if (isCollapsed) {
      card.classList.add("is-collapsed");
    }
    if (anchor && anchor.parentNode) {
      anchor.parentNode.insertBefore(card, anchor.nextSibling);
    } else {
      container.insertBefore(card, container.firstChild);
    }
    const toggle = card.querySelector(".onboarding-tab");
    if (toggle) {
      toggle.addEventListener("click", () => {
        const collapsed = card.classList.toggle("is-collapsed");
        toggle.setAttribute("aria-expanded", String(!collapsed));
        const lang = (function () {
          try { return window.localStorage ? window.localStorage.getItem('suite_language') || 'en' : 'en'; } catch (e) { return 'en'; }
        })();
        const I18N = window.I18N || {};
        const dict = I18N[lang] || I18N.ja || {};
        const onb = dict.onboarding || {};
        toggle.textContent = collapsed ? (onb.toggleShow || "Show Guide") : (onb.toggleHide || "Hide Guide");
        if (storage) {
          storage.setItem(ONBOARDING_COLLAPSED_KEY, collapsed ? "1" : "0");
        }
      });
    }

    if (!document.getElementById("onboarding-style")) {
      const style = document.createElement("style");
      style.id = "onboarding-style";
      style.textContent = `
        .onboarding-card {
          margin: 16px 0 20px;
          background: #fff;
          border: 1px solid var(--gray-200, #e5e7eb);
          border-radius: 12px;
          padding: 16px 18px;
          box-shadow: var(--shadow-sm, 0 1px 2px 0 rgb(0 0 0 / 0.05));
          display: grid;
          gap: 12px;
        }
        .onboarding-card.is-collapsed {
          padding: 10px 12px;
        }
        .onboarding-card.is-collapsed .onboarding-content {
          display: none;
        }
        .onboarding-tab {
          justify-self: end;
          background: var(--primary, #0066ff);
          color: #fff;
          border: 1px solid var(--primary-dark, #0052cc);
          border-radius: 999px;
          padding: 6px 12px;
          font-size: 11px;
          font-weight: 700;
          letter-spacing: 0.2px;
          cursor: pointer;
          box-shadow: var(--shadow-sm, 0 1px 2px 0 rgb(0 0 0 / 0.05));
        }
        .onboarding-tab:hover {
          background: var(--primary-dark, #0052cc);
        }
        .onboarding-tab:focus-visible {
          outline: 2px solid #93c5fd;
          outline-offset: 2px;
        }
        .onboarding-content {
          display: grid;
          gap: 12px;
        }
        .onboarding-head {
          display: flex;
          justify-content: space-between;
          gap: 12px;
          flex-wrap: wrap;
        }
        .onboarding-title {
          font-size: 16px;
          font-weight: 700;
          color: var(--gray-900, #111827);
        }
        .onboarding-subtitle {
          font-size: 13px;
          color: var(--gray-600, #4b5563);
          margin-top: 4px;
          max-width: 720px;
        }
        .onboarding-badge {
          align-self: flex-start;
          background: #eef2ff;
          color: #3730a3;
          border: 1px solid #c7d2fe;
          border-radius: 999px;
          padding: 4px 8px;
          font-size: 11px;
          font-weight: 700;
          letter-spacing: 0.2px;
        }
        .onboarding-steps {
          list-style: none;
          display: grid;
          gap: 8px;
          margin: 0;
          padding: 0;
        }
        .onboarding-step {
          display: grid;
          grid-template-columns: 24px 1fr;
          gap: 10px;
          font-size: 13px;
          color: var(--gray-700, #374151);
          line-height: 1.5;
        }
        .onboarding-step-index {
          width: 24px;
          height: 24px;
          border-radius: 999px;
          background: var(--primary, #0066ff);
          color: #fff;
          font-weight: 700;
          font-size: 12px;
          display: inline-flex;
          align-items: center;
          justify-content: center;
        }
        .onboarding-actions {
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }
        .onboarding-link {
          text-decoration: none;
          font-size: 12px;
          font-weight: 600;
          color: #1d4ed8;
          background: #eff6ff;
          border: 1px solid #bfdbfe;
          border-radius: 999px;
          padding: 6px 10px;
        }
        .onboarding-link:hover {
          background: #dbeafe;
        }
        .onboarding-note {
          font-size: 12px;
          color: var(--gray-600, #4b5563);
        }
      `;
      document.head.appendChild(style);
    }

    // Apply i18n to injected onboarding card
    if (typeof window.applyI18n === 'function') {
      const lang = (function () {
        try { return storage ? storage.getItem('suite_language') || 'en' : 'en'; } catch (e) { return 'en'; }
      })();
      window.applyI18n(lang);
    }
  }

  if (typeof document !== "undefined") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", injectOnboardingCard);
    } else {
      injectOnboardingCard();
    }
  }

  // Common I18N for all pages
  const LANG_KEY = "suite_language";
  let runtimeLang = "en";

	  const CommonI18N = {
	    en: {
	      dashboard: {
	        title: "Policy Dashboard",
	        subtitle: "AllowList / Shadow Audit / Scan / Council status and policy control overview",
	        errorLoad: "Failed to load dashboard data. Please establish an admin session.",
	        shadowUnavailable: "Data unavailable",
	        severityTitle: "Severity Breakdown",
	        severitySubtitle: "Breakdown by severity of detected issues",
	        severityCritical: "Critical",
	        severityHigh: "High",
	        severityMedium: "Medium",
	        severityLow: "Low"
	      },
      allowlist: {
        title: "AllowList",
        subtitle: "List of approved MCP servers (read-only).",
        statusSummary: "AllowList health summary (read-only)",
        detailsLink: "View details",
        statusUnavailable: "Could not retrieve status",
        noEntries: "No allowlist entries"
      },
      scans: {
        title: "Security Scans",
        subtitle: "View and analyze MCP Gateway security scan results",
        statTotal: "Total Scans",
        statPassed: "Passed",
        statFailed: "Failed",
        statCritical: "Critical Issues",
        filterStatus: "Status",
        filterEnv: "Environment",
        filterStatusAll: "All Status",
        filterStatusPassed: "Passed",
        filterStatusFailed: "Failed",
        filterEnvPlaceholder: "Search environment...",
        tableTimestamp: "Timestamp",
        tableEnvironment: "Environment",
        tableActor: "Actor",
        tableStatus: "Status",
        tableSeverity: "Severity",
        tableOwasp: "OWASP LLM",
        tableProfile: "Profile",
        tableActions: "Actions",
        actionViewDetails: "View Details"
      },
      billing: {
        title: "Billing & Subscription",
        subtitle: "Manage your subscription, payment method, and billing history",
        currentPlan: "Current Plan",
        planFree: "Free",
        planStarter: "Starter",
        planTeam: "Team",
        planEnterprise: "Enterprise",
        seats: "Seats",
        seatsUsed: "used",
        seatsLimit: "limit",
        status: "Status",
        statusActive: "Active",
        statusTrialing: "Trial",
        statusPastDue: "Past Due",
        statusCanceled: "Canceled",
        statusUnpaid: "Unpaid",
        periodEnd: "Current Period Ends",
        trialEnd: "Trial Ends",
        upgradePlan: "Upgrade Plan",
        manageBilling: "Manage Billing",
        noSubscription: "No active subscription",
        selectPlan: "Select a Plan",
        planFeatureBasic: "Basic features",
        planFeatureFull: "Full features",
        planFeaturePriority: "Priority support",
        planFeatureSla: "SLA guarantee",
        subscribe: "Subscribe",
        loadingSubscription: "Loading subscription...",
        errorLoad: "Failed to load billing data"
      },
	      auditLog: {
	        title: "Audit Log",
	        subtitle: "Audit log of operations and decisions (read-only)",
        typeLabel: "Type",
        typeTitle: "Event type: upstream config, token issue/revoke, environment, Proxy/MCP block",
        typeFilterTitle: "Filter audit log by event type",
        actorLabel: "Actor",
        actorTitle: "User/system that performed the operation",
        actorPlaceholder: "admin / service-account...",
        actorFilterTitle: "Search by actor name",
	        adminTokenLabel: "Admin Session",
	        adminTokenPlaceholder: "Paste Admin Token to start session",
	        adminTokenTitle: "Establish an admin session to access control plane logs",
	        adminTokenHint: "Environments → Start session",
	        adminTokenHintLink: "Environments",
	        emptyDefault: "No audit logs.",
	        emptyNoToken: "Please establish an admin session."
	      },
	      common: {
	        gatewayOnline: "Gateway Online",
	        gatewayOfflineTitle: "Gateway unreachable",
	        gatewayOfflineBody: "Start the gateway, then reload this page.",
	        gatewayOfflineFileBody: "This page is opened via file://. Open via HTTP (http://localhost:4100/...) to access the API.",
	        gatewayOfflineHint: "Run from the mcp-gateway-release repo root.",
	        gatewayOfflineStart: "Start (one command)",
	        gatewayOfflineAutostart: "Autostart (recommended)",
	        gatewayOfflineCopy: "Copy",
	        gatewayOfflineCopied: "Copied",
	        gatewayOfflineReload: "Reload",
	        adminSessionRequiredTitle: "Admin session required",
        adminSessionRequiredBody: "Go to Environments, paste the Admin Token, and click Start Session (not stored by default).",
        adminSessionRequiredCta: "Open Environments",
        dangerModeTitle: "Danger Zone (not recommended): Admin Token storage",
        dangerModeSession: "Not stored (short-lived session recommended)",
        dangerModeLocal: "Store persistently (dangerous: requires explicit consent)",
        dangerModeExpiresIn: "Expires in",
        dangerModeUntilClose: "Expires when the browser closes",
        dangerModeDisable: "Disable",
	        policyBundlePresentPresent: "Policy bundle: Present",
	        policyBundlePresentMissing: "Policy bundle: Missing",
	        policyBundlePresentNA: "Policy bundle: N/A",
	        policyBundleSignatureVerified: "Signature: Verified",
	        policyBundleSignatureNotVerified: "Signature: Not verified",
	        policyBundleSignatureInvalid: "Signature: Invalid",
	        policyBundleSignatureNA: "Signature: N/A",
	        shadowChainOk: "Shadow Audit chain: OK",
	        shadowChainNg: "Shadow Audit chain: NG",
	        shadowChainNA: "Shadow Audit chain: N/A"
	      }
	    },
	    ja: {
	      dashboard: {
	        title: "Policy Dashboard",
	        subtitle: "AllowList / Shadow Audit / Scan / Council ステータスと政策制御概要",
	        errorLoad: "ダッシュボードデータの読み込みに失敗しました。管理者セッションを確立してください。",
	        shadowUnavailable: "データを取得できません",
	        severityTitle: "深刻度別内訳",
	        severitySubtitle: "検出された問題の深刻度別内訳",
	        severityCritical: "クリティカル",
	        severityHigh: "高",
	        severityMedium: "中",
	        severityLow: "低"
	      },
      allowlist: {
        title: "AllowList",
        subtitle: "許可済み MCP サーバの一覧（読み取り専用）。",
        statusSummary: "AllowList 健全性のサマリ（読み取り専用）",
        detailsLink: "詳細を開く",
        statusUnavailable: "ステータスを取得できませんでした",
        noEntries: "No allowlist entries"
      },
      scans: {
        title: "Security Scans",
        subtitle: "MCP Gateway のセキュリティスキャン結果を表示・分析します",
        statTotal: "総スキャン数",
        statPassed: "合格",
        statFailed: "失敗",
        statCritical: "重大問題",
        filterStatus: "ステータス",
        filterEnv: "環境",
        filterStatusAll: "すべて",
        filterStatusPassed: "合格",
        filterStatusFailed: "失敗",
        filterEnvPlaceholder: "環境を検索...",
        tableTimestamp: "時刻",
        tableEnvironment: "環境",
        tableActor: "実行者",
        tableStatus: "ステータス",
        tableSeverity: "深刻度",
        tableOwasp: "OWASP LLM",
        tableProfile: "プロファイル",
        tableActions: "操作",
        actionViewDetails: "詳細を開く"
      },
      billing: {
        title: "課金・サブスクリプション",
        subtitle: "サブスクリプション、支払い方法、請求履歴を管理",
        currentPlan: "現在のプラン",
        planFree: "Free",
        planStarter: "Starter",
        planTeam: "Team",
        planEnterprise: "Enterprise",
        seats: "席数",
        seatsUsed: "使用中",
        seatsLimit: "上限",
        status: "ステータス",
        statusActive: "有効",
        statusTrialing: "トライアル",
        statusPastDue: "支払い遅延",
        statusCanceled: "キャンセル済み",
        statusUnpaid: "未払い",
        periodEnd: "現在の期間終了日",
        trialEnd: "トライアル終了日",
        upgradePlan: "プランをアップグレード",
        manageBilling: "請求管理",
        noSubscription: "有効なサブスクリプションがありません",
        selectPlan: "プランを選択",
        planFeatureBasic: "基本機能",
        planFeatureFull: "全機能",
        planFeaturePriority: "優先サポート",
        planFeatureSla: "SLA保証",
        subscribe: "購読する",
        loadingSubscription: "サブスクリプション読み込み中...",
        errorLoad: "課金データの読み込みに失敗しました"
      },
	      auditLog: {
	        title: "Audit Log",
	        subtitle: "操作と判定の監査ログ（read-only）",
        typeLabel: "Type",
        typeTitle: "イベントタイプ: 上流設定、トークン発行・失効、環境、Proxy/MCP ブロック",
        typeFilterTitle: "監査ログのイベントタイプで絞り込む",
        actorLabel: "Actor",
        actorTitle: "操作を実施したユーザー/システム",
        actorPlaceholder: "admin / service-account...",
        actorFilterTitle: "操作者名で検索",
	        adminTokenLabel: "管理者セッション",
	        adminTokenPlaceholder: "Admin Token を貼り付けてセッション開始",
	        adminTokenTitle: "Control Plane にアクセスするには管理者セッションが必要です",
	        adminTokenHint: "環境設定 → セッション開始",
	        adminTokenHintLink: "環境設定",
	        emptyDefault: "監査ログはありません。",
	        emptyNoToken: "管理者セッションを確立してください。"
	      },
	      common: {
	        gatewayOnline: "Gateway Online",
	        gatewayOfflineTitle: "Gateway に接続できません",
	        gatewayOfflineBody: "Gateway を起動してから、このページを再読み込みしてください。",
	        gatewayOfflineFileBody: "file:// で開いているため API に接続できません。HTTP（http://localhost:4100/...）で開いてください。",
	        gatewayOfflineHint: "mcp-gateway-release リポジトリ直下で実行してください。",
	        gatewayOfflineStart: "起動（1コマンド）",
	        gatewayOfflineAutostart: "常駐化（推奨）",
	        gatewayOfflineCopy: "コピー",
	        gatewayOfflineCopied: "コピーしました",
	        gatewayOfflineReload: "再読み込み",
	        adminSessionRequiredTitle: "管理者セッションが必要です",
        adminSessionRequiredBody: "Environments で Admin Token を貼り付けて「セッション開始」を実行してください（既定で保存しません）。",
        adminSessionRequiredCta: "Environments を開く",
        dangerModeTitle: "Danger Zone（非推奨）: Admin Token の保存設定",
        dangerModeSession: "保存しない（短命セッション推奨）",
        dangerModeLocal: "ブラウザに保存（危険: 明示同意が必要）",
        dangerModeExpiresIn: "残り",
        dangerModeUntilClose: "有効期限: ブラウザを閉じるまで",
        dangerModeDisable: "無効化",
	        policyBundlePresentPresent: "ポリシーバンドル: あり",
	        policyBundlePresentMissing: "ポリシーバンドル: 不在",
	        policyBundlePresentNA: "ポリシーバンドル: N/A",
	        policyBundleSignatureVerified: "署名: 検証済み",
	        policyBundleSignatureNotVerified: "署名: 未検証",
	        policyBundleSignatureInvalid: "署名: 無効",
	        policyBundleSignatureNA: "署名: N/A",
	        shadowChainOk: "監査チェーン（Shadow Audit）: OK",
	        shadowChainNg: "監査チェーン（Shadow Audit）: NG",
	        shadowChainNA: "監査チェーン（Shadow Audit）: N/A"
	      }
	    }
	  };

  function getLanguage() {
    const storage = getStorage();
    try {
      const stored = storage ? storage.getItem(LANG_KEY) : null;
      if (stored) {
        runtimeLang = stored;
        return stored;
      }
    } catch (e) {
    }
    return runtimeLang || "en";
  }

	  function setLanguage(lang) {
	    const next = lang === "en" ? "en" : "ja";
	    runtimeLang = next;
	    const storage = getStorage();
	    try {
	      if (storage) storage.setItem(LANG_KEY, next);
	    } catch (e) { }
	    if (typeof document !== 'undefined' && document.documentElement) {
	      document.documentElement.lang = next;
	    }
	    updateDangerBanner();
	    updateAdminSessionBanner();
	  }

	  function updateDangerBanner() {
	    if (typeof document === "undefined") return;
	    const state = getDangerModeState();
	    const existing = document.getElementById("danger-mode-banner");
	    if (!state) {
	      if (existing) existing.remove();
	      return;
	    }
	    const storageLabel =
	      state.storageType === "local" ? tCommon("common.dangerModeLocal") : tCommon("common.dangerModeSession");
	    const expiresText =
	      state.expiresAt === null
	        ? tCommon("common.dangerModeUntilClose")
	        : `${tCommon("common.dangerModeExpiresIn")} ${formatTimeRemaining(state.expiresAt - Date.now())}`;
	    const html = `
	      <div class="danger-banner-inner">
	        <div class="danger-banner-text">
	          <div class="danger-banner-title">${tCommon("common.dangerModeTitle")}</div>
	          <div class="danger-banner-meta">${storageLabel} · ${expiresText}</div>
	        </div>
	        <button type="button" class="danger-banner-btn" id="danger-mode-disable">${tCommon("common.dangerModeDisable")}</button>
	      </div>
	    `;
	    const banner = existing || document.createElement("div");
	    banner.id = "danger-mode-banner";
	    banner.className = "danger-banner";
	    banner.innerHTML = html;
	    if (!existing) {
	      const root = document.body || document.documentElement;
	      root.insertBefore(banner, root.firstChild);
	      if (!document.getElementById("danger-banner-style")) {
	        const style = document.createElement("style");
	        style.id = "danger-banner-style";
	        style.textContent = `
	          .danger-banner{background:#7f1d1d;color:#fff;padding:10px 14px;border-bottom:1px solid #991b1b;}
	          .danger-banner-inner{display:flex;gap:12px;align-items:center;justify-content:space-between;max-width:1200px;margin:0 auto;}
	          .danger-banner-title{font-weight:800;font-size:12px;letter-spacing:0.2px;text-transform:uppercase;}
	          .danger-banner-meta{font-size:12px;opacity:0.95;}
	          .danger-banner-btn{background:#fff;color:#7f1d1d;border:1px solid #fecaca;border-radius:8px;padding:6px 10px;font-weight:800;font-size:12px;cursor:pointer;}
	          .danger-banner-btn:hover{background:#fee2e2;}
	        `;
	        document.head.appendChild(style);
	      }
	    }
	    const btn = banner.querySelector("#danger-mode-disable");
	    if (btn && !btn.dataset.bound) {
	      btn.dataset.bound = "1";
	      btn.addEventListener("click", () => {
	        disableDangerMode();
	        updateDangerBanner();
	      });
	    }
	  }

	  function tickBanners() {
	    updateDangerBanner();
	    updateAdminSessionBanner();
	    updateGatewayOfflineBanner();
	  }

	  async function copyToClipboard(text) {
	    try {
	      if (typeof navigator !== "undefined" && navigator.clipboard && navigator.clipboard.writeText) {
	        await navigator.clipboard.writeText(text);
	        return true;
	      }
	    } catch (e) {}

	    try {
	      if (typeof document === "undefined") return false;
	      const ta = document.createElement("textarea");
	      ta.value = text;
	      ta.style.position = "fixed";
	      ta.style.top = "-1000px";
	      ta.style.left = "-1000px";
	      document.body.appendChild(ta);
	      ta.focus();
	      ta.select();
	      const ok = document.execCommand && document.execCommand("copy");
	      ta.remove();
	      return !!ok;
	    } catch (e) {
	      return false;
	    }
	  }

	  function updateGatewayOfflineBanner() {
	    if (typeof document === "undefined") return;
	    const existing = document.getElementById("gateway-offline-banner");
	    if (!gatewayOffline) {
	      if (existing) existing.remove();
	      return;
	    }

	    const title = tCommon("common.gatewayOfflineTitle");
	    const body =
	      gatewayOfflineReason === "file"
	        ? tCommon("common.gatewayOfflineFileBody")
	        : tCommon("common.gatewayOfflineBody");
	    const hint = tCommon("common.gatewayOfflineHint");
	    const copyLabel = tCommon("common.gatewayOfflineCopy");
	    const copiedLabel = tCommon("common.gatewayOfflineCopied");
	    const reloadLabel = tCommon("common.gatewayOfflineReload");
	    const startLabel = tCommon("common.gatewayOfflineStart");
	    const autostartLabel = tCommon("common.gatewayOfflineAutostart");

	    const cmdUnix = "./scripts/step8_start_suite.sh";
	    const cmdWin = ".\\scripts\\step8_start_suite.ps1";
	    const cmdAutoWin = ".\\scripts\\step8_autostart_windows.ps1 -Action Install";
	    const cmdAutoMac = "./scripts/step8_autostart_macos.sh install";
	    const cmdAutoLinux = "./scripts/step8_autostart_linux.sh install";

	    const html = `
	      <div class="gateway-offline-banner-inner">
	        <div class="gateway-offline-banner-text">
	          <div class="gateway-offline-banner-title">${title}</div>
	          <div class="gateway-offline-banner-meta">${body}</div>
	          <div class="gateway-offline-banner-hint">${hint}</div>
	          <div class="gateway-offline-banner-section-title">${startLabel}</div>
	          <div class="gateway-offline-banner-cmd">
	            <code>${cmdUnix}</code>
	            <button type="button" class="gateway-offline-banner-btn" data-copy-text="${cmdUnix}">${copyLabel}</button>
	          </div>
	          <div class="gateway-offline-banner-cmd">
	            <code>${cmdWin}</code>
	            <button type="button" class="gateway-offline-banner-btn" data-copy-text="${cmdWin}">${copyLabel}</button>
	          </div>
	          <details class="gateway-offline-banner-details">
	            <summary>${autostartLabel}</summary>
	            <div class="gateway-offline-banner-cmd">
	              <code>${cmdAutoMac}</code>
	              <button type="button" class="gateway-offline-banner-btn" data-copy-text="${cmdAutoMac}">${copyLabel}</button>
	            </div>
	            <div class="gateway-offline-banner-cmd">
	              <code>${cmdAutoLinux}</code>
	              <button type="button" class="gateway-offline-banner-btn" data-copy-text="${cmdAutoLinux}">${copyLabel}</button>
	            </div>
	            <div class="gateway-offline-banner-cmd">
	              <code>${cmdAutoWin}</code>
	              <button type="button" class="gateway-offline-banner-btn" data-copy-text="${cmdAutoWin}">${copyLabel}</button>
	            </div>
	          </details>
	        </div>
	        <button type="button" class="gateway-offline-banner-reload" id="gateway-offline-reload">${reloadLabel}</button>
	      </div>
	    `;

	    const banner = existing || document.createElement("div");
	    banner.id = "gateway-offline-banner";
	    banner.className = "gateway-offline-banner";
	    banner.innerHTML = html;

	    if (!existing) {
	      if (!document.getElementById("gateway-offline-banner-style") && document.head) {
	        const style = document.createElement("style");
	        style.id = "gateway-offline-banner-style";
	        style.textContent = `
	          .gateway-offline-banner{background:#fffbeb;color:#92400e;padding:12px 14px;border-bottom:1px solid #fcd34d;}
	          .gateway-offline-banner-inner{display:flex;gap:12px;align-items:flex-start;justify-content:space-between;max-width:1200px;margin:0 auto;}
	          .gateway-offline-banner-title{font-weight:900;font-size:12px;letter-spacing:0.2px;text-transform:uppercase;}
	          .gateway-offline-banner-meta{font-size:12px;line-height:1.4;margin-top:2px;}
	          .gateway-offline-banner-hint{font-size:12px;opacity:0.9;margin-top:4px;}
	          .gateway-offline-banner-section-title{margin-top:10px;font-weight:800;font-size:12px;}
	          .gateway-offline-banner-cmd{display:flex;gap:8px;align-items:center;margin-top:6px;flex-wrap:wrap;}
	          .gateway-offline-banner-cmd code{background:#fff;border:1px solid #fcd34d;border-radius:8px;padding:6px 8px;font-size:12px;white-space:nowrap;}
	          .gateway-offline-banner-btn{background:#fff;color:#92400e;border:1px solid #fcd34d;border-radius:8px;padding:6px 10px;font-weight:800;font-size:12px;cursor:pointer;}
	          .gateway-offline-banner-btn:hover{background:#fef3c7;}
	          .gateway-offline-banner-reload{background:#92400e;color:#fff;border:1px solid #fcd34d;border-radius:10px;padding:8px 12px;font-weight:900;font-size:12px;cursor:pointer;white-space:nowrap;}
	          .gateway-offline-banner-reload:hover{filter:brightness(1.05);}
	          .gateway-offline-banner-details{margin-top:10px;}
	          .gateway-offline-banner-details summary{cursor:pointer;font-weight:800;font-size:12px;}
	          @media (max-width: 720px){
	            .gateway-offline-banner-inner{flex-direction:column;align-items:flex-start;}
	            .gateway-offline-banner-reload{align-self:flex-start;}
	          }
	        `;
	        document.head.appendChild(style);
	      }

	      const nav = document.querySelector(".nav");
	      if (nav && nav.parentNode) {
	        nav.parentNode.insertBefore(banner, nav.nextSibling);
	      } else {
	        const root = document.body || document.documentElement;
	        root.insertBefore(banner, root.firstChild);
	      }
	    }

	    const reloadBtn = banner.querySelector("#gateway-offline-reload");
	    if (reloadBtn && !reloadBtn.dataset.bound) {
	      reloadBtn.dataset.bound = "1";
	      reloadBtn.addEventListener("click", () => {
	        if (typeof window !== "undefined" && window.location && window.location.reload) {
	          window.location.reload();
	        }
	      });
	    }

	    banner.querySelectorAll("[data-copy-text]").forEach((btn) => {
	      if (btn.dataset.bound) return;
	      btn.dataset.bound = "1";
	      btn.dataset.defaultLabel = btn.textContent || copyLabel;
	      btn.addEventListener("click", async () => {
	        const text = btn.getAttribute("data-copy-text") || "";
	        if (!text) return;
	        const ok = await copyToClipboard(text);
	        if (!ok) return;
	        btn.textContent = copiedLabel;
	        setTimeout(() => {
	          btn.textContent = btn.dataset.defaultLabel || copyLabel;
	        }, 1200);
	      });
	    });
	  }

	  function updateAdminSessionBanner() {
	    if (typeof document === "undefined") return;
	    const existing = document.getElementById("admin-session-banner");
	    if (!adminSessionRequired) {
	      if (existing) existing.remove();
	      return;
	    }

	    const title = tCommon("common.adminSessionRequiredTitle");
	    const body = tCommon("common.adminSessionRequiredBody");
	    const cta = tCommon("common.adminSessionRequiredCta");
	    const href = "settings_environments.html#adminToken";
	    const anchor = document.querySelector("[data-admin-session-banner-anchor]");
	    const variantClass = anchor ? "admin-session-banner--inline" : "admin-session-banner--top";

	    const html = `
	      <div class="admin-session-banner-inner">
	        <div class="admin-session-banner-text">
	          <div class="admin-session-banner-title">${title}</div>
	          <div class="admin-session-banner-meta">${body}</div>
	        </div>
	        <a class="admin-session-banner-btn" href="${href}">${cta}</a>
	      </div>
	    `;

	    const banner = existing || document.createElement("div");
	    banner.id = "admin-session-banner";
	    banner.className = `admin-session-banner ${variantClass}`;
	    banner.innerHTML = html;
	    if (!existing) {
	      if (!document.getElementById("admin-session-banner-style") && document.head) {
	        const style = document.createElement("style");
	        style.id = "admin-session-banner-style";
	        style.textContent = `
	          .admin-session-banner{background:#fee2e2;color:#7f1d1d;padding:10px 14px;}
	          .admin-session-banner--top{border-bottom:1px solid #fca5a5;}
	          .admin-session-banner--inline{border:1px solid #fca5a5;border-radius:999px;margin-top:6px;padding:6px 10px;display:inline-flex;align-items:center;background:#fecaca;}
	          .admin-session-banner-inner{display:flex;gap:12px;align-items:flex-start;justify-content:space-between;}
	          .admin-session-banner--top .admin-session-banner-inner{align-items:center;max-width:1200px;margin:0 auto;}
	          .admin-session-banner--inline .admin-session-banner-inner{align-items:center;gap:8px;}
	          .admin-session-banner-title{font-weight:800;font-size:12px;letter-spacing:0.2px;text-transform:uppercase;}
	          .admin-session-banner-meta{font-size:12px;opacity:0.95;line-height:1.35;}
	          .admin-session-banner-btn{background:#b91c1c;color:#fff;border:1px solid #fecaca;border-radius:8px;padding:6px 10px;font-weight:800;font-size:12px;text-decoration:none;white-space:nowrap;}
	          .admin-session-banner--inline .admin-session-banner-title{font-size:11px;}
	          .admin-session-banner--inline .admin-session-banner-meta{font-size:11px;}
	          .admin-session-banner--inline .admin-session-banner-btn{padding:4px 8px;font-size:11px;}
	          .admin-session-banner-btn:hover{filter:brightness(1.05);}
	          @media (max-width: 720px){
	            .admin-session-banner-inner{flex-direction:column;align-items:flex-start;}
	            .admin-session-banner-btn{align-self:flex-start;}
	          }
	        `;
	        document.head.appendChild(style);
	      }
	    }
	    if (anchor) {
	      if (banner.parentNode !== anchor) {
	        anchor.innerHTML = "";
	        anchor.appendChild(banner);
	      }
	    } else if (!existing) {
	      const root = document.body || document.documentElement;
	      const danger = document.getElementById("danger-mode-banner");
	      if (danger && danger.parentNode) {
	        danger.parentNode.insertBefore(banner, danger.nextSibling);
	      } else {
	        root.insertBefore(banner, root.firstChild);
	      }
	    }
	  }

  function tCommon(key) {
    const lang = getLanguage();
    const dict = CommonI18N[lang] || CommonI18N.ja;
    const keys = key.split('.');
    let val = dict;
    for (const k of keys) { val = val && val[k]; }
    return val || key;
  }

	  function applyCommonI18n() {
	    const lang = getLanguage();
	    const dict = CommonI18N[lang] || CommonI18N.ja;
	    if (typeof document !== 'undefined' && document.documentElement) {
	      document.documentElement.lang = lang;
	    }
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const keys = key.split('.');
      let val = dict;
      for (const k of keys) { val = val && val[k]; }
      if (val === undefined || val === null) val = '';
      el.textContent = val;
    });
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      const key = el.getAttribute('data-i18n-title');
      const keys = key.split('.');
      let val = dict;
      for (const k of keys) { val = val && val[k]; }
      if (val !== undefined && val !== null) el.setAttribute('title', val);
    });
	    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
	      const key = el.getAttribute('data-i18n-placeholder');
	      const keys = key.split('.');
	      let val = dict;
	      for (const k of keys) { val = val && val[k]; }
	      if (val !== undefined && val !== null) el.setAttribute('placeholder', val);
	    });
	    updateDangerBanner();
	    updateAdminSessionBanner();
	  }

  window.CommonI18N = CommonI18N;
  window.getLanguage = getLanguage;
  window.setLanguage = setLanguage;
  window.tCommon = tCommon;
  window.applyCommonI18n = applyCommonI18n;
  window.getSetupCompletion = getSetupCompletion;
  window.applyNavOrder = applyNavOrder;

	  if (typeof document !== "undefined") {
	    if (document.readyState === "loading") {
	      document.addEventListener("DOMContentLoaded", () => {
	        applyNavOrder();
	        updateDangerBanner();
	        updateAdminSessionBanner();
	        setInterval(tickBanners, 1000);
	      });
	    } else {
	      applyNavOrder();
	      updateDangerBanner();
	      updateAdminSessionBanner();
	      setInterval(tickBanners, 1000);
	    }
	  }

})();
