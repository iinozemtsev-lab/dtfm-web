// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

import {
  DEFAULT_RELAY_WS_URL,
  FRAME_AGENT_CONNECTED,
  FRAME_AGENT_DISCONNECTED,
  FRAME_DATA,
  FRAME_KEEPALIVE,
  FRAME_KICK_AGENT,
  RECORD_TYPE_DATA,
  RECORD_TYPE_EOF,
  ROLE_OPERATOR,
  buildOperatorAuthFrame,
  buildOperatorHandshake,
  decodeRelayFrame,
  deriveAuthTokens,
  deriveConnCipher,
  encodeRelayFrame,
  generateSessionID,
  generateSessionKey,
  handshakeKey,
  hexToBytes,
  utf8Decode,
  utf8Encode,
  verifyAgentHandshake,
} from "./e2ee.js";

const KEEPALIVE_INTERVAL_MS = 20_000;
const WS_CONNECT_TIMEOUT_MS = 10_000;
const RECONNECT_BASE_DELAY_MS = 1_000;
const RECONNECT_MAX_DELAY_MS = 5_000;
const RECONNECT_JITTER_FRACTION = 0.2;
const WATCHDOG_ALARM_NAME = "dtfm-web-keepalive-watchdog";
const WATCHDOG_PERIOD_MINUTES = 0.5;
const STORAGE_RELAY_URL_KEY = "dtfm_web_relay_url";
const STORAGE_SESSION_KEY = "dtfm_web_active_session";

const state = {
  active: false,
  connected: false,
  reconnecting: false,
  tabId: null,
  windowId: null,
  tabTitle: "",
  tabUrl: "",
  origin: null,
  originPattern: null,
  relayUrl: DEFAULT_RELAY_WS_URL,
  sessionID: null,
  keyHex: null,
  secretKey: null,
  hk: null,
  authFrame: null,
  ws: null,
  keepaliveTimer: null,
  connectTimer: null,
  reconnectTimer: null,
  reconnectAttempts: 0,
  connGen: 0,
  pendingFinish: null,
  activeAgent: null, // { connID: bigint, opNonce: Uint8Array|null, cipher: ConnCipher|null, chain: Promise }
  lastError: null,
};

let restoreInFlight = null;

/**
 * Classifies WebSocket close codes into permanent (no auto-reconnect) vs transient.
 * @param {number} code
 * @returns {boolean}
 */
export function isPermanentCloseCode(code) {
  return code === 1000 || code === 4000 || code === 4003;
}

/**
 * Computes jittered exponential backoff delay in milliseconds (1s -> 2s -> 4s -> cap 5s, +/-20% jitter).
 * @param {number} attempt
 * @param {() => number} [randomFn]
 * @returns {number}
 */
export function computeReconnectDelay(attempt, randomFn = Math.random) {
  const exp = Math.min(Math.max(0, attempt), 10);
  const base = Math.min(RECONNECT_MAX_DELAY_MS, RECONNECT_BASE_DELAY_MS * (2 ** exp));
  const jitterFactor = 1 + RECONNECT_JITTER_FRACTION * (2 * randomFn() - 1);
  return Math.round(base * jitterFactor);
}

function isLoopbackHostname(hostname) {
  const host = (hostname || "").toLowerCase();
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
}

function validateRelayUrl(rawUrl) {
  const normalized = (rawUrl || DEFAULT_RELAY_WS_URL).trim();
  const parsed = new URL(normalized);
  if (parsed.protocol === "wss:") {
    return normalized;
  }
  if (parsed.protocol === "ws:") {
    if (isLoopbackHostname(parsed.hostname)) {
      return normalized;
    }
    throw new Error("Unencrypted ws:// relay is only allowed for loopback hosts (localhost, 127.0.0.1, ::1); use wss://");
  }
  throw new Error("Relay URL must use wss:// (or ws:// for localhost)");
}

function isPinnedOrigin(tab) {
  if (!tab || typeof tab.url !== "string" || !state.origin) {
    return false;
  }
  try {
    return new URL(tab.url).origin === state.origin;
  } catch (_) {
    return false;
  }
}

async function revokeOriginPermission(originPattern) {
  if (!originPattern) return;
  try {
    await chrome.permissions.remove({ origins: [originPattern] });
  } catch (_) {
    // Permission may have already been revoked.
  }
}

async function loadSavedRelayUrl() {
  try {
    const data = await chrome.storage.local.get(STORAGE_RELAY_URL_KEY);
    if (typeof data[STORAGE_RELAY_URL_KEY] === "string" && data[STORAGE_RELAY_URL_KEY].trim()) {
      state.relayUrl = data[STORAGE_RELAY_URL_KEY].trim();
    }
  } catch (_) {
    // Ignore storage read errors.
  }
  return state.relayUrl;
}

async function saveRelayUrl(url) {
  state.relayUrl = url;
  try {
    await chrome.storage.local.set({ [STORAGE_RELAY_URL_KEY]: url });
  } catch (_) {
    // Ignore storage write errors.
  }
}

function getPublicState() {
  return {
    active: state.active,
    connected: state.connected,
    reconnecting: state.reconnecting,
    tabId: state.tabId,
    tabTitle: state.tabTitle,
    tabUrl: state.tabUrl,
    origin: state.origin,
    relayUrl: state.relayUrl,
    pairingToken: state.active && state.sessionID && state.keyHex ? `${state.sessionID}#${state.keyHex}` : null,
    lastError: state.lastError,
  };
}

async function setLiveBadge(tabId) {
  try {
    await chrome.action.setBadgeText({ text: "LIVE", tabId });
    await chrome.action.setBadgeBackgroundColor({ color: "#16a34a", tabId });
  } catch (_) {
    // Tab may have closed.
  }
}

async function setReconnectingBadge(tabId) {
  try {
    await chrome.action.setBadgeText({ text: "...", tabId });
    await chrome.action.setBadgeBackgroundColor({ color: "#d97706", tabId });
  } catch (_) {
    // Tab may have closed.
  }
}

async function clearLiveBadge(tabId) {
  try {
    if (typeof tabId === "number") {
      await chrome.action.setBadgeText({ text: "", tabId });
    }
    await chrome.action.setBadgeText({ text: "" });
  } catch (_) {
    // Ignore if tab no longer exists.
  }
}

async function saveSessionToStorage() {
  if (!chrome?.storage?.session || !state.active || !state.sessionID || !state.keyHex) {
    return;
  }
  try {
    await chrome.storage.session.set({
      [STORAGE_SESSION_KEY]: {
        tabId: state.tabId,
        windowId: state.windowId,
        tabTitle: state.tabTitle,
        tabUrl: state.tabUrl,
        origin: state.origin,
        originPattern: state.originPattern,
        relayUrl: state.relayUrl,
        sessionID: state.sessionID,
        keyHex: state.keyHex,
      },
    });
  } catch (_) {
    // Ignore session storage write errors.
  }
}

async function clearSessionStorage() {
  if (!chrome?.storage?.session) return;
  try {
    await chrome.storage.session.remove(STORAGE_SESSION_KEY);
  } catch (_) {
    // Ignore session storage remove errors.
  }
}

async function ensureWatchdogAlarm() {
  if (!chrome?.alarms) return;
  try {
    await chrome.alarms.create(WATCHDOG_ALARM_NAME, { periodInMinutes: WATCHDOG_PERIOD_MINUTES });
  } catch (_) {
    // Ignore alarm creation errors.
  }
}

async function clearWatchdogAlarm() {
  if (!chrome?.alarms) return;
  try {
    await chrome.alarms.clear(WATCHDOG_ALARM_NAME);
  } catch (_) {
    // Ignore alarm clear errors.
  }
}

async function stopSharingInternal(reason = null) {
  state.connGen += 1;
  const prevTabId = state.tabId;
  const prevOriginPattern = state.originPattern;
  const prevWs = state.ws;
  const prevFinish = state.pendingFinish;

  if (state.keepaliveTimer !== null) {
    clearInterval(state.keepaliveTimer);
    state.keepaliveTimer = null;
  }
  if (state.connectTimer !== null) {
    clearTimeout(state.connectTimer);
    state.connectTimer = null;
  }
  if (state.reconnectTimer !== null) {
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
  }

  state.ws = null;
  state.pendingFinish = null;
  state.active = false;
  state.connected = false;
  state.reconnecting = false;
  state.reconnectAttempts = 0;
  state.tabId = null;
  state.windowId = null;
  state.tabTitle = "";
  state.tabUrl = "";
  state.origin = null;
  state.originPattern = null;
  state.sessionID = null;
  state.keyHex = null;
  state.activeAgent = null;
  state.lastError = reason;

  if (state.secretKey) {
    state.secretKey.fill(0);
    state.secretKey = null;
  }
  if (state.hk) {
    state.hk.fill(0);
    state.hk = null;
  }
  if (state.authFrame) {
    state.authFrame.fill(0);
    state.authFrame = null;
  }

  if (prevWs) {
    prevWs.onopen = null;
    prevWs.onclose = null;
    prevWs.onerror = null;
    prevWs.onmessage = null;
    try {
      prevWs.close(1000, "operator stopped sharing");
    } catch (_) {
      // Ignore close errors.
    }
  }

  await clearSessionStorage();
  await clearWatchdogAlarm();
  await clearLiveBadge(prevTabId);
  await revokeOriginPermission(prevOriginPattern);

  if (prevFinish) {
    prevFinish();
  }
}

async function stopSharing(reason = null) {
  state.connGen += 1;
  if (restoreInFlight) {
    await restoreInFlight.catch(() => {});
  }
  await stopSharingInternal(reason);
}

function sendKickAgent(ws, connID) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(encodeRelayFrame(FRAME_KICK_AGENT, connID));
}

async function handleAgentRequest(req) {
  const id = typeof req?.id === "string" ? req.id : "";
  const cmd = typeof req?.cmd === "string" ? req.cmd : "";

  if (!state.active || typeof state.tabId !== "number") {
    return {
      id,
      ok: false,
      error_code: "ERR_TAB_CLOSED",
      error: "No tab is currently shared",
    };
  }

  let tab;
  try {
    tab = await chrome.tabs.get(state.tabId);
  } catch (_) {
    await stopSharing("Shared tab was closed");
    return {
      id,
      ok: false,
      error_code: "ERR_TAB_CLOSED",
      error: "Shared tab is no longer open",
    };
  }

  // Enforce strict single-origin pinning across all commands (status, dom, shot).
  if (!isPinnedOrigin(tab)) {
    return {
      id,
      ok: false,
      error_code: "ERR_PERMISSION_DENIED",
      error: `Shared tab navigated away from pinned origin (${state.origin})`,
    };
  }

  state.tabTitle = tab.title || "";
  state.tabUrl = tab.url || "";

  if (cmd === "status") {
    return {
      id,
      ok: true,
      tab: {
        id: tab.id,
        title: tab.title || "",
        url: tab.url || "",
        active: Boolean(tab.active),
        status: tab.status || "",
        origin: state.origin || "",
      },
    };
  }

  if (cmd === "shot") {
    // Fail-closed screenshot guard: verify shared tab is still the active tab in its window.
    if (tab.active !== true) {
      return {
        id,
        ok: false,
        error_code: "ERR_TAB_NOT_ACTIVE",
        error: "Shared tab is not active in its window; refusing to capture a non-shared tab",
      };
    }

    try {
      const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });

      // Post-capture TOCTOU check: ensure tab is still active and on the pinned origin.
      let postTab;
      try {
        postTab = await chrome.tabs.get(state.tabId);
      } catch (_) {
        await stopSharing("Shared tab was closed");
        return {
          id,
          ok: false,
          error_code: "ERR_TAB_CLOSED",
          error: "Shared tab closed during screenshot capture",
        };
      }
      if (!isPinnedOrigin(postTab)) {
        return {
          id,
          ok: false,
          error_code: "ERR_PERMISSION_DENIED",
          error: `Shared tab navigated away from pinned origin (${state.origin}) during capture`,
        };
      }
      if (postTab.active !== true) {
        return {
          id,
          ok: false,
          error_code: "ERR_TAB_NOT_ACTIVE",
          error: "Shared tab became inactive during capture; discarding screenshot",
        };
      }

      const prefix = "data:image/png;base64,";
      if (!dataUrl || !dataUrl.startsWith(prefix)) {
        return {
          id,
          ok: false,
          error_code: "ERR_INTERNAL",
          error: "Unexpected screenshot format from browser",
        };
      }
      return {
        id,
        ok: true,
        mime_type: "image/png",
        image_base64: dataUrl.slice(prefix.length),
      };
    } catch (err) {
      return {
        id,
        ok: false,
        error_code: "ERR_PERMISSION_DENIED",
        error: `Failed to capture screenshot: ${err.message}`,
      };
    }
  }

  if (cmd === "dom") {
    const format = req.format === "json" ? "json" : "md";

    try {
      await chrome.scripting.executeScript({
        target: { tabId: state.tabId },
        files: ["content.js"],
      });
      const results = await chrome.scripting.executeScript({
        target: { tabId: state.tabId },
        func: (fmt) => {
          if (typeof globalThis.__dtfmWebExtract !== "function") {
            throw new Error("extractor not initialized");
          }
          return globalThis.__dtfmWebExtract(fmt);
        },
        args: [format],
      });
      const extracted = results && results[0] ? results[0].result : null;
      if (!extracted) {
        return {
          id,
          ok: false,
          error_code: "ERR_INTERNAL",
          error: "DOM extractor returned empty result",
        };
      }
      if (extracted.format === "json") {
        return {
          id,
          ok: true,
          format: "json",
          dom: extracted.dom,
        };
      }
      return {
        id,
        ok: true,
        format: "md",
        markdown: extracted.markdown || "",
      };
    } catch (err) {
      return {
        id,
        ok: false,
        error_code: "ERR_PERMISSION_DENIED",
        error: `Failed to extract DOM: ${err.message}`,
      };
    }
  }

  return {
    id,
    ok: false,
    error_code: "ERR_INVALID_REQUEST",
    error: `Unsupported read-only command: ${cmd}`,
  };
}

async function processAgentFrame(ws, agent, payload) {
  if (ws !== state.ws || state.activeAgent !== agent) {
    return;
  }

  if (!agent.cipher) {
    if (!agent.opNonce) {
      if (state.activeAgent === agent) state.activeAgent = null;
      sendKickAgent(ws, agent.connID);
      return;
    }

    // First frame from agent must be the 69-byte authenticated handshake packet.
    let agentNonce;
    try {
      agentNonce = await verifyAgentHandshake(state.hk, state.sessionID, payload);
    } catch (_) {
      if (state.activeAgent === agent) state.activeAgent = null;
      sendKickAgent(ws, agent.connID);
      return;
    }

    if (ws !== state.ws || state.activeAgent !== agent) {
      return;
    }

    try {
      agent.cipher = await deriveConnCipher(
        ROLE_OPERATOR,
        state.sessionID,
        state.secretKey,
        agent.opNonce,
        agentNonce
      );
    } catch (_) {
      if (state.activeAgent === agent) state.activeAgent = null;
      sendKickAgent(ws, agent.connID);
      return;
    }
    return;
  }

  let record;
  try {
    record = await agent.cipher.decryptRecord(payload);
  } catch (_) {
    if (state.activeAgent === agent) state.activeAgent = null;
    sendKickAgent(ws, agent.connID);
    return;
  }

  if (record.recordType === RECORD_TYPE_EOF) {
    if (state.activeAgent === agent) state.activeAgent = null;
    return;
  }

  if (record.recordType !== RECORD_TYPE_DATA) {
    if (state.activeAgent === agent) state.activeAgent = null;
    sendKickAgent(ws, agent.connID);
    return;
  }

  let req;
  try {
    req = JSON.parse(utf8Decode(record.plaintext));
  } catch (err) {
    const respBytes = utf8Encode(
      JSON.stringify({
        ok: false,
        error_code: "ERR_INVALID_REQUEST",
        error: `Malformed JSON request: ${err.message}`,
      }) + "\n"
    );
    await sendEncryptedResponse(ws, agent, respBytes);
    return;
  }

  const resp = await handleAgentRequest(req);
  const respBytes = utf8Encode(JSON.stringify(resp) + "\n");
  await sendEncryptedResponse(ws, agent, respBytes);
}

async function sendEncryptedResponse(ws, agent, respBytes) {
  if (ws !== state.ws || state.activeAgent !== agent || ws.readyState !== WebSocket.OPEN || !agent.cipher) {
    return;
  }
  const encryptedData = await agent.cipher.encryptRecord(RECORD_TYPE_DATA, respBytes);
  ws.send(encodeRelayFrame(FRAME_DATA, agent.connID, encryptedData));

  const encryptedEOF = await agent.cipher.encryptRecord(RECORD_TYPE_EOF, new Uint8Array(0));
  ws.send(encodeRelayFrame(FRAME_DATA, agent.connID, encryptedEOF));
}

function handleAgentChainError(ws, agent, err) {
  console.error("[dtfm-web] agent frame error:", err);
  if (state.activeAgent === agent) {
    state.activeAgent = null;
  }
  sendKickAgent(ws, agent.connID);
}

function handleRelayMessage(ws, data) {
  if (ws !== state.ws || !(data instanceof ArrayBuffer)) {
    return;
  }
  const bytes = new Uint8Array(data);
  if (bytes.length < 9) {
    return;
  }

  const { ctrlByte, connID, payload } = decodeRelayFrame(bytes);

  if (ctrlByte === FRAME_AGENT_CONNECTED) {
    // Synchronously register activeAgent before any await so immediately-arriving
    // FRAME_DATA(agentHandshake) or FRAME_AGENT_DISCONNECTED frames are never dropped.
    const agent = {
      connID,
      opNonce: null,
      cipher: null,
      chain: Promise.resolve(),
    };
    state.activeAgent = agent;
    agent.chain = agent.chain
      .then(async () => {
        if (ws !== state.ws || state.activeAgent !== agent) {
          return;
        }
        const { opNonce, packet } = await buildOperatorHandshake(state.hk, state.sessionID);
        if (ws !== state.ws || state.activeAgent !== agent || ws.readyState !== WebSocket.OPEN) {
          return;
        }
        agent.opNonce = opNonce;
        ws.send(encodeRelayFrame(FRAME_DATA, connID, packet));
      })
      .catch((err) => handleAgentChainError(ws, agent, err));
    return;
  }

  if (ctrlByte === FRAME_AGENT_DISCONNECTED) {
    if (state.activeAgent && state.activeAgent.connID === connID) {
      state.activeAgent = null;
    }
    return;
  }

  if (ctrlByte === FRAME_DATA) {
    const agent = state.activeAgent;
    if (!agent || agent.connID !== connID) {
      return;
    }
    // Serialize async crypto & handler operations per agent connection.
    const payloadCopy = new Uint8Array(payload);
    agent.chain = agent.chain
      .then(() => processAgentFrame(ws, agent, payloadCopy))
      .catch((err) => handleAgentChainError(ws, agent, err));
  }
}

function scheduleReconnect(gen) {
  if (!state.active || gen !== state.connGen) {
    return;
  }

  if (state.keepaliveTimer !== null) {
    clearInterval(state.keepaliveTimer);
    state.keepaliveTimer = null;
  }
  if (state.connectTimer !== null) {
    clearTimeout(state.connectTimer);
    state.connectTimer = null;
  }
  if (state.reconnectTimer !== null) {
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
  }

  state.connected = false;
  state.reconnecting = true;
  state.activeAgent = null;
  state.ws = null;

  setReconnectingBadge(state.tabId);

  const delay = computeReconnectDelay(state.reconnectAttempts);
  state.reconnectAttempts += 1;

  state.reconnectTimer = setTimeout(async () => {
    state.reconnectTimer = null;
    if (!state.active || gen !== state.connGen) {
      return;
    }

    try {
      await chrome.tabs.get(state.tabId);
    } catch (_) {
      if (state.active && gen === state.connGen) {
        await stopSharing("Shared tab was closed");
      }
      return;
    }

    if (!state.active || gen !== state.connGen) {
      return;
    }

    openRelaySocket({ isInitial: false });
  }, delay);
}

function openRelaySocket({ isInitial = false } = {}) {
  if (!state.active || !state.sessionID) {
    return Promise.resolve(getPublicState());
  }

  state.connGen += 1;
  const gen = state.connGen;

  if (state.keepaliveTimer !== null) {
    clearInterval(state.keepaliveTimer);
    state.keepaliveTimer = null;
  }
  if (state.connectTimer !== null) {
    clearTimeout(state.connectTimer);
    state.connectTimer = null;
  }
  if (state.reconnectTimer !== null) {
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
  }

  const wsUrl = new URL(state.relayUrl);
  wsUrl.searchParams.set("session", state.sessionID);
  wsUrl.searchParams.set("role", ROLE_OPERATOR);

  return new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (!settled) {
        settled = true;
        if (state.pendingFinish === finish) {
          state.pendingFinish = null;
        }
        resolve(getPublicState());
      }
    };
    if (isInitial) {
      state.pendingFinish = finish;
    }

    let ws;
    try {
      ws = new WebSocket(wsUrl.toString());
      ws.binaryType = "arraybuffer";
    } catch (err) {
      if (isInitial) {
        stopSharing(`Failed to open relay WebSocket: ${err.message}`).finally(finish);
      } else {
        scheduleReconnect(gen);
        finish();
      }
      return;
    }
    state.ws = ws;

    let hadError = false;
    let timedOut = false;
    let hasOpened = false;

    state.connectTimer = setTimeout(() => {
      if (gen !== state.connGen || !state.active || state.ws !== ws || ws.readyState === WebSocket.OPEN) {
        return;
      }
      state.connectTimer = null;
      state.ws = null;
      ws.onopen = null;
      ws.onclose = null;
      ws.onerror = null;
      ws.onmessage = null;
      try {
        ws.close();
      } catch (_) {
        // Ignore close errors.
      }
      if (isInitial) {
        stopSharing("Relay WebSocket connection timed out").finally(finish);
      } else {
        scheduleReconnect(gen);
        finish();
      }
    }, WS_CONNECT_TIMEOUT_MS);

    ws.onopen = () => {
      if (gen !== state.connGen || !state.active || ws !== state.ws) {
        try {
          ws.close();
        } catch (_) {
          // Ignore close errors.
        }
        finish();
        return;
      }
      if (state.connectTimer !== null) {
        clearTimeout(state.connectTimer);
        state.connectTimer = null;
      }
      hasOpened = true;
      ws.send(state.authFrame);
      state.connected = true;
      state.reconnecting = false;
      state.reconnectAttempts = 0;
      state.lastError = null;

      // Set LIVE badge only once relay connection is established.
      setLiveBadge(state.tabId);

      // 1-byte keepalive every 20s keeps MV3 service worker awake, refreshes relay idle timer,
      // and verifies the pinned tab is still open.
      state.keepaliveTimer = setInterval(() => {
        if (gen !== state.connGen || !state.active || state.ws !== ws || ws.readyState !== WebSocket.OPEN) {
          return;
        }
        ws.send(new Uint8Array([FRAME_KEEPALIVE]));
        chrome.tabs.get(state.tabId).catch(() => {
          if (state.active && state.connGen === gen) {
            stopSharing("Shared tab was closed");
          }
        });
      }, KEEPALIVE_INTERVAL_MS);

      Promise.all([saveSessionToStorage(), ensureWatchdogAlarm()]).finally(finish);
    };

    ws.onmessage = (event) => {
      if (gen !== state.connGen || !state.active || ws !== state.ws) {
        return;
      }
      handleRelayMessage(ws, event.data);
    };

    ws.onerror = () => {
      if (gen !== state.connGen || !state.active || ws !== state.ws) {
        return;
      }
      hadError = true;
    };

    ws.onclose = (event) => {
      if (gen !== state.connGen || !state.active || ws !== state.ws) {
        finish();
        return;
      }
      if (state.connectTimer !== null) {
        clearTimeout(state.connectTimer);
        state.connectTimer = null;
      }
      if (state.keepaliveTimer !== null) {
        clearInterval(state.keepaliveTimer);
        state.keepaliveTimer = null;
      }

      const code = event?.code ?? 1006;
      if ((isInitial && !hasOpened) || isPermanentCloseCode(code)) {
        let reason = null;
        if (timedOut) {
          reason = "Relay WebSocket connection timed out";
        } else if (code !== 1000) {
          reason = hadError
            ? `Relay WebSocket connection failed (code ${code})`
            : `Relay disconnected (code ${code}${event?.reason ? `: ${event.reason}` : ""})`;
        }
        stopSharing(reason).finally(finish);
        return;
      }

      scheduleReconnect(gen);
      finish();
    };

    if (!isInitial) {
      finish();
    }
  });
}

async function startSharing({ tabId, windowId, tabTitle, tabUrl, origin, relayUrl }) {
  await stopSharing(null);

  const originPattern = origin ? `${origin}/*` : null;

  let normalizedRelay;
  try {
    normalizedRelay = validateRelayUrl(relayUrl);
  } catch (err) {
    await revokeOriginPermission(originPattern);
    state.lastError = `Invalid relay URL: ${err.message}`;
    return getPublicState();
  }

  await saveRelayUrl(normalizedRelay);

  let sessionID;
  let secretKey;
  let keyHex;
  let authFrame;
  let hk;
  try {
    sessionID = generateSessionID();
    const generated = generateSessionKey();
    secretKey = generated.key;
    keyHex = generated.keyHex;
    const { opAuth, agentVerifier } = await deriveAuthTokens(secretKey, sessionID);
    hk = await handshakeKey(secretKey, sessionID);
    authFrame = buildOperatorAuthFrame(opAuth, agentVerifier);
  } catch (err) {
    if (secretKey) secretKey.fill(0);
    if (hk) hk.fill(0);
    await revokeOriginPermission(originPattern);
    state.lastError = `Failed to initialize E2EE session: ${err.message}`;
    return getPublicState();
  }

  state.active = true;
  state.connected = false;
  state.reconnecting = false;
  state.reconnectAttempts = 0;
  state.tabId = tabId;
  state.windowId = windowId;
  state.tabTitle = tabTitle || "";
  state.tabUrl = tabUrl || "";
  state.origin = origin;
  state.originPattern = originPattern;
  state.sessionID = sessionID;
  state.keyHex = keyHex;
  state.secretKey = secretKey;
  state.hk = hk;
  state.authFrame = authFrame;
  state.activeAgent = null;
  state.lastError = null;

  return openRelaySocket({ isInitial: true });
}

/**
 * Idempotently restores an active sharing session from RAM-only chrome.storage.session
 * after MV3 service worker hibernation, or ensures an active session's socket is healthy.
 */
export async function ensureRestored() {
  if (restoreInFlight) {
    return restoreInFlight;
  }

  restoreInFlight = (async () => {
    const gen = state.connGen;
    const isAborted = () => state.connGen !== gen || state.active;

    if (state.active) {
      if (
        !state.connected &&
        !state.reconnecting &&
        state.reconnectTimer === null &&
        (!state.ws || state.ws.readyState === WebSocket.CLOSED)
      ) {
        scheduleReconnect(state.connGen);
      }
      return getPublicState();
    }

    if (!chrome?.storage?.session) {
      return getPublicState();
    }

    let data;
    try {
      data = await chrome.storage.session.get(STORAGE_SESSION_KEY);
    } catch (_) {
      return getPublicState();
    }
    if (isAborted()) {
      return getPublicState();
    }

    const saved = data?.[STORAGE_SESSION_KEY];
    let normalizedRelay = null;
    if (saved && typeof saved.relayUrl === "string") {
      try {
        normalizedRelay = validateRelayUrl(saved.relayUrl);
      } catch (_) {
        normalizedRelay = null;
      }
    }
    if (
      !saved ||
      typeof saved.tabId !== "number" ||
      typeof saved.sessionID !== "string" ||
      typeof saved.keyHex !== "string" ||
      typeof saved.origin !== "string" ||
      saved.origin.length === 0 ||
      saved.originPattern !== `${saved.origin}/*` ||
      !normalizedRelay
    ) {
      if (saved) {
        await clearSessionStorage();
      }
      return getPublicState();
    }

    try {
      await chrome.tabs.get(saved.tabId);
    } catch (_) {
      if (isAborted()) {
        return getPublicState();
      }
      state.tabId = saved.tabId;
      state.originPattern = saved.originPattern;
      await stopSharingInternal("Shared tab was closed");
      return getPublicState();
    }
    if (isAborted()) {
      return getPublicState();
    }

    if (chrome?.permissions?.contains) {
      let hasPerm = false;
      try {
        hasPerm = await chrome.permissions.contains({ origins: [saved.originPattern] });
      } catch (_) {
        hasPerm = false;
      }
      if (isAborted()) {
        return getPublicState();
      }
      if (!hasPerm) {
        state.tabId = saved.tabId;
        state.originPattern = saved.originPattern;
        await stopSharingInternal("Host permission was revoked");
        return getPublicState();
      }
    }

    let secretKey;
    let hk;
    let authFrame;
    const zeroizeLocals = () => {
      if (secretKey) secretKey.fill(0);
      if (hk) hk.fill(0);
      if (authFrame) authFrame.fill(0);
    };
    try {
      secretKey = hexToBytes(saved.keyHex);
      const { opAuth, agentVerifier } = await deriveAuthTokens(secretKey, saved.sessionID);
      if (isAborted()) {
        zeroizeLocals();
        return getPublicState();
      }
      hk = await handshakeKey(secretKey, saved.sessionID);
      if (isAborted()) {
        zeroizeLocals();
        return getPublicState();
      }
      authFrame = buildOperatorAuthFrame(opAuth, agentVerifier);
    } catch (_) {
      zeroizeLocals();
      if (isAborted()) {
        return getPublicState();
      }
      state.tabId = saved.tabId;
      state.originPattern = saved.originPattern;
      await stopSharingInternal("Failed to restore E2EE session");
      return getPublicState();
    }

    state.active = true;
    state.connected = false;
    state.reconnecting = true;
    state.reconnectAttempts = 0;
    state.tabId = saved.tabId;
    state.windowId = saved.windowId ?? null;
    state.tabTitle = saved.tabTitle || "";
    state.tabUrl = saved.tabUrl || "";
    state.origin = saved.origin;
    state.originPattern = saved.originPattern;
    state.relayUrl = normalizedRelay;
    state.sessionID = saved.sessionID;
    state.keyHex = saved.keyHex;
    state.secretKey = secretKey;
    state.hk = hk;
    state.authFrame = authFrame;
    state.activeAgent = null;
    state.lastError = null;

    await ensureWatchdogAlarm();
    if (state.connGen !== gen || !state.active) {
      return getPublicState();
    }
    await setReconnectingBadge(state.tabId);
    if (state.connGen !== gen || !state.active) {
      return getPublicState();
    }
    openRelaySocket({ isInitial: false });
    return getPublicState();
  })().finally(() => {
    restoreInFlight = null;
  });

  return restoreInFlight;
}

export {
  getPublicState,
  startSharing,
  state,
  stopSharing,
};

if (typeof chrome !== "undefined" && chrome.tabs && chrome.runtime) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    (async () => {
      if (restoreInFlight) {
        await restoreInFlight.catch(() => {});
      }
      if (state.active && state.tabId === tabId) {
        await stopSharing("Shared tab was closed");
      }
    })();
  });

  if (chrome.alarms?.onAlarm) {
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm?.name === WATCHDOG_ALARM_NAME) {
        ensureRestored();
      }
    });
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    // Restrict messages strictly to this extension's own UI pages (popup), never content scripts or external senders.
    if (!sender || sender.id !== chrome.runtime.id || sender.tab) {
      return;
    }

    (async () => {
      if (!msg || typeof msg.type !== "string") {
        sendResponse({ error: "invalid message" });
        return;
      }

      if (msg.type === "GET_STATE") {
        await ensureRestored();
        if (!state.active) {
          await loadSavedRelayUrl();
        }
        sendResponse(getPublicState());
        return;
      }

      if (msg.type === "START_SHARING") {
        const result = await startSharing(msg);
        sendResponse(result);
        return;
      }

      if (msg.type === "STOP_SHARING") {
        await stopSharing(null);
        sendResponse(getPublicState());
        return;
      }

      sendResponse({ error: `unknown message type: ${msg.type}` });
    })().catch((err) => {
      sendResponse({ error: err.message });
    });
    return true;
  });

  ensureRestored();
}
