// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

const statusBadge = document.getElementById("statusBadge");
const idleView = document.getElementById("idleView");
const liveView = document.getElementById("liveView");
const relayUrlInput = document.getElementById("relayUrlInput");
const shareBtn = document.getElementById("shareBtn");
const stopBtn = document.getElementById("stopBtn");
const copyTokenBtn = document.getElementById("copyTokenBtn");
const tabTitleEl = document.getElementById("tabTitle");
const tabOriginEl = document.getElementById("tabOrigin");
const tokenBox = document.getElementById("tokenBox");
const errorBox = document.getElementById("errorBox");

let currentToken = "";

function showError(msg) {
  if (msg) {
    errorBox.textContent = msg;
    errorBox.classList.remove("hidden");
  } else {
    errorBox.textContent = "";
    errorBox.classList.add("hidden");
  }
}

function renderState(state) {
  if (state.relayUrl) {
    relayUrlInput.value = state.relayUrl;
  }

  if (state.active) {
    if (state.connected) {
      statusBadge.textContent = "LIVE";
      statusBadge.className = "badge live";
    } else if (state.reconnecting) {
      statusBadge.textContent = "RECONNECTING";
      statusBadge.className = "badge reconnecting";
    } else {
      statusBadge.textContent = "CONNECTING";
      statusBadge.className = "badge reconnecting";
    }
    idleView.classList.add("hidden");
    liveView.classList.remove("hidden");
    tabTitleEl.textContent = state.tabTitle || "(Untitled tab)";
    tabOriginEl.textContent = state.origin || state.tabUrl || "";
    currentToken = state.pairingToken || "";
    tokenBox.textContent = currentToken;
  } else {
    statusBadge.textContent = "IDLE";
    statusBadge.className = "badge idle";
    liveView.classList.add("hidden");
    idleView.classList.remove("hidden");
    currentToken = "";
    tokenBox.textContent = "";
  }

  showError(state.lastError || "");
}

async function refreshState() {
  const state = await chrome.runtime.sendMessage({ type: "GET_STATE" });
  renderState(state);
}

function validateRelayUrl(rawUrl) {
  const normalized = (rawUrl || "wss://relay.dtfm.dev/ws").trim();
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch (_) {
    throw new Error("Invalid relay URL");
  }
  if (parsed.protocol === "wss:") {
    return normalized;
  }
  if (parsed.protocol === "ws:") {
    const host = parsed.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1") {
      return normalized;
    }
    throw new Error("Unencrypted ws:// relay is only allowed for loopback hosts (localhost, 127.0.0.1, ::1); use wss://");
  }
  throw new Error("Relay URL must use wss:// (or ws:// for localhost)");
}

shareBtn.addEventListener("click", async () => {
  showError("");
  shareBtn.disabled = true;

  try {
    const relayUrl = validateRelayUrl(relayUrlInput.value);

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || typeof tab.id !== "number" || !tab.url) {
      throw new Error("No active HTTP(S) tab found");
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(tab.url);
    } catch (_) {
      throw new Error("Active tab URL cannot be shared");
    }

    if (parsedUrl.protocol !== "https:" && parsedUrl.protocol !== "http:") {
      throw new Error(`Cannot share ${parsedUrl.protocol} pages; open an http:// or https:// tab`);
    }

    const origin = parsedUrl.origin;
    const originPattern = `${origin}/*`;

    // Must be called directly inside the user-gesture click handler.
    const granted = await chrome.permissions.request({ origins: [originPattern] });
    if (!granted) {
      throw new Error(`Host permission for ${origin} was denied`);
    }

    const state = await chrome.runtime.sendMessage({
      type: "START_SHARING",
      tabId: tab.id,
      windowId: tab.windowId,
      tabTitle: tab.title || "",
      tabUrl: tab.url,
      origin,
      relayUrl,
    });
    renderState(state);
  } catch (err) {
    showError(err.message);
  } finally {
    shareBtn.disabled = false;
  }
});

stopBtn.addEventListener("click", async () => {
  stopBtn.disabled = true;
  try {
    const state = await chrome.runtime.sendMessage({ type: "STOP_SHARING" });
    renderState(state);
  } catch (err) {
    showError(err.message);
  } finally {
    stopBtn.disabled = false;
  }
});

copyTokenBtn.addEventListener("click", async () => {
  if (!currentToken) return;
  try {
    await navigator.clipboard.writeText(currentToken);
    copyTokenBtn.textContent = "Copied!";
    setTimeout(() => {
      copyTokenBtn.textContent = "Copy Pairing Token";
    }, 1500);
  } catch (err) {
    showError(`Clipboard copy failed: ${err.message}`);
  }
});

refreshState().catch((err) => showError(err.message));
