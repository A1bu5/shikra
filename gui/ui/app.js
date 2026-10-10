// Shikra Console frontend. Talks to the Tauri backend via `invoke`.

const invoke = window.__TAURI__.core.invoke;

window.addEventListener("error", (event) => {
  try {
    invoke("frontend_log", {
      message: `${event.message} @ ${event.filename}:${event.lineno}`,
    }).catch(() => {});
  } catch {
    /* backend unavailable */
  }
});
window.addEventListener("unhandledrejection", (event) => {
  try {
    invoke("frontend_log", {
      message: `unhandled rejection: ${event.reason}`,
    }).catch(() => {});
  } catch {
    /* backend unavailable */
  }
});

const state = {
  activeSession: null,
  previewFile: null,
  sessionsTimer: null,
  sessions: [],
  serverMaterial: null,
  consoleConfig: {},
  stageUrlManual: false,
};

const $ = (id) => document.getElementById(id);

const nativeDialog = window.__TAURI__?.dialog ?? null;
const nativePath = window.__TAURI__?.path ?? null;

// ---------- i18n ----------

const SUPPORTED_LANGS = ["en", "zh", "ja", "ko", "ru"];
let translations = {};
let currentLang = "en";

function t(key, vars = {}) {
  let text = translations[key] ?? key;
  for (const [name, value] of Object.entries(vars)) {
    text = text.replaceAll(`{${name}}`, value);
  }
  return text;
}

async function loadLocale(lang) {
  const normalized = SUPPORTED_LANGS.includes(lang) ? lang : "en";
  try {
    const response = await fetch(`locales/${normalized}.json`);
    translations = await response.json();
  } catch {
    translations = {};
  }
  currentLang = normalized;
  document.documentElement.lang = normalized;
}

function applyTranslations() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  });
  document.querySelectorAll("[data-i18n-title]").forEach((el) => {
    el.title = t(el.dataset.i18nTitle);
  });
  document.querySelectorAll("[data-i18n-alt]").forEach((el) => {
    el.alt = t(el.dataset.i18nAlt);
  });
  document.title = t("app.title");
}

async function setLanguage(lang, persist = true) {
  await loadLocale(lang);
  applyTranslations();
  $("lang-select").value = currentLang;
  refreshDynamicText();
  if (persist) saveConsoleConfig();
}

function detectLanguage() {
  const browser = (navigator.language || "en").slice(0, 2).toLowerCase();
  return SUPPORTED_LANGS.includes(browser) ? browser : "en";
}

function refreshDynamicText() {
  renderSessions(state.sessions ?? []);
  renderActiveSession();
  refreshCopilotPills();
  if (!$("tab-listen").classList.contains("active")) return;
  loadListeners();
}

$("lang-select").addEventListener("change", (event) => {
  setLanguage(event.target.value);
});

async function pickFile(title = "Select file") {
  if (!nativeDialog) return null;
  const selected = await nativeDialog.open({ title, multiple: false, directory: false });
  return typeof selected === "string" ? selected : null;
}

async function pickDirectory(title = "Select folder") {
  if (!nativeDialog) return null;
  const selected = await nativeDialog.open({ title, multiple: false, directory: true });
  return typeof selected === "string" ? selected : null;
}

async function pickSave(defaultPath, title = "Save as") {
  if (!nativeDialog) return null;
  const selected = await nativeDialog.save({ title, defaultPath });
  return typeof selected === "string" ? selected : null;
}

function toast(message, isError = false) {
  const el = $("toast");
  el.textContent = message;
  el.classList.toggle("error", isError);
  el.classList.remove("hidden");
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.add("hidden"), 4000);
}

function setConnected(online, label) {
  const status = $("conn-status");
  status.textContent = label;
  status.classList.toggle("online", online);
  status.classList.toggle("offline", !online);
  const barDot = document.querySelector("#status-conn .dot");
  if (barDot) barDot.classList.toggle("offline", !online);
}

async function safeInvoke(command, args = {}) {
  try {
    return await invoke(command, args);
  } catch (err) {
    toast(typeof err === "string" ? err : JSON.stringify(err), true);
    throw err;
  }
}

// ---------- login view ----------

function showLogin(overlay = false) {
  $("login-view").classList.remove("hidden");
  $("app").classList.toggle("hidden", !overlay);
  $("login-back").classList.toggle("hidden", !overlay);
}

function hideLogin() {
  $("login-view").classList.add("hidden");
  $("app").classList.remove("hidden");
}

function showLoginError(message) {
  const el = $("login-error");
  el.textContent = message;
  el.classList.toggle("hidden", !message);
}

function selectLoginTab(tab) {
  document.querySelectorAll(".login-tabs button").forEach((button) => {
    button.classList.toggle("active", button.dataset.loginTab === tab);
  });
  document.querySelectorAll(".login-pane").forEach((pane) => {
    pane.classList.toggle("active", pane.id === `login-${tab}`);
  });
  if (tab === "host") refreshServerStatus();
}

document.querySelectorAll(".login-tabs button").forEach((button) => {
  button.addEventListener("click", () => selectLoginTab(button.dataset.loginTab));
});

function applyServerMaterial(material) {
  $("host-material").classList.remove("hidden");
  $("mat-ca").textContent = material.ca_pem ?? "";
  $("mat-enroll").textContent = material.enroll_token ?? "";
  $("mat-operator").textContent = material.operator_token ?? "";
  $("mat-identity").textContent = material.server_identity ?? "";
  state.serverMaterial = material;
}

document.querySelectorAll(".copy-btn").forEach((button) => {
  button.addEventListener("click", async () => {
    const value = $(button.dataset.copy).textContent;
    try {
      await navigator.clipboard.writeText(value);
      toast(t("msg.copied"));
    } catch {
      toast(t("msg.clipboardUnavailable"), true);
    }
  });
});

function randomPassword() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function ensureDbCredentials() {
  if (!state.dbPassword) state.dbPassword = randomPassword();
  // initdb provisions the "postgres" superuser for the embedded cluster.
  return { password: state.dbPassword };
}

function dbMode() {
  return $("host-db-mode").value;
}

function applyDbModeVisibility() {
  const embedded = dbMode() === "embedded";
  $("host-db-embedded").classList.toggle("hidden", !embedded);
  $("host-db-external").classList.toggle("hidden", embedded);
}

async function startEmbeddedDatabase() {
  if (dbMode() !== "embedded") return $("host-database").value.trim();
  const existing = await invoke("database_embedded_status");
  if (existing.running) {
    $("host-db-status").textContent = t("host.dbRunningInfo", { port: existing.port });
    $("host-db-status").className = "status online";
    state.embeddedDbUrl = existing.url;
    return existing.url;
  }
  const dir = $("host-state-dir").value.trim();
  if (!dir) throw new Error(t("host.requireStateDir"));
  const creds = ensureDbCredentials();
  $("host-db-status").textContent = t("host.provisioning");
  $("host-db-status").className = "status warn";
  const info = await invoke("database_embedded_start", {
    options: { stateDir: dir, ...creds },
  });
  $("host-db-status").textContent = t("host.dbRunningInfo", { port: info.port });
  $("host-db-status").className = "status online";
  state.embeddedDbUrl = info.url;
  return info.url;
}

function hostOptions() {
  const port = Number($("host-operator-port").value) || 8443;
  return {
    stateDir: $("host-state-dir").value.trim(),
    databaseUrl:
      dbMode() === "embedded" ? state.embeddedDbUrl ?? "" : $("host-database").value.trim(),
    grpcAddr: `${$("host-operator-host").value.trim()}:${port}`,
    healthAddr: "127.0.0.1:0",
  };
}

async function findFreeOperatorPort() {
  const host = $("host-operator-host").value.trim();
  const from = Number($("host-operator-port").value) || 8443;
  try {
    const port = await invoke("pick_free_port", { host, fromPort: from });
    $("host-operator-port").value = port;
    toast(`using free port ${port}`);
  } catch (err) {
    toast(String(err), true);
  }
}

async function refreshServerStatus() {
  try {
    const status = await invoke("server_status");
    const el = $("host-status");
    if (status.running) {
      el.textContent = t("host.runningInfo", { pid: status.pid });
      el.className = "status online";
    } else {
      el.textContent = t("host.stopped");
      el.className = "status offline";
    }
    const dir = $("host-state-dir").value.trim();
    if (dir) {
      const log = await invoke("server_log", { stateDir: dir, lines: 80 });
      $("host-log").textContent = log;
    }
    try {
      const db = await invoke("database_embedded_status");
      if (db.running) {
        $("host-db-status").textContent = t("host.dbRunningInfo", { port: db.port });
        $("host-db-status").className = "status online";
        state.embeddedDbUrl = db.url;
      } else if ($("host-db-status").textContent.startsWith("running")) {
        $("host-db-status").textContent = t("host.dbStopped");
        $("host-db-status").className = "status offline";
      }
    } catch {
      /* database not managed */
    }
  } catch {
    /* not running / not initialized */
  }
}

$("host-db-mode").addEventListener("change", applyDbModeVisibility);
$("btn-host-free-port").addEventListener("click", findFreeOperatorPort);

$("btn-db-start").addEventListener("click", async () => {
  try {
    await startEmbeddedDatabase();
    toast(t("host.dbReady"));
    saveConsoleConfig();
  } catch (err) {
    $("host-db-status").textContent = t("host.dbFailed");
    $("host-db-status").className = "status offline";
    toast(String(err), true);
  }
});

$("btn-db-stop").addEventListener("click", async () => {
  if (dbMode() !== "embedded") return;
  if (!(await confirmAction({ body: t("confirm.stopDatabase") }))) return;
  try {
    toast(await invoke("database_embedded_stop"));
    state.embeddedDbUrl = null;
    $("host-db-status").textContent = t("host.dbStopped");
    $("host-db-status").className = "status offline";
  } catch (err) {
    toast(String(err), true);
  }
});

$("btn-host-init").addEventListener("click", async () => {
  const options = hostOptions();
  if (!options.stateDir) {
    toast(t("host.requireStateDir"), true);
    return;
  }
  try {
    const material = await invoke("server_bootstrap", { options });
    applyServerMaterial(material);
    if (!options.databaseUrl) {
      $("host-database").focus();
    }
    toast(t("host.materialReady", { dir: material.state_dir }));
    saveConsoleConfig();
  } catch (err) {
    toast(String(err), true);
  }
});

$("btn-host-start").addEventListener("click", async () => {
  if (!$("host-state-dir").value.trim()) {
    toast(t("host.requireStateDir"), true);
    return;
  }
  try {
    const databaseUrl = await startEmbeddedDatabase();
    if (!databaseUrl) {
      toast(t("host.requireExternalDb"), true);
      return;
    }
    const options = { ...hostOptions(), databaseUrl };
    const info = await invoke("server_start", { options });
    toast(t("host.started", { pid: info.pid }));
    setTimeout(refreshServerStatus, 1200);
    saveConsoleConfig();
  } catch (err) {
    toast(String(err), true);
  }
});

$("btn-host-stop").addEventListener("click", async () => {
  if (!(await confirmAction({ body: t("confirm.stopServer") }))) return;
  try {
    toast(await invoke("server_stop"));
    refreshServerStatus();
  } catch (err) {
    toast(String(err), true);
  }
});

$("btn-host-use").addEventListener("click", async () => {
  const material = state.serverMaterial;
  if (!material) return;
  const bind = $("host-operator-host").value.trim();
  const host = bind === "0.0.0.0" ? "127.0.0.1" : bind;
  $("login-endpoint").value = `https://${host}:${$("host-operator-port").value.trim()}`;
  $("login-ca").value = material.ca_pem ?? "";
  $("login-token").value = material.operator_token ?? "";
  selectLoginTab("connect");
  saveConsoleConfig();
});

let serverStatusTimer = null;
setInterval(() => {
  if (!$("login-view").classList.contains("hidden") &&
      $("login-host").classList.contains("active")) {
    refreshServerStatus();
  }
}, 3000);

async function saveConsoleConfig() {
  const config = {
    language: currentLang,
    host: {
      stateDir: $("host-state-dir").value.trim(),
      dbMode: dbMode(),
      dbPassword: state.dbPassword ?? "",
      externalDatabaseUrl: $("host-database").value.trim(),
      operatorHost: $("host-operator-host").value,
      operatorPort: Number($("host-operator-port").value) || 8443,
    },
    client: {
      endpoint: $("login-endpoint").value.trim(),
      caPath: $("login-ca").value.trim(),
      token: $("login-token").value.trim(),
    },
  };
  try {
    await invoke("console_config_save", { config });
  } catch {
    /* non-fatal */
  }
}

async function loadConsoleConfig() {
  let config = {};
  try {
    config = await invoke("console_config_get");
  } catch {
    config = {};
  }
  state.consoleConfig = config;
  await loadLocale(config.language || detectLanguage());
  applyTranslations();
  $("lang-select").value = currentLang;
  try {
    if (config.host) {
      $("host-state-dir").value = config.host.stateDir ?? "";
      $("host-db-mode").value = config.host.dbMode || "embedded";
      $("host-database").value = config.host.externalDatabaseUrl ?? "";
      $("host-operator-host").value = config.host.operatorHost || "127.0.0.1";
      $("host-operator-port").value = config.host.operatorPort || 8443;
      if (config.host.dbPassword) state.dbPassword = config.host.dbPassword;
    }
    if (config.client) {
      $("login-endpoint").value = config.client.endpoint ?? "";
      $("login-ca").value = config.client.caPath ?? "";
      $("login-token").value = config.client.token ?? "";
    }
    renderRecent(config.client);
  } catch {
    /* first run */
  }
}

function renderRecent(client) {
  const container = $("login-recent");
  container.innerHTML = "";
  if (!client?.endpoint) return;
  const item = document.createElement("div");
  item.className = "recent-item";
  item.innerHTML = `<span>${t("login.recent")}</span><code>${client.endpoint}</code>`;
  item.addEventListener("click", () => {
    $("login-endpoint").value = client.endpoint ?? "";
    $("login-ca").value = client.caPath ?? "";
    $("login-token").value = client.token ?? "";
    toast(t("msg.fillRecent"));
  });
  container.appendChild(item);
}

// ---------- connection ----------

$("btn-login-connect").addEventListener("click", async () => {
  const server = $("login-endpoint").value.trim();
  const caPath = $("login-ca").value.trim();
  const token = $("login-token").value.trim();
  if (!server || !caPath || !token) {
    showLoginError(t("login.errorRequired"));
    return;
  }
  showLoginError("");
  const button = $("btn-login-connect");
  button.disabled = true;
  button.textContent = t("login.connecting");
  try {
    const version = await invoke("connect", { server, caPath, token });
    setConnected(true, t("msg.onlineVersion", { version }));
    const serverLabel = $("status-server");
    if (serverLabel) serverLabel.textContent = server;
    hideLogin();
    await saveConsoleConfig();
    await refreshSessions();
    clearInterval(state.sessionsTimer);
    state.sessionsTimer = setInterval(refreshSessions, 5000);
    toast(t("msg.connected", { server }));
  } catch (err) {
    showLoginError(typeof err === "string" ? err : JSON.stringify(err));
    setConnected(false, t("top.offline"));
  } finally {
    button.disabled = false;
    button.textContent = t("login.connect");
  }
});

$("btn-settings").addEventListener("click", () => showLogin(true));

$("login-back").addEventListener("click", () => hideLogin());

$("btn-disconnect").addEventListener("click", async () => {
  await safeInvoke("disconnect");
  clearInterval(state.sessionsTimer);
  state.activeSession = null;
  setConnected(false, t("top.offline"));
  renderSessions([]);
  renderActiveSession();
  showLogin(false);
});

// ---------- sessions ----------

const PLATFORM_ICONS = {
  windows:
    '<svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor"><path d="M1 3.2l5.6-.8v5.1H1V3.2zm6.6-.9L15 1v7.5H7.6V2.3zM1 8.5h5.6v5.1L1 12.8V8.5zm6.6 0H15V15l-7.4-1V8.5z"/></svg>',
  macos:
    '<svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor"><path d="M11.2 8.4c0-1.6 1.3-2.3 1.4-2.4-.8-1.1-2-1.3-2.4-1.3-1-.1-2 .6-2.5.6-.5 0-1.3-.6-2.2-.6-1.1 0-2.2.7-2.7 1.7-1.2 2-.3 5 .8 6.6.5.8 1.2 1.6 2 1.5.8 0 1.1-.5 2.1-.5s1.3.5 2.1.5c.9 0 1.5-.8 2-1.6.6-.9.9-1.9.9-2-.1 0-1.5-.6-1.5-2.5zM9.6 3.6c.4-.6.8-1.3.7-2.1-.7 0-1.5.5-1.9 1-.4.5-.8 1.3-.7 2.1.8 0 1.5-.4 1.9-1z"/></svg>',
  linux:
    '<svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor"><path d="M8 1c-1.7 0-2.6 1.4-2.6 3 0 1-.3 1.7-.8 2.5-.8 1.3-1.9 2.4-1.9 4 0 1 .5 1.7 1.3 2.1-.3.3-.5.6-.5 1 0 1 1.3 1.4 2.3 1.4.8 0 1.4-.2 2.2-.2s1.4.2 2.2.2c1 0 2.3-.4 2.3-1.4 0-.4-.2-.7-.5-1 .8-.4 1.3-1.1 1.3-2.1 0-1.6-1.1-2.7-1.9-4-.5-.8-.8-1.5-.8-2.5 0-1.6-.9-3-2.6-3zM6.7 4.2c.4 0 .7.5.7 1s-.3 1-.7 1-.7-.5-.7-1 .3-1 .7-1zm2.6 0c.4 0 .7.5.7 1s-.3 1-.7 1-.7-.5-.7-1 .3-1 .7-1zM8 6.7c.6 0 1.3.4 1.3.7 0 .4-.8.9-1.3.9s-1.3-.5-1.3-.9c0-.3.7-.7 1.3-.7z"/></svg>',
  unknown:
    '<svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor"><path d="M2 2h12v3H2V2zm0 4.5h12v3H2v-3zM2 11h12v3H2v-3z"/></svg>',
};

function platformIcon(platform) {
  return PLATFORM_ICONS[platform] ?? PLATFORM_ICONS.unknown;
}

function sessionHealth(session) {
  if (session.status === "dead" || session.operator_status === "dead") return "dead";
  if (session.killdate_unix && Date.now() / 1000 >= session.killdate_unix) return "killdate";
  if (session.working_hours && outsideWorkingHours(session.working_hours)) return "offhours";
  const age = Math.max(0, Math.floor(Date.now() / 1000) - (session.last_seen_unix || 0));
  if (!session.last_seen_unix || age > 120) return "unresponsive";
  return "healthy";
}

function outsideWorkingHours(spec) {
  const match = /^(\d{1,2})(?::(\d{2}))?-(\d{1,2})(?::(\d{2}))?$/.exec(spec.trim());
  if (!match) return false;
  const start = Number(match[1]) * 60 + Number(match[2] || 0);
  const end = Number(match[3]) * 60 + Number(match[4] || 0);
  const now = new Date();
  const minutes = now.getHours() * 60 + now.getMinutes();
  return start <= end ? minutes < start || minutes >= end : minutes < start && minutes >= end;
}

function healthLabel(health) {
  return t(`sessions.health_${health}`);
}

function timeAgo(unixSeconds) {
  if (!unixSeconds) return t("sessions.never");
  const delta = Math.max(0, Math.floor(Date.now() / 1000) - unixSeconds);
  if (delta < 5) return t("sessions.justNow");
  if (delta < 60) return t("sessions.secondsAgo", { n: delta });
  if (delta < 3600) return t("sessions.minutesAgo", { n: Math.floor(delta / 60) });
  if (delta < 86400) return t("sessions.hoursAgo", { n: Math.floor(delta / 3600) });
  return t("sessions.daysAgo", { n: Math.floor(delta / 86400) });
}

function sessionSortKey(session) {
  const order = { healthy: 0, unresponsive: 1, offhours: 2, killdate: 3, dead: 4 };
  return `${order[sessionHealth(session)] ?? 5}-${String(1e12 - session.last_seen_unix).padStart(13, "0")}`;
}

async function refreshSessions() {
  try {
    const sessions = await invoke("sessions");
    state.sessions = sessions;
    renderSessions(sessions);
  } catch {
    /* keep previous list on transient errors */
  }
}

function renderSessions(sessions) {
  state.sessions = sessions;
  const showDead = $("show-dead").checked;
  const filter = ($("session-filter")?.value ?? "").trim().toLowerCase();
  const visible = sessions
    .filter((session) => showDead || session.status !== "dead")
    .filter(
      (session) =>
        !filter ||
        `${session.hostname} ${session.username} ${session.id} ${session.platform}`
          .toLowerCase()
          .includes(filter)
    )
    .sort((a, b) => sessionSortKey(a).localeCompare(sessionSortKey(b)));

  const body = $("session-table-body");
  body.innerHTML = "";
  for (const session of visible) {
    const health = sessionHealth(session);
    const tr = document.createElement("tr");
    if (state.activeSession && state.activeSession.id === session.id) {
      tr.classList.add("selected");
    }
    if (session.color) {
      tr.style.boxShadow = `inset 3px 0 0 ${session.color}`;
    }
    tr.innerHTML = `
      <td>
        <div class="cell-host"><span class="platform-${session.platform}">${platformIcon(session.platform)}</span><span>${copilotEscape(session.hostname || t("sessions.unknownHost"))}</span></div>
        <div class="cell-mono">${copilotEscape(session.id.slice(0, 8))}</div>
      </td>
      <td>${copilotEscape(session.username || "?")}</td>
      <td class="cell-mono">${copilotEscape(session.platform)} / ${copilotEscape(session.architecture)}</td>
      <td><span class="kind-pill ${copilotEscape(session.kind)}">${copilotEscape(session.kind)}</span></td>
      <td><span class="health-pill ${health}"><span class="health-dot"></span>${healthLabel(health)}</span></td>
      <td>${timeAgo(session.last_seen_unix)}</td>
      <td class="cell-mono">${copilotEscape(session.remote_addr || t("sessions.noAddress"))}</td>
    `;
    tr.addEventListener("click", () => selectSession(session));
    tr.addEventListener("dblclick", () => openSessionWorkspace(session));
    tr.addEventListener("contextmenu", (event) => showSessionMenu(event, session));
    body.appendChild(tr);
  }
  $("session-count").textContent = t("sessions.count", { n: visible.length });
  $("sessions-empty").classList.toggle("hidden", visible.length > 0);
  const badge = $("badge-sessions");
  if (badge) {
    const activeCount = sessions.filter((session) => session.status !== "dead").length;
    badge.textContent = activeCount || "";
  }
  updateStatusBar();
}

function selectSession(session) {
  state.activeSession = session;
  renderSessions(state.sessions ?? []);
  renderActiveSession();
}

$("session-filter").addEventListener("input", () => renderSessions(state.sessions ?? []));

$("show-dead").addEventListener("change", () => renderSessions(state.sessions ?? []));

function renderActiveSession() {
  const session = state.activeSession;
  const details = $("session-details-body");
  const title = $("session-head-title");
  const meta = $("session-head-meta");
  const actions = $("session-head-actions");
  if (!session) {
    details.innerHTML = `<p class="muted">${t("detail.select")}</p>`;
    title.textContent = t("session.none");
    meta.innerHTML = "";
    actions.innerHTML = "";
    updateSessionControls();
    return;
  }
  const health = sessionHealth(session);
  const rows = [
    ["Host", session.hostname || t("sessions.unknownHost")],
    ["User", session.username || "?"],
    ["Platform", `${session.platform} / ${session.architecture}`],
    ["Kind", session.kind],
    ["Health", healthLabel(health)],
    ["Last seen", timeAgo(session.last_seen_unix)],
    ["Address", session.remote_addr || t("sessions.noAddress")],
    ["Session ID", session.id],
  ];
  details.innerHTML =
    rows
      .map(
        ([key, value]) =>
          `<div class="detail-row"><span class="k">${copilotEscape(key)}</span><span class="v">${copilotEscape(String(value))}</span></div>`
      )
      .join("") +
    `<div class="detail-actions">
       <button class="primary" id="detail-interact">${t("detail.interact")}</button>
       <button class="ghost" id="detail-export">${t("session.export")}</button>
       <button class="ghost" id="detail-color">${t("session.color")}</button>
     </div>`;
  details.querySelector("#detail-interact").addEventListener("click", () => openSessionWorkspace(session));
  details.querySelector("#detail-export").addEventListener("click", () => exportSession(session));
  details.querySelector("#detail-color").addEventListener("click", (event) => showSessionMenu(event, session));

  title.innerHTML = `${platformIcon(session.platform)} ${copilotEscape(session.hostname || t("sessions.unknownHost"))}`;
  meta.innerHTML = `
    <span>${copilotEscape(session.username || "?")}</span>
    <span>·</span>
    <span>${copilotEscape(session.platform)}/${copilotEscape(session.architecture)}</span>
    <span>·</span>
    <span class="kind-pill ${copilotEscape(session.kind)}">${copilotEscape(session.kind)}</span>
    <span>·</span>
    <span class="health-pill ${health}"><span class="health-dot"></span>${healthLabel(health)}</span>
    <span>·</span>
    <span>${timeAgo(session.last_seen_unix)}</span>`;

  const nextStatus = session.status === "dead" ? "alive" : "dead";
  actions.innerHTML = `
    <button class="ghost" id="session-mark">${nextStatus === "dead" ? t("session.markDead") : t("session.markAlive")}</button>
    <button class="ghost" id="session-close-workspace">${t("session.close")}</button>`;
  actions.querySelector("#session-close-workspace").addEventListener("click", closeSessionWorkspace);
  actions.querySelector("#session-mark").addEventListener("click", async () => {
    if (nextStatus === "dead" && !(await confirmAction({ body: t("confirm.markDead", { host: session.hostname }) }))) {
      return;
    }
    await applySessionUi(session.id, "", nextStatus);
  });
  updateSessionControls();
}

function updateSessionControls() {
  const hasSession = !!state.activeSession;
  const runBtn = $("btn-run-command");
  const commandInput = $("terminal-command");
  if (runBtn) runBtn.disabled = !hasSession;
  if (commandInput) commandInput.disabled = !hasSession;
}

function updateStatusBar() {
  const count = (state.sessions ?? []).filter((session) => session.status !== "dead").length;
  const element = $("status-sessions");
  if (element) element.textContent = t("status.sessions", { n: count });
}

$("btn-refresh").addEventListener("click", refreshSessions);

// ---------- terminal ----------

function appendTerminal(text, cls = "") {
  const output = $("terminal-output");
  const line = document.createElement("div");
  line.className = `term-line ${cls}`;
  line.textContent = text;
  output.appendChild(line);
  output.scrollTop = output.scrollHeight;
}

const shellHistory = { entries: [], index: -1 };

async function runShell(command) {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  if (!command) return;
  appendTerminal(`$ ${command}`, "cmd");
  const result = await safeInvoke("shell", {
    sessionId: state.activeSession.id,
    command,
  });
  if (result.output) appendTerminal(result.output.trimEnd());
  if (result.exit_code !== 0) {
    appendTerminal(`[exit code ${result.exit_code}]`, "err");
  }
  appendTerminal("", "meta");
}

function rememberShellCommand(command) {
  const trimmed = command.trim();
  if (!trimmed) return;
  if (shellHistory.entries[shellHistory.entries.length - 1] !== trimmed) {
    shellHistory.entries.push(trimmed);
    if (shellHistory.entries.length > 200) shellHistory.entries.shift();
  }
  shellHistory.index = shellHistory.entries.length;
}

$("btn-run-command").addEventListener("click", async () => {
  const input = $("terminal-command");
  const command = input.value;
  input.value = "";
  rememberShellCommand(command);
  await runShell(command);
});

$("terminal-command").addEventListener("keydown", async (event) => {
  const input = $("terminal-command");
  if (event.key === "ArrowUp") {
    event.preventDefault();
    if (!shellHistory.entries.length) return;
    shellHistory.index = Math.max(0, shellHistory.index - 1);
    input.value = shellHistory.entries[shellHistory.index] ?? "";
    return;
  }
  if (event.key === "ArrowDown") {
    event.preventDefault();
    shellHistory.index = Math.min(shellHistory.entries.length, shellHistory.index + 1);
    input.value = shellHistory.entries[shellHistory.index] ?? "";
    return;
  }
  if (event.key === "Enter") {
    const command = input.value;
    input.value = "";
    rememberShellCommand(command);
    await runShell(command);
  }
});

document.querySelectorAll(".quick-actions button").forEach((button) => {
  button.addEventListener("click", async () => {
    if (!state.activeSession) {
      toast(t("msg.selectSession"), true);
      return;
    }
    const task = button.dataset.task;
    appendTerminal(`$ ${task}`, "cmd");
    const result = await safeInvoke("run_task", {
      sessionId: state.activeSession.id,
      kind: task,
      args: null,
    });
    if (result.output) appendTerminal(result.output.trimEnd());
    appendTerminal("", "meta");
  });
});

// ---------- file browser ----------

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function joinRemotePath(base, name) {
  const trimmed = (base ?? "").trim();
  if (trimmed === "" || trimmed === "." || trimmed === "./") return name;
  return `${trimmed.replace(/\/+$/, "")}/${name}`;
}

async function listFiles() {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const path = $("files-path").value.trim() || ".";
  const entries = await safeInvoke("fs_ls", {
    sessionId: state.activeSession.id,
    path,
  });
  if (!Array.isArray(entries)) {
    toast(t("files.listFailed"), true);
    return;
  }
  const rows = $("file-rows");
  rows.innerHTML = "";
  for (const entry of entries) {
    const tr = document.createElement("tr");
    const nameTd = document.createElement("td");
    const isDir = entry.is_dir;
    nameTd.textContent = isDir ? `📁 ${entry.name}` : entry.name;
    const typeTd = document.createElement("td");
    typeTd.textContent = isDir ? "dir" : "file";
    const sizeTd = document.createElement("td");
    sizeTd.className = "right";
    sizeTd.textContent = isDir ? "" : formatSize(entry.size);
    const actionTd = document.createElement("td");
    {
      const rename = document.createElement("button");
      rename.textContent = t("files.rename");
      rename.className = "ghost";
      rename.addEventListener("click", (event) => {
        event.stopPropagation();
        renameSelectedFile(entry, path);
      });
      actionTd.appendChild(rename);
      const remove = document.createElement("button");
      remove.textContent = t("files.delete");
      remove.className = "ghost";
      remove.addEventListener("click", (event) => {
        event.stopPropagation();
        deleteSelectedFile(entry, path);
      });
      actionTd.appendChild(remove);
    }
    if (isDir) {
      const open = document.createElement("button");
      open.textContent = t("files.open");
      open.className = "ghost";
      open.addEventListener("click", (event) => {
        event.stopPropagation();
        $("files-path").value = joinRemotePath(path, entry.name);
        listFiles();
      });
      actionTd.appendChild(open);
    }
    tr.append(nameTd, typeTd, sizeTd, actionTd);
    if (!isDir) {
      tr.addEventListener("click", async () => {
        document
          .querySelectorAll("#file-rows tr")
          .forEach((row) => row.classList.remove("selected"));
        tr.classList.add("selected");
        const full = joinRemotePath(path, entry.name);
        state.previewFile = full;
        $("preview-name").textContent = full;
        const result = await safeInvoke("fs_cat", {
          sessionId: state.activeSession.id,
          path: full,
        });
        $("preview-content").textContent =
          result.exit_code === 0 ? result.output : `cat failed: ${result.output}`;
      });
    }
    rows.appendChild(tr);
  }
}

$("btn-ls").addEventListener("click", listFiles);

async function runFileOp(kind, args, refresh = true) {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return null;
  }
  const result = await safeInvoke("run_task", {
    sessionId: state.activeSession.id,
    kind,
    args,
  });
  if (result.exit_code !== 0) {
    toast(result.output.trim() || t("files.opFailed"), true);
    return null;
  }
  if (refresh) listFiles();
  return result;
}

$("btn-mkdir").addEventListener("click", async () => {
  const name = window.prompt(t("files.newFolderName"));
  if (!name) return;
  const path = joinRemotePath($("files-path").value.trim() || ".", name);
  await runFileOp("mkdir", { path });
  toast(t("files.created", { path }));
});

async function deleteSelectedFile(entry, path) {
  const full = joinRemotePath(path, entry.name);
  if (!window.confirm(t("files.confirmDelete", { path: full }))) return;
  await runFileOp("rm", { path: full });
  toast(t("files.deleted", { path: full }));
}

async function renameSelectedFile(entry, path) {
  const full = joinRemotePath(path, entry.name);
  const target = window.prompt(t("files.renameTo"), entry.name);
  if (!target) return;
  const destination = joinRemotePath(path, target);
  await runFileOp("mv", { from: full, to: destination });
  toast(t("files.renamed", { path: destination }));
}

$("btn-download").addEventListener("click", async () => {
  if (!state.previewFile) {
    toast(t("files.selectFirst"), true);
    return;
  }
  const defaultPath = state.previewFile.split("/").pop();
  let local = await pickSave(defaultPath, "Save downloaded file");
  if (!local && lenientPathFallbackEnabled()) {
    local = window.prompt(t("msg.promptLocalPath"), defaultPath);
  }
  if (!local) return;
  const bytes = await safeInvoke("fs_download", {
    sessionId: state.activeSession.id,
    remote: state.previewFile,
    local,
  });
  toast(t("msg.downloaded", { bytes, path: local }));
});

$("btn-upload").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const local = await pickFile("File to upload to the target");
  if (!local) return;
  const base = $("files-path").value.trim().replace(/\/$/, "");
  const remote = window.prompt(t("msg.promptRemotePath"), `${base}/${local.split("/").pop()}`);
  if (!remote) return;
  const bytes = await safeInvoke("fs_upload", {
    sessionId: state.activeSession.id,
    local,
    remote,
  });
  toast(t("msg.uploaded", { bytes, path: remote }));
  listFiles();
});

// ---------- extensions ----------

$("btn-bof").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const file = $("bof-path").value.trim();
  const args = $("bof-args").value;
  const result = await safeInvoke("bof_run", {
    sessionId: state.activeSession.id,
    file,
    args,
  });
  toast(result.output.trim() || `BOF exit ${result.exit_code}`);
});

$("btn-wasm-load").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const name = $("wasm-name").value.trim();
  const file = $("wasm-path").value.trim();
  const result = await safeInvoke("wasm_load", {
    sessionId: state.activeSession.id,
    name,
    file,
  });
  toast(result.output.trim() || `exit ${result.exit_code}`);
});

$("btn-wasm-run").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const name = $("wasm-name").value.trim();
  const args = $("wasm-args").value;
  const result = await safeInvoke("wasm_run", {
    sessionId: state.activeSession.id,
    name,
    args,
  });
  toast(result.output.trim() || `exit ${result.exit_code}`);
});

$("btn-wasm-list").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const result = await safeInvoke("wasm_list", {
    sessionId: state.activeSession.id,
  });
  toast(result.trim() || t("msg.noExtensions"));
});

// ---------- tunnels ----------

$("btn-socks").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const message = await safeInvoke("socks_start", {
    sessionId: state.activeSession.id,
    listen: $("socks-listen").value.trim(),
  });
  toast(message);
});

$("btn-portfwd").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const message = await safeInvoke("portfwd_start", {
    sessionId: state.activeSession.id,
    listen: $("portfwd-listen").value.trim(),
    target: $("portfwd-target").value.trim(),
  });
  toast(message);
});

$("btn-rport").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const status = await safeInvoke("rportfwd_start", {
    sessionId: state.activeSession.id,
    bind: $("rport-bind").value.trim(),
    to: $("rport-to").value.trim(),
  });
  $("rport-id").value = status.forward_id;
  toast(`${status.message} (${status.forward_id})`);
});

$("btn-rport-stop").addEventListener("click", async () => {
  const forwardId = $("rport-id").value.trim();
  if (!forwardId) {
    toast(t("msg.enterForwardId"), true);
    return;
  }
  const status = await safeInvoke("rportfwd_stop", { forwardId });
  toast(status.message);
});

$("btn-pivots").addEventListener("click", async () => {
  const output = $("pivots-output");
  try {
    const forwards = await invoke("pivots");
    if (!forwards.length) {
      output.textContent = t("tun.noPivots");
      return;
    }
    output.textContent = forwards
      .map(
        (fwd) =>
          `${fwd.forward_id}  ${fwd.transport}  ${fwd.bind} -> ${fwd.to}  ` +
          `via ${fwd.session_id}  conns=${fwd.connections}`
      )
      .join("\n");
  } catch (err) {
    toast(String(err), true);
  }
});

$("btn-portscan").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const output = $("portscan-output");
  output.textContent = t("msg.scanning");
  try {
    const result = await invoke("portscan", {
      sessionId: state.activeSession.id,
      target: $("scan-target").value.trim(),
      ports: $("scan-ports").value.trim(),
      timeoutMs: 800,
      banner: true,
    });
    output.textContent = result.output.trim() || t("msg.noOutput");
  } catch (err) {
    output.textContent = "";
    toast(String(err), true);
  }
});

$("btn-screenshot").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  try {
    const shot = await invoke("screenshot", { sessionId: state.activeSession.id });
    const img = $("screenshot-img");
    img.src = `data:${shot.mime};base64,${shot.data_b64}`;
    img.classList.remove("hidden");
    toast(t("msg.captured", { size: formatSize(shot.size) }));
  } catch (err) {
    toast(String(err), true);
  }
});

// ---------- native extensions ----------

$("btn-native-load").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const name = $("native-name").value.trim();
  const localPath = $("native-path").value.trim();
  const result = await safeInvoke("native_load", {
    sessionId: state.activeSession.id,
    name,
    localPath,
  });
  toast(result.output.trim() || `exit ${result.exit_code}`);
});

$("btn-native-run").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const result = await safeInvoke("native_run", {
    sessionId: state.activeSession.id,
    name: $("native-name").value.trim(),
    args: $("native-args").value,
  });
  toast(result.output.trim() || `exit ${result.exit_code}`);
});

$("btn-native-list").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const result = await safeInvoke("native_list", {
    sessionId: state.activeSession.id,
  });
  toast(result.trim() || t("msg.noNative"));
});

$("btn-registry-list").addEventListener("click", async () => {
  const output = $("registry-output");
  try {
    const extensions = await invoke("extensions");
    if (!extensions.length) {
      output.textContent = "registry is empty";
      return;
    }
    output.textContent = extensions
      .map(
        (ext) =>
          `${ext.name} v${ext.version} [${ext.kind}/${ext.platform}] ` +
          `${formatSize(ext.size)} by ${ext.installed_by}`
      )
      .join("\n");
  } catch (err) {
    toast(String(err), true);
  }
});

$("btn-registry-push").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const name = $("registry-name").value.trim();
  if (!name) {
    toast(t("msg.requireExtensionName"), true);
    return;
  }
  const platform = state.activeSession.platform;
  try {
    const result = await invoke("extension_push", {
      sessionId: state.activeSession.id,
      name,
      platform,
    });
    toast(result.output.trim() || `exit ${result.exit_code}`);
  } catch (err) {
    toast(String(err), true);
  }
});

// ---------- team panel ----------

async function loadOperators() {
  const list = $("operator-list");
  list.innerHTML = "";
  try {
    const operators = await invoke("team_operators");
    if (!operators.length) {
      list.innerHTML = `<li class="muted">${t("team.noOperators")}</li>`;
      return;
    }
    for (const op of operators) {
      const li = document.createElement("li");
      li.innerHTML = `<span>${op.name}</span><span class="muted">${op.role}</span>`;
      list.appendChild(li);
    }
  } catch {
    list.innerHTML = `<li class="muted">${t("team.connectFirst")}</li>`;
  }
}

$("btn-op-add").addEventListener("click", async () => {
  const name = $("op-name").value.trim();
  const role = $("op-role").value;
  if (!name) {
    toast(t("msg.requireOperatorName"), true);
    return;
  }
  const result = await safeInvoke("team_operator_add", { name, role });
  toast(`operator created — token: ${result.token}`);
  $("op-name").value = "";
  loadOperators();
});

async function loadCredentials() {
  const list = $("cred-list");
  list.innerHTML = "";
  try {
    const credentials = await invoke("team_credentials");
    if (!credentials.length) {
      list.innerHTML = `<li class="muted">${t("team.noCredentials")}</li>`;
      return;
    }
    for (const cred of credentials) {
      const li = document.createElement("li");
      li.innerHTML = `<span>${cred.host || "-"} · ${cred.username}</span><span class="muted">${cred.kind}</span>`;
      list.appendChild(li);
    }
  } catch {
    list.innerHTML = `<li class="muted">${t("team.connectFirst")}</li>`;
  }
}

$("btn-cred-add").addEventListener("click", async () => {
  const host = $("cred-host").value.trim();
  const username = $("cred-user").value.trim();
  const secret = $("cred-secret").value;
  if (!username || !secret) {
    toast(t("msg.requireUsernameSecret"), true);
    return;
  }
  await safeInvoke("team_credential_add", {
    host,
    username,
    secret,
    kind: "password",
  });
  toast(t("msg.credentialStored"));
  $("cred-user").value = "";
  $("cred-secret").value = "";
  loadCredentials();
});

async function loadLoot() {
  const list = $("loot-list");
  list.innerHTML = "";
  try {
    const loot = await invoke("team_loot");
    if (!loot.length) {
      list.innerHTML = `<li class="muted">${t("team.noLoot")}</li>`;
      return;
    }
    for (const item of loot) {
      const li = document.createElement("li");
      li.innerHTML = `<span>${item.name}</span><span class="muted">${item.size} B</span>`;
      list.appendChild(li);
    }
  } catch {
    list.innerHTML = `<li class="muted">${t("team.connectFirst")}</li>`;
  }
}

$("btn-loot-add").addEventListener("click", async () => {
  const name = $("loot-name").value.trim();
  const file = $("loot-file").value.trim();
  if (!name || !file) {
    toast(t("msg.nameFileRequired"), true);
    return;
  }
  await safeInvoke("team_loot_add", { name, file, kind: "file" });
  toast(t("msg.lootStored"));
  loadLoot();
});

async function loadCanaries() {
  const list = $("canary-list");
  list.innerHTML = "";
  try {
    const canaries = await invoke("team_canaries");
    if (!canaries.length) {
      list.innerHTML = `<li class="muted">${t("team.noCanaries")}</li>`;
      return;
    }
    for (const canary of canaries) {
      const li = document.createElement("li");
      li.innerHTML = `<span>${canary.note || canary.kind}</span><span class="${canary.triggered ? "triggered" : "muted"}">${canary.triggered ? "TRIGGERED" : "armed"}</span>`;
      list.appendChild(li);
    }
  } catch {
    list.innerHTML = `<li class="muted">${t("team.connectFirst")}</li>`;
  }
}

$("btn-canary-add").addEventListener("click", async () => {
  const note = $("canary-note").value.trim();
  const token = await safeInvoke("team_canary_create", { kind: "http", note });
  toast(`canary created — token: ${token}`);
  loadCanaries();
});

$("btn-audit").addEventListener("click", async () => {
  const status = await safeInvoke("team_audit");
  const el = $("audit-status");
  el.textContent = status.valid
    ? `valid · ${status.entries} entries`
    : `BROKEN · ${status.message}`;
  el.classList.toggle("online", status.valid);
  el.classList.toggle("offline", !status.valid);
});

$("btn-report").addEventListener("click", async () => {
  const report = await safeInvoke("team_report");
  $("report-output").textContent = report;
  toast(t("msg.reportGenerated"));
});

function loadTeam() {
  loadOperators();
  loadCredentials();
  loadLoot();
  loadCanaries();
}

// ---------- navigation ----------

const VIEW_TARGETS = {
  sessions: "view-sessions",
  session: "view-session",
  "tab-listen": "tab-listen",
  "tab-payload": "tab-payload",
  "tab-profiles": "tab-profiles",
  "tab-extensions": "tab-extensions",
  "tab-scripts": "tab-scripts",
  "tab-graph": "tab-graph",
  "tab-team": "tab-team",
  "tab-events": "tab-events",
  "tab-chat": "tab-chat",
  "tab-copilot": "tab-copilot",
};

const SUBTAB_TARGETS = {
  terminal: "tab-terminal",
  files: "tab-files",
  processes: "tab-processes",
  tasks: "tab-tasks",
  tunnels: "tab-tunnels",
};

function showView(view) {
  const target = VIEW_TARGETS[view] ?? view;
  document.querySelectorAll(".rail-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.view === view);
  });
  document.querySelectorAll(".stage > .tab-page").forEach((pane) => {
    pane.classList.toggle("active", pane.id === target);
  });
  state.currentView = view;
  if (view === "sessions") refreshSessions().catch(() => {});
  if (view === "tab-listen") loadListeners();
  if (view === "tab-team") {
    loadTeam();
    loadWebhook();
  }
  if (view === "tab-payload") {
    refreshBuilderDefaults();
    refreshBuildListeners();
  }
  if (view === "tab-graph") renderGraph();
  if (view === "tab-chat") {
    loadChat();
    clearInterval(chatTimer);
    chatTimer = setInterval(loadChat, 5000);
  } else {
    clearInterval(chatTimer);
    chatTimer = null;
  }
  if (view === "tab-events") loadEvents();
  if (view === "tab-scripts") loadScripts();
  if (view === "tab-profiles") loadProfiles();
  if (view === "tab-copilot") loadCopilot();
}

function showSessionTab(subtab) {
  const target = SUBTAB_TARGETS[subtab] ?? subtab;
  document.querySelectorAll(".subtab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.subtab === subtab);
  });
  document.querySelectorAll(".substage > .tab-page").forEach((pane) => {
    pane.classList.toggle("active", pane.id === target);
  });
  state.sessionTab = subtab;
  if (subtab === "files") listFiles();
  if (subtab === "processes") loadProcesses();
  if (subtab === "tasks") loadTasks();
}

document.querySelectorAll(".rail-item").forEach((item) => {
  item.addEventListener("click", () => {
    showView(item.dataset.view);
  });
});

document.querySelectorAll(".subtab").forEach((tab) => {
  tab.addEventListener("click", () => showSessionTab(tab.dataset.subtab));
});

function openSessionWorkspace(session) {
  if (!session) {
    toast(t("msg.selectSession"), true);
    return;
  }
  state.activeSession = session;
  renderSessions(state.sessions ?? []);
  renderActiveSession();
  showView("session");
  showSessionTab(state.sessionTab ?? "terminal");
}

function closeSessionWorkspace() {
  showView("sessions");
}

function confirmAction({
  title = t("confirm.title"),
  body = "",
  ok = t("confirm.confirm"),
  danger = true,
} = {}) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "modal-overlay";
    overlay.innerHTML = `
      <div class="modal ${danger ? "danger" : ""}">
        <div class="modal-title">${copilotEscape(title)}</div>
        <div class="modal-body">${copilotEscape(body)}</div>
        <div class="modal-actions">
          <button class="ghost" id="modal-cancel">${copilotEscape(t("confirm.cancel"))}</button>
          <button class="${danger ? "danger" : "primary"}" id="modal-ok">${copilotEscape(ok)}</button>
        </div>
      </div>`;
    const finish = (value) => {
      overlay.remove();
      resolve(value);
    };
    overlay.querySelector("#modal-cancel").addEventListener("click", () => finish(false));
    overlay.querySelector("#modal-ok").addEventListener("click", () => finish(true));
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) finish(false);
    });
    document.addEventListener("keydown", function onKey(event) {
      if (event.key === "Escape") {
        document.removeEventListener("keydown", onKey);
        finish(false);
      }
    });
    document.body.appendChild(overlay);
  });
}

setInterval(() => {
  const clock = $("status-clock");
  if (clock) clock.textContent = new Date().toLocaleTimeString();
}, 1000);

// ---------- native file pickers ----------

function lenientPathFallbackEnabled() {
  return !nativeDialog;
}

document.querySelectorAll(".browse-btn").forEach((button) => {
  button.addEventListener("click", async () => {
    const target = $(button.dataset.target);
    if (!target) return;
    const value =
      button.dataset.kind === "dir"
        ? await pickDirectory()
        : await pickFile();
    if (value) target.value = value;
  });
});

// ---------- drag & drop onto path fields ----------

const pathInputs = Array.from(document.querySelectorAll(".path-input"));
let dropTarget = null;

for (const input of pathInputs) {
  input.addEventListener("focus", () => {
    dropTarget = input;
    pathInputs.forEach((i) => i.classList.toggle("drop-armed", i === input));
  });
  input.addEventListener("input", () => input.classList.remove("drop-armed"));
}

try {
  const webview = window.__TAURI__.webview.getCurrentWebview();
  webview.onDragDropEvent((event) => {
    const { type } = event.payload;
    if (type === "enter" || type === "over") {
      document.body.classList.add("dragging");
      return;
    }
    if (type === "leave") {
      document.body.classList.remove("dragging");
      return;
    }
    if (type !== "drop") return;
    document.body.classList.remove("dragging");
    const paths = event.payload.paths ?? [];
    if (!paths.length) return;
    const target = dropTarget ?? pathInputs.find((i) => i.classList.contains("drop-armed"));
    if (!target) {
      toast(t("msg.dropHint"), true);
      return;
    }
    target.value = paths[0];
    target.classList.remove("drop-armed");
    toast(t("msg.attached", { name: paths[0].split("/").pop(), field: target.dataset.dropLabel ?? target.id }));
  });
} catch {
  // drag & drop events are unavailable outside the Tauri runtime
}

// ---------- scripts ----------

function appendScriptOutput(text) {
  const output = $("script-output");
  output.textContent += `${text}\n`;
  output.scrollTop = output.scrollHeight;
}

async function loadScripts() {
  const list = $("script-list");
  try {
    const scripts = await invoke("scripts_list");
    list.innerHTML = "";
    for (const script of scripts) {
      const li = document.createElement("li");
      li.innerHTML = `<span>${escapeHtml(script.name)}</span><span class="muted">${formatSize(script.size)}</span>`;
      li.addEventListener("click", () => openScript(script.name));
      list.appendChild(li);
    }
  } catch (err) {
    toast(String(err), true);
  }
}

async function openScript(name) {
  try {
    const content = await invoke("scripts_read", { name });
    $("script-code").value = content;
    $("script-name").value = name;
    $("script-output").textContent = "";
  } catch (err) {
    toast(String(err), true);
  }
}

function scriptApi() {
  return {
    sessions: () => invoke("sessions"),
    run: (sessionId, kind, args) => invoke("run_task", { sessionId, kind, args: args ?? {} }),
    listeners: () => invoke("listeners"),
    startListener: (kind, addr, dnsZone = "") =>
      invoke("listener_start", { kind, addr, dnsZone }),
    stopListener: (id) => invoke("listener_stop", { id }),
    pivots: () => invoke("pivots"),
    chat: () => invoke("chat_list"),
    sendChat: (message) => invoke("chat_send", { message }),
    toast: (message) => toast(String(message)),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  };
}

$("btn-script-run").addEventListener("click", async () => {
  const code = $("script-code").value;
  if (!code.trim()) return;
  const output = $("script-output");
  output.textContent = "";
  appendScriptOutput(`▶ ${t("scripts.running")}`);
  const consoleProxy = {
    log: (...args) =>
      appendScriptOutput(
        args
          .map((arg) => (typeof arg === "string" ? arg : JSON.stringify(arg)))
          .join(" ")
      ),
    error: (...args) => appendScriptOutput(`error: ${args.join(" ")}`),
  };
  try {
    const fn = new AsyncFunction("shikra", "console", code);
    await fn(scriptApi(), consoleProxy);
    appendScriptOutput(`✔ ${t("scripts.done")}`);
  } catch (err) {
    appendScriptOutput(`✖ ${err}`);
    toast(String(err), true);
  }
});

$("btn-script-save").addEventListener("click", async () => {
  const name = $("script-name").value.trim();
  if (!name) {
    toast(t("scripts.nameRequired"), true);
    return;
  }
  try {
    await invoke("scripts_write", { name, content: $("script-code").value });
    toast(t("scripts.saved", { name }));
    loadScripts();
  } catch (err) {
    toast(String(err), true);
  }
});

$("btn-script-new").addEventListener("click", () => {
  $("script-name").value = "";
  $("script-code").value = "";
  $("script-output").textContent = "";
  $("script-name").focus();
});

$("btn-script-delete").addEventListener("click", async () => {
  const name = $("script-name").value.trim();
  if (!name) return;
  if (!(await confirmAction({ body: t("scripts.confirmDelete", { name }) }))) return;
  try {
    await invoke("scripts_delete", { name });
    $("script-name").value = "";
    $("script-code").value = "";
    loadScripts();
  } catch (err) {
    toast(String(err), true);
  }
});

$("btn-script-import").addEventListener("click", async () => {
  const file = await pickFile(t("scripts.import"));
  if (!file) return;
  try {
    const content = await invoke("read_text", { path: file });
    $("script-code").value = content;
    const base = file.split("/").pop().replace(/\.js$/, "");
    $("script-name").value = base;
  } catch (err) {
    toast(String(err), true);
  }
});

$("btn-script-export").addEventListener("click", async () => {
  const name = $("script-name").value.trim() || "script";
  const path = await pickSave(`${name}.js`, t("scripts.export"));
  if (!path) return;
  try {
    const saved = await invoke("write_text", { path, contents: $("script-code").value });
    toast(t("session.exported", { path: saved }));
  } catch (err) {
    toast(String(err), true);
  }
});

// ---------- team chat ----------

const SESSION_COLORS = [
  "#f87171", "#fb923c", "#fbbf24", "#34d399",
  "#38bdf8", "#a78bfa", "#f472b6", "#94a3b8",
];

let chatTimer = null;

function formatClock(unixSeconds) {
  if (!unixSeconds) return "";
  const date = new Date(unixSeconds * 1000);
  return date.toLocaleTimeString();
}

async function loadChat() {
  const container = $("chat-messages");
  try {
    const messages = await invoke("chat_list");
    container.innerHTML = messages
      .map((message) => {
        const mine = message.operator === state.operatorName;
        return `<div class="chat-row ${mine ? "mine" : ""}">
          <span class="chat-meta">${escapeHtml(message.operator)} · ${formatClock(message.created_at)}</span>
          <div class="chat-bubble">${escapeHtml(message.message)}</div>
        </div>`;
      })
      .join("");
    container.scrollTop = container.scrollHeight;
  } catch {
    container.innerHTML = `<p class="muted">${t("chat.connectFirst")}</p>`;
  }
}

async function sendChat() {
  const input = $("chat-input");
  const message = input.value.trim();
  if (!message) return;
  input.value = "";
  try {
    await invoke("chat_send", { message });
    await loadChat();
  } catch (err) {
    toast(String(err), true);
  }
}

$("btn-chat-send").addEventListener("click", sendChat);
$("chat-input").addEventListener("keydown", (event) => {
  if (event.key === "Enter") sendChat();
});

// ---------- event feed ----------

async function loadEvents() {
  const list = $("event-list");
  try {
    const events = await invoke("events_list");
    list.innerHTML = events
      .map((event) => {
        const severity = event.kind.includes("failed")
          ? "error"
          : event.kind.includes("registered") || event.kind.includes("started")
            ? "ok"
            : "info";
        return `<div class="event-row ${severity}">
          <span class="event-time">${formatClock(event.occurred_at)}</span>
          <span class="event-kind">${escapeHtml(event.kind)}</span>
          <span class="event-payload">${escapeHtml(event.payload)}</span>
        </div>`;
      })
      .join("");
  } catch {
    list.innerHTML = `<p class="muted">${t("events.connectFirst")}</p>`;
  }
}

$("btn-events-refresh").addEventListener("click", loadEvents);

// ---------- session context menu ----------

function hideSessionMenu() {
  $("session-menu").classList.add("hidden");
}

async function applySessionUi(sessionId, color, status) {
  try {
    await invoke("session_set_ui", {
      sessionId,
      color: color ?? "",
      operatorStatus: status ?? "",
    });
    await refreshSessions();
  } catch (err) {
    toast(String(err), true);
  }
}

async function exportSession(session) {
  const path = await pickSave(`${session.hostname || session.id}.json`, t("session.exportTitle"));
  if (!path) return;
  try {
    const saved = await invoke("write_text", {
      path,
      contents: JSON.stringify(session, null, 2),
    });
    toast(t("session.exported", { path: saved }));
  } catch (err) {
    toast(String(err), true);
  }
}

function showSessionMenu(event, session) {
  event.preventDefault();
  const menu = $("session-menu");
  menu.innerHTML = `
    <div class="menu-label">${t("session.color")}</div>
    <div class="menu-colors">${SESSION_COLORS.map(
      (color) => `<span class="menu-color" data-color="${color}" style="background:${color}"></span>`
    ).join("")}</div>
    <button class="menu-item" data-action="clear-color">${t("session.colorClear")}</button>
    <button class="menu-item" data-action="${session.status === "dead" ? "alive" : "dead"}">
      ${session.status === "dead" ? t("session.markAlive") : t("session.markDead")}
    </button>
    <button class="menu-item" data-action="export">${t("session.export")}</button>
  `;
  menu.classList.remove("hidden");
  const rect = menu.getBoundingClientRect();
  const x = Math.min(event.clientX, window.innerWidth - rect.width - 8);
  const y = Math.min(event.clientY, window.innerHeight - rect.height - 8);
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;

  menu.querySelectorAll(".menu-color").forEach((swatch) => {
    swatch.addEventListener("click", async () => {
      hideSessionMenu();
      await applySessionUi(session.id, swatch.dataset.color, "");
    });
  });
  menu.querySelectorAll(".menu-item").forEach((item) => {
    item.addEventListener("click", async () => {
      hideSessionMenu();
      const action = item.dataset.action;
      if (action === "clear-color") await applySessionUi(session.id, "", "");
      else if (action === "dead") {
        if (await confirmAction({ body: t("confirm.markDead", { host: session.hostname }) })) {
          await applySessionUi(session.id, "", "dead");
        }
      } else if (action === "alive") await applySessionUi(session.id, "", "alive");
      else if (action === "export") await exportSession(session);
    });
  });
}

document.addEventListener("click", hideSessionMenu);

// ---------- webhook ----------

async function loadWebhook() {
  try {
    const url = await invoke("webhook_get");
    $("webhook-url").value = url;
  } catch {
    $("webhook-url").value = "";
  }
}

$("btn-webhook-save").addEventListener("click", async () => {
  try {
    toast(await invoke("webhook_set", { url: $("webhook-url").value.trim() }));
  } catch (err) {
    toast(String(err), true);
  }
});

$("btn-webhook-clear").addEventListener("click", async () => {
  try {
    $("webhook-url").value = "";
    toast(await invoke("webhook_set", { url: "" }));
  } catch (err) {
    toast(String(err), true);
  }
});

// ---------- process browser ----------

let processCache = [];

async function loadProcesses() {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const result = await safeInvoke("run_task", {
    sessionId: state.activeSession.id,
    kind: "procs",
    args: {},
  });
  if (!result || result.exit_code !== 0) {
    toast(result?.output?.trim() || t("procs.failed"), true);
    return;
  }
  try {
    processCache = JSON.parse(result.output);
  } catch {
    processCache = [];
  }
  renderProcesses();
}

function renderProcesses() {
  const rows = $("proc-rows");
  const filter = $("proc-filter").value.trim().toLowerCase();
  rows.innerHTML = "";
  const visible = processCache.filter((proc) => {
    if (!filter) return true;
    return (
      (proc.name ?? "").toLowerCase().includes(filter) ||
      (proc.user ?? "").toLowerCase().includes(filter) ||
      String(proc.pid).includes(filter)
    );
  });
  const sorted = visible.slice().sort((a, b) => a.pid - b.pid);
  for (const proc of sorted) {
    const tr = document.createElement("tr");
    const indent = $("procs-tree").checked ? "　".repeat(depthOf(proc.pid)) : "";
    tr.innerHTML = `
      <td>${proc.pid}</td>
      <td>${proc.ppid || ""}</td>
      <td>${indent}${escapeHtml(proc.name ?? "")}</td>
      <td>${escapeHtml(proc.user ?? "")}</td>
      <td class="right"></td>
    `;
    const actions = tr.lastElementChild;
    const kill = document.createElement("button");
    kill.className = "ghost";
    kill.textContent = t("procs.kill");
    kill.addEventListener("click", async (event) => {
      event.stopPropagation();
      await safeInvoke("run_task", {
        sessionId: state.activeSession.id,
        kind: "kill",
        args: { pid: proc.pid },
      });
      toast(t("procs.killed", { pid: proc.pid }));
      loadProcesses();
    });
    actions.appendChild(kill);
    if (state.activeSession.platform === "windows") {
      const migrate = document.createElement("button");
      migrate.className = "ghost";
      migrate.textContent = t("procs.migrate");
      migrate.addEventListener("click", async (event) => {
        event.stopPropagation();
        const result = await safeInvoke("run_task", {
          sessionId: state.activeSession.id,
          kind: "migrate",
          args: { pid: proc.pid },
        });
        toast(result.output.trim() || t("procs.migrateQueued", { pid: proc.pid }));
      });
      actions.appendChild(migrate);
    }
    tr.addEventListener("click", () => {
      $("proc-detail").textContent = proc.name ?? "";
      $("proc-detail-body").textContent = [
        `pid:  ${proc.pid}`,
        `ppid: ${proc.ppid || "-"}`,
        `name: ${proc.name}`,
        `user: ${proc.user || "-"}`,
        `arch: ${proc.architecture || "-"}`,
      ].join("\n");
    });
    rows.appendChild(tr);
  }
}

function depthOf(pid) {
  let depth = 0;
  let current = processCache.find((proc) => proc.pid === pid);
  const seen = new Set();
  while (current && current.ppid && depth < 8) {
    if (seen.has(current.pid)) break;
    seen.add(current.pid);
    current = processCache.find((proc) => proc.pid === current.ppid);
    if (!current) break;
    depth += 1;
  }
  return depth;
}

function escapeHtml(text) {
  return text.replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[ch]);
}

$("btn-procs-refresh").addEventListener("click", loadProcesses);

$("btn-reflect-dll").addEventListener("click", async () => {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const file = await pickFile(t("procs.reflectPick"));
  if (!file) return;
  if (!(await confirmAction({ body: t("confirm.reflectDll", { file: file.split("/").pop() }) }))) {
    return;
  }
  try {
    const result = await invoke("reflect_dll", {
      sessionId: state.activeSession.id,
      localPath: file,
    });
    toast(result.output.trim() || `exit ${result.exit_code}`);
  } catch (err) {
    toast(String(err), true);
  }
});
$("proc-filter").addEventListener("input", renderProcesses);
$("procs-tree").addEventListener("change", renderProcesses);

// ---------- tasks ----------

async function cancelTask(taskId) {
  if (!state.activeSession) return;
  if (!(await confirmAction({ body: t("confirm.cancelTask", { id: taskId.slice(0, 8) }) }))) {
    return;
  }
  try {
    toast(await invoke("task_cancel", {
      sessionId: state.activeSession.id,
      taskId,
    }));
    loadTasks();
  } catch (err) {
    toast(String(err), true);
  }
}

async function loadTasks() {
  if (!state.activeSession) {
    toast(t("msg.selectSession"), true);
    return;
  }
  const rows = $("task-rows");
  try {
    const tasks = await invoke("tasks_list", { sessionId: state.activeSession.id });
    rows.innerHTML = "";
    for (const task of tasks) {
      const tr = document.createElement("tr");
      const cancellable = task.state === "dispatched" || task.state === "running";
      tr.innerHTML = `
        <td><span class="badge task-${task.state}">${t(`tasks.state_${task.state}`)}</span></td>
        <td>${escapeHtml(task.command)}</td>
        <td class="muted">${formatClock(task.created_at)}</td>
        <td class="right">${task.exit_code ?? ""}</td>
        <td class="right"></td>
      `;
      if (cancellable) {
        const cancel = document.createElement("button");
        cancel.className = "ghost";
        cancel.textContent = t("tasks.cancel");
        cancel.addEventListener("click", (event) => {
          event.stopPropagation();
          cancelTask(task.id);
        });
        tr.lastElementChild.appendChild(cancel);
      }
      tr.addEventListener("click", () => {
        $("task-output").textContent = `# ${task.command} (${task.id})

${task.output ?? ""}`;
      });
      rows.appendChild(tr);
    }
    if (!tasks.length) {
      rows.innerHTML = `<tr><td colspan="5" class="muted">${t("tasks.empty")}</td></tr>`;
    }
  } catch (err) {
    toast(String(err), true);
  }
}

$("btn-tasks-refresh").addEventListener("click", loadTasks);

// ---------- pivot graph ----------

async function renderGraph() {
  const canvas = $("graph-canvas");
  canvas.innerHTML = "";
  let sessions = [];
  let pivots = [];
  try {
    sessions = await invoke("sessions");
    pivots = await invoke("pivots");
  } catch {
    canvas.innerHTML = `<p class="muted">${t("graph.connectFirst")}</p>`;
    return;
  }
  const width = canvas.clientWidth || 900;
  const nodeW = 150;
  const nodeH = 54;
  const perRow = Math.max(1, Math.floor((width - 40) / (nodeW + 30)));
  const positions = new Map();
  const nodes = [];
  nodes.push({ id: "__server", x: width / 2 - nodeW / 2, y: 20, label: "teamserver", kind: "server" });
  sessions.forEach((session, index) => {
    const row = Math.floor(index / perRow);
    const col = index % perRow;
    const x = 20 + col * (nodeW + 30);
    const y = 130 + row * (nodeH + 70);
    positions.set(session.id, { x: x + nodeW / 2, y: y + nodeH / 2 });
    nodes.push({ id: session.id, x, y, label: session.hostname || session.id.slice(0, 8), kind: "session", session });
  });
  const height = 130 + Math.ceil(sessions.length / perRow) * (nodeH + 70) + 60;
  const svg = [];
  svg.push(`<svg viewBox="0 0 ${width} ${height}" width="100%" height="${height}" xmlns="http://www.w3.org/2000/svg">`);
  for (const session of sessions) {
    const pos = positions.get(session.id);
    svg.push(
      `<line x1="${width / 2}" y1="${20 + nodeH}" x2="${pos.x}" y2="${pos.y - nodeH / 2}" class="graph-edge" />`
    );
  }
  for (const pivot of pivots) {
    const parent = positions.get(pivot.session_id);
    if (!parent) continue;
    const targetY = parent.y + 84;
    svg.push(
      `<line x1="${parent.x}" y1="${parent.y + nodeH / 2}" x2="${parent.x}" y2="${targetY}" class="graph-edge pivot" />`,
      `<circle cx="${parent.x}" cy="${targetY}" r="4" class="graph-pivot-dot" />`,
      `<text x="${parent.x + 10}" y="${targetY + 4}" class="graph-pivot-label">${escapeHtml(pivot.transport)} ${escapeHtml(pivot.bind)} → ${escapeHtml(pivot.to)} (${pivot.connections})</text>`
    );
  }
  for (const node of nodes) {
    const cls = node.kind === "server" ? "graph-node server" : `graph-node ${node.session.kind} health-${sessionHealth(node.session)}`;
    const sub = node.kind === "server" ? "" : `${node.session.username || ""} · ${platformIcon(node.session.platform)}`;
    svg.push(
      `<g class="${cls}" data-session="${node.id}" transform="translate(${node.x},${node.y})">`,
      `<rect width="${nodeW}" height="${nodeH}" rx="9" />`,
      `<text x="12" y="22" class="graph-node-title">${escapeHtml(node.label)}</text>`,
      `<text x="12" y="40" class="graph-node-sub">${sub}</text>`,
      `</g>`
    );
  }
  svg.push("</svg>");
  canvas.innerHTML = svg.join("");
  canvas.querySelectorAll("g.graph-node[data-session]").forEach((group) => {
    group.addEventListener("click", () => {
      const id = group.dataset.session;
      const session = sessions.find((item) => item.id === id);
      if (!session) return;
      state.activeSession = session;
      renderSessions(state.sessions ?? []);
      renderActiveSession();
      toast(t("graph.selected", { host: session.hostname || id.slice(0, 8) }));
    });
  });
}

$("btn-graph-refresh").addEventListener("click", renderGraph);

// ---------- listeners ----------

const LISTENER_DEFAULTS = {
  http: "0.0.0.0:8080",
  quic: "0.0.0.0:8444",
  dns: "0.0.0.0:5353",
  wireguard: "0.0.0.0:51820",
};

function applyListenerKindVisibility() {
  $("listen-zone-row").classList.toggle("hidden", $("listen-kind").value !== "dns");
}

$("listen-kind").addEventListener("change", () => {
  $("listen-addr").value = LISTENER_DEFAULTS[$("listen-kind").value] ?? "";
  applyListenerKindVisibility();
});

function listenerPayloadTarget(listener) {
  const [host, port] = listener.addr.split(":");
  const reachable =
    host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
  return { host: reachable, port };
}

async function loadListeners() {
  const list = $("listener-list");
  try {
    const listeners = await invoke("listeners");
    const badge = $("badge-listeners");
    if (badge) badge.textContent = listeners.length || "";
    const statusListeners = $("status-listeners");
    if (statusListeners) statusListeners.textContent = t("status.listeners", { n: listeners.length });
    list.innerHTML = "";
    if (!listeners.length) {
      list.innerHTML = `<p class="muted">${t("listen.empty")}</p>`;
      return;
    }
    for (const listener of listeners) {
      const card = document.createElement("div");
      card.className = "listener-row";
      card.innerHTML = `
        <div class="listener-main">
          <span class="listener-kind">${copilotEscape(listener.kind)}</span>
          <code>${copilotEscape(listener.addr)}</code>
          <span class="session-dot active"></span>
          <span class="muted listener-detail">${copilotEscape(listener.detail || "")}</span>
        </div>
        <div class="listener-actions">
          <button class="ghost use-btn">${t("listen.useForPayload")}</button>
          <button class="ghost stop-btn">${t("listen.stop")}</button>
        </div>
      `;
      card.querySelector(".use-btn").addEventListener("click", () => {
        const target = listenerPayloadTarget(listener);
        if (listener.kind === "http") {
          $("build-http").value = `http://${target.host}:${target.port}`;
        } else if (listener.kind === "quic") {
          $("build-http").value = `quic://${target.host}:${target.port}`;
        } else if (listener.kind === "dns") {
          $("build-dns").value = `${target.host}:${target.port}`;
          $("build-dns-zone").value = (listener.detail || "").replace("zone ", "") || "dns.shikra";
        } else if (listener.kind === "wireguard") {
          $("build-wg").value = `${target.host}:${target.port}`;
          $("build-wg-key").value = listener.detail || "";
        }
        toast(t("listen.copied", { kind: listener.kind }));
      });
      card.querySelector(".stop-btn").addEventListener("click", async () => {
        if (
          !(await confirmAction({
            body: t("confirm.stopListener", { kind: listener.kind, addr: listener.addr }),
          }))
        ) {
          return;
        }
        try {
          toast(await invoke("listener_stop", { id: listener.id }));
          loadListeners();
          refreshBuildListeners();
        } catch (err) {
          toast(String(err), true);
        }
      });
      list.appendChild(card);
    }
  } catch (err) {
    list.innerHTML = `<p class="muted">${t("listen.connectFirst")}</p>`;
  }
}

$("btn-listeners-refresh").addEventListener("click", loadListeners);
$("btn-listener-start").addEventListener("click", async () => {
  const kind = $("listen-kind").value;
  const addr = $("listen-addr").value.trim();
  if (!addr) {
    toast(t("listen.requireAddr"), true);
    return;
  }
  try {
    const listener = await invoke("listener_start", {
      kind,
      addr,
      dnsZone: $("listen-zone").value.trim(),
    });
    toast(t("listen.started", { kind: listener.kind, addr: listener.addr }));
    loadListeners();
    refreshBuildListeners();
  } catch (err) {
    toast(String(err), true);
  }
});

applyListenerKindVisibility();

// ---------- payload builder ----------

function applyBuilderVisibility() {
  const mode = $("build-mode")?.value ?? "beacon";
  document.querySelectorAll(".mode-field").forEach((el) => {
    el.classList.toggle("hidden", !(el.dataset.modes ?? "").split(",").includes(mode));
  });
  const stager = $("build-stager")?.checked ?? false;
  document.querySelectorAll(".mode-stager").forEach((el) => {
    el.classList.toggle("hidden", !stager);
  });
}

async function autofillMaterialFromCa(announce = false) {
  const caPath = $("build-ca").value.trim();
  if (!caPath) return;
  try {
    const siblings = await invoke("material_siblings", { caPath });
    let filled = [];
    if (siblings.enrollTokenFile && !$("build-token").value.trim()) {
      $("build-token").value = siblings.enrollTokenFile;
      filled.push("enroll.token");
    }
    if (siblings.serverIdentityFile && !$("build-identity").value.trim()) {
      $("build-identity").value = siblings.serverIdentityFile;
      filled.push("server-identity.pub");
    }
    if (filled.length && announce) {
      toast(t("build.autofilled", { name: filled.join(", ") }));
    }
  } catch {
    /* not a local path */
  }
}

async function refreshBuilderDefaults() {
  if (nativePath && !$("build-output").value.trim()) {
    try {
      const home = await nativePath.homeDir();
      $("build-output").value = `${home}/shikra-builds`;
    } catch {
      $("build-output").value = "./builds";
    }
  }
  try {
    const info = await invoke("connection_info");
    if (info) {
      if (!$("build-c2").value.trim()) $("build-c2").value = info.endpoint;
      if (!$("build-ca").value.trim()) $("build-ca").value = info.ca_path;
      await autofillMaterialFromCa();
      if (!$("build-http").value.trim()) {
        try {
          const host = new URL(info.endpoint).hostname;
          $("build-http").value = `http://${host}:8080`;
        } catch {
          /* leave empty */
        }
      }
    }
  } catch {
    // not connected yet
  }
}

$("build-mode").addEventListener("change", applyBuilderVisibility);
$("build-ca").addEventListener("change", () => autofillMaterialFromCa(true));
$("build-stager").addEventListener("change", () => {
  state.stageUrlManual = false;
  autoFillStageUrl(true);
});
$("build-name").addEventListener("input", () => autoFillStageUrl());
$("build-http").addEventListener("input", () => autoFillStageUrl());
$("build-stage-url").addEventListener("input", () => {
  state.stageUrlManual = $("build-stage-url").value.trim() !== "";
});
$("build-stager").addEventListener("change", applyBuilderVisibility);

function killdateUnix() {
  const value = $("build-killdate").value;
  if (!value) return null;
  const millis = new Date(value).getTime();
  if (Number.isNaN(millis)) return null;
  return Math.floor(millis / 1000);
}

async function refreshBuildListeners() {
  const select = $("build-listener");
  const previous = select.value;
  let listeners = [];
  try {
    listeners = await invoke("listeners");
  } catch {
    listeners = [];
  }
  select.innerHTML = "";
  const manual = document.createElement("option");
  manual.value = "";
  manual.textContent = t("build.listenerManual");
  select.appendChild(manual);
  for (const listener of listeners) {
    const option = document.createElement("option");
    option.value = listener.id;
    option.dataset.kind = listener.kind;
    option.dataset.addr = listener.addr;
    option.dataset.detail = listener.detail ?? "";
    option.textContent = `${listener.kind} · ${listener.addr}`;
    select.appendChild(option);
  }
  if (listeners.length === 0) {
    const none = document.createElement("option");
    none.value = "__none";
    none.disabled = true;
    none.textContent = t("build.listenerNone");
    select.appendChild(none);
  }
  if (previous && listeners.some((listener) => listener.id === previous)) {
    select.value = previous;
  }
}

function autoFillStageUrl(force = false) {
  const input = $("build-stage-url");
  if (!$("build-stager").checked) return;
  if (state.stageUrlManual && !force) return;
  const name = $("build-name").value.trim() || "beacon";
  const http = $("build-http").value.trim();
  try {
    const url = new URL(http);
    input.value = `http://${url.hostname}:${url.port || 80}/cdn/${name}.stage`;
  } catch {
    /* no usable HTTP URL yet */
  }
}

function applyListenerToBuilder(option) {
  if (!option || !option.dataset.kind) return;
  const [host, port] = option.dataset.addr.split(":");
  const reachable = host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
  const kind = option.dataset.kind;
  if (kind === "http") {
    $("build-mode").value = "beacon";
    $("build-http").value = `http://${reachable}:${port}`;
  } else if (kind === "quic") {
    $("build-mode").value = "quic";
    $("build-quic").value = `${reachable}:${port}`;
  } else if (kind === "dns") {
    $("build-mode").value = "dns";
    $("build-dns").value = `${reachable}:${port}`;
    const zone = (option.dataset.detail || "").replace("zone ", "");
    if (zone) $("build-dns-zone").value = zone;
  } else if (kind === "wireguard") {
    $("build-mode").value = "wireguard";
    $("build-wg").value = `${reachable}:${port}`;
    $("build-wg-key").value = option.dataset.detail ?? "";
  } else {
    toast(t("build.listenerUnsupported", { kind }), true);
    return;
  }
  applyBuilderVisibility();
  autoFillStageUrl();
  toast(t("build.listenerUsed", { kind, addr: option.dataset.addr }));
}

$("build-listener").addEventListener("change", (event) => {
  applyListenerToBuilder(event.target.selectedOptions[0]);
});

function localPort(raw, scheme) {
  try {
    if (scheme === "url") {
      const parsed = new URL(raw);
      const host = parsed.hostname;
      if (!["127.0.0.1", "localhost", "0.0.0.0", "::1"].includes(host)) return null;
      return Number(parsed.port);
    }
    const [host, port] = raw.trim().split(":");
    if (!["127.0.0.1", "localhost", "0.0.0.0", "::1"].includes(host)) return null;
    return Number(port);
  } catch {
    return null;
  }
}

async function ensureLocalListener(options) {
  if (options.mode === "session") return true;
  const raw =
    options.mode === "beacon"
      ? options.httpUrl
      : options.mode === "quic"
        ? options.quicUrl
        : options.mode === "dns"
          ? options.dnsUrl
          : options.wgUrl;
  const port = localPort(raw, options.mode === "beacon" ? "url" : "addr");
  if (!port) return true;
  const kind =
    options.mode === "beacon"
      ? "http"
      : options.mode === "quic"
        ? "quic"
        : options.mode === "dns"
          ? "dns"
          : "wireguard";
  let listeners = [];
  try {
    listeners = await invoke("listeners");
  } catch {
    return true;
  }
  const match = listeners.some((listener) => {
    if (listener.kind !== kind) return false;
    const [, lport] = listener.addr.split(":");
    return Number(lport) === port;
  });
  if (!match) {
    toast(t("build.listenerMissing", { kind, addr: raw }), true);
    return false;
  }
  return true;
}

function builderOptions() {
  const numberOrNull = (id) => {
    const value = $(id).value.trim();
    return value === "" ? null : Number(value);
  };
  return {
    name: $("build-name").value.trim(),
    mode: $("build-mode").value,
    c2Url: $("build-c2").value.trim(),
    httpUrl: $("build-http").value.trim(),
    quicUrl: $("build-quic").value.trim(),
    dnsUrl: $("build-dns").value.trim(),
    dnsZone: $("build-dns-zone").value.trim(),
    wgUrl: $("build-wg").value.trim(),
    wgServerPublic: $("build-wg-key").value.trim(),
    tlsDomain: $("build-tls-domain").value.trim(),
    heartbeatSecs: numberOrNull("build-heartbeat"),
    jitterSecs: numberOrNull("build-jitter"),
    pollIntervalSecs: numberOrNull("build-poll"),
    obfSeed: $("build-seed").value.trim(),
    noObfuscation: $("build-no-obf").checked,
    release: $("build-release").checked,
    useServerProfiles: $("build-use-profiles").checked,
    outputDir: $("build-output").value.trim(),
    caCert: $("build-ca").value.trim(),
    enrollTokenFile: $("build-token").value.trim(),
    serverIdentityFile: $("build-identity").value.trim(),
    target: $("build-target").value.trim(),
    stager: $("build-stager").checked,
    stageUrl: $("build-stage-url").value.trim(),
    stageArgs: $("build-stage-args").value.trim(),
    killdateUnix: killdateUnix(),
    workingHours: $("build-working-hours").value.trim(),
    replaceStrings: $("build-replace-strings").value
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean),
    peTimestamp: $("build-pe-timestamp").value.trim(),
    serviceName: $("build-service-name").value.trim(),
    pipePath: $("build-pipe-path").value.trim(),
  };
}

function renderBuildResult(result) {
  const rows = [];
  const row = (label, value) => {
    if (value === undefined || value === null || value === "") return;
    rows.push(`<div class="result-row"><span>${label}</span><code>${value}</code></div>`);
  };
  const stageUrl = result.stage_path ? $("build-stage-url").value.trim() : "";
  row(t("build.artifact"), result.path);
  row(t("build.targetLabel"), result.target);
  row(t("build.size"), result.size ? `${(result.size / 1024 / 1024).toFixed(2)} MiB` : null);
  row(t("build.sha"), result.sha256);
  row(t("build.seedLabel"), result.obf_seed);
  row(t("build.stage"), result.stage_path);
  row(t("build.stagerLabel"), result.stager_path);
  row(t("build.stageUrlLabel"), stageUrl);
  let html = rows.join("");
  if (result.stage_path) {
    html += `<div class="row"><button id="btn-publish-stage" class="primary">${t("build.publishStage")}</button>
      <button id="btn-copy-stage-url" class="ghost">${t("build.copyStageUrl")}</button></div>`;
  }
  $("build-result").innerHTML = html;
  if (result.stage_path) {
    $("btn-publish-stage").addEventListener("click", () => publishStage(result));
    $("btn-copy-stage-url").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText($("build-stage-url").value.trim());
        toast(t("build.stageUrlCopied"));
      } catch {
        toast(t("msg.clipboardUnavailable"), true);
      }
    });
  }
}

async function publishStage(result) {
  const name = $("build-name").value.trim() || "beacon";
  const fileName = `${name}.stage`;
  let destDir = "";
  const stateDir = $("host-state-dir").value.trim() || state.consoleConfig?.host?.stateDir || "";
  if (stateDir) {
    destDir = `${stateDir.replace(/\/+$/, "")}/hosted`;
  } else {
    destDir = await pickDirectory(t("build.publishPickDir"));
    if (!destDir) return;
  }
  try {
    const published = await invoke("publish_stage", {
      sourcePath: result.stage_path,
      destDir,
      fileName,
    });
    toast(t("build.published", { path: published }));
  } catch (err) {
    toast(String(err), true);
  }
}

$("btn-build").addEventListener("click", async () => {
  const options = builderOptions();
  if (!options.name) {
    toast(t("build.requireName"), true);
    return;
  }
  if (!options.caCert) {
    toast(t("build.requireCa"), true);
    return;
  }
  if (!options.outputDir) {
    toast(t("build.requireOutput"), true);
    return;
  }
  if (options.stager && !options.stageUrl) {
    toast(t("build.requireStageUrl"), true);
    return;
  }
  if (!(await ensureLocalListener(options))) {
    return;
  }
  const status = $("build-status");
  const button = $("btn-build");
  status.textContent = t("build.building");
  status.className = "status warn";
  button.disabled = true;
  try {
    const result = await invoke("build_payload", { options });
    status.textContent = t("build.complete");
    status.className = "status online";
    renderBuildResult(result);
    $("build-log").textContent = result.log ?? "";
    toast(t("build.built", { path: result.path ?? options.name }));
  } catch (err) {
    status.textContent = t("build.failed");
    status.className = "status offline";
    $("build-log").textContent = String(err);
    toast(t("build.failedToast"), true);
  } finally {
    button.disabled = false;
  }
});

$("btn-build-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(JSON.stringify(builderOptions(), null, 2));
    toast(t("build.optionsCopied"));
  } catch {
    toast(t("msg.clipboardUnavailable"), true);
  }
});

// ---------- C2 profiles ----------

function headerLines(headers) {
  return Object.entries(headers ?? {})
    .map(([name, value]) => `${name}: ${value}`)
    .join("\n");
}

function parseHeaderLines(text) {
  const out = {};
  for (const line of (text ?? "").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const index = trimmed.indexOf(":");
    if (index <= 0) continue;
    out[trimmed.slice(0, index).trim()] = trimmed.slice(index + 1).trim();
  }
  return out;
}

function profileCard(profile = {}) {
  const card = document.createElement("div");
  card.className = "card profile-card";
  card.innerHTML = `
    <div class="profile-head">
      <input class="profile-name" data-field="name" value="${profile.name ?? "profile"}" spellcheck="false" />
      <button class="ghost profile-remove" title="${t("profiles.remove")}">✕</button>
    </div>
    <div class="grid-2">
      <label>${t("profiles.enrollUri")}
        <input data-field="enroll_uri" value="${profile.enroll_uri ?? "/api/v1/enroll"}" spellcheck="false" />
      </label>
      <label>${t("profiles.pollUri")}
        <input data-field="poll_uri" value="${profile.poll_uri ?? "/api/v1/poll"}" spellcheck="false" />
      </label>
    </div>
    <label>${t("profiles.userAgent")}
      <input data-field="user_agent" value="${(profile.user_agent ?? "").replaceAll('"', "&quot;")}" spellcheck="false" />
    </label>
    <div class="grid-2">
      <label>${t("profiles.pollInterval")}
        <input type="number" min="1" data-field="poll_interval_secs" value="${profile.poll_interval_secs ?? 5}" />
      </label>
      <label>${t("profiles.jitter")}
        <input type="number" min="0" data-field="jitter_secs" value="${profile.jitter_secs ?? 3}" />
      </label>
    </div>
    <div class="grid-2">
      <label>${t("profiles.reqHeaders")}
        <textarea data-field="request_headers" rows="3" spellcheck="false">${headerLines(profile.request_headers)}</textarea>
      </label>
      <label>${t("profiles.respHeaders")}
        <textarea data-field="response_headers" rows="3" spellcheck="false">${headerLines(profile.response_headers)}</textarea>
      </label>
    </div>
  `;
  card.querySelector(".profile-remove").addEventListener("click", () => {
    if (document.querySelectorAll(".profile-card").length === 1) {
      toast(t("profiles.atLeastOne"), true);
      return;
    }
    card.remove();
  });
  return card;
}

async function loadProfiles() {
  const container = $("profile-cards");
  try {
    const profiles = await invoke("profiles");
    container.innerHTML = "";
    if (!profiles.length) {
      container.appendChild(profileCard());
      return;
    }
    profiles.forEach((profile) => container.appendChild(profileCard(profile)));
  } catch {
    container.innerHTML = "";
    container.appendChild(profileCard());
  }
}

$("btn-profiles-refresh").addEventListener("click", loadProfiles);

$("btn-profile-add").addEventListener("click", () => {
  $("profile-cards").appendChild(profileCard());
});

$("btn-profiles-save").addEventListener("click", async () => {
  const cards = Array.from(document.querySelectorAll(".profile-card"));
  const profiles = cards.map((card) => {
    const value = (field) => card.querySelector(`[data-field="${field}"]`).value;
    return {
      name: value("name").trim(),
      user_agent: value("user_agent"),
      enroll_uri: value("enroll_uri").trim(),
      poll_uri: value("poll_uri").trim(),
      request_headers: parseHeaderLines(value("request_headers")),
      response_headers: parseHeaderLines(value("response_headers")),
      poll_interval_secs: Number(value("poll_interval_secs")) || 5,
      jitter_secs: Number(value("jitter_secs")) || 0,
    };
  });
  try {
    const message = await invoke("profiles_save", { profiles });
    toast(message);
  } catch (err) {
    toast(String(err), true);
  }
});

applyBuilderVisibility();
applyDbModeVisibility();
if (nativePath) refreshBuilderDefaults();

loadConsoleConfig().then(() => {
  appendTerminal(t("terminal.ready"), "meta");
  appendTerminal(t("terminal.hint"), "meta");
  refreshServerStatus().catch(() => {});
});

// ---------- AI copilot ----------

const COPILOT_TOOLS = [
  ["list_sessions", "read_only"], ["session_info", "read_only"], ["list_tasks", "read_only"],
  ["list_listeners", "read_only"], ["list_pivots", "read_only"], ["list_extensions", "read_only"],
  ["list_credentials", "read_only"], ["list_loot", "read_only"], ["fs_ls", "read_only"],
  ["fs_cat", "read_only"], ["ps", "read_only"], ["netstat", "read_only"],
  ["ifconfig", "read_only"], ["env_dump", "read_only"], ["wasm_list", "read_only"],
  ["run_shell", "mutating"], ["fs_upload", "mutating"], ["fs_download", "mutating"],
  ["portscan", "mutating"], ["screenshot", "mutating"],
  ["listener_start", "destructive"], ["listener_stop", "destructive"], ["bof_run", "destructive"],
  ["wasm_load", "destructive"], ["wasm_run", "destructive"],
];

const RISK_LABELS = { read_only: "read-only", mutating: "mutating", destructive: "destructive" };
const copilotCards = new Map();
let copilotStatus = null;
let copilotWired = false;
let copilotBusy = false;
let copilotThinking = null;

function copilotEscape(text) {
  return String(text ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[ch]);
}

function copilotInline(text) {
  return text
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
}

function copilotSplitRow(line) {
  return line.trim().replace(/^\||\|$/g, "").split("|").map((cell) => cell.trim());
}

function renderMarkdown(text) {
  const lines = copilotEscape(text).split("\n");
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.trim().startsWith("```")) {
      const buffer = [];
      i += 1;
      while (i < lines.length && !lines[i].trim().startsWith("```")) { buffer.push(lines[i]); i += 1; }
      i += 1;
      out.push(`<pre class="md-code"><code>${buffer.join("\n")}</code></pre>`);
      continue;
    }
    if (/^\s*\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
      const header = copilotSplitRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { rows.push(copilotSplitRow(lines[i])); i += 1; }
      out.push(`<table class="md-table"><thead><tr>${header.map((h) => `<th>${copilotInline(h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${copilotInline(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`);
      continue;
    }
    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    if (heading) {
      const level = Math.min(6, heading[1].length + 2);
      out.push(`<h${level}>${copilotInline(heading[2])}</h${level}>`);
      i += 1;
      continue;
    }
    if (/^\s*[-*]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) { items.push(copilotInline(lines[i].replace(/^\s*[-*]\s+/, ""))); i += 1; }
      out.push(`<ul>${items.map((item) => `<li>${item}</li>`).join("")}</ul>`);
      continue;
    }
    if (/^\s*\d+[.)]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*\d+[.)]\s+/.test(lines[i])) { items.push(copilotInline(lines[i].replace(/^\s*\d+[.)]\s+/, ""))); i += 1; }
      out.push(`<ol>${items.map((item) => `<li>${item}</li>`).join("")}</ol>`);
      continue;
    }
    if (/^\s*>\s?/.test(line)) {
      out.push(`<blockquote>${copilotInline(line.replace(/^\s*>\s?/, ""))}</blockquote>`);
      i += 1;
      continue;
    }
    if (line.trim() === "") { i += 1; continue; }
    const paragraph = [];
    while (
      i < lines.length && lines[i].trim() !== "" &&
      !/^\s*([-*]|\d+[.)])\s+/.test(lines[i]) &&
      !lines[i].trim().startsWith("```") && !/^#{1,4}\s/.test(lines[i]) && !/^\s*\|/.test(lines[i])
    ) { paragraph.push(lines[i]); i += 1; }
    out.push(`<p>${paragraph.map(copilotInline).join("<br/>")}</p>`);
  }
  return out.join("");
}

function copilotScroll() {
  const box = $("copilot-messages");
  box.scrollTop = box.scrollHeight;
}

function copilotHideEmpty() {
  $("copilot-empty").classList.add("hidden");
}

function appendCopilotNode(node) {
  copilotHideEmpty();
  $("copilot-messages").appendChild(node);
  copilotScroll();
}

function appendCopilotMessage(kind, content) {
  const wrapper = document.createElement("div");
  wrapper.className = `msg ${kind}`;
  const head = document.createElement("div");
  head.className = "msg-head";
  head.textContent = kind === "user" ? t("ai.you") : kind === "assistant" ? t("ai.copilot") : "";
  const body = document.createElement("div");
  body.className = "msg-body";
  if (kind === "assistant") body.innerHTML = renderMarkdown(content);
  else body.textContent = content;
  if (head.textContent) wrapper.appendChild(head);
  wrapper.appendChild(body);
  appendCopilotNode(wrapper);
}

function appendCopilotError(message) {
  const wrapper = document.createElement("div");
  wrapper.className = "msg error";
  const body = document.createElement("div");
  body.className = "msg-body";
  body.textContent = message;
  wrapper.appendChild(body);
  appendCopilotNode(wrapper);
}

function copilotArgSummary(args) {
  const text = JSON.stringify(args ?? {});
  return text.length > 84 ? `${text.slice(0, 84)}…` : text;
}

function copilotPretty(value) {
  let text;
  try { text = JSON.stringify(value ?? null, null, 2); } catch { text = String(value); }
  return text.length > 6000 ? `${text.slice(0, 6000)}\n… (truncated)` : text;
}

function copilotToolCard(data, state) {
  const card = document.createElement("div");
  card.className = `tool-card ${state}`;
  card.dataset.callId = data.call_id;
  const risk = data.risk ?? "destructive";
  card.innerHTML = `
    <div class="tool-head">
      <span class="risk-badge ${risk}">${RISK_LABELS[risk] ?? risk}</span>
      <span class="tool-name">${copilotEscape(data.name)}</span>
      <span class="tool-args">${copilotEscape(copilotArgSummary(data.arguments))}</span>
      <span class="tool-status ${state}">${state}</span>
      <span class="tool-chevron">›</span>
    </div>
    <div class="tool-body">
      <div class="tool-label">${t("ai.arguments")}</div>
      <pre>${copilotEscape(copilotPretty(data.arguments))}</pre>
      <div class="tool-result"></div>
    </div>`;
  card.querySelector(".tool-head").addEventListener("click", () => card.classList.toggle("open"));
  return card;
}

function copilotMountCard(callId, card, open = false) {
  const previous = copilotCards.get(callId);
  if (previous && previous.parentNode) previous.parentNode.replaceChild(card, previous);
  else appendCopilotNode(card);
  copilotCards.set(callId, card);
  if (open) card.classList.add("open");
}

function copilotStartTool(data) {
  const card = copilotToolCard({ ...data }, "running");
  copilotMountCard(data.call_id, card, true);
}

function copilotFinishTool(data) {
  const state = !data.approved ? "denied" : data.error ? "error" : "ok";
  const card = copilotToolCard({ ...data }, state);
  // Successful calls collapse to a single row; failures stay open.
  copilotMountCard(data.call_id, card, state !== "ok");
  const result = card.querySelector(".tool-result");
  if (data.error) {
    result.innerHTML = `<div class="tool-label">${t(state === "denied" ? "ai.denied" : "ai.error")}</div><pre>${copilotEscape(data.error)}</pre>`;
  } else if (data.result !== undefined && data.result !== null) {
    result.innerHTML = `<div class="tool-label">${t("ai.result")}</div><pre>${copilotEscape(copilotPretty(data.result))}</pre>`;
  }
}

function copilotApprovalRequest(data) {
  const risk = data.risk ?? "destructive";
  const card = document.createElement("div");
  card.className = "tool-card pending";
  card.dataset.callId = data.call_id;
  card.innerHTML = `
    <div class="approval-card">
      <div class="approval-title">✦ ${t("ai.approvalTitle")}</div>
      <div class="approval-desc">
        <span class="risk-badge ${risk}">${RISK_LABELS[risk] ?? risk}</span>
        <span class="tool-name">${copilotEscape(data.name)}</span>
        <span class="tool-args">${copilotEscape(copilotArgSummary(data.arguments))}</span>
      </div>
      <div class="tool-label">${t("ai.arguments")}</div>
      <pre>${copilotEscape(copilotPretty(data.arguments))}</pre>
      <div class="approval-actions">
        <button class="approve">${t("ai.approve")}</button>
        <button class="deny">${t("ai.deny")}</button>
      </div>
    </div>`;
  const approve = card.querySelector("button.approve");
  const deny = card.querySelector("button.deny");
  const answer = (approved) => {
    approve.disabled = true;
    deny.disabled = true;
    invoke("ai_approve", { callId: data.call_id, approved }).catch((err) => toast(String(err), true));
  };
  approve.addEventListener("click", () => answer(true));
  deny.addEventListener("click", () => answer(false));
  copilotMountCard(data.call_id, card, true);
  copilotScroll();
}

function copilotApprovalResolved(data) {
  const card = copilotCards.get(data.call_id);
  if (!card) return;
  const actions = card.querySelector(".approval-actions");
  if (!actions) return;
  const note = document.createElement("div");
  note.className = "approval-resolved";
  note.textContent = data.approved ? t("ai.approved") : t("ai.deniedNote");
  actions.replaceWith(note);
}

function copilotShowThinking() {
  if (copilotThinking) return;
  const wrapper = document.createElement("div");
  wrapper.className = "msg assistant";
  const body = document.createElement("div");
  body.className = "msg-body";
  body.innerHTML = '<span class="typing"><span></span><span></span><span></span></span>';
  wrapper.appendChild(body);
  copilotThinking = wrapper;
  appendCopilotNode(wrapper);
}

function copilotClearThinking() {
  if (copilotThinking?.parentNode) copilotThinking.parentNode.removeChild(copilotThinking);
  copilotThinking = null;
}

function copilotSetBusy(busy) {
  copilotBusy = busy;
  $("btn-copilot-send").disabled = busy;
  $("copilot-status").textContent = busy ? t("ai.working") : "";
}

function handleCopilotEvent(event) {
  const data = event.payload ?? {};
  switch (data.type) {
    case "user_message":
      appendCopilotMessage("user", data.content ?? "");
      copilotShowThinking();
      break;
    case "assistant_message":
      copilotClearThinking();
      appendCopilotMessage("assistant", data.content ?? "");
      break;
    case "tool_start":
      copilotClearThinking();
      copilotStartTool(data);
      copilotShowThinking();
      break;
    case "tool_call":
      copilotClearThinking();
      copilotFinishTool(data);
      copilotShowThinking();
      break;
    case "approval_request":
      copilotClearThinking();
      copilotApprovalRequest(data);
      break;
    case "approval_resolved":
      copilotApprovalResolved(data);
      copilotShowThinking();
      break;
    case "error":
      copilotClearThinking();
      appendCopilotError(data.message ?? "copilot error");
      break;
    case "turn_done":
      copilotClearThinking();
      copilotSetBusy(false);
      break;
    default:
      break;
  }
}

async function sendCopilotPrompt(text) {
  if (copilotBusy) return;
  const input = $("copilot-input");
  const prompt = (text ?? input.value).trim();
  if (!prompt) return;
  input.value = "";
  copilotAutoGrow(input);
  copilotSetBusy(true);
  copilotShowThinking();
  try {
    await invoke("ai_send", { prompt });
  } catch (err) {
    copilotClearThinking();
    copilotSetBusy(false);
    appendCopilotError(String(err));
  }
}

function copilotAutoGrow(element) {
  element.style.height = "auto";
  element.style.height = `${Math.min(180, element.scrollHeight)}px`;
}

function renderCopilotTools() {
  const container = $("copilot-tools");
  container.innerHTML = "";
  for (const [group, label] of [["read_only", "ai.riskReadOnly"], ["mutating", "ai.riskMutating"], ["destructive", "ai.riskDestructive"]]) {
    const heading = document.createElement("div");
    heading.className = "copilot-tools-group";
    heading.textContent = t(label).split("—")[0].trim();
    container.appendChild(heading);
    for (const [name, risk] of COPILOT_TOOLS.filter(([, value]) => value === group)) {
      const chip = document.createElement("span");
      chip.className = `tool-chip ${risk}`;
      chip.textContent = name;
      container.appendChild(chip);
    }
  }
}

function updateCopilotPills() {
  if (!copilotStatus) return;
  const modelPill = $("copilot-model-pill");
  const keyPill = $("copilot-key-pill");
  if (copilotStatus.configured) {
    modelPill.textContent = copilotStatus.model;
    modelPill.className = "pill ok";
  } else {
    modelPill.textContent = t("ai.notConfigured");
    modelPill.className = "pill warn";
  }
  keyPill.textContent = copilotStatus.has_key ? t("ai.keySet") : t("ai.keyMissing");
  keyPill.className = copilotStatus.has_key ? "pill ok" : "pill muted";
  $("copilot-source-note").textContent = copilotStatus.source === "environment" ? t("ai.sourceEnv") : t("ai.sourceConfig");
}

async function refreshCopilotStatus() {
  try {
    copilotStatus = await invoke("ai_status");
  } catch {
    copilotStatus = null;
  }
  if (!copilotStatus) return;
  $("copilot-base-url").value = copilotStatus.base_url ?? "";
  $("copilot-model").value = copilotStatus.model ?? "";
  $("copilot-auto-approve").checked = !!copilotStatus.auto_approve;
  $("copilot-allow-destructive").checked = !!copilotStatus.allow_destructive;
  updateCopilotPills();
}

function refreshCopilotPills() {
  updateCopilotPills();
}

async function saveCopilotSettings(announce = true) {
  const settings = {
    base_url: $("copilot-base-url").value.trim(),
    model: $("copilot-model").value.trim(),
    api_key: $("copilot-api-key").value.trim(),
    auto_approve: $("copilot-auto-approve").checked,
    allow_destructive: $("copilot-allow-destructive").checked,
  };
  try {
    await invoke("ai_config_save", { settings });
    await refreshCopilotStatus();
    if (announce) toast(t("ai.saved"));
  } catch (err) {
    toast(String(err), true);
  }
}

function wireCopilot() {
  const input = $("copilot-input");
  input.addEventListener("input", () => copilotAutoGrow(input));
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      sendCopilotPrompt();
    }
  });
  $("btn-copilot-send").addEventListener("click", () => sendCopilotPrompt());
  $("btn-copilot-save").addEventListener("click", () => saveCopilotSettings());
  $("btn-copilot-reset").addEventListener("click", async () => {
    try {
      await invoke("ai_reset");
      $("copilot-messages").innerHTML = "";
      $("copilot-empty").classList.remove("hidden");
      copilotCards.clear();
      toast(t("ai.resetDone"));
    } catch (err) {
      toast(String(err), true);
    }
  });
  document.querySelectorAll(".copilot-suggestions button").forEach((button) => {
    button.addEventListener("click", () => sendCopilotPrompt(button.dataset.prompt));
  });
  $("copilot-auto-approve").addEventListener("change", () => saveCopilotSettings(false));
  $("copilot-allow-destructive").addEventListener("change", () => saveCopilotSettings(false));
}

async function loadCopilot() {
  if (!copilotWired) {
    copilotWired = true;
    renderCopilotTools();
    wireCopilot();
    const listen = window.__TAURI__?.event?.listen;
    if (listen) {
      await listen("ai-event", handleCopilotEvent);
    }
  }
  await refreshCopilotStatus();
}
