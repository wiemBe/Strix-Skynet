/* Skynet – Strix pentest management UI. No external dependencies.
 * Untrusted text is always inserted with textContent. The only innerHTML sink is markdown rendered by
 * the server with raw HTML disabled; a strict CSP applies on top. */
"use strict";

// ================================================================== core helpers
const _rc = Element.prototype.replaceChildren;
Element.prototype.replaceChildren = function (...k) { return _rc.apply(this, k.flat(Infinity).filter((x) => x != null && x !== false)); };
const $ = (s, r = document) => r.querySelector(s);
const app = $("#app");

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || (v === false && !k.startsWith("aria-"))) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "html") el.innerHTML = v; // server-rendered markdown (raw HTML disabled) only
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, k.startsWith("aria-") && typeof v === "boolean" ? String(v) : v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const ICONS = {
  overview: '<path d="M4 4h6v7H4zM14 4h6v4h-6zM14 12h6v8h-6zM4 15h6v5H4z"/>',
  targets: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>',
  scans: '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
  schedules: '<rect x="3.5" y="5" width="17" height="15.5" rx="2"/><path d="M3.5 10h17M8 3v4M16 3v4"/>',
  settings: '<path d="M4 7h9M17 7h3M4 12h3M11 12h9M4 17h11M19 17h1"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="17" r="2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  stop: '<rect x="7" y="7" width="10" height="10" rx="1.5"/>',
  play: '<path d="M8 5.5v13l10.5-6.5z"/>',
  more: '<circle cx="5.5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="18.5" cy="12" r="1"/>',
  chevron: '<path d="M9.5 6l6 6-6 6"/>',
  back: '<path d="M14.5 6l-6 6 6 6"/>',
  download: '<path d="M12 4v11M7.5 10.5L12 15l4.5-4.5M5 20h14"/>',
  alert: '<path d="M12 3.5l9.5 16.5h-19z"/><path d="M12 10v4.5M12 17.2v.3"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8v.3"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  refresh: '<path d="M19.5 8A8 8 0 1 0 20 13"/><path d="M20 4v4.5h-4.5"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  pause: '<path d="M9 6v12M15 6v12"/>',
  trash: '<path d="M4.5 7h15M9.5 7V4.5h5V7M6.5 7l1 13h9l1-13"/>',
  edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/>',
  campaigns: '<path d="M4 5h16M4 5v14M4 19h16M8 9h8M8 13h5"/><circle cx="18" cy="9" r="1.3"/>',
  inventory: '<rect x="3.5" y="4" width="17" height="5" rx="1.2"/><rect x="3.5" y="11" width="17" height="5" rx="1.2"/><path d="M7 6.5h2M7 13.5h2"/>',
  auth: '<rect x="4" y="4.5" width="16" height="15" rx="2"/><circle cx="12" cy="12" r="3.2"/><path d="M12 15.2V18M15.2 12H18"/>',
  archive: '<rect x="3.5" y="5" width="17" height="4" rx="1"/><path d="M5 9v10h14V9M10 13h4"/>',
  audit: '<path d="M7 4.5h10a1.5 1.5 0 0 1 1.5 1.5v13.5H5.5V6A1.5 1.5 0 0 1 7 4.5z"/><path d="M9 9h6M9 12.5h6M9 16h3.5"/>',
  users: '<circle cx="9" cy="9" r="3.2"/><path d="M3.5 19c.6-3 2.8-4.6 5.5-4.6s4.9 1.6 5.5 4.6"/><path d="M15.5 6.2a3 3 0 0 1 0 5.6M17.5 14.8c1.5.6 2.6 2 3 4.2"/>',
  report: '<path d="M6 3.5h8l4 4V20.5H6z"/><path d="M14 3.5V8h4M9 17v-3M12 17v-5M15 17v-2"/>',
};
function icon(name) {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("class", "i"); s.setAttribute("aria-hidden", "true");
  s.innerHTML = ICONS[name] || ""; // static, trusted markup
  return s;
}

async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: { "X-Requested-With": "skynet" } };
  if (opts.body !== undefined) { init.body = JSON.stringify(opts.body); init.headers["Content-Type"] = "application/json"; }
  let r;
  try { r = await fetch(path, init); } catch { throw new Error("Can't reach the server. Check your connection."); }
  if (r.status === 401) { location.href = "/login"; throw new Error("Session expired"); }
  let data = null;
  try { data = await r.json(); } catch { /* no body */ }
  if (!r.ok) {
    const d = data && data.detail;
    throw new Error(typeof d === "string" ? d : Array.isArray(d) ? d.map((x) => x.msg).join("; ") : `Request failed (HTTP ${r.status})`);
  }
  return data;
}

function toast(msg, err = false) {
  const t = h("div", { class: "toast" + (err ? " err" : ""), role: "status" }, msg);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), err ? 8000 : 3500);
}
const guard = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, true); } };

// Polling wrapper: on failure show a persistent connection banner with the last successful update time,
// instead of a stream of error toasts. Recovers silently on the next success.
let _lastSync = Date.now();
function setConnected(ok) {
  let el = document.getElementById("connStatus");
  if (ok) { _lastSync = Date.now(); if (el) el.remove(); return; }
  if (!el) { el = h("div", { id: "connStatus", class: "conn-status", role: "status" }); document.body.append(el); }
  el.replaceChildren(icon("alert"), h("span", {}, "Can't reach the server"),
    h("span", { class: "faint" }, `last updated ${relTime(new Date(_lastSync).toISOString())}`));
}
const pollGuard = (fn) => async (...a) => { try { const r = await fn(...a); setConnected(true); return r; } catch (e) { setConnected(false); } };

// ================================================================== formatting
let TZ = "Europe/Istanbul";
// Signed-in account (from /api/me). The server enforces every permission; the UI only hides what a role can't use.
let ME = { username: "", role: "viewer", role_label: "Viewer" };
const ROLE_RANK = { viewer: 1, analyst: 2, admin: 3 };
const ROLE_NAMES = { viewer: "Viewer", analyst: "Analyst", admin: "Admin" };
const ROLE_HELP = { viewer: "Read-only: sees scans, findings and reports.", analyst: "Viewer + starts/stops scans, messages agents, verifies and triages findings, manages targets, schedules and campaigns.", admin: "Analyst + settings, LLM connections, auth profiles (secrets), deletions, users and the audit log." };
const can = (need) => (ROLE_RANK[ME.role] || 0) >= (ROLE_RANK[need] || 3);
// Action labels that need more than read access; used by button()/menu() so each call site stays unchanged.
const LABEL_NEEDS = {
  "New target": "analyst", "Create target": "analyst", "New scan": "analyst", "Start scan": "analyst", "Scan": "analyst",
  "Scan now": "analyst", "Scan again": "analyst", "Resume": "analyst", "Stop": "analyst", "Remove from queue": "analyst",
  "Create schedule": "analyst", "Add schedule": "analyst", "New campaign": "analyst", "Verify": "analyst",
  "Start verification": "analyst", "Re-verify": "analyst", "Send": "analyst", "Add note": "analyst", "Save revision": "analyst",
  "Edit": "analyst", "Pause": "analyst", "Enable": "analyst", "Archive": "analyst", "Unarchive": "analyst",
  "New profile": "admin", "Add connection": "admin", "Delete": "admin", "Delete target": "admin", "Make default": "admin",
};
const dateFmt = (iso, opts) => { if (!iso) return "—"; const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleString("en-US", { timeZone: TZ, ...opts }); };
const fmtDate = (iso) => dateFmt(iso, { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
const fmtDateSec = (iso) => dateFmt(iso, { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
const fmtShort = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso), now = new Date();
  const sameDay = d.toLocaleDateString("en-US", { timeZone: TZ }) === now.toLocaleDateString("en-US", { timeZone: TZ });
  return sameDay ? "Today " + dateFmt(iso, { hour: "2-digit", minute: "2-digit" }) : dateFmt(iso, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
};
function relTime(iso) {
  if (!iso) return "";
  const s = (new Date(iso) - Date.now()) / 1000, a = Math.abs(s);
  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  if (a < 45) return s < 0 ? "just now" : "shortly";
  if (a < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (a < 86400) return rtf.format(Math.round(s / 3600), "hour");
  return rtf.format(Math.round(s / 86400), "day");
}
const ACTIVE = ["queued", "running", "stopping"];
function durationText(scan) {
  const a = scan.started_at, b = scan.finished_at;
  if (!a || (!b && !ACTIVE.includes(scan.status))) return "—";
  const s = Math.max(0, ((b ? new Date(b) : new Date()) - new Date(a)) / 1000);
  const hh = Math.floor(s / 3600), mm = Math.floor((s % 3600) / 60), ss = Math.floor(s % 60);
  return hh ? `${hh} h ${mm} m` : mm ? `${mm} m` : `${ss} s`;
}
const fmtTokens = (n) => n == null ? "—" : n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? Math.round(n / 1e3) + "K" : String(n);
const modelShort = (m) => m ? m.replace(/^(openrouter|openai)\//, "") : "—";

const SEV = ["critical", "high", "medium", "low", "info"];
const SEV_TR = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const STATUS_TR = { queued: "Queued", running: "Running", stopping: "Stopping", completed: "Completed",
  failed: "Failed", cancelled: "Cancelled", interrupted: "Interrupted" };
const TRIGGER_TR = { manual: "Started manually", schedule: "Scheduling", api: "CI / API", cli: "Strix TUI (imported)", verify: "Verification" };
const MODE_TR = { quick: "Quick", standard: "Standard", deep: "Deep" };
const OUTCOME_TR = { started: "Started", skipped_busy: "Skipped: target had an active scan", missed: "Missed: app was down", error: "Couldn't start" };
const KIND_TR = { once: "One-time", daily: "Daily", weekly: "Weekly", interval: "Hourly interval", cron: "Custom (cron)" };
const DAYS = [["mon", "Mon"], ["tue", "Tue"], ["wed", "Wed"], ["thu", "Thu"], ["fri", "Fri"], ["sat", "Sat"], ["sun", "Sun"]];
const ENV_TR = { development: "Development", test: "Test", staging: "Staging", production: "Production" };
const CAMP_STATUS_TR = { planned: "Planned", active: "Active", on_hold: "Pending", completed: "Completed" };
const KIND_ASSET_TR = { host: "Host", service: "Service", endpoint: "Endpoint", technology: "Technology" };
const SCOPE_TR = { in: "In scope", out: "Out of scope", unknown: "Unknown" };
const TIER_TR = { observed: "Observed", reported: "Agent-reported" };
const REMEDIATION_TR = { open: "Open", fixed: "Fixed", accepted: "Accepted", false_positive: "False positive" };
const AUTHKIND_TR = { anonymous: "Anonymous", credentials: "Username + password", header: "HTTP header", cookie: "Cookie" };
const VERIFY_TR = { verified: "Pre-check passed", failed: "Failed", not_configured: "No URL set", not_verifiable: "Not verifiable",
  not_applicable: "Not applicable", blocked: "Out of scope", not_checked: "Not checked" };

// ================================================================== components
function button(label, { kind = "", ic, onclick, disabled, title, size, type = "button", need } = {}) {
  const req = need || LABEL_NEEDS[label];
  return h("button", { type, class: ["btn", kind, size, !label && ic ? "icon" : "", req && !can(req) ? "role-hidden" : ""].filter(Boolean).join(" "), onclick, disabled, title, "aria-label": !label ? title : null },
    ic ? icon(ic) : null, label || null);
}
function errorHeadline(err) {
  if (!err) return "";
  const lines = err.split("\n").map((l) => l.trim()).filter(Boolean);
  return lines.find((l) => /^Error:/.test(l)) || lines.find((l) => /FAILED|Traceback|not found|unavailable|deleted/.test(l)) || lines[lines.length > 1 ? 1 : 0];
}
const statusChip = (s) => h("span", { class: `status ${s}` }, h("span", { class: "dot" }), STATUS_TR[s] || s);
function statusCell(scan) {
  let sub = null;
  if (scan.status === "running") sub = `Running for ${durationText(scan)}`;
  else if (scan.status === "queued") sub = "Waiting in queue";
  else if (scan.status === "stopping") sub = "Shutting the process down";
  else if (scan.status === "failed" && scan.error) sub = errorHeadline(scan.error);
  return h("div", { class: "cell-clip" }, statusChip(scan.status), sub ? h("div", { class: "status-sub", title: scan.error || sub }, sub) : null);
}
const envTag = (e) => e ? h("span", { class: `env ${e}` }, ENV_TR[e] || e) : null;
function sevSummary(counts, { status, max = 3 } = {}) {
  if (!counts) return h("span", { class: "sevsum" }, h("span", { class: "none" }, ACTIVE.includes(status) ? "None yet" : "—"));
  const items = SEV.filter((s) => counts[s]);
  if (!items.length) {
    const txt = ACTIVE.includes(status) ? "None yet" : status && status !== "completed" ? "—" : "No findings";
    return h("span", { class: "sevsum", title: status && status !== "completed" && !ACTIVE.includes(status) ? "Scan did not finish; results may be incomplete" : null }, h("span", { class: "none" }, txt));
  }
  const shown = items.slice(0, max), rest = items.slice(max).reduce((n, s) => n + counts[s], 0);
  return h("span", { class: "sevsum", title: items.map((s) => `${counts[s]} ${SEV_TR[s]}`).join(", ") },
    shown.map((s) => h("span", { class: "item" }, h("span", { class: `sq ${s}` }), h("span", { class: "n" }, counts[s]), SEV_TR[s].toLowerCase())),
    rest ? h("span", { class: "none" }, `+${rest}`) : null);
}
const VERDICT_HELP = "Finding gate: if there is a finding at or above the selected level, the result is 'Gate failed'. Used to block a release in CI.";
function verdict(scan) {
  const g = scan && scan.summary && scan.summary.gate;
  if (!scan.fail_on) return h("span", { class: "verdict na" }, "No gate set");
  if (!g || scan.status !== "completed") return h("span", { class: "verdict na", title: VERDICT_HELP }, `${SEV_TR[scan.fail_on]} and above · awaiting result`);
  return h("span", { class: `verdict ${g}`, title: VERDICT_HELP }, icon(g === "pass" ? "check" : "alert"), g === "pass" ? "Gate passed" : "Gate failed",
    h("span", { class: "faint" }, ` (${SEV_TR[scan.fail_on].toLowerCase()} and above)`));
}
const whenCell = (iso) => iso ? h("div", { class: "when" }, h("div", {}, fmtShort(iso)), h("div", { class: "rel" }, relTime(iso))) : h("span", { class: "faint" }, "—");

function table(cols, rows, empty) {
  if (!rows.length) return empty;
  return h("div", { class: "table-scroll" }, h("table", { class: "t" },
    h("thead", {}, h("tr", {}, cols.map((c) => h("th", { class: c.cls || null, style: null }, c.label)))),
    h("tbody", {}, rows)));
}
function emptyState(title, desc, actions) {
  return h("div", { class: "empty-state" }, h("div", { class: "title" }, title), desc ? h("div", { class: "desc" }, desc) : null,
    actions ? h("div", { class: "actions" }, actions) : null);
}
function alertBox(kind, title, desc, extra) {
  return h("div", { class: `alert ${kind}`, role: kind === "danger" ? "alert" : null }, icon(kind === "info" ? "info" : "alert"),
    h("div", { class: "body" }, h("div", { class: "title" }, title), desc ? h("div", { class: "desc" }, desc) : null, extra || null));
}
function section(title, body, { hint, right } = {}) {
  return h("section", { class: "section" },
    h("div", { class: "section-head" }, h("h2", {}, title), h("div", { class: "actions" }, hint ? h("span", { class: "hint" }, hint) : null, right || null)), body);
}
function pageHead(title, { crumb, lead, meta, actions } = {}) {
  return h("div", { class: "page-head" },
    h("div", { class: "titles" }, crumb ? h("div", { class: "crumb" }, icon("back"), crumb) : null, h("h1", {}, title),
      lead ? h("div", { class: "lead" }, lead) : null, meta ? h("div", { class: "meta" }, meta) : null),
    actions ? h("div", { class: "actions" }, actions) : null);
}
function menu(items, { label = null, title = "More actions" } = {}) {
  const wrap = h("div", { class: "menu-wrap" });
  const box = h("div", { class: "menu", hidden: true, role: "menu" });
  const close = () => { box.hidden = true; document.removeEventListener("click", outside, true); };
  const outside = (e) => { if (!wrap.contains(e.target)) close(); };
  const visible = items.filter((it) => it && (it === "-" || can(it.need || LABEL_NEEDS[it.label] || "viewer")))
    .filter((it, i, a) => it !== "-" || (i > 0 && a[i - 1] !== "-" && i < a.length - 1));
  if (!visible.length) return h("span", { class: "menu-wrap" });
  for (const it of visible) {
    if (it === "-") { box.append(h("hr")); continue; }
    box.append(h("button", { type: "button", role: "menuitem", class: it.danger ? "danger" : null, onclick: (e) => { e.stopPropagation(); close(); it.onclick(); } }, it.icon ? icon(it.icon) : null, it.label));
  }
  const trigger = button(label, { ic: label ? null : "more", title, kind: label ? "" : "", onclick: (e) => {
    e.stopPropagation();
    if (box.hidden) { box.hidden = false; document.addEventListener("click", outside, true); } else close();
  } });
  wrap.append(trigger, box);
  return wrap;
}
function select(options, value) {
  const s = h("select", {}, options.map(([v, l]) => h("option", { value: v }, l)));
  if (value != null) s.value = String(value);
  return s;
}
let fieldId = 0;
function field(label, input, help) {
  if (!input.id) input.id = `field-${++fieldId}`;
  return h("div", { class: "field" }, h("label", { for: input.id }, label), input, help ? h("div", { class: "help" }, help) : null);
}
const formSection = (title, desc, fields) => h("div", { class: "form-section" }, h("div", { class: "about" }, h("h3", {}, title), desc ? h("p", {}, desc) : null), h("div", { class: "fields" }, fields));

// dialogs
function dialog(title, body, foot, { wide = false } = {}) {
  const bg = h("div", { class: "dlg-bg", onmousedown: (e) => { if (e.target === bg) close(); } });
  const box = h("div", { class: "dlg" + (wide ? " wide" : ""), role: "dialog", "aria-modal": "true", "aria-label": title },
    h("div", { class: "dlg-head" }, h("h3", {}, title), button(null, { ic: "plus", kind: "ghost", title: "Close", onclick: () => close() })),
    h("div", { class: "dlg-body" }, body), foot ? h("div", { class: "dlg-foot" }, foot) : null);
  box.querySelector(".dlg-head svg").style.transform = "rotate(45deg)";
  bg.append(box);
  const esc = (e) => { if (e.key === "Escape") close(); };
  function close() { bg.remove(); document.removeEventListener("keydown", esc); }
  document.addEventListener("keydown", esc);
  $("#dialogs").append(bg);
  const first = box.querySelector("input, select, textarea");
  if (first) setTimeout(() => first.focus(), 0);
  return close;
}
function confirmDialog(title, desc, { confirmLabel = "Confirm", danger = false } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; close(); resolve(v); } };
    const close = dialog(title, h("div", { class: "muted" }, desc), [
      button("Cancel", { onclick: () => finish(false) }),
      button(confirmLabel, { kind: danger ? "danger-solid" : "primary", onclick: () => finish(true) })]);
    const obs = new MutationObserver(() => { if (!document.body.contains($(".dlg-bg"))) { obs.disconnect(); if (!done) { done = true; resolve(false); } } });
    obs.observe($("#dialogs"), { childList: true });
  });
}
const closeDialogs = () => $("#dialogs").replaceChildren();

// ================================================================== shell: navigation + system status
const NAV = [["overview", "#/", "Overview"], ["targets", "#/targets", "Targets"], ["campaigns", "#/campaigns", "Campaigns"], ["scans", "#/scans", "Scans"], ["schedules", "#/schedules", "Schedules"], ["inventory", "#/inventory", "Inventory"], ["auth", "#/auth-profiles", "Auth profiles"], ["audit", "#/audit", "Audit log", "admin"], ["settings", "#/settings", "Settings"]];
function renderShell() {
  document.body.dataset.role = ME.role;
  $("#nav").replaceChildren(NAV.filter((n) => can(n[3] || "viewer")).map(([k, href, label]) => h("a", { href, "data-nav": k }, icon(k), h("span", {}, label), k === "scans" ? h("span", { class: "badge-count", id: "activeCount" }) : null)));
  $("#whoami").replaceChildren(h("span", { class: "who-name", title: ME.username }, ME.display_name || ME.username || "—"), h("span", { class: "who-role" }, ME.role_label || ROLE_NAMES[ME.role] || ""));
}
$("#logoutBtn").addEventListener("click", guard(async () => { await api("/api/logout", { method: "POST" }); location.href = "/login"; }));

let lastOverview = null;
// System health is shown in Settings. The sidebar only surfaces a link when something needs attention.
async function refreshSystem() {
  const box = $("#sysStatus");
  try {
    const o = await api("/api/overview");
    lastOverview = o;
    const issues = [];
    if (!o.docker.ok) issues.push("Docker is down");
    if (!o.strix.ok) issues.push("Strix not found");
    if (!o.llm_default) issues.push("No LLM connection");
    box.replaceChildren(issues.length ? h("a", { class: "sys-alert", href: "#/settings", title: issues.join("\n") },
      h("span", { class: "dot-bad" }), h("span", { class: "lbl" }, issues.length === 1 ? issues[0] : `${issues.length} sistem sorunu`)) : null);
    const ac = document.getElementById("activeCount"); if (ac) ac.textContent = o.active.length ? String(o.active.length) : "";
    return o;
  } catch (e) {
    box.replaceChildren(h("div", { class: "sys-alert", title: e.message }, h("span", { class: "dot-bad" }), h("span", { class: "lbl" }, "Can't reach the server")));
    return null;
  }
}

// ================================================================== routing
let timers = [];
const every = (ms, fn) => timers.push(setInterval(fn, ms));
const routes = [
  [/^#?\/?$/, "overview", viewOverview],
  [/^#\/targets$/, "targets", viewTargets],
  [/^#\/targets\/new$/, "targets", () => viewTargetForm(null)],
  [/^#\/targets\/(\d+)$/, "targets", (id) => viewTarget(+id)],
  [/^#\/targets\/(\d+)\/edit$/, "targets", (id) => viewTargetForm(+id)],
  [/^#\/targets\/(\d+)\/compare(?:\?(.*))?$/, "targets", (id, q) => viewCompare(+id, q)],
  [/^#\/findings\/(\d+)(?:\?(.*))?$/, "scans", (id, q) => viewWorkspace(+id, q)],
  [/^#\/scans$/, "scans", viewScans],
  [/^#\/scans\/(\d+)$/, "scans", (id) => viewScan(+id)],
  [/^#\/schedules$/, "schedules", viewSchedules],
  [/^#\/schedules\/new(?:\?target=(\d+))?$/, "schedules", (t) => viewScheduleForm(null, t ? +t : null)],
  [/^#\/schedules\/(\d+)$/, "schedules", (id) => viewScheduleForm(+id)],
  [/^#\/campaigns$/, "campaigns", viewCampaigns],
  [/^#\/campaigns\/new$/, "campaigns", () => viewCampaignForm(null)],
  [/^#\/campaigns\/(\d+)$/, "campaigns", (id) => viewCampaign(+id)],
  [/^#\/campaigns\/(\d+)\/edit$/, "campaigns", (id) => viewCampaignForm(+id)],
  [/^#\/inventory(?:\?target=(\d+))?$/, "inventory", (t) => viewInventory(t ? +t : null)],
  [/^#\/auth-profiles$/, "auth", viewAuthProfiles],
  [/^#\/settings$/, "settings", viewSettings],
  [/^#\/audit(?:\?(.*))?$/, "audit", (q) => viewAudit(q)],
  [/^#\/targets\/(\d+)\/report$/, "targets", (id) => viewReport("targets", +id)],
  [/^#\/campaigns\/(\d+)\/report$/, "campaigns", (id) => viewReport("campaigns", +id)],
];
async function router() {
  timers.forEach(clearInterval); timers = [];
  closeDialogs();
  const hash = location.hash || "#/";
  for (const [re, nav, fn] of routes) {
    const m = hash.match(re);
    if (!m) continue;
    document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.nav === nav));
    app.replaceChildren(h("div", { class: "loading" }, "Loading…"));
    try { await fn(...m.slice(1)); }
    catch (e) { app.replaceChildren(pageHead("Page failed to load"), alertBox("danger", "Could not load data", e.message, h("div", { class: "actions" }, button("Try again", { ic: "refresh", onclick: router })))); }
    window.scrollTo(0, 0);
    return;
  }
  location.hash = "#/";
}
window.addEventListener("hashchange", router);
const go = (hash) => { location.hash = hash; };

// ================================================================== shared scan table
function scanTable(list, { empty, showTarget = true } = {}) {
  const cols = [...(showTarget ? [{ label: "Target" }] : []), { label: "Status" }, { label: "Findings" }, { label: "Started" }, { label: "Duration" }, { label: "", cls: "shrink" }];
  return table(cols, list.map((s) => {
    const active = ACTIVE.includes(s.status);
    return h("tr", { class: "clickable", onclick: () => go(`#/scans/${s.id}`) },
      showTarget ? h("td", {}, h("div", { class: "cell-clip" },
        h("div", { class: "primary-line", title: s.target_name || s.name }, s.target_name || s.name || "Untitled"),
        h("div", { class: "secondary-line mono", title: (s.targets || []).join("\n") }, (s.targets || [])[0] || "—"))) : null,
      h("td", {}, statusCell(s)),
      h("td", {}, sevSummary((s.summary || {}).counts, { status: s.status })),
      h("td", {}, whenCell(s.started_at || s.created_at)),
      h("td", { class: "nowrap" }, s.status === "queued" ? h("span", { class: "faint" }, "—") : durationText(s)),
      h("td", { class: "shrink right", onclick: (e) => e.stopPropagation() },
        active && s.status !== "stopping" ? button(s.status === "queued" ? "Remove from queue" : "Stop", { kind: "danger", size: "sm", ic: "stop", onclick: () => stopScan(s, router) }) : null,
        !active ? h("a", { class: "btn ghost sm icon", href: `#/scans/${s.id}`, title: "Details", "aria-label": "Details" }, icon("chevron")) : null));
  }), empty || emptyState("No scans", "Scans appear here once you pick a target and start one."));
}
async function stopScan(s, after) {
  const queued = s.status === "queued";
  const ok = await confirmDialog(queued ? "Remove scan from queue?" : "Stop the scan?",
    queued ? "The scan hasn't started yet; it will be removed from the queue and marked cancelled."
      : "Strix is first sent an interrupt and given time to write its report. If it doesn't respond, the process group is killed and the sandbox container is cleaned up.",
    { confirmLabel: queued ? "Remove from queue" : "Stop scan", danger: true });
  if (!ok) return;
  try { await api(`/api/scans/${s.id}/cancel`, { method: "POST" }); toast(queued ? "Scan removed from queue" : "Stop request sent"); if (after) after(); }
  catch (e) { toast(e.message, true); }
}

// ================================================================== overview
async function viewOverview() {
  const [o, recent] = await Promise.all([refreshSystem(), api("/api/scans?status=completed,failed&limit=6")]);
  if (!o) throw new Error("Could not load system status.");
  const box = h("div", {});
  const render = (o, recent) => {
    const running = o.active.filter((s) => s.status !== "queued"), queued = o.active.filter((s) => s.status === "queued");
    const withScan = o.latest_by_target.filter((r) => r.scan);
    const crit = withScan.reduce((n, r) => n + (((r.scan.summary || {}).counts || {}).critical || 0), 0);
    const high = withScan.reduce((n, r) => n + (((r.scan.summary || {}).counts || {}).high || 0), 0);
    const next = o.upcoming[0];
    const problems = [];
    if (!o.docker.ok) problems.push([h("b", {}, "Docker is not running."), " Strix can't start its sandbox; new scans will fail."]);
    if (!o.llm_default) problems.push([h("b", {}, "No LLM connection."), " ", h("a", { href: "#/settings" }, "Add one in Settings.")]);
    o.problems.forEach((s) => problems.push([h("a", { href: `#/scans/${s.id}` }, `${s.target_name || s.name}`), ` · scan ${STATUS_TR[s.status].toLowerCase()} (${fmtShort(s.finished_at || s.created_at)})`, s.error ? h("span", { class: "faint" }, ` · ${errorHeadline(s.error).slice(0, 140)}`) : null]));
    o.schedule_problems.forEach((p) => problems.push([h("a", { href: `#/schedules/${p.id}` }, `${p.target_name} schedule`), ` · ${OUTCOME_TR[p.last_outcome] || p.last_outcome}`, h("span", { class: "faint" }, ` · ${p.last_note || fmtShort(p.event_at)}`)]));

    const parts = [];
    parts.push(running.length ? `${running.length} scans running` : "No scans running right now");
    if (queued.length) parts.push(`${queued.length} scans queued`);
    parts.push(problems.length ? `${problems.length} items need attention` : "nothing needs attention");
    const lead = parts.join(", ") + "." + (next ? ` Next scan ${fmtShort(next.next_run_at)} (${next.target_name}).` : "");

    box.replaceChildren(
      pageHead("Overview", { lead, actions: [button("Create schedule", { ic: "schedules", onclick: () => go("#/schedules/new") }), button("New scan", { kind: "primary", ic: "plus", onclick: () => scanDialog(null) })] }),
      problems.length ? alertBox("danger", problems.length === 1 ? "1 item needs attention" : `${problems.length} items need attention`, null,
        h("ul", {}, problems.slice(0, 6).map((p) => h("li", {}, p)))) : null,
      h("div", { class: "stats" },
        h("div", { class: "stat" }, h("div", { class: "k" }, "Active scans"), h("div", { class: "v" }, running.length), h("div", { class: "s" }, `Concurrency limit ${o.max_concurrent}`)),
        h("div", { class: "stat" }, h("div", { class: "k" }, "Queued"), h("div", { class: "v" }, queued.length), h("div", { class: "s" }, queued.length ? "Waiting in line" : "Queue empty")),
        h("div", { class: "stat" + (crit ? " is-alert" : "") }, h("div", { class: "k" }, "Open critical / high findings"),
          h("div", { class: "v" }, withScan.length ? `${crit} / ${high}` : "—"),
          h("div", { class: "s", title: "Based on each target's last completed scan" }, withScan.length ? "Based on targets' latest scans" : "No completed scans yet")),
        h("div", { class: "stat" }, h("div", { class: "k" }, "Next scan"),
          h("div", { class: "v sm" }, next ? fmtShort(next.next_run_at) : "No scheduled scan"),
          h("div", { class: "s", title: next ? next.target_name : "" }, next ? `${next.target_name} · ${relTime(next.next_run_at)}` : h("a", { href: "#/schedules/new" }, "Create schedule")))),
      section("Scans in progress", h("div", { class: "table-card" }, scanTable(o.active, {
        empty: emptyState("No scans in progress", "Pick a target to start a scan now, or create a schedule for recurring scans.",
          [button("New scan", { kind: "primary", ic: "plus", onclick: () => scanDialog(null) })]) })),
      { hint: o.active.length ? "Strix doesn't report percentage progress; duration and live findings are shown." : null }),
      h("div", { class: "grid-2 wide-left" },
        section("Recently completed scans", h("div", { class: "table-card" }, recentTable(recent)), { right: h("a", { href: "#/scans" }, "All") }),
        section("Upcoming schedules", h("div", { class: "table-card" }, upcomingTable(o.upcoming)), { right: h("a", { href: "#/schedules" }, "All") })));
  };
  render(o, recent);
  app.replaceChildren(box);
  every(5000, pollGuard(async () => {
    const [n, r] = await Promise.all([refreshSystem(), api("/api/scans?status=completed,failed&limit=6")]);
    if (n) render(n, r);
  }));
}
function recentTable(list) {
  return table([{ label: "Target" }, { label: "Result" }, { label: "Finished" }], list.map((s) => h("tr", { class: "clickable", onclick: () => go(`#/scans/${s.id}`) },
    h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line", title: s.target_name || s.name }, s.target_name || s.name), h("div", { class: "secondary-line mono", title: (s.targets || [])[0] || "" }, (s.targets || [])[0] || ""))),
    h("td", {}, s.status === "completed" ? sevSummary((s.summary || {}).counts, { status: s.status, max: 2 }) : statusChip(s.status)),
    h("td", {}, whenCell(s.finished_at || s.started_at)))),
  emptyState("No completed scans yet", "Results will appear here once the first scan finishes."));
}
function upcomingTable(list) {
  return table([{ label: "Target" }, { label: "Scheduling" }, { label: "When" }], list.map((u) => h("tr", { class: "clickable", onclick: () => go(`#/schedules/${u.id}`) },
    h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, u.target_name), h("div", { class: "secondary-line" }, envTag(u.environment)))),
    h("td", { class: "muted" }, u.describe),
    h("td", {}, whenCell(u.next_run_at)))),
  emptyState("No active schedules", "Create a schedule to scan targets regularly.", [button("Create schedule", { onclick: () => go("#/schedules/new") })]));
}

// ================================================================== new scan dialog
function scanOptions(profiles, init) {
  const def = profiles.find((p) => p.is_default);
  const f = {
    llm_profile_id: select(profiles.map((p) => [String(p.id), `${p.name} — ${p.provider_label}${p.is_default ? " (default)" : ""}`]), String(init.llm_profile_id || (def && def.id) || "")),
    scan_mode: select([["quick", "Quick — for CI checks"], ["standard", "Standard — routine testing"], ["deep", "Deep — thorough, long and costly"]], init.scan_mode || "standard"),
    max_turns: h("input", { type: "number", min: "1", step: "1", value: init.max_turns ?? "", placeholder: "Strix default" }),
    fail_on: select([["", "No gate"], ...SEV.map((s) => [s, `${SEV_TR[s]} and above`])], init.fail_on ?? "high"),
  };
  const llmHelp = h("div", { class: "help" });
  const upd = () => {
    const p = profiles.find((x) => String(x.id) === f.llm_profile_id.value);
    llmHelp.textContent = !p ? "" : (p.provider === "openrouter" ? `Model: ${p.strix_model}. Scan content goes to the selected provider via OpenRouter.` : `Model: ${p.strix_model}. Content goes to the in-house gateway (${p.base_url}).`) + " On error it does not switch to another connection.";
  };
  f.llm_profile_id.addEventListener("change", upd); upd();
  const fields = [
    h("div", { class: "field" }, h("label", {}, "LLM connection"), f.llm_profile_id, llmHelp),
    field("Scan mode", f.scan_mode),
    h("div", { class: "field-row limits" },
      field("Turns per agent", f.max_turns),
      field("Finding gate", f.fail_on)),
    h("div", { class: "help" }, "Finding gate: if a finding at or above the selected level is found, the result becomes “Gate failed”; used to block a release in CI."),
  ];
  const value = () => ({ llm_profile_id: f.llm_profile_id.value, scan_mode: f.scan_mode.value, max_turns: f.max_turns.value || null, fail_on: f.fail_on.value });
  return { fields, value, f };
}

async function scanDialog(target, preset) {
  preset = preset || {};
  // Always load the full target list (we need each target's assigned auth profiles), plus campaigns.
  const [profiles, allTargets, campaignList] = await Promise.all([api("/api/llm-profiles"), api("/api/targets"), api("/api/campaigns")]);
  if (!profiles.length) { toast("First add a connection under Settings > LLM connections.", true); return; }
  let targets = allTargets;
  if (preset.target_ids && preset.target_ids.length) targets = allTargets.filter((x) => preset.target_ids.includes(x.id));
  if (!targets.length) {
    const close = dialog("New scan", emptyState("No targets yet", "To start a scan, first define the application to scan as a target."),
      [button("Cancel", { onclick: () => close() }), button("Create target", { kind: "primary", onclick: () => { close(); go("#/targets/new"); } })]);
    return;
  }
  // If a specific target object was passed, use the full version from the list (it carries auth_profiles).
  let t = (target && targets.find((x) => x.id === target.id)) || targets.find((x) => !x.active_scan) || targets[0];
  const targetSel = select(targets.map((x) => [String(x.id), `${x.name} · ${ENV_TR[x.environment]}${x.active_scan ? " (scan in progress)" : ""}`]), String(t.id));
  const summary = h("div", { class: "target-summary" });
  const optsBox = h("div", { class: "fields" });
  const extrasBox = h("div", { class: "fields" });
  const instruction = h("textarea", { rows: 3, placeholder: "Extra instructions specific to this scan (optional)" });
  const prodOk = h("input", { type: "checkbox" });
  const prodRow = h("label", { class: "check" }, prodOk, "I understand active testing will run against a production environment and I am authorized for this system.");
  let opts, extras;
  const renderTarget = () => {
    summary.replaceChildren(h("div", { class: "primary-line" }, t.name, " ", envTag(t.environment)), h("div", { class: "mono faint" }, t.base_url),
      t.active_scan ? h("div", { class: "help" }, "This target already has an active scan; a new one can't be started.") : null);
    opts = scanOptions(profiles, { scan_mode: t.default_scan_mode, llm_profile_id: t.llm_profile_id, fail_on: "high" });
    extras = scanExtras(t.auth_profiles || [], campaignList, { campaign_id: preset.campaign_id });
    optsBox.replaceChildren(opts.fields);
    extrasBox.replaceChildren(extras.fields);
    prodRow.hidden = t.environment !== "production"; prodOk.checked = false;
  };
  targetSel.addEventListener("change", () => { t = targets.find((x) => String(x.id) === targetSel.value); renderTarget(); });
  renderTarget();
  const close = dialog("New scan", [field("Target", targetSel), summary, optsBox, extrasBox, field("Extra instructions", instruction), prodRow], [
    button("Cancel", { onclick: () => close() }),
    button("Start scan", { kind: "primary", ic: "play", onclick: guard(async () => {
      if (t.environment === "production" && !prodOk.checked) { toast("Check the confirmation box for a production scan.", true); return; }
      const s = await api(`/api/targets/${t.id}/scan`, { method: "POST", body: { ...opts.value(), ...extras.value(), instruction: instruction.value } });
      close(); toast("Scan queued"); go(`#/scans/${s.id}`);
    }) })], { wide: true });
}

// ================================================================== targets
async function viewTargets() {
  const list = await api("/api/targets");
  app.replaceChildren(
    pageHead("Targets", { lead: "Scanned applications, their environments and scopes.", actions: [button("New target", { kind: "primary", ic: "plus", onclick: () => go("#/targets/new") })] }),
    h("div", { class: "table-card" }, table(
      [{ label: "Target" }, { label: "Environment" }, { label: "Last scan" }, { label: "Last findings" }, { label: "Next scan" }, { label: "", cls: "shrink" }],
      list.map((t) => {
        const ls = t.active_scan || t.last_scan;
        return h("tr", { class: "clickable", onclick: () => go(`#/targets/${t.id}`) },
          h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line", title: t.name }, t.name), h("div", { class: "secondary-line mono", title: t.base_url }, t.base_url))),
          h("td", {}, envTag(t.environment)),
          h("td", {}, ls ? h("div", {}, statusChip(ls.status), h("div", { class: "status-sub" }, fmtShort(ls.started_at || ls.created_at))) : h("span", { class: "faint" }, "Never scanned")),
          h("td", {}, t.last_scan ? sevSummary((t.last_scan.summary || {}).counts, { status: t.last_scan.status, max: 2 }) : h("span", { class: "faint" }, "—")),
          h("td", {}, t.next_run_at ? whenCell(t.next_run_at) : h("span", { class: "faint" }, "No schedules")),
          h("td", { class: "shrink right", onclick: (e) => e.stopPropagation() },
            button("Scan", { size: "sm", ic: "play", disabled: !!t.active_scan, title: t.active_scan ? "This target has an active scan" : "Scan this target now", onclick: () => scanDialog(t) })));
      }),
      emptyState("No targets yet", "Define the application to scan with its address, environment and scope. Then you can start an on-demand scan or schedule one.",
        [button("New target", { kind: "primary", ic: "plus", onclick: () => go("#/targets/new") })]))));
}

async function viewTarget(id) {
  const [t, schedules, scans, findings] = await Promise.all([api(`/api/targets/${id}`), api(`/api/schedules?target_id=${id}`), api(`/api/scans?target_id=${id}&limit=300`), api(`/api/targets/${id}/findings`)]);
  const del = guard(async () => {
    if (!await confirmDialog("Delete target?", `“${t.name}” and its ${schedules.length} schedules will be deleted. Scan history and report files are kept.`, { confirmLabel: "Delete target", danger: true })) return;
    await api(`/api/targets/${id}`, { method: "DELETE" }); toast("Target deleted"); go("#/targets");
  });
  app.replaceChildren(
    pageHead(t.name, {
      crumb: h("a", { href: "#/targets" }, "Targets"),
      meta: [envTag(t.environment), t.application ? h("span", {}, t.application) : null, h("span", { class: "mono" }, t.base_url)],
      actions: [
        menu([{ label: "Edit", icon: "edit", onclick: () => go(`#/targets/${id}/edit`) },
          { label: "View inventory", icon: "inventory", onclick: () => go(`#/inventory?target=${id}`) },
          { label: "Compare scans", icon: "scans", onclick: () => go(`#/targets/${id}/compare`) }, "-",
          { label: "Delete target", icon: "trash", danger: true, need: "admin", onclick: del }]),
        button("Report", { ic: "report", title: "Management report (print or save as PDF)", onclick: () => go(`#/targets/${id}/report`) }),
        button("Add schedule", { ic: "schedules", onclick: () => go(`#/schedules/new?target=${id}`) }),
        button(t.active_scan ? "Scan in progress" : "Scan now", { kind: "primary", ic: "play", disabled: !!t.active_scan, onclick: () => scanDialog(t) })] }),
    t.active_scan ? alertBox("info", "This target has an active scan", ["Scan ", h("a", { href: `#/scans/${t.active_scan.id}` }, `#${t.active_scan.id}`), ` is ${STATUS_TR[t.active_scan.status].toLowerCase()}. Back-to-back scans on the same target aren't allowed.`]) : null,
    h("div", { class: "grid-main-side" },
      h("div", {},
        findings.summary && findings.summary.unique ? section("Finding groups", findingsCard(findings.summary, id), { hint: plural(findings.summary.unique, "group") }) : null,
        section("Scan history", h("div", { class: "table-card" }, scanTable(scans, { showTarget: false, empty: emptyState("This target hasn't been scanned yet", "Start the first scan to see its security posture.", [button("Scan now", { kind: "primary", ic: "play", onclick: () => scanDialog(t) })]) })), { hint: scans.length ? `${scans.length} records` : null }),
        section("Schedules", h("div", { class: "table-card" }, scheduleTable(schedules, { showTarget: false, empty: emptyState("No schedules", "Plan recurring scans for this target.", [button("Add schedule", { onclick: () => go(`#/schedules/new?target=${id}`) })]) })))),
      h("div", {},
        section("Configuration", h("div", { class: "card card-pad" }, h("dl", { class: "dl stacked" },
          h("dt", {}, "Strix targets"), h("dd", { class: "mono" }, t.strix_targets.map((x) => h("div", {}, x))),
          h("dt", {}, "In scope"), h("dd", { class: t.in_scope.length ? "mono" : "faint" }, t.in_scope.length ? t.in_scope.map((x) => h("div", {}, x)) : "Not set"),
          h("dt", {}, "Out of scope"), h("dd", { class: t.out_of_scope.length ? "mono" : "faint" }, t.out_of_scope.length ? t.out_of_scope.map((x) => h("div", {}, x)) : "Not set"),
          h("dt", {}, "Auth profiles"), h("dd", {}, (t.auth_profiles || []).length ? (t.auth_profiles || []).map((p) => h("div", {}, p.name, " ", h("span", { class: "tag" }, AUTHKIND_TR[p.kind] || p.kind))) : h("span", { class: "faint" }, "None assigned")),
          h("dt", {}, "Default mode"), h("dd", {}, MODE_TR[t.default_scan_mode])))),
        section("Instructions sent to Strix", h("div", { class: "card card-pad" },
          h("div", { class: "note", style: null }, "Strix has no separate scope or authentication option; this information is passed via the instruction file and goes to the selected LLM provider. Secret values are masked here."),
          h("pre", { class: "mono", style: null }, t.instruction_preview))))));
  app.querySelectorAll(".card pre").forEach((p) => { p.style.whiteSpace = "pre-wrap"; p.style.margin = "12px 0 0"; p.style.color = "var(--text-2)"; });
}

async function viewTargetForm(id) {
  const [t, profiles] = await Promise.all([id ? api(`/api/targets/${id}`) : null, api("/api/llm-profiles")]);
  const v = t || { environment: "test", auth_type: "none", default_scan_mode: "standard", in_scope: [], out_of_scope: [], extra_targets: [] };
  const f = {
    name: h("input", { type: "text", value: v.name || "", placeholder: "e.g. Mobile Banking API" }),
    application: h("input", { type: "text", value: v.application || "", placeholder: "Project or application name" }),
    environment: select(Object.entries(ENV_TR), v.environment),
    base_url: h("input", { type: "text", value: v.base_url || "", placeholder: "https://staging.app.local", class: "mono" }),
    extra_targets: h("textarea", { rows: 2, value: (v.extra_targets || []).join("\n"), placeholder: "https://github.com/org/repo\n./openapi.yaml" }),
    in_scope: h("textarea", { rows: 3, value: (v.in_scope || []).join("\n"), placeholder: "staging.app.local\napi.staging.app.local" }),
    out_of_scope: h("textarea", { rows: 3, value: (v.out_of_scope || []).join("\n"), placeholder: "/admin/delete\npayments.app.local" }),
    instruction: h("textarea", { rows: 4, value: v.instruction || "", placeholder: "e.g. Focus on authentication, IDOR and business-logic flaws." }),
    default_scan_mode: select([["quick", "Quick"], ["standard", "Standard"], ["deep", "Deep"]], v.default_scan_mode),
    llm_profile_id: select([["", "Default connection"], ...profiles.map((p) => [String(p.id), `${p.name} — ${p.provider_label}`])], v.llm_profile_id ? String(v.llm_profile_id) : ""),
  };
  const save = guard(async () => {
    const body = Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.value]));
    const r = await api(id ? `/api/targets/${id}` : "/api/targets", { method: id ? "PUT" : "POST", body });
    toast("Target saved"); go(`#/targets/${r.id}`);
  });
  app.replaceChildren(
    pageHead(id ? "Edit target" : "New target", { crumb: id ? h("a", { href: `#/targets/${id}` }, v.name) : h("a", { href: "#/targets" }, "Targets") }),
    h("form", { class: "card card-pad form", onsubmit: (e) => { e.preventDefault(); save(); } },
      formSection("General", "Define the application to scan and its environment.", [
        field("Target name", f.name), field("Application / project", f.application),
        field("Environment", f.environment, "Production targets require an extra confirmation before a scan starts."),
        field("Target address", f.base_url, "Passed to Strix as the target: URL, domain, IP, git repository or local folder."),
        field("Extra targets", f.extra_targets, "Optional, one per line: source repository, OpenAPI/Postman file or extra host.")]),
      formSection("Scope", "Strix has no technical scope restriction; this list is passed as instructions and agents are asked to honor it.", [
        field("In scope", f.in_scope, "One host or URL per line."), field("Out of scope", f.out_of_scope, "Hosts, URLs or paths that must receive no traffic.")]),
      formSection("Authentication", "Credentials are no longer stored on the target. Define reusable auth profiles (vault) and assign them to this target; secret values are given to the scan only as a sandbox file, never written into the instruction.", [
        h("div", { class: "note" }, id && (v.auth_profiles || []).length
          ? ["Assigned profiles: ", (v.auth_profiles || []).map((p) => p.name).join(", "), ". "]
          : "No auth profile assigned to this target. ",
          h("a", { href: "#/auth-profiles" }, "Manage auth profiles"))]),
      formSection("Defaults", "Can be changed when starting a scan.", [
        field("Scan instruction", f.instruction, "Added to the Strix instruction file."),
        h("div", { class: "field-row two" }, field("Default mode", f.default_scan_mode), field("LLM connection", f.llm_profile_id))]),
      h("div", { class: "form-actions" }, button("Cancel", { onclick: () => history.back() }), button("Save", { kind: "primary", type: "submit" }))));
}

// ================================================================== scans
async function viewScans() {
  const targets = await api("/api/targets");
  const st = { tab: "all", target: "", q: "", limit: 50 };
  const TABS = [["all", "All", ""], ["active", "Active", "queued,running,stopping"], ["completed", "Completed", "completed"], ["failed", "Failed", "failed"], ["stopped", "Cancelled / interrupted", "cancelled,interrupted"]];
  const seg = h("div", { class: "seg" });
  const targetSel = select([["", "All targets"], ...targets.map((t) => [String(t.id), t.name])], "");
  const search = h("input", { type: "search", placeholder: "Search target, address or run name" });
  const box = h("div", { class: "table-card" }, h("div", { class: "loading" }, "Loading…"));
  const renderSeg = () => seg.replaceChildren(TABS.map(([k, l]) => h("button", { type: "button", class: st.tab === k ? "on" : null, onclick: () => { st.tab = k; st.limit = 50; renderSeg(); load(); } }, l)));
  targetSel.addEventListener("change", () => { st.target = targetSel.value; st.limit = 50; load(); });
  let qt; search.addEventListener("input", () => { clearTimeout(qt); qt = setTimeout(() => { st.q = search.value.trim().toLowerCase(); st.limit = 50; load(); }, 200); });
  const load = guard(async () => {
    const status = TABS.find((x) => x[0] === st.tab)[2];
    let list = await api(`/api/scans?limit=1000${status ? "&status=" + status : ""}${st.target ? "&target_id=" + st.target : ""}`);
    if (st.q) list = list.filter((s) => [s.target_name, s.name, s.run_name, ...(s.targets || [])].join(" ").toLowerCase().includes(st.q));
    const shown = list.slice(0, st.limit);
    box.replaceChildren(scanTable(shown, { empty: emptyState(st.q || st.target || status ? "No scans match the filter" : "No scans yet", st.q || st.target || status ? "Try changing the filters." : "Scans appear here once you pick a target and start one.") }),
      list.length > 0 ? h("div", { class: "table-foot" }, h("span", {}, `Showing ${shown.length} of ${list.length} scans`),
        list.length > shown.length ? button("Show more", { size: "sm", onclick: () => { st.limit += 50; load(); } }) : null) : null);
  });
  renderSeg();
  app.replaceChildren(
    pageHead("Scans", { lead: "All runs started manually, by a schedule, from CI or imported from the Strix TUI.",
      actions: [menu([{ label: "Re-scan the strix_runs folder", icon: "refresh", onclick: guard(async () => { const r = await api("/api/import", { method: "POST" }); toast(`${r.imported} runs imported`); load(); }) }]),
        button("New scan", { kind: "primary", ic: "plus", onclick: () => scanDialog(null) })] }),
    h("div", { class: "toolbar" }, seg, h("span", { class: "grow" }), targetSel, search), box);
  await load();
  every(5000, load);
}

async function viewScan(id) {
  let scan = await api(`/api/scans/${id}`);
  let tab = ACTIVE.includes(scan.status) ? "live" : "findings";
  const headBox = h("div", {}), alertsBox = h("div", {}), factsBox = h("div", {}), tabsBox = h("div", { class: "tabs scan-tabs" }), body = h("div", {});
  const log = { source: "strix", offset: -1, box: null, level: "info", follow: null };
  let findingsCount = null;
  const live = { cursor: -1, agent: "", list: null, tree: null, follow: null, state: null, busy: false, generation: 0, calls: new Map(), count: null, events: 0 };
  const compose = { box: null, select: null, text: null, send: null, hint: null, history: null, count: null, rid: null, ridFor: "", sending: false, agentsSig: "", chosen: "", busy: false, gen: 0 };

  const renderHead = () => {
    const active = ACTIVE.includes(scan.status);
    const canResume = scan.trigger !== "verify" && ["cancelled", "failed", "interrupted"].includes(scan.status) && scan.run_name && scan.target_id;
    const files = scan.files || {};
    const DL = [["report", "Report (Markdown)"], ["sarif", "SARIF"], ["json", "Findings (JSON)"], ["csv", "Findings (CSV)"], ["coverage", "Coverage (JSON)"], ["log", "Strix log"]].filter(([k]) => files[k]);
    headBox.replaceChildren(pageHead(scan.target_name || scan.name || `Scan #${scan.id}`, {
      crumb: h("a", { href: "#/scans" }, "Scans"),
      meta: [statusChip(scan.status), envTag(scan.environment || scan.target_environment), h("span", { class: "mono", title: (scan.targets || []).join("\n") }, (scan.targets || [])[0] || ""), h("span", { class: "faint" }, `#${scan.id}`)],
      actions: [
        !active && scan.trigger !== "verify" ? menu([{ label: "Delete record", icon: "trash", danger: true, onclick: guard(async () => {
          if (!await confirmDialog("Delete scan record?", "The record is removed from the list. The Strix output folder on disk is not deleted.", { confirmLabel: "Delete record", danger: true })) return;
          await api(`/api/scans/${id}`, { method: "DELETE" }); go("#/scans");
        }) }]) : null,
        DL.length ? menu(DL.map(([k, l]) => ({ label: l, icon: "download", onclick: () => { location.href = `/api/scans/${id}/download/${k}`; } })), { label: "Download" }) : null,
        canResume ? button("Resume", { ic: "play", title: "Continues the same run with strix --resume", onclick: guard(async () => { const n = await api(`/api/scans/${id}/resume`, { method: "POST" }); go(`#/scans/${n.id}`); }) }) : null,
        scan.target_id && !active ? button("Scan again", { onclick: guard(async () => { const t = await api(`/api/targets/${scan.target_id}`); scanDialog(t); }) }) : null,
        active ? button(scan.status === "stopping" ? "Stopping…" : scan.status === "queued" ? "Remove from queue" : "Stop scan", { kind: "danger", ic: "stop", disabled: scan.status === "stopping", onclick: () => stopScan(scan, async () => { scan = await api(`/api/scans/${id}`); renderAll(); }) }) : null] }));
  };

  const renderAlerts = () => {
    alertsBox.replaceChildren(
      scan.error ? alertBox(scan.status === "failed" ? "danger" : "warn", scan.status === "failed" ? "Scan failed" : "Note", null, h("pre", { class: "mono" }, scan.error)) : null);
  };

  const renderFacts = () => {
    const sm = scan.summary || {}, rm = scan.run_meta || {};
    const cost = sm.cost || rm.cost;
    const fact = (k, v, title) => h("div", { title }, h("div", { class: "k" }, k), h("div", { class: "v" }, v));
    factsBox.replaceChildren(h("div", { class: "facts" },
      fact("Findings", sevSummary(sm.counts, { status: scan.status, max: 5 })),
      fact("Finding gate", verdict(scan), VERDICT_HELP),
      fact("Started", fmtDateSec(scan.started_at)),
      fact("Duration", ACTIVE.includes(scan.status) && scan.status !== "queued" ? `${durationText(scan)} (ongoing)` : durationText(scan)),
      fact("Model", h("span", { class: "mono" }, scan.model || "—")),
      fact("LLM connection", scan.llm_profile_name ? `${scan.llm_profile_name} · ${scan.llm_provider === "litellm" ? "LiteLLM" : "OpenRouter"}` : "—"),
      fact("Scan mode", MODE_TR[scan.scan_mode] || scan.scan_mode || "—"),
      fact("Started by", TRIGGER_TR[scan.trigger] || scan.trigger),
      fact("LLM cost", cost ? `$${Number(cost) < 0.01 ? Number(cost).toFixed(4) : Number(cost).toFixed(2)}` : h("span", { class: "faint" }, "Not reported by Strix"), cost ? null : "When Strix doesn't know the model price it writes cost as 0"),
      fact("Tokens / requests", `${fmtTokens(sm.tokens ?? rm.tokens)} / ${sm.requests ?? rm.requests ?? "—"}`),
      fact("Finished", scan.finished_at ? fmtDateSec(scan.finished_at) : ACTIVE.includes(scan.status) ? "Ongoing" : "—"),
      fact("Output folder", h("span", { class: "mono" }, scan.run_name || "—"), scan.run_dir || "")));
  };

  const TABS = [["live", "Live activity"], ["timeline", "Timeline"], ["findings", "Findings"], ["coverage", "Coverage"], ["sessions", "Session health"], ["instructions", "Instructions"], ["browser", "Browser"], ["log", "Live log"], ["agents", "Agents"], ["telemetry", "Telemetry"], ["report", "Report"], ["details", "Details"]];
  const renderTabs = () => { factsBox.hidden = tab === "live"; tabsBox.replaceChildren(TABS.map(([k, l]) => h("button", { type: "button", class: tab === k ? "on" : null, onclick: () => { tab = k; renderTabs(); renderBody(); } },
    l, k === "findings" && findingsCount != null ? h("span", { class: "cnt" }, findingsCount) : null))); };
  const renderAll = () => { renderHead(); renderAlerts(); renderFacts(); };

  const renderBody = guard(async () => {
    log.box = null;
    live.list = null; live.busy = false; live.generation++;
    if (tab === "live") { compose.loaded = false; body.replaceChildren(liveView()); await Promise.all([pollLive(), pollMessages(true)]); }
    else if (tab === "findings") body.replaceChildren(await findingsView());
    else if (tab === "timeline") body.replaceChildren(await skyTimelineTab(id, scan));
    else if (tab === "coverage") body.replaceChildren(await skyCoverageTab(id));
    else if (tab === "sessions") body.replaceChildren(await skySessionTab(id, scan));
    else if (tab === "instructions") body.replaceChildren(await skyInstructionsTab(id, scan));
    else if (tab === "browser") body.replaceChildren(await skyBrowserTab(id, scan));
    else if (tab === "log") body.replaceChildren(logView());
    else if (tab === "agents") body.replaceChildren(await agentsView());
    else if (tab === "telemetry") body.replaceChildren(await telemetryView());
    else if (tab === "report") {
      const r = await api(`/api/scans/${id}/report`);
      body.replaceChildren(r.available ? h("div", { class: "card card-pad" }, h("div", { class: "md report", html: r.html }))
        : h("div", { class: "card" }, emptyState("No report", ACTIVE.includes(scan.status) ? "Strix writes the report when the scan finishes." : "Strix did not produce a report file for this run.")));
    } else body.replaceChildren(detailsView());
  });

  async function findingsView() {
    const r = await api(`/api/scans/${id}/findings`);
    findingsCount = r.items.length; renderTabs();
    if (!r.items.length) return h("div", { class: "card" }, emptyState(
      ACTIVE.includes(scan.status) ? "No findings reported yet" : scan.status === "completed" ? "Strix reported no findings in this scan" : "No findings",
      ACTIVE.includes(scan.status) ? "Strix writes confirmed findings while the scan runs; this list updates automatically." : scan.status === "completed" ? "This does not guarantee the target is secure; see the scan scope and mode on the Details tab." : "Results may be incomplete because the scan did not finish."));
    const tbody = h("tbody", {});
    r.items.forEach((v) => {
      const detail = h("tr", { class: "detail-row", hidden: true }, h("td", { colspan: 5 }, findingDetail(v)));
      tbody.append(h("tr", { class: "clickable", onclick: () => { detail.hidden = !detail.hidden; } },
        h("td", { class: "shrink" }, h("span", { class: `sevpill ${v.severity}` }, SEV_TR[v.severity] || v.severity)),
        h("td", {}, h("div", { class: "cell-clip", style: null }, h("div", { class: "primary-line", title: v.title }, v.title), h("div", { class: "secondary-line mono", title: v.endpoint || "" }, [v.method, v.endpoint].filter(Boolean).join(" ") || v.target || ""))),
        h("td", { class: "nowrap" }, v.cvss != null ? `CVSS ${v.cvss}` : "—"),
        h("td", { class: "nowrap muted" }, v.cwe || "—"),
        h("td", { class: "shrink" }, icon("chevron")), detail));
      tbody.append(detail);
    });
    tbody.querySelectorAll(".cell-clip").forEach((c) => { c.style.maxWidth = "min(880px, 44vw)"; });
    return h("div", {},
      r.source === "vulnerabilities/*.md" ? alertBox("info", "Preliminary findings", "Read from the per-finding files Strix writes while the scan runs. The final list is produced when the scan ends.") : null,
      h("div", { class: "table-card" }, h("div", { class: "table-scroll" }, h("table", { class: "t" },
        h("thead", {}, h("tr", {}, ["Severity", "Finding", "CVSS", "CWE", ""].map((c) => h("th", {}, c)))), tbody))),
      r.source === "vulnerabilities.json" ? h("div", { class: "note", style: null }, "Source: Strix vulnerabilities.json. Click a row to expand details.") : null);
  }

  function findingDetail(v) {
    const sec = (t, html) => html ? [h("h4", {}, t), h("div", { class: "md", html })] : null;
    if (v.markdown_html) return h("div", { class: "finding-body" }, v.group_id ? verificationPanel(v.group_id) : null, h("div", { class: "md", html: v.markdown_html }));
    return h("div", { class: "finding-body" },
      v.group_id ? verificationPanel(v.group_id) : null,
      h("div", { class: "note" }, [v.target ? `Target: ${v.target}` : null, v.timestamp ? `Found: ${v.timestamp}` : null, v.confidence ? `Confidence: ${v.confidence}` : null, v.fix_effort ? `Fix effort: ${v.fix_effort}` : null].filter(Boolean).join(" · ")),
      sec("Description", v.description_html), sec("Impact", v.impact_html), sec("Technical analysis", v.technical_analysis_html),
      sec("Evidence", v.evidence_html), sec("Proof of concept (PoC)", v.poc_description_html),
      v.poc_script_code ? h("div", { class: "md" }, h("pre", {}, h("code", {}, v.poc_script_code))) : null,
      sec("Remediation", v.remediation_steps_html), sec("Assumptions", v.assumptions_html), sec("Counterevidence", v.counterevidence_html),
      v.cvss_breakdown ? [h("h4", {}, "CVSS breakdown"), h("dl", { class: "dl" }, Object.entries(v.cvss_breakdown).flatMap(([k, x]) => [h("dt", {}, k), h("dd", {}, x)]))] : null);
  }

  function liveView() {
    live.cursor = -1; live.agent = ""; live.calls = new Map(); live.events = 0;
    live.follow = h("input", { type: "checkbox", checked: true });
    live.list = h("div", { class: "live-feed", role: "log", "aria-label": "Strix activity feed", "aria-live": "off" });
    live.tree = h("div", { class: "live-agents" });
    live.state = h("span", { class: "live-sync", role: "status" }, "Loading activity…");
    live.count = h("span", { class: "live-count" }, "");
    const sm = scan.summary || {};
    return h("div", { class: "live-layout" },
      h("section", { class: "card live-main" },
        h("div", { class: "live-toolbar" },
          h("div", { class: "live-title" }, h("span", { class: "live-signal" + (ACTIVE.includes(scan.status) ? " active" : "") }),
            h("div", {}, h("h2", {}, "Activity stream"), h("div", { class: "live-subtitle" }, ACTIVE.includes(scan.status) ? "Live updates from Strix" : "Recorded activity from this scan"))),
          h("label", { class: "check live-follow" }, live.follow, "Auto-follow")),
        h("div", { class: "live-state" }, live.state, live.count), live.list, composerView()),
      h("aside", { class: "live-sidebar" },
        h("div", { class: "live-side-head" }, h("h2", {}, "Agents"), h("span", { class: "tag", id: "liveAgentCount" }, "—")),
        h("p", { class: "live-side-help" }, "Select an agent to focus its activity."), live.tree,
        h("div", { class: "live-run-info" }, h("div", { class: "live-info-label" }, "THIS RUN"),
          h("div", { class: "live-info-row" }, h("span", {}, "Duration"), h("strong", {}, durationText(scan))),
          h("div", { class: "live-info-row" }, h("span", {}, "Tokens"), h("strong", {}, fmtTokens(sm.tokens))),
          h("div", { class: "live-info-row" }, h("span", {}, "Mode"), h("strong", {}, MODE_TR[scan.scan_mode] || "—")),
          h("div", { class: "live-model", title: scan.model || "" }, modelShort(scan.model)))));
  }

  const MSG_STATE = { sending: ["Sending", "neutral"], queued: ["Queued for next model call", "queued"], delivered: ["In agent context", "completed"],
    expired: ["Not delivered", "neutral"], rejected: ["Rejected", "failed"], unknown: ["Unconfirmed", "queued"] };
  const MSG_HELP = { queued: "Strix accepted it. It is added to the agent's context before the agent's next model call.",
    delivered: "Added to the agent's conversation. Whether the agent follows it shows in the activity stream.",
    unknown: "No confirmation arrived. It may have been accepted, so it was not resent. Check again asks Strix without sending a second copy." };

  function composerView() {
    compose.gen++;
    compose.agentsSig = ""; compose.rid = null; compose.ridFor = ""; compose.sending = false; compose.busy = false;
    compose.select = h("select", { id: "composeAgent", "aria-label": "Agent to message", onchange: () => { compose.chosen = compose.select.value; } });
    compose.text = h("textarea", { id: "composeText", rows: 2, maxlength: 4000, placeholder: "Write an instruction for the selected agent…", "aria-label": "Message to the agent",
      oninput: () => { compose.count.textContent = `${compose.text.value.length}/4000`; compose.text.style.height = "auto"; compose.text.style.height = Math.min(compose.text.scrollHeight, 168) + "px"; updateSend(); },
      onkeydown: (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.preventDefault(); sendMessage(); } } });
    compose.count = h("span", { class: "compose-count" }, "0/4000");
    compose.send = button("Send", { kind: "primary", size: "sm", onclick: () => sendMessage(), disabled: true, title: "Send (⌘/Ctrl+Enter)" });
    compose.hint = h("div", { class: "compose-hint", role: "status" }, "Checking whether this scan accepts messages…");
    compose.history = h("div", { class: "compose-history" });
    compose.form = h("div", { class: "compose-form" + (can("analyst") ? "" : " role-hidden"), hidden: true },
      h("div", { class: "compose-row" }, h("label", { class: "compose-label", for: "composeAgent" }, "Message"), compose.select, compose.count),
      compose.text,
      h("div", { class: "compose-foot" }, h("span", { class: "help" }, "Added to the agent's context before its next model call. Keep credentials in the Vault."), compose.send));
    compose.box = h("section", { class: "compose", "aria-label": "Message an agent" }, compose.form, compose.hint, compose.history);
    return compose.box;
  }

  function updateSend() {
    if (!compose.send) return;
    compose.send.disabled = compose.sending || !compose.select.value || !compose.text.value.trim() || compose.form.hidden;
    compose.send.textContent = compose.sending ? "Sending…" : "Send";
  }

  function renderMessages(m) {
    const accepting = (m.agents || []).filter((a) => a.accepting);
    compose.form.hidden = !m.available || !accepting.length;
    compose.hint.textContent = !m.available ? (ACTIVE.includes(scan.status) ? m.reason : "Messages can only be sent while a scan is running.")
      : !accepting.length ? "No agent is currently running or waiting." : "";
    compose.hint.hidden = !compose.hint.textContent;
    const sig = accepting.map((a) => `${a.id}:${a.name}:${a.status}`).join("|");
    if (sig !== compose.agentsSig) {
      compose.agentsSig = sig;
      const want = compose.chosen || compose.select.value || (accepting.some((a) => a.id === live.agent) ? live.agent : (accepting[0] || {}).id);
      compose.select.replaceChildren(...accepting.map((a) => h("option", { value: a.id }, `${a.name} · ${a.status === "running" ? "Running" : "Waiting"}`)));
      if (accepting.some((a) => a.id === want)) compose.select.value = want;
    }
    const rows = m.messages || [];
    compose.history.hidden = !rows.length;
    compose.history.replaceChildren(rows.length ? h("details", { class: "compose-sent", open: compose.history.dataset.open === "1" || null,
      ontoggle: (e) => { compose.history.dataset.open = e.target.open ? "1" : ""; } },
      h("summary", {}, `Sent messages · ${rows.length}`),
      h("ol", {}, rows.map((x) => {
        const [label, cls] = MSG_STATE[x.state] || [x.state, "neutral"];
        return h("li", { class: "compose-msg" },
          h("div", { class: "compose-msg-head" }, h("strong", {}, x.agent_name || x.agent_id), h("time", { datetime: x.created_at || "" }, fmtShort(x.created_at)),
            h("span", { class: `status ${cls}`, title: MSG_HELP[x.state] || "" }, h("span", { class: "dot" }), label)),
          h("div", { class: "compose-msg-text" }, x.content || h("span", { class: "faint" }, "Content unavailable")),
          x.reason || MSG_HELP[x.state] ? h("div", { class: "help" }, x.reason || MSG_HELP[x.state]) : null,
          x.state === "unknown" && m.available ? button("Check again", { size: "sm", onclick: guard(async () => { await api(`/api/scans/${id}/messages/${x.id}/recheck`, { method: "POST" }); await pollMessages(true); }) }) : null);
      }))) : []);
    updateSend();
  }

  async function pollMessages(force = false) {
    if (!compose.box || compose.busy) return;
    if (!force && !ACTIVE.includes(scan.status) && compose.loaded) return;
    compose.busy = true;
    const gen = compose.gen;
    try {
      const m = await api(`/api/scans/${id}/messages`);
      if (gen !== compose.gen) return;
      compose.loaded = true;
      renderMessages(m);
    } catch (e) {
      if (gen === compose.gen) { compose.hint.hidden = false; compose.hint.textContent = "Message status unavailable · retrying…"; }
    } finally { if (gen === compose.gen) compose.busy = false; }
  }

  async function sendMessage() {
    const agentId = compose.select.value, content = compose.text.value.trim();
    if (compose.sending || !agentId || !content) return;
    const key = `${agentId}\n${content}`;
    if (compose.ridFor !== key) { compose.rid = crypto.randomUUID(); compose.ridFor = key; }   // a retry of the same text reuses its ID
    compose.sending = true; updateSend();
    try {
      const r = await api(`/api/scans/${id}/messages`, { method: "POST", body: { agent_id: agentId, content, request_id: compose.rid } });
      if (r.state === "rejected") toast(r.reason || "Strix rejected the message.", true);
      else {
        compose.text.value = ""; compose.text.style.height = ""; compose.count.textContent = "0/4000";
        compose.rid = null; compose.ridFor = "";
        toast(r.state === "unknown" ? "No confirmation from Strix yet; the message was not resent." : "Message accepted by Strix");
      }
    } catch (e) { toast(e.message, true); }
    finally { compose.sending = false; updateSend(); compose.loaded = false; await pollMessages(true); }
  }

  function activityPreview(text, tool) {
    let value = text || "";
    try {
      const o = JSON.parse(value);
      const summaries = { view_agent_graph: "Agent status and task hierarchy", list_reports: "Recorded vulnerability reports", list_coverage: "Tested surfaces and coverage status", wait_for_agents: "Waiting for child agents to finish" };
      value = o.cmd || o.task || o.url || o.content || o.message || o.output || o.executive_summary || o.surface ||
        (o.request_id ? `HTTP request #${o.request_id} · ${o.part === "response" ? "response" : "request"}` : summaries[tool]) ||
        Object.entries(o).filter(([, v]) => v != null && v !== "").map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join(" · ") || "No parameters required";
      if (typeof value !== "string") value = JSON.stringify(value);
    } catch { /* ordinary tool text */ }
    const lines = String(value).split("\n").map((x) => x.trim()).filter(Boolean);
    return (lines.find((ln) => !/^(Chunk ID:|Wall time:|Process exited|Final output:|Output:|[{}]$|"success":)/.test(ln)) || "View details").slice(0, 210);
  }

  async function pollLive() {
    if (!live.list || live.busy) return;
    live.busy = true;
    const gen = live.generation, list = live.list;
    try {
      const [r, a] = await Promise.all([api(`/api/scans/${id}/activity?after=${live.cursor}${live.agent ? "&agent_id=" + encodeURIComponent(live.agent) : ""}`), api(`/api/scans/${id}/agents`)]);
      if (gen !== live.generation || list !== live.list) return;
      const byId = Object.fromEntries(a.agents.map((x) => [x.id, x]));
      if (live.cursor === -1) { list.replaceChildren(); live.calls = new Map(); live.events = 0; }
      else list.querySelector(".live-empty")?.remove();
      const TOOL_LABELS = { exec_command: "Command", write_stdin: "Command output", create_agent: "Spawn agent", agent_finish: "Agent finished",
        view_request: "HTTP exchange", list_requests: "HTTP requests", list_reports: "Finding list", send_request: "HTTP request", repeat_request: "Repeat request",
        create_todo: "Task list", update_todo: "Task update", list_coverage: "Coverage summary", record_coverage: "Coverage update",
        create_vulnerability_report: "New finding", update_vulnerability_report: "Finding update", finish_scan: "Scan report",
        view_agent_graph: "Agent status", wait_for_agents: "Waiting for agents", get_threat_model: "Threat model", amend_threat_model: "Threat model update" };
      for (const x of r.items || []) {
        live.events++;
        const paired = x.kind === "tool_result" && x.call_id ? live.calls.get(x.call_id) : null;
        if (paired && list.contains(paired.entry)) {
          paired.state.textContent = "Response received";
          paired.state.classList.add("received");
          paired.detail.append(h("div", { class: "live-code-label" }, "OUTPUT"), h("pre", { class: "live-text" }, x.text || "(empty output)"));
          if (x.truncated) paired.detail.append(h("div", { class: "help" }, "Long output truncated."));
          continue;
        }
        const agent = byId[x.agent_id];
        const agentName = agent ? agent.name : x.agent_id;
        const isMessage = x.kind === "message";
        const initials = String(agentName || "A").split(/[\s/—]+/).slice(0, 2).map((v) => v[0] || "").join("").toUpperCase();
        const state = h("span", { class: "live-tool-state" + (x.kind === "tool_result" ? " received" : "") }, x.kind === "tool_result" ? "Response received" : "Call recorded");
        const entry = h("article", { class: "live-event " + (isMessage ? "message" : "tool"), "data-event-id": x.id },
          h("header", {}, h("span", { class: "live-avatar", "aria-hidden": "true" }, initials),
            h("strong", {}, agentName), h("time", { datetime: x.at || "" }, fmtShort(x.at))));
        if (isMessage) entry.append(h("div", { class: "live-message-text" }, x.text));
        else {
          const detail = h("details", {},
            h("summary", {}, h("div", { class: "live-tool-top" }, h("span", { class: "live-tool-label" }, TOOL_LABELS[x.tool] || "Tool activity"), state),
              h("div", { class: "live-tool-preview" }, activityPreview(x.text, x.tool)), h("span", { class: "live-tool-name" }, x.tool || "Strix")),
            h("div", { class: "live-code-label" }, x.kind === "tool_result" ? "OUTPUT" : "INPUT"), h("pre", { class: "live-text" }, x.text || "(empty output)"));
          entry.append(detail);
          if (x.kind === "tool_call" && x.call_id) live.calls.set(x.call_id, { entry, detail, state });
        }
        if (x.truncated) entry.append(h("div", { class: "help" }, "Long output truncated."));
        list.append(entry);
      }
      live.cursor = r.cursor;
      while (list.childElementCount > 180) list.firstElementChild.remove();
      for (const [cid, item] of live.calls) if (!list.contains(item.entry)) live.calls.delete(cid);
      if (!list.childElementCount) list.append(h("div", { class: "live-empty faint" }, r.available ? "No visible activity for this agent yet." : "Strix has not created the activity store yet."));
      if (live.follow.checked && (r.items || []).length) list.scrollTop = list.scrollHeight;
      const labels = { ...STATUS_TR, waiting: "Waiting", idle: "Idle", stopped: "Stopped", crashed: "Crashed", budget_paused: "Paused at budget limit" };
      const seen = new Set(), nodes = [];
      const pick = (aid) => {
        live.agent = aid; live.cursor = -1; live.generation++; live.busy = false;
        if (aid && compose.select && [...compose.select.options].some((o) => o.value === aid)) { compose.select.value = aid; compose.chosen = aid; }
        pollLive();
      };
      nodes.push(h("button", { type: "button", class: "live-all" + (!live.agent ? " selected" : ""), onclick: () => pick(""), "aria-pressed": !live.agent }, icon("scans"), "All agents", h("span", {}, a.agents.length)));
      // Nested <ul> tree: each sub-agent hangs off its parent with an elbow connector (see .live-subtree in style.css).
      const tone = (s) => s === "running" ? "running" : s === "completed" ? "completed" : ["failed", "error", "crashed"].includes(s) ? "failed" : "idle";
      const visit = (agent, depth) => {
        if (seen.has(agent.id)) return null;
        seen.add(agent.id);
        const kids = a.agents.filter((x) => x.parent === agent.id && !seen.has(x.id));
        const selected = live.agent === agent.id;
        const node = h("li", { class: "live-node" + (depth ? "" : " root") },
          h("button", { type: "button", class: "live-agent" + (selected ? " selected" : ""), "aria-pressed": selected, onclick: () => pick(agent.id) },
            h("span", { class: "live-agent-row" }, h("span", { class: "live-agent-dot " + tone(agent.status), "aria-hidden": "true" }), h("span", { class: "live-agent-name" }, agent.name)),
            h("span", { class: "live-agent-meta" }, labels[agent.status] || agent.status,
              kids.length ? ` · ${kids.length} sub-agent${kids.length === 1 ? "" : "s"}` : null)));
        if (selected && agent.task) node.append(h("details", { class: "live-agent-task" }, h("summary", {}, "View task"), h("div", {}, agent.task)));
        const sub = h("ul", { class: "live-subtree" + (depth >= 3 ? " flat" : "") });
        kids.forEach((x) => { const n = visit(x, depth + 1); if (n) sub.append(n); });
        if (sub.childElementCount) node.append(sub);
        return node;
      };
      const tree = h("ul", { class: "live-tree" });
      a.agents.filter((x) => !x.parent || !byId[x.parent]).forEach((x) => { const n = visit(x, 0); if (n) tree.append(n); });
      a.agents.forEach((x) => { const n = visit(x, 0); if (n) tree.append(n); });
      nodes.push(tree);
      live.tree.replaceChildren(...nodes);
      const agentCount = document.getElementById("liveAgentCount"); if (agentCount) agentCount.textContent = a.agents.length;
      live.state.textContent = r.note || `${ACTIVE.includes(scan.status) ? "Live connection · 2s updates" : "Recorded session"} · ${new Date().toLocaleTimeString("en-US", { timeZone: TZ })}`;
      live.count.textContent = `${list.querySelectorAll(".live-event").length} events`;
      if (r.has_more) setTimeout(() => { if (live.list === list) pollLive(); }, 0);
    } catch (e) {
      if (live.state) live.state.textContent = "Connection lost · reconnecting…";
    } finally { if (gen === live.generation) live.busy = false; }
  }

  function logView() {
    const box = h("div", { class: "logbox", role: "log", "aria-live": "off" });
    log.box = box; log.offset = -1;
    const src = select([["strix", "Strix log"], ["process", "Process output"]], log.source);
    const lvl = select([["all", "All lines"], ["info", "Hide DEBUG"], ["warn", "Warnings and errors"]], log.level);
    const follow = h("input", { type: "checkbox", checked: true });
    log.follow = follow;
    [src, lvl].forEach((s) => s.addEventListener("change", () => { log.source = src.value; log.level = lvl.value; log.offset = -1; box.replaceChildren(); pollLog(); }));
    pollLog();
    return h("div", { class: "log-card" }, h("div", { class: "log-toolbar" }, src, lvl, h("label", { class: "check" }, follow, "Scroll to end"),
      h("span", { class: "note" }, "Strix doesn't report percentage progress; progress is tracked from the log and agent states.")), box);
  }
  const pollLog = guard(async () => {
    const box = log.box;
    if (!box) return;
    const r = await api(`/api/scans/${id}/log?source=${log.source}&offset=${log.offset}`);
    if (!r.available) {
      if (!box.childNodes.length) box.append(h("span", { class: "d" }, scan.status === "queued" ? "Scan is waiting in the queue.\n" : log.source === "strix" ? "Strix log not created yet; the sandbox may be starting.\n" : "No process output.\n"));
      return;
    }
    if (log.offset === -1) box.replaceChildren();
    log.offset = r.offset;
    if (!r.text) return;
    const frag = document.createDocumentFragment();
    for (const line of r.text.split("\n")) {
      if (!line) continue;
      const dbg = / DEBUG /.test(line), warn = / WARNING /.test(line), err = / (ERROR|CRITICAL) |Traceback/.test(line);
      if (log.level === "info" && dbg) continue;
      if (log.level === "warn" && !(warn || err)) continue;
      frag.append(h("span", { class: err ? "e" : warn ? "w" : dbg ? "d" : null }, line + "\n"));
    }
    box.append(frag);
    while (box.childNodes.length > 5000) box.firstChild.remove();
    if (log.follow && log.follow.checked) box.scrollTop = box.scrollHeight;
  });

  async function agentsView() {
    const [a, tel] = await Promise.all([api(`/api/scans/${id}/agents`), api(`/api/scans/${id}/telemetry`)]);
    if (!a.agents.length) return h("div", { class: "card" }, emptyState("No agent info", "Strix writes agent states after the scan starts."));
    const stMap = { running: "running", completed: "completed", failed: "failed", crashed: "failed", waiting: "queued", cancelled: "cancelled", interrupted: "interrupted" };
    const labels = { ...STATUS_TR, waiting: "Waiting", idle: "Idle", stopped: "Stopped", crashed: "Crashed", budget_paused: "Paused at budget limit", budget_stopped: "Stopped at budget limit" };
    const name = (aid) => (a.agents.find((y) => y.id === aid) || {}).name || aid;
    const byId = {}; ((tel.telemetry || {}).agents || []).forEach((g) => { byId[g.agent_id] = g; });
    const ordered = [], visited = new Set();
    const visit = (agent) => {
      if (visited.has(agent.id)) return;
      visited.add(agent.id); ordered.push(agent);
      a.agents.filter((x) => x.parent === agent.id).forEach(visit);
    };
    a.agents.filter((x) => !x.parent || !a.agents.some((p) => p.id === x.parent)).forEach(visit);
    a.agents.forEach(visit);
    return h("div", {}, h("div", { class: "note" }, Object.entries(a.counts).map(([k, n]) => `${n} ${labels[k] || k}`).join(" · ")),
      h("div", { class: "agent-grid" }, ordered.map((x) => {
        const g = byId[x.id] || {};
        return h("article", { class: "card agent-card", id: `agent-${x.id}` },
          h("header", {}, h("h3", {}, x.name), h("span", { class: `status ${stMap[x.status] || "neutral"}` }, h("span", { class: "dot" }), labels[x.status] || x.status)),
          x.parent ? h("div", { class: "agent-parent" }, "Parent agent: ", h("a", { href: `#agent-${x.parent}`, onclick: (e) => { e.preventDefault(); document.getElementById(`agent-${x.parent}`)?.scrollIntoView({ block: "center" }); } }, name(x.parent))) : h("div", { class: "agent-parent" }, "Root agent"),
          h("div", { class: "agent-task" }, x.task || "Strix did not record a task description."),
          g.model ? h("div", { class: "secondary-line mono", title: g.model }, g.model) : null,
          h("div", { class: "agent-metrics" }, h("span", {}, "Requests: ", g.requests ?? "—"), h("span", {}, "Token: ", fmtTokens(g.tokens)), h("span", {}, "Tool calls: ", g.tools_total ?? "—")),
          h("div", { class: "agent-activity" }, (x.activities || []).length ? [h("h4", {}, "Recent activity"), ...x.activities.map((v) => h("div", {}, h("span", { class: "mono" }, v.tool), " · ", fmtShort(v.at && !/[Z+]/.test(v.at) ? v.at.replace(" ", "T") + "Z" : v.at)))] : "No tool activity recorded."));
      })));
  }

  async function telemetryView() {
    const r = await api(`/api/scans/${id}/telemetry`);
    const t = r.telemetry || {};
    if (!r.available) return h("div", { class: "card" }, emptyState("No telemetry", ACTIVE.includes(scan.status) ? "As the scan progresses, model calls, retries and tool usage are collected here." : "No Strix telemetry data was found for this run."));
    const stat = (k, v, s, title) => h("div", { class: "stat", title: title || "" }, h("div", { class: "k" }, k), h("div", { class: "v" }, v), s ? h("div", { class: "s" }, s) : null);
    const req = t.requests || {}, ret = t.retries || {}, lat = t.latency || {}, cost = t.cost || {}, tok = t.tokens || {}, tools = t.tools || {};
    const na = h("span", { class: "faint" }, "no data");
    const costStr = cost.value != null ? `$${cost.value < 0.01 ? cost.value.toFixed(4) : cost.value.toFixed(2)}` : null;
    return h("div", {},
      h("div", { class: "stats" },
        stat("Completed requests", req.completed ?? na, req.attempts ? `${req.attempts} attempts` : null, "run.json: completed model requests · log: total attempts"),
        stat("Failed requests", req.errors ?? h("span", { class: "faint" }, "no data"), null, "Requests that ended with a model/provider error"),
        stat("Retries", ret.total ?? h("span", { class: "faint" }, "no data"), ret.total ? `rate limit ${ret.rate_limit} · timeout ${ret.timeout} · connection ${ret.connection}` : ret.total === 0 ? "none" : null),
        stat("LLM cost", costStr || na, cost.note, cost.note)),
      h("div", { class: "stats" },
        stat("Tokens (total)", tok.total != null ? fmtTokens(tok.total) : na, tok.cached != null ? `${fmtTokens(tok.cached)} cached` : null),
        stat("Input / output tokens", (tok.input != null || tok.output != null) ? `${tok.input != null ? fmtTokens(tok.input) : "—"} / ${tok.output != null ? fmtTokens(tok.output) : "—"}` : na),
        stat("Average response", lat.avg_request_ms != null ? `${(lat.avg_request_ms / 1000).toFixed(1)} s` : na, lat.avg_ttft_ms != null ? `first token ${(lat.avg_ttft_ms / 1000).toFixed(1)} s` : null),
        stat("Tool calls", tools.total ?? na, t.last_activity ? `last activity ${relTime(t.last_activity)}` : null)),
      t.models && t.models.length ? h("div", { class: "note" }, "Model: " + t.models.join(", ")) : null,
      cost.source === "unknown" ? alertBox("info", "Cost could not be computed", cost.note || "Strix has no price info for this model; cost can't be shown.") : null,
      tools.by_name && Object.keys(tools.by_name).length ? section("Tool usage", h("div", { class: "table-card" }, table([{ label: "Tool" }, { label: "Calls", cls: "num" }],
        Object.entries(tools.by_name).map(([name, n]) => h("tr", {}, h("td", { class: "mono" }, name), h("td", { class: "num" }, n))), null))) : null);
  }

  function detailsView() {
    return h("div", { class: "grid-2 scan-details" },
      h("div", { class: "card card-pad" }, h("div", { class: "card-title" }, "Parameters"), h("dl", { class: "dl" },
        h("dt", {}, "Strix targets"), h("dd", { class: "mono" }, (scan.targets || []).map((t) => h("div", {}, t))),
        h("dt", {}, "Turns per agent"), h("dd", {}, scan.max_turns || "Strix default (500)"),
        h("dt", {}, "Finding gate"), h("dd", {}, scan.fail_on ? `${SEV_TR[scan.fail_on]} and above` : "Not set"),
        h("dt", {}, "Resumed run"), h("dd", { class: scan.resume_run ? "mono" : "faint" }, scan.resume_run || "—"),
        h("dt", {}, "Strix exit code"), h("dd", {}, scan.exit_code ?? "—", scan.exit_code === 2 ? h("span", { class: "faint" }, " · findings found") : scan.exit_code === 1 ? h("span", { class: "faint" }, " · error or interruption") : null),
        h("dt", {}, "Output folder"), h("dd", { class: "mono" }, scan.run_dir || "—"),
        h("dt", {}, "Extra instructions"), h("dd", {}, scan.instruction ? h("pre", { class: "mono scan-instructions" }, scan.instruction) : h("span", { class: "faint" }, "None")))),
      h("div", { class: "card card-pad" }, h("div", { class: "card-title" }, "Executive summary (Strix)"),
        scan.executive_summary_html ? h("div", { class: "md", html: scan.executive_summary_html }) : h("div", { class: "faint" }, "Strix did not write a summary for this run.")));
  }

  every(2000, () => { if (live.list) { pollLive(); pollMessages(); } });
  renderAll(); renderTabs();
  app.replaceChildren(headBox, alertsBox, factsBox, tabsBox, body);
  await renderBody();
  every(3000, pollGuard(async () => {
    const wasActive = ACTIVE.includes(scan.status);
    if (wasActive) {
      scan = await api(`/api/scans/${id}`);
      renderAll();
      if (!ACTIVE.includes(scan.status)) { toast(`Scan ${STATUS_TR[scan.status].toLowerCase()}`); if (tab !== "log") renderBody(); }
      else if (tab === "findings" || tab === "agents" || tab === "telemetry") renderBody();
    }
    if (log.box) pollLog();
  }));
}

// ================================================================== schedules
function scheduleTable(list, { showTarget = true, empty } = {}) {
  const cols = [...(showTarget ? [{ label: "Target" }] : []), { label: "Scheduling" }, { label: "Next run" }, { label: "Last run" }, { label: "Status" }, { label: "", cls: "shrink" }];
  return table(cols, list.map((s) => {
    const done = !s.enabled && s.kind === "once" && s.last_outcome;
    const last = s.last_scan && s.last_outcome === "started"
      ? h("div", {}, statusChip(s.last_scan.status), h("div", { class: "status-sub" }, fmtShort(s.last_run_at)))
      : s.last_outcome ? h("div", { class: "cell-clip" }, h("span", { class: "status failed" }, h("span", { class: "dot" }), s.last_outcome === "missed" ? "Missed" : s.last_outcome === "skipped_busy" ? "Skipped" : "Couldn't start"), h("div", { class: "status-sub", title: s.last_note || "" }, OUTCOME_TR[s.last_outcome]))
        : h("span", { class: "faint" }, "Not run yet");
    return h("tr", { class: "clickable", onclick: () => go(`#/schedules/${s.id}`) },
      showTarget ? h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, s.target_name), h("div", { class: "secondary-line" }, envTag(s.environment)))) : null,
      h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, s.name || KIND_TR[s.kind]), h("div", { class: "secondary-line" }, s.describe + (s.timezone !== TZ ? ` · ${s.timezone}` : "")))),
      h("td", {}, s.enabled && s.next_run_at ? whenCell(s.next_run_at) : h("span", { class: "faint" }, "—")),
      h("td", {}, last),
      h("td", {}, h("span", { class: `status ${s.enabled ? "active" : "paused"}` }, h("span", { class: "dot" }), s.enabled ? "Enabled" : done ? "Completed" : "Paused"),
        !s.llm_profile_name ? h("div", { class: "status-sub" }, "LLM connection deleted") : null),
      h("td", { class: "shrink right", onclick: (e) => e.stopPropagation() },
        button(showTarget ? (s.enabled ? "Pause" : "Enable") : null, { size: "sm", ic: s.enabled ? "pause" : "play", title: s.enabled ? "Pause" : "Enable", disabled: done, onclick: guard(async () => {
          await api(`/api/schedules/${s.id}/${s.enabled ? "pause" : "resume"}`, { method: "POST" });
          toast(s.enabled ? "Schedule paused" : "Schedule enabled"); router();
        }) })));
  }), empty || emptyState("No schedules", "Create a schedule to scan targets regularly.", [button("Create schedule", { kind: "primary", ic: "plus", onclick: () => go("#/schedules/new") })]));
}

async function viewSchedules() {
  const list = await api("/api/schedules");
  app.replaceChildren(
    pageHead("Schedules", { lead: `Recurring and future scans. Time zone: ${TZ}.`, actions: [button("Create schedule", { kind: "primary", ic: "plus", onclick: () => go("#/schedules/new") })] }),
    alertBox("info", "How do schedules work?", "Runs whose time passed while the app was down are not started afterwards; they are recorded as “Missed”. A run that arrives while the target has an active scan is skipped. Failed scans are not retried automatically."),
    h("div", { class: "table-card" }, scheduleTable(list)));
}

async function viewScheduleForm(id, presetTarget) {
  const [s, targets, profiles, campaignList] = await Promise.all([id ? api(`/api/schedules/${id}`) : null, api("/api/targets"), api("/api/llm-profiles"), api("/api/campaigns")]);
  if (!targets.length || !profiles.length) {
    app.replaceChildren(pageHead("Create schedule", { crumb: h("a", { href: "#/schedules" }, "Schedules") }), h("div", { class: "card" },
      !targets.length ? emptyState("Create a target first", "A schedule is tied to a target.", [button("New target", { kind: "primary", onclick: () => go("#/targets/new") })])
        : emptyState("No LLM connection", "Scans need an LLM connection.", [button("Go to Settings", { kind: "primary", onclick: () => go("#/settings") })])));
    return;
  }
  const v = s || { kind: "weekly", time_of_day: "02:00", weekdays: ["mon"], timezone: TZ, enabled: 1, target_id: presetTarget || targets[0].id, fail_on: "high" };
  const tgt0 = targets.find((t) => t.id === v.target_id) || targets[0];
  let kind = v.kind;
  const f = {
    target_id: select(targets.map((t) => [String(t.id), `${t.name} · ${ENV_TR[t.environment]}`]), String(v.target_id)),
    name: h("input", { type: "text", value: v.name || "", placeholder: "e.g. Weekly staging scan" }),
    run_at: h("input", { type: "datetime-local", value: (v.run_at || "").slice(0, 16) }),
    time_of_day: h("input", { type: "time", value: v.time_of_day || "02:00" }),
    interval_hours: h("input", { type: "number", min: "1", step: "1", value: v.interval_hours ?? 24 }),
    cron_expr: h("input", { type: "text", value: v.cron_expr || "", placeholder: "0 3 * * 1-5", class: "mono" }),
    timezone: h("input", { type: "text", value: v.timezone || TZ }),
    enabled: h("input", { type: "checkbox", checked: v.enabled !== 0 }),
  };
  const days = new Set(v.weekdays || []);
  const daySeg = h("div", { class: "seg" });
  const renderDays = () => daySeg.replaceChildren(DAYS.map(([k, l]) => h("button", { type: "button", class: days.has(k) ? "on" : null, onclick: () => { days.has(k) ? days.delete(k) : days.add(k); renderDays(); preview(); } }, l)));
  renderDays();
  const opts = scanOptions(profiles, { ...v, scan_mode: v.scan_mode || tgt0.default_scan_mode, llm_profile_id: v.llm_profile_id || tgt0.llm_profile_id });
  const extras = scanExtras(tgt0.auth_profiles || [], campaignList, { campaign_id: v.campaign_id, auth_profile_ids: v.auth_profile_ids });
  const kindSeg = h("div", { class: "seg" });
  const kf = {
    once: field("Date and time", f.run_at), time: field("Time", f.time_of_day), days: h("div", { class: "field" }, h("div", { class: "label" }, "Days"), daySeg),
    interval: field("Every how many hours", f.interval_hours, "The first run happens one minute after saving, then continues at this interval."),
    cron: field("Cron expression", f.cron_expr, "Standard five-field cron: minute hour day month day-of-week."),
  };
  const renderKind = () => {
    kindSeg.replaceChildren(Object.entries(KIND_TR).map(([k, l]) => h("button", { type: "button", class: kind === k ? "on" : null, onclick: () => { kind = k; renderKind(); preview(); } }, l)));
    kf.once.hidden = kind !== "once"; kf.time.hidden = !["daily", "weekly"].includes(kind); kf.days.hidden = kind !== "weekly";
    kf.interval.hidden = kind !== "interval"; kf.cron.hidden = kind !== "cron";
  };
  const nextBox = h("div", {});
  const collect = () => ({ target_id: f.target_id.value, name: f.name.value, kind, run_at: f.run_at.value, time_of_day: f.time_of_day.value,
    weekdays: [...days], interval_hours: f.interval_hours.value, cron_expr: f.cron_expr.value, timezone: f.timezone.value, enabled: f.enabled.checked, ...opts.value(), ...extras.value() });
  let pt;
  const preview = () => { clearTimeout(pt); pt = setTimeout(async () => {
    try {
      const r = await api("/api/schedules/preview", { method: "POST", body: collect() });
      nextBox.replaceChildren(r.ok ? h("ol", { class: "next-runs" }, r.next.map((n) => h("li", {}, h("span", {}, fmtDate(n)), h("span", { class: "faint" }, ` · ${relTime(n)}`))))
        : h("div", { class: "verdict fail" }, icon("alert"), r.error));
    } catch (e) { nextBox.replaceChildren(h("div", { class: "faint" }, e.message)); }
  }, 250); };
  Object.values(f).forEach((el) => el.addEventListener("input", preview));
  const save = guard(async () => {
    const r = await api(id ? `/api/schedules/${id}` : "/api/schedules", { method: id ? "PUT" : "POST", body: collect() });
    toast("Schedule saved"); if (id) router(); else go(`#/schedules/${r.id}`);
  });
  app.replaceChildren(
    pageHead(id ? (s.name || `${KIND_TR[s.kind]} schedule`) : "Create schedule", {
      crumb: h("a", { href: "#/schedules" }, "Schedules"),
      meta: id ? [h("span", { class: `status ${s.enabled ? "active" : "paused"}` }, h("span", { class: "dot" }), s.enabled ? "Enabled" : "Paused"), h("span", {}, s.target_name), envTag(s.environment)] : null,
      actions: id ? [
        menu([{ label: "Delete schedule", icon: "trash", danger: true, onclick: guard(async () => {
          if (!await confirmDialog("Delete schedule?", "The schedule and its history are deleted. Scans started from this schedule are kept.", { confirmLabel: "Delete schedule", danger: true })) return;
          await api(`/api/schedules/${id}`, { method: "DELETE" }); go("#/schedules");
        }) }]),
        button(s.enabled ? "Pause" : "Enable", { ic: s.enabled ? "pause" : "play", onclick: guard(async () => { await api(`/api/schedules/${id}/${s.enabled ? "pause" : "resume"}`, { method: "POST" }); router(); }) })] : null }),
    h("div", { class: "grid-main-side" },
      h("form", { class: "card card-pad form", onsubmit: (e) => { e.preventDefault(); save(); } },
        formSection("Scheduling", "Choose when and on which target it runs.", [
          field("Target", f.target_id), field("Name (optional)", f.name),
          h("div", { class: "field" }, h("div", { class: "label" }, "Repeat"), kindSeg),
          kf.once, kf.time, kf.days, kf.interval, kf.cron,
          h("div", { class: "field-row two" }, field("Time zone", f.timezone, "IANA name, default Europe/Istanbul."), h("div", { class: "field" }, h("div", { class: "label" }, "Status"), h("label", { class: "check" }, f.enabled, "Enabled when saved")))]),
        formSection("Scan settings", "These settings are used on every run. The LLM connection is fixed; on error it does not switch to another one.", [...opts.fields, ...extras.fields]),
        h("div", { class: "form-actions" }, button("Cancel", { onclick: () => history.back() }), button("Save", { kind: "primary", type: "submit" }))),
      h("div", {},
        h("div", { class: "card card-pad" }, h("div", { class: "card-title" }, "Next 5 runs"), nextBox),
        id ? h("div", { class: "card card-pad" }, h("div", { class: "card-title" }, "Schedule history"),
          s.events.length ? h("ol", { class: "events" }, s.events.map((e) => h("li", {},
            h("div", {}, OUTCOME_TR[e.outcome] || e.outcome, e.scan_id ? [" · ", h("a", { href: `#/scans/${e.scan_id}` }, `scan #${e.scan_id}`)] : null),
            h("div", { class: "faint" }, fmtDate(e.at)), e.note && e.outcome !== "started" ? h("div", { class: "faint" }, e.note) : null)))
            : h("div", { class: "faint" }, "This schedule hasn't fired yet.")) : null)));
  [opts.f.llm_profile_id, opts.f.scan_mode, f.target_id].forEach((el) => el.addEventListener("change", preview));
  f.target_id.addEventListener("change", () => extras.setTarget(targets.find((t) => String(t.id) === f.target_id.value)));
  renderKind(); preview();
}

// ================================================================== settings
// Own account: identity, role and password. Shown to every role (non-admins see only this on Settings).
function accountSection({ wide = false } = {}) {
  const pw = { current: h("input", { type: "password", autocomplete: "current-password" }), next: h("input", { type: "password", autocomplete: "new-password" }) };
  const info = h("dl", { class: "dl" },
    h("dt", {}, "Username"), h("dd", { class: "mono" }, ME.username),
    h("dt", {}, "Role"), h("dd", {}, h("span", { class: `role-chip ${ME.role}` }, ROLE_NAMES[ME.role] || ME.role), h("div", { class: "help" }, ROLE_HELP[ME.role] || "")),
    h("dt", {}, "Last sign-in"), h("dd", {}, ME.last_login_at ? fmtDate(ME.last_login_at) : "—"));
  const form = ME.password_from_env
    ? h("div", { class: "muted account-note" }, "This built-in account's password comes from the SKYNET_PASSWORD environment variable; change it in the server configuration.")
    : h("form", { class: "fields account-pw", onsubmit: guard(async (e) => {
      e.preventDefault();
      await api("/api/settings/password", { method: "POST", body: { current: pw.current.value, new: pw.next.value } });
      toast("Password changed. Please sign in again."); setTimeout(() => (location.href = "/login"), 1200);
    }) }, field("Current password", pw.current), field("New password", pw.next, "At least 10 characters. Your other sessions are signed out."), h("div", {}, button("Change password", { type: "submit" })));
  return section("Your account", h("div", { class: "card card-pad account" + (wide ? " wide" : "") }, info, form));
}

async function viewSettings() {
  if (!can("admin")) {
    app.replaceChildren(pageHead("Settings", { lead: "Your account. System settings, users and the audit log are managed by admins." }), accountSection({ wide: true }));
    return;
  }
  const [st, profiles, users, siem] = await Promise.all([api("/api/settings"), api("/api/llm-profiles"), api("/api/users"), api("/api/syslog")]);
  const f = {
    strix_bin: h("input", { type: "text", value: st.strix_bin, class: "mono" }),
    strix_workdir: h("input", { type: "text", value: st.strix_workdir, class: "mono" }),
    max_concurrent: h("input", { type: "number", min: "1", max: "10", value: st.max_concurrent }),
    default_scan_mode: select([["quick", "Quick"], ["standard", "Standard"], ["deep", "Deep"]], st.default_scan_mode),
    telemetry: h("input", { type: "checkbox", checked: st.telemetry === "1" }),
    agent_messaging: h("input", { type: "checkbox", checked: st.agent_messaging !== "0" }),
    webhook_url: h("input", { type: "text", value: st.webhook_url, placeholder: "https://… (Teams or Slack incoming webhook)", class: "mono" }),
  };
  const saveRuntime = guard(async () => {
    await api("/api/settings", { method: "PUT", body: Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.type === "checkbox" ? el.checked : el.value])) });
    toast("Settings saved"); refreshSystem();
  });
  const llmRows = profiles.map((p) => h("tr", {},
    h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, p.name, p.is_default ? [" ", h("span", { class: "tag accent" }, "Default")] : null),
      h("div", { class: "secondary-line mono", title: p.strix_model }, p.strix_model))),
    h("td", {}, p.provider_label, h("div", { class: "secondary-line mono", title: p.base_url || "" }, p.base_url || "Provider default")),
    h("td", {}, p.has_api_key ? "Stored" : h("span", { class: "faint" }, "None")),
    h("td", {}, p.used_by_schedules ? `${p.used_by_schedules} schedules` : h("span", { class: "faint" }, "—")),
    h("td", { class: "shrink right" }, h("div", { class: "actions" },
      button("Test", { size: "sm", onclick: guard(async () => {
        const r = await api("/api/llm-profiles/test", { method: "POST", body: { id: p.id, provider: p.provider, base_url: p.base_url, model: p.model, ca_cert_path: p.ca_cert_path } });
        toast((r.ok ? "Connection OK. " : "Connection failed. ") + r.message, !r.ok || r.model_found === false);
      }) }),
      menu([!p.is_default ? { label: "Make default", icon: "check", onclick: guard(async () => { await api(`/api/llm-profiles/${p.id}/default`, { method: "POST" }); router(); refreshSystem(); }) } : null,
        { label: "Edit", icon: "edit", onclick: () => llmDialog(p) }, "-",
        { label: "Delete", icon: "trash", danger: true, onclick: guard(async () => {
          if (!await confirmDialog("Delete LLM connection?", `“${p.name}” will be deleted. A connection used by schedules cannot be deleted.`, { confirmLabel: "Delete", danger: true })) return;
          await api(`/api/llm-profiles/${p.id}`, { method: "DELETE" }); router(); refreshSystem();
        }) }])))));
  const o = lastOverview || await api("/api/overview");
  const d = o.llm_default;
  const health = (ok, name, value, detail) => h("div", { class: "health" },
    h("div", { class: "health-head" }, h("span", { class: ok ? "dot-ok" : "dot-bad" }), h("span", { class: "name" }, name)),
    h("div", { class: "value" }, value), detail ? h("div", { class: "detail mono", title: detail }, detail) : null);
  app.replaceChildren(
    pageHead("Settings", { lead: "System status, LLM connections, Strix runtime environment and integrations." }),
    section("System status", h("div", { class: "health-grid" },
      health(o.docker.ok, "Docker", o.docker.ok ? "Running" : "Unreachable", o.docker.ok ? `Engine ${o.docker.version}` : (o.docker.error || "").slice(0, 160)),
      health(o.strix.ok, "Strix", o.strix.ok ? o.strix.version : "Not found", st.strix_bin),
      health(!!d, "Default LLM", d ? `${d.name} · ${d.provider_label}` : "Not set", d ? d.strix_model : null),
      health(true, "Scheduling", `Time zone ${o.timezone}`, `Strix telemetry ${o.telemetry ? "on" : "off"} · concurrency limit ${o.max_concurrent}`))),
    section("LLM connections", h("div", {},
      h("div", { class: "table-card" }, table([{ label: "Connection" }, { label: "Provider" }, { label: "API key" }, { label: "Usage" }, { label: "", cls: "shrink" }], llmRows,
        emptyState("No LLM connection", "Add an OpenRouter or in-house LiteLLM connection for scans.", [button("Add connection", { kind: "primary", ic: "plus", onclick: () => llmDialog(null) })]))),
      h("div", { class: "note", style: null }, "Connections are passed to Strix via the STRIX_LLM, LLM_API_KEY and LLM_API_BASE environment variables. API keys are stored encrypted on the server and never sent to the browser.")),
    { right: button("Add connection", { ic: "plus", size: "sm", onclick: () => llmDialog(null) }) }),
    section("Data protection", h("div", { class: "card card-pad" },
      h("dl", { class: "dl" },
        h("dt", {}, "Encryption key"), h("dd", { class: "mono" }, (st.key_status || {}).source === "env" ? "Environment variable" : (st.key_status || {}).path || "Not reported"),
        h("dt", {}, "Key storage"), h("dd", {}, (st.key_status || {}).colocated ? "Inside the data directory" : "Outside the data directory"),
        h("dt", {}, "Schema version"), h("dd", {}, st.schema_version ?? "—")),
      h("details", {}, h("summary", {}, "Migration history"),
        h("div", { class: "occ-list" }, (st.migrations || []).map((m) => h("div", { class: "occ" },
          h("strong", {}, `Version ${m.version}`), " · ", fmtDate(m.applied_at),
          m.backup ? h("div", { class: "secondary-line mono", title: m.backup }, `Backup: ${m.backup}`) : h("div", { class: "faint" }, "No backup recorded by this migration"))))))),
    section("Strix runtime environment", h("form", { class: "card card-pad form", onsubmit: (e) => { e.preventDefault(); saveRuntime(); } },
      formSection("Strix", "Installed Strix CLI and output folder.", [
        field("Strix binary", f.strix_bin),
        field("Working folder", f.strix_workdir, "Strix writes output under <folder>/strix_runs/. Scans run with the TUI are also imported from here.")]),
      formSection("Execution", "Queue and defaults.", [
        h("div", { class: "field-row two" }, field("Concurrent scans", f.max_concurrent, "The rest wait in the queue. Only one scan runs on the same target at a time."), field("Default mode", f.default_scan_mode)),
        h("div", { class: "field" }, h("div", { class: "label" }, "Strix telemetry"), h("label", { class: "check" }, f.telemetry, "Telemetry on (STRIX_TELEMETRY=1)"),
          h("div", { class: "help" }, "Strix defaults to on; Skynet starts it off. Keeping it off in-house is recommended.")),
        h("div", { class: "field" }, h("div", { class: "label" }, "Agent messaging"), h("label", { class: "check" }, f.agent_messaging, "Start new scans with the messaging bridge"),
          h("div", { class: "help" }, (st.agent_messaging_status || {}).available
            ? `Available · Strix runtime ${st.agent_messaging_status.runtime_version} matches the binary. Applies to scans started after saving.`
            : `Unavailable · ${(st.agent_messaging_status || {}).reason || "Unknown"} Scans run without messaging.`))]),
      formSection("Notification", "A JSON payload is sent to the webhook when a scan finishes.", [field("Webhook URL", f.webhook_url)]),
      h("div", { class: "form-actions" }, button("Save", { kind: "primary", type: "submit" })))),
    syslogSettingsSection(siem),
    h("div", { class: "grid-2" },
      section("CI / pipeline access", h("div", { class: "card card-pad" },
        h("div", { class: "muted" }, "Use the X-API-Token header to start a scan from a pre-prod pipeline. The token is shown only when created."),
        h("pre", { class: "mono ci" }, "POST /api/ci/targets/<target_id>/scan\nGET  /api/ci/scans/<scan_id>\n     → status, finished, gate (pass | fail)"),
        button(st.has_api_token ? "Rotate token" : "Create token", { onclick: guard(async () => {
          if (st.has_api_token && !await confirmDialog("Rotate token?", "The old token becomes invalid immediately; pipelines using it must be updated.", { confirmLabel: "Rotate", danger: true })) return;
          const r = await api("/api/settings/api-token", { method: "POST" });
          const inp = h("input", { type: "text", value: r.api_token, readonly: true, class: "mono" });
          dialog("New CI token", [alertBox("warn", "This value won't be shown again", "Save it in your CI system's secret variable."), inp],
            [button("Copy", { kind: "primary", onclick: guard(async () => { await navigator.clipboard.writeText(r.api_token); toast("Copied"); }) })]);
          inp.select(); st.has_api_token = true;
        }) }))),
      accountSection()),
    usersSection(users));
  app.querySelectorAll("pre.ci").forEach((p) => { p.style.margin = "14px 0"; p.style.color = "var(--text-2)"; });
  app.querySelectorAll(".section > div > .note").forEach((n) => { n.style.marginTop = "10px"; });
}

function syslogSettingsSection(initial) {
  const config = initial.settings;
  const fields = {
    enabled: h("input", { type: "checkbox", checked: config.enabled }),
    host: h("input", { type: "text", value: config.host, placeholder: "siem.corp.example or 10.0.0.20", class: "mono" }),
    port: h("input", { type: "number", min: 1, max: 65535, value: config.port }),
    transport: select([["tls", "TLS"], ["tcp", "TCP"], ["udp", "UDP"]], config.transport),
    facility: select(Array.from({ length: 24 }, (_, n) => [String(n), n >= 16 ? `local${n - 16} (${n})` : `Facility ${n}`]), String(config.facility)),
    source_hostname: h("input", { type: "text", value: config.source_hostname, class: "mono" }),
    ca_file: h("input", { type: "text", value: config.ca_file, placeholder: "Empty: system trust store", class: "mono" }),
    server_name: h("input", { type: "text", value: config.server_name, placeholder: "Empty: collector address", class: "mono" }),
    client_cert: h("input", { type: "text", value: config.client_cert, placeholder: "/var/lib/skynet-tls/client.crt", class: "mono" }),
    client_key: h("input", { type: "text", value: config.client_key, placeholder: "/var/lib/skynet-tls/client.key", class: "mono" }),
  };
  const statusBox = h("div", { class: "syslog-status" }), resultBox = h("div", {});
  const renderStatus = (data) => {
    const s = data.status;
    statusBox.replaceChildren(h("div", { class: "syslog-metrics" },
      ...[["Pending", s.pending], ["Handed to transport", s.handed_off], ["Queue overflow", s.overflow], ["Superseded", s.superseded]].map(([label, value]) => h("div", {}, h("span", { class: "faint" }, label), h("strong", {}, value)))),
      h("div", { class: "help" }, `${data.settings.enabled ? "Forwarding enabled" : "Forwarding disabled"} · Dispatcher ${s.worker_running ? "running" : "stopped"} · Last handoff: ${s.last_handoff_at ? fmtDateSec(s.last_handoff_at) : "Never"}`),
      s.last_error ? alertBox("warn", "Forwarding retries pending", `${s.last_error}${s.last_error_at ? ` Last failed attempt: ${fmtDateSec(s.last_error_at)}.` : ""}`) : null,
      h("div", { class: "help" }, `Counters are cumulative; last handoff refers to current settings. Pending limit ${s.pending_limit.toLocaleString()}. A handoff does not confirm SIEM ingestion. Retries may duplicate an event; deduplicate by event_id. Instance: ${data.instance_id}`));
  };
  const tls = h("details", { class: "syslog-tls" }, h("summary", {}, "TLS trust and optional client certificate"),
    h("div", { class: "field-row two" }, field("CA bundle path", fields.ca_file, "Absolute path on the Skynet server. Certificate verification stays enabled."), field("TLS server name", fields.server_name)),
    h("div", { class: "field-row two" }, field("Client certificate path", fields.client_cert), field("Client private key path", fields.client_key, "Optional mTLS: provide both files. Contents are never uploaded.")));
  const sync = () => { tls.hidden = fields.transport.value !== "tls"; };
  fields.transport.addEventListener("change", () => { if ([514, 6514].includes(+fields.port.value)) fields.port.value = fields.transport.value === "tls" ? "6514" : "514"; sync(); });
  const payload = () => Object.fromEntries(Object.entries(fields).map(([k, f]) => [k, f.type === "checkbox" ? f.checked : ["port", "facility"].includes(k) ? +f.value : f.value]));
  const save = button("Save syslog settings", { type: "submit", kind: "primary", need: "admin" });
  const probe = button("Send test event", { need: "admin", onclick: guard(async () => {
    const tested = payload();
    const endpoint = `${tested.transport.toUpperCase()} · ${tested.host}:${tested.port}`;
    probe.disabled = true;
    resultBox.replaceChildren(h("div", { class: "help" }, "Testing transport…"));
    try {
      const r = await api("/api/syslog/test", { method: "POST", body: tested });
      resultBox.replaceChildren(alertBox(r.ok ? "info" : "warn", r.ok ? "Test handed to transport" : "Test failed", `${endpoint} · ${r.message}`));
    } catch (error) {
      resultBox.replaceChildren(alertBox("warn", "Test failed", error.message || "Could not test syslog transport."));
    } finally { probe.disabled = false; }
  }) });
  Object.values(fields).forEach((f) => {
    f.addEventListener("input", () => resultBox.replaceChildren());
    f.addEventListener("change", () => resultBox.replaceChildren());
  });
  const form = h("form", { class: "card card-pad form", onsubmit: (e) => { e.preventDefault(); guard(async () => {
    save.disabled = true;
    try { const r = await api("/api/syslog", { method: "PUT", body: payload() }); renderStatus(r); toast("Syslog settings saved"); }
    finally { save.disabled = false; }
  })(); } },
    h("label", { class: "check" }, fields.enabled, "Forward new security audit events to SIEM"),
    h("p", { class: "help" }, "RFC 5424 + JSON audit metadata. Includes sign-ins, denied actions, user/settings changes, scan operations and report access. Raw agent output, request bodies and credentials are not exported. UDP/TCP are unencrypted; TLS is recommended."),
    h("div", { class: "field-row two" }, field("Collector address", fields.host), field("Collector port", fields.port)),
    h("div", { class: "field-row two" }, field("Transport", fields.transport, "TCP/TLS use octet-counted framing."), field("Facility", fields.facility)),
    field("Source hostname", fields.source_hostname, "An ASCII source label to identify this Skynet instance."), tls,
    h("div", { class: "note" }, "Only new events are queued while enabled. Saving changed settings supersedes pending events; local audit records remain. A test uses the form values without enabling forwarding."),
    h("div", { class: "form-actions" }, save, probe, button("Refresh delivery status", { need: "admin", onclick: guard(async () => { renderStatus(await api("/api/syslog")); }) })),
    resultBox, statusBox);
  sync(); renderStatus(initial);
  return section("SIEM / Syslog", form);
}

function llmDialog(p) {
  const v = p || { provider: "openrouter", api_type: "", reasoning_effort: "" };
  const f = {
    name: h("input", { type: "text", value: v.name || "", placeholder: "e.g. OpenRouter – DeepSeek" }),
    provider: select([["openrouter", "OpenRouter"], ["litellm", "LiteLLM (in-house gateway)"]], v.provider),
    base_url: h("input", { type: "text", value: v.base_url || "", class: "mono" }),
    api_key: h("input", { type: "password", value: "", autocomplete: "new-password", placeholder: v.has_api_key ? "Stored — enter a new key to change it" : "" }),
    model: h("input", { type: "text", value: v.model || "", class: "mono", list: "modelList" }),
    api_type: select([["", "Strix default"], ["chat_completions", "chat_completions"], ["responses", "responses"]], v.api_type),
    reasoning_effort: select([["", "Strix default"], ...["none", "minimal", "low", "medium", "high", "xhigh", "max"].map((x) => [x, x])], v.reasoning_effort),
    ca_cert_path: h("input", { type: "text", value: v.ca_cert_path || "", class: "mono", placeholder: "/etc/ssl/corp-ca.pem" }),
    is_default: h("input", { type: "checkbox", checked: !!v.is_default }),
  };
  const dl = h("datalist", { id: "modelList" });
  const providerHelp = h("div", { class: "help" }), modelHelp = h("div", { class: "help" });
  const testOut = h("div", {});
  const sync = () => {
    const lit = f.provider.value === "litellm";
    f.base_url.placeholder = lit ? "http://litellm.corp.local:4000" : "Leave empty (https://openrouter.ai/api/v1)";
    f.model.placeholder = lit ? "model name on the gateway" : "deepseek/deepseek-v4.1-flash-1017";
    providerHelp.textContent = lit ? "Passed to Strix as openai/<model> and LLM_API_BASE (OpenAI-compatible gateway method). If the gateway supports only chat completions, set the API type to chat_completions." : "Passed to Strix as openrouter/<provider>/<model>.";
    modelHelp.textContent = `Value sent to Strix: ${lit ? "openai/" : "openrouter/"}${f.model.value.replace(/^(openai|openrouter)\//, "") || "<model>"}`;
  };
  f.provider.addEventListener("change", sync); f.model.addEventListener("input", sync); sync();
  const body = () => ({ id: p && p.id, ...Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.type === "checkbox" ? el.checked : el.value])) });
  const close = dialog(p ? "Edit LLM connection" : "New LLM connection", [
    h("div", { class: "field-row two" }, field("Connection name", f.name), h("div", { class: "field" }, h("label", {}, "Provider"), f.provider)),
    providerHelp,
    field("Base URL", f.base_url),
    field("API key", f.api_key, "Stored encrypted; can't be viewed after saving. Usually a virtual key for LiteLLM; can be left empty if the gateway requires no key."),
    h("div", { class: "field" }, h("label", {}, "Model"), f.model, dl, modelHelp),
    h("div", { class: "field-row two" }, field("API type", f.api_type), field("Reasoning effort", f.reasoning_effort)),
    field("Custom CA certificate", f.ca_cert_path, "For in-house TLS; passed to Strix as SSL_CERT_FILE."),
    h("label", { class: "check" }, f.is_default, "Make default connection"),
    testOut], [
    button("Test connection", { onclick: guard(async () => {
      testOut.replaceChildren(h("div", { class: "faint" }, "Testing…"));
      const r = await api("/api/llm-profiles/test", { method: "POST", body: body() });
      dl.replaceChildren(r.models.map((m) => h("option", { value: m })));
      testOut.replaceChildren(alertBox(r.ok ? (r.model_found === false ? "warn" : "info") : "danger", r.ok ? "Connection OK" : "Connection failed", r.message + (r.models.length ? " Suggestions are listed in the Model field." : "")));
    }) }),
    h("span", { class: "spacer" }),
    button("Cancel", { onclick: () => close() }),
    button("Save", { kind: "primary", onclick: guard(async () => {
      await api(p ? `/api/llm-profiles/${p.id}` : "/api/llm-profiles", { method: p ? "PUT" : "POST", body: body() });
      close(); toast("Connection saved"); router(); refreshSystem();
    }) })], { wide: true });
}

// ================================================================== shared pickers
function targetMulti(targets, selectedIds) {
  const sel = new Set((selectedIds || []).map(Number));
  const box = h("div", { class: "checklist" }, targets.length ? targets.map((t) => {
    const cb = h("input", { type: "checkbox", checked: sel.has(t.id) });
    cb.addEventListener("change", () => cb.checked ? sel.add(t.id) : sel.delete(t.id));
    return h("label", { class: "check" }, cb, h("span", {}, t.name), " ", envTag(t.environment));
  }) : h("div", { class: "faint" }, "Create a target first."));
  return { el: box, value: () => [...sel] };
}

// Campaign + auth-profile selectors shared by the scan dialog and the schedule form. Auth profiles are the ones
// assigned to the selected target; the list is swapped when the target changes.
function scanExtras(authProfiles, campaignList, init) {
  const camp = select([["", "No campaign"], ...campaignList.filter((c) => !c.archived).map((c) => [String(c.id), c.name])],
    init.campaign_id ? String(init.campaign_id) : "");
  const sel = new Set((init.auth_profile_ids || []).map(Number));
  const authWrap = h("div", { class: "checklist sm" });
  let profiles = authProfiles;
  const renderAuth = () => {
    authWrap.replaceChildren(profiles.length ? profiles.map((p) => {
      const cb = h("input", { type: "checkbox", checked: sel.has(p.id) });
      cb.addEventListener("change", () => cb.checked ? sel.add(p.id) : sel.delete(p.id));
      return h("label", { class: "check" }, cb, h("span", {}, p.name), " ",
        h("span", { class: "tag" }, AUTHKIND_TR[p.kind] || p.kind),
        p.secret_readable === false ? h("span", { class: "tag danger" }, "unreadable") : null);
    }) : h("div", { class: "faint" }, "No auth profile assigned to this target."));
  };
  renderAuth();
  const fields = [
    h("div", { class: "field" }, h("label", {}, "Campaign"), camp),
    h("div", { class: "field" }, h("div", { class: "label" }, "Auth profiles"), authWrap,
      h("div", { class: "help" }, "Only profiles assigned to the selected target. Manage them in the Auth profiles menu.")),
  ];
  return {
    fields,
    value: () => ({ campaign_id: camp.value || null, auth_profile_ids: [...sel] }),
    setTarget: (t) => { profiles = (t && t.auth_profiles) || []; for (const id of [...sel]) if (!profiles.find((p) => p.id === id)) sel.delete(id); renderAuth(); },
  };
}

// ================================================================== campaigns
function campStatusChip(s) {
  const cls = { active: "active", completed: "completed", on_hold: "paused", planned: "queued" }[s] || "queued";
  return h("span", { class: `status ${cls}` }, h("span", { class: "dot" }), CAMP_STATUS_TR[s] || s);
}

async function viewCampaigns() {
  const list = await api("/api/campaigns?include_archived=1");
  const live = list.filter((c) => !c.archived), archived = list.filter((c) => c.archived);
  const cols = [{ label: "Campaign" }, { label: "Status" }, { label: "Environment" }, { label: "Targets" }, { label: "Scans" }, { label: "", cls: "shrink" }];
  const row = (c) => h("tr", { class: "clickable", onclick: () => go(`#/campaigns/${c.id}`) },
    h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, c.name), c.description ? h("div", { class: "secondary-line", title: c.description }, c.description) : null)),
    h("td", {}, campStatusChip(c.status)),
    h("td", {}, c.environment ? envTag(c.environment) : h("span", { class: "faint" }, "Mixed")),
    h("td", {}, `${c.target_ids.length}`),
    h("td", {}, c.scan_count ? `${c.scan_count}${c.active_scans ? ` · ${c.active_scans} active` : ""}` : h("span", { class: "faint" }, "—")),
    h("td", { class: "shrink" }, icon("chevron")));
  app.replaceChildren(
    pageHead("Campaigns", { lead: "Pentest engagements: track targets, scans and findings together.", actions: [button("New campaign", { kind: "primary", ic: "plus", onclick: () => go("#/campaigns/new") })] }),
    h("div", { class: "table-card" }, table(cols, live.map(row),
      emptyState("No campaigns yet", "Name an engagement and group its targets; see scans and findings in one place.", [button("New campaign", { kind: "primary", ic: "plus", onclick: () => go("#/campaigns/new") })]))),
    archived.length ? section("Archived campaigns", h("div", { class: "table-card" }, table(cols, archived.map(row))), { hint: "Read-only; scans are kept." }) : null);
}

async function viewCampaign(id) {
  const c = await api(`/api/campaigns/${id}`);
  const fs = c.findings || {};
  const archive = guard(async () => { await api(`/api/campaigns/${id}/archive`, { method: "POST", body: { unarchive: c.archived } }); toast(c.archived ? "Unarchived" : "Archived"); router(); });
  const del = guard(async () => {
    if (!await confirmDialog("Delete campaign?", "Only the grouping is deleted; scans, schedules and findings are kept and keep running independently.", { confirmLabel: "Delete campaign", danger: true })) return;
    await api(`/api/campaigns/${id}`, { method: "DELETE" }); toast("Campaign deleted"); go("#/campaigns");
  });
  const scans = c.scans || [];
  app.replaceChildren(
    pageHead(c.name, {
      crumb: h("a", { href: "#/campaigns" }, "Campaigns"),
      meta: [campStatusChip(c.status), c.environment ? envTag(c.environment) : null, c.archived ? h("span", { class: "tag" }, "Archived") : null],
      actions: [
        menu([c.archived ? null : { label: "Edit", icon: "edit", onclick: () => go(`#/campaigns/${id}/edit`) },
          { label: c.archived ? "Unarchive" : "Archive", icon: "archive", onclick: archive }, "-",
          { label: "Delete", icon: "trash", danger: true, onclick: del }]),
        button("Report", { ic: "report", title: "Management report (print or save as PDF)", onclick: () => go(`#/campaigns/${id}/report`) }),
        button("New scan", { kind: "primary", ic: "play", onclick: () => scanDialog(null, { campaign_id: id, target_ids: c.target_ids }) })] }),
    c.description ? h("p", { class: "lead-text" }, c.description) : null,
    c.scope ? alertBox("info", "Engagement scope", c.scope) : null,
    h("div", { class: "stats" },
      h("div", { class: "stat" }, h("div", { class: "k" }, "Targets"), h("div", { class: "v" }, c.target_ids.length)),
      h("div", { class: "stat" + (fs.open_counts && (fs.open_counts.critical || fs.open_counts.high) ? " is-alert" : "") }, h("div", { class: "k" }, "Open critical / high"),
        h("div", { class: "v" }, fs.open_counts ? `${fs.open_counts.critical || 0} / ${fs.open_counts.high || 0}` : "—")),
      h("div", { class: "stat" }, h("div", { class: "k" }, "Finding groups"), h("div", { class: "v" }, fs.unique ?? "—"), fs.seen_after_fix ? h("div", { class: "s alert-text" }, `${fs.seen_after_fix} seen after remediation`) : null),
      h("div", { class: "stat" }, h("div", { class: "k" }, "Scans"), h("div", { class: "v" }, c.scan_count), h("div", { class: "s" }, c.active_scans ? `${c.active_scans} active` : "all done"))),
    h("div", { class: "grid-main-side" },
      h("div", {},
        section("Findings", findingsCard(fs, scans.map((s) => s.id), id), { hint: fs.unique ? `${plural(fs.unique, "group")}, ${plural(fs.occurrences, "occurrence")}` : null }),
        section("Scans", h("div", { class: "table-card" }, scanTable(scans, { empty: emptyState("No scans in this campaign", "Start a scan linked to the campaign.") }))),
        c.schedules && c.schedules.length ? section("Schedules", h("div", { class: "table-card" }, scheduleTable(c.schedules))) : null),
      h("div", {},
        section("Targets", h("div", { class: "card card-pad" }, c.targets.length ? h("ul", { class: "linklist" }, c.targets.map((t) => h("li", {},
          h("a", { href: `#/targets/${t.id}` }, t.name), " ", envTag(t.environment)))) : h("div", { class: "faint" }, "No targets added."))))));
}

// Compact findings summary card with a severity breakdown; links to the full findings table (campaign or target).
function findingsCard(fs, scanIds, campaignId) {
  if (!fs || !fs.unique) return h("div", { class: "card" }, emptyState("No findings", "No finding groups in this scope. They are collected as scans complete."));
  const openSev = fs.open_counts || {};
  const rem = fs.remediation || {};
  const open = rem.open || 0;
  const closed = Object.entries(rem).filter(([k, n]) => k !== "open" && n);
  const max = Math.max(...SEV.map((s) => fs.counts[s] || 0));
  // Widths go through CSSOM: the CSP (style-src 'self') blocks inline style attributes.
  const sized = (el, prop, value) => { el.style[prop] = value; return el; };
  const rows = SEV.map((s) => {
    const total = fs.counts[s] || 0;
    if (!total) return null;
    const o = openSev[s] || 0;
    const bar = sized(h("div", { class: `fc-bar ${s}` },
      o ? sized(h("span", { class: "fc-open" }), "flex", String(o)) : null,
      total - o ? sized(h("span", { class: "fc-closed" }), "flex", String(total - o)) : null), "width", `${(total / max) * 100}%`);
    return h("div", { class: "fc-row" },
      h("span", { class: "fc-sev" }, h("span", { class: `sq ${s}` }), SEV_TR[s]),
      h("div", { class: "fc-track", title: `${o} of ${plural(total, "group")} open` }, bar),
      h("span", { class: "fc-groups" }, plural(total, "group")),
      o ? h("span", { class: "fc-state" }, `${o} open`) : h("span", { class: "fc-state done" }, icon("check"), "Resolved"));
  });
  return h("div", { class: "card fcard" },
    h("div", { class: "fc-head" },
      h("div", { class: "fc-total" },
        h("span", { class: `fc-num${open ? "" : " done"}` }, String(open)),
        h("span", { class: "fc-lbl" }, open ? `open of ${plural(fs.unique, "group")}` : "open · all resolved")),
      closed.length ? h("div", { class: "fc-rem" }, closed.map(([k, n]) => h("span", { class: `rem ${k}` }, `${REMEDIATION_TR[k]} ${n}`))) : null),
    h("div", { class: "fc-rows" }, rows),
    h("div", { class: "fc-foot" }, button("Review findings", { size: "sm", onclick: () => findingsDialog(scanIds, campaignId) })));
}
function plural(n, one, many = `${one}s`) { return `${n} ${n === 1 ? one : many}`; }

async function viewCampaignForm(id) {
  const [c, targets] = await Promise.all([id ? api(`/api/campaigns/${id}`) : null, api("/api/targets")]);
  const v = c || { status: "planned", environment: "", target_ids: [] };
  const f = {
    name: h("input", { type: "text", value: v.name || "", placeholder: "e.g. 2026 Q4 External Pentest" }),
    status: select(Object.entries(CAMP_STATUS_TR), v.status),
    environment: select([["", "Mixed / unspecified"], ...Object.entries(ENV_TR)], v.environment || ""),
    description: h("textarea", { rows: 2, value: v.description || "", placeholder: "Short description" }),
    scope: h("textarea", { rows: 3, value: v.scope || "", placeholder: "Engagement scope, rules, contacts (free text). Technical scope is defined on the targets." }),
  };
  const tsel = targetMulti(targets, v.target_ids);
  const save = guard(async () => {
    const body = { name: f.name.value, status: f.status.value, environment: f.environment.value, description: f.description.value, scope: f.scope.value, target_ids: tsel.value() };
    const r = await api(id ? `/api/campaigns/${id}` : "/api/campaigns", { method: id ? "PUT" : "POST", body });
    toast("Campaign saved"); go(`#/campaigns/${r.id}`);
  });
  app.replaceChildren(
    pageHead(id ? "Edit campaign" : "New campaign", { crumb: id ? h("a", { href: `#/campaigns/${id}` }, v.name) : h("a", { href: "#/campaigns" }, "Campaigns") }),
    h("form", { class: "card card-pad form", onsubmit: (e) => { e.preventDefault(); save(); } },
      formSection("General", "Name the engagement and choose its status.", [
        field("Name", f.name), h("div", { class: "field-row two" }, field("Status", f.status), field("Environment", f.environment)),
        field("Description", f.description), field("Scope note", f.scope, "Free text; does not affect scanning. Technical scope is defined on the targets.")]),
      formSection("Targets", "Targets included in this campaign. Scans and findings are collected from them.", [h("div", { class: "field" }, tsel.el)]),
      h("div", { class: "form-actions" }, button("Cancel", { onclick: () => history.back() }), button("Save", { kind: "primary", type: "submit" }))));
}

function verificationPanel(gid) {
    const verifBox = h("div", { class: "verif-section" }, h("div", { class: "faint" }, "Loading…"));
    const VLABEL = { reverified: "Re-verified", not_reproduced: "Not reproduced (this attempt)", inconclusive: "Inconclusive", error: "Run error", pending: "Pending" };
    const VCLS = { reverified: "failed", not_reproduced: "neutral", inconclusive: "queued", error: "failed", pending: "running" };
    let vpoll = null;
    const stopPoll = () => { if (vpoll) { clearInterval(vpoll); vpoll = null; } };
    const startVerify = guard(async () => {
      const g = await api(`/api/findings/${gid}`);
      const [target, profiles, campaigns] = await Promise.all([api(`/api/targets/${g.target_id}`), api("/api/llm-profiles"), api("/api/campaigns")]);
      const connection = select(profiles.map((p) => [String(p.id), `${p.name} · ${p.model}`]), String(target.llm_profile_id || (profiles.find((p) => p.is_default) || profiles[0] || {}).id || ""));
      const extras = scanExtras(target.auth_profiles || [], campaigns, { auth_profile_ids: (target.auth_profiles || []).map((p) => p.id) });
      const turns = h("input", { type: "number", min: "1", step: "1", placeholder: "Strix default" });
      let submitting = false;
      const close = dialog("Verification", [
        h("div", { class: "note" }, g.title, " · ", target.base_url),
        h("div", { class: "help" }, "Start a separate, focused Strix run using current Vault profiles. Original evidence and remediation status are preserved."),
        field("LLM connection", connection), extras.fields,
        field("Turns per agent", turns)
      ], [button("Cancel", { onclick: () => close() }), button("Start verification", { kind: "primary", onclick: guard(async (e) => {
        if (submitting) return;
        submitting = true; e.currentTarget.disabled = true;
        try {
          await api(`/api/findings/${gid}/verify`, { method: "POST", body: { llm_profile_id: connection.value, ...extras.value(), max_turns: turns.value } });
          close(); toast("Verification started"); await pollVerifs();
        } finally { submitting = false; if (e.currentTarget) e.currentTarget.disabled = false; }
      }) })]);
    });
    const renderVerifs = (list) => {
      const anyActive = (list || []).some((v) => v.scan && ACTIVE.includes(v.scan.status));
      const rows = (list || []).map((v) => {
        const active = v.scan && ACTIVE.includes(v.scan.status);
        const res = active ? "pending" : v.result;
        return h("div", { class: "verif" },
          h("span", { class: `status ${VCLS[res] || "queued"}` }, h("span", { class: "dot" }), active ? (STATUS_TR[v.scan.status] || "Running") : (VLABEL[res] || res)),
          v.scan ? h("a", { href: `#/scans/${v.scan.id}`, class: "faint" }, ` scan #${v.scan.id}`) : null,
          h("span", { class: "faint" }, ` · ${fmtShort(v.finished_at || v.created_at)}`),
          (v.profiles || []).length ? h("span", { class: "faint" }, " · " + v.profiles.map((p) => p.name).join(", ")) : null,
          v.note ? h("div", { class: "note vnote" }, v.note) : null);
      });
      verifBox.replaceChildren(
        h("div", { class: "verif-head" }, h("h4", {}, "Verification"),
          h("div", { class: "actions" }, button("Evidence workspace", { size: "sm", title: "Attack/control evidence side by side, with analyst notes", onclick: () => { closeDialogs(); go(`#/findings/${gid}`); } }),
            button(rows.length ? "Re-verify" : "Verify", { size: "sm", ic: "refresh", disabled: anyActive, title: "Re-run Strix focused on this finding", onclick: startVerify }))),
        h("div", { class: "help" }, "Run a focused verification using current Vault profiles. Results never change remediation automatically. Fingerprint grouping is a correlation hint, not proof of the same vulnerability."),
        rows.length ? h("div", { class: "verif-list" }, rows) : h("div", { class: "faint" }, "Not verified yet."));
      if (anyActive && !vpoll) vpoll = setInterval(pollVerifs, 3000);
      if (!anyActive) stopPoll();
    };
    const pollVerifs = async () => {
      if (!document.body.contains(verifBox)) { stopPoll(); return; }
      try { const full = await api(`/api/findings/${gid}`); renderVerifs(full.verifications); } catch { setConnected(false); }
    };
    api(`/api/findings/${gid}`).then((full) => renderVerifs(full.verifications)).catch(() => verifBox.replaceChildren(h("div", { class: "faint" }, "Could not load verifications.")));
    return verifBox;
}

// ================================================================== deduplicated findings (dialog)
async function findingsDialog(scanIds, campaignId) {
  const data = campaignId ? await api(`/api/campaigns/${campaignId}/findings`) : await api(`/api/targets/${scanIds}/findings`);
  const groups = data.groups || [];
  const body = h("div", {});
  const render = () => {
    const tbody = h("tbody", {});
    groups.forEach((g) => {
      const detail = h("tr", { class: "detail-row", hidden: true }, h("td", { colspan: 5 }, findingGroupDetail(g)));
      tbody.append(h("tr", { class: "clickable", onclick: () => { detail.hidden = !detail.hidden; } },
        h("td", { class: "shrink" }, h("span", { class: `sevpill ${g.severity}` }, SEV_TR[g.severity] || g.severity)),
        h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line", title: g.title }, g.title), h("div", { class: "secondary-line mono" }, [g.method, g.endpoint].filter(Boolean).join(" ") || g.host || ""))),
        h("td", { class: "nowrap" }, h("span", { class: `rem ${g.remediation}` }, REMEDIATION_TR[g.remediation]), g.seen_after_fix ? h("span", { class: "tag danger", title: "Seen again after being marked fixed" }, "again") : null),
        h("td", { class: "nowrap muted" }, plural(g.runs, "scan")),
        h("td", { class: "shrink" }, icon("chevron")), detail));
      tbody.append(detail);
    });
    body.replaceChildren(h("div", { class: "table-scroll tall" }, h("table", { class: "t" },
      h("thead", {}, h("tr", {}, ["Severity", "Finding", "Status", "Occurrences", ""].map((x) => h("th", {}, x)))), tbody)));
  };
  function findingGroupDetail(g) {
    const remSel = select(Object.entries(REMEDIATION_TR), g.remediation);
    const note = h("input", { type: "text", value: g.remediation_note || "", placeholder: "Note (optional)" });
    const occ = h("div", { class: "faint" }, "Loading…");
    const verifBox = verificationPanel(g.id);
    api(`/api/findings/${g.id}`).then((full) => {
      occ.replaceChildren(h("div", { class: "occ-list" }, (full.occurrences_list || []).map((o) => h("div", { class: "occ" },
        h("a", { href: `#/scans/${o.scan_id}` }, `#${o.scan_id}`), " ", h("span", { class: "mono" }, o.run_name), " ", h("span", { class: "faint" }, fmtShort(o.observed_at)), " ", h("span", { class: `sevpill ${o.severity}` }, SEV_TR[o.severity] || o.severity)))));
    }).catch(() => { occ.replaceChildren(h("div", { class: "faint" }, "Could not load occurrences.")); verifBox.replaceChildren(h("div", { class: "faint" }, "Could not load verifications.")); });
    return h("div", { class: "finding-body" },
      h("div", { class: "note" }, [g.cwe, g.host, `first: ${fmtShort(g.first_seen_at)}`, `last: ${fmtShort(g.last_seen_at)}`].filter(Boolean).join(" · ")),
      h("div", { class: "rem-edit" + (can("analyst") ? "" : " role-hidden") }, h("label", {}, "Remediation status"), remSel, note,
        button("Save", { size: "sm", kind: "primary", onclick: guard(async () => {
          await api(`/api/findings/${g.id}`, { method: "PATCH", body: { remediation: remSel.value, remediation_note: note.value } });
          g.remediation = remSel.value; g.remediation_note = note.value; toast("Updated"); render();
        }) })),
      verifBox,
      h("h4", {}, "Occurrences"), occ);
  }
  render();
  const close = dialog("Finding groups", groups.length ? body : emptyState("No findings", "No finding groups recorded in this scope."),
    [button("Close", { onclick: () => close() })], { wide: true });
}

// ================================================================== auth profiles (vault)
function verifyChip(p) {
  if (p.last_verify_ok === 1) return h("span", { class: "status completed", title: p.last_verify_note || "" }, h("span", { class: "dot" }), "Pre-check passed");
  if (p.last_verify_ok === 0) return h("span", { class: "status failed", title: p.last_verify_note || "" }, h("span", { class: "dot" }), "Failed");
  return h("span", { class: "faint" }, "—");
}

async function viewAuthProfiles() {
  const list = await api("/api/auth-profiles");
  app.replaceChildren(
    pageHead("Auth profiles", { lead: "Reusable authentication profiles (vault) used across targets. Secret values are stored encrypted and given to scans only as a sandbox file.", actions: [button("New profile", { kind: "primary", ic: "plus", onclick: () => authProfileDialog(null) })] }),
    alertBox("info", "Strix's authentication limit", "Strix has no authentication option of its own; secret values are copied to the sandbox as a 0600 file and only the file path appears in the instruction. Strix does not report whether the login succeeded; the verification below is Skynet's own pre-check (header/cookie only)."),
    h("div", { class: "table-card" }, table(
      [{ label: "Profile" }, { label: "Method" }, { label: "Targets" }, { label: "Verification" }, { label: "", cls: "shrink" }],
      list.map((p) => h("tr", { class: "clickable", onclick: () => authProfileDialog(p) },
        h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, p.name, p.secret_readable === false ? h("span", { class: "tag danger" }, "unreadable") : null), p.description ? h("div", { class: "secondary-line", title: p.description }, p.description) : null)),
        h("td", {}, h("span", { class: "tag" }, AUTHKIND_TR[p.kind] || p.kind)),
        h("td", {}, (p.targets || []).length ? (p.targets || []).map((t) => t.name).join(", ") : h("span", { class: "faint" }, "None assigned")),
        h("td", {}, p.verifiable ? verifyChip(p) : h("span", { class: "faint" }, "—")),
        h("td", { class: "shrink" }, icon("chevron")))),
      emptyState("No auth profiles", "Define one once and use it across multiple targets and schedules.", [button("New profile", { kind: "primary", ic: "plus", onclick: () => authProfileDialog(null) })]))));
}

// Key/value rows editor for header and cookie profiles. Existing names show a "stored" placeholder; a blank value
// keeps the stored secret, a new value replaces it.
function kvRows(names, placeholder) {
  const wrap = h("div", { class: "kv-rows" });
  const rows = [];
  const add = (name = "", stored = false) => {
    const n = h("input", { type: "text", value: name, placeholder, class: "mono" });
    const val = h("input", { type: "password", autocomplete: "new-password", placeholder: stored ? "Stored — enter to change" : "value" });
    const r = { n, val };
    const rowEl = h("div", { class: "kv-row" }, n, val, button("", { ic: "trash", size: "sm", kind: "ghost", title: "Remove row", onclick: () => { wrap.removeChild(rowEl); rows.splice(rows.indexOf(r), 1); } }));
    rows.push(r); wrap.append(rowEl);
  };
  (names && names.length ? names : [""]).forEach((nm) => add(nm, !!nm));
  const addBtn = button("Add row", { size: "sm", ic: "plus", onclick: () => add() });
  return { el: h("div", {}, wrap, addBtn), value: () => rows.map((r) => ({ name: r.n.value.trim(), value: r.val.value })).filter((x) => x.name) };
}

async function authProfileDialog(p) {
  const targets = await api("/api/targets");
  const v = p || { kind: "header", header_names: [], cookie_names: [], target_ids: [] };
  const f = {
    name: h("input", { type: "text", value: v.name || "", placeholder: "e.g. Staging user token" }),
    kind: select(Object.entries(AUTHKIND_TR), v.kind),
    description: h("input", { type: "text", value: v.description || "", placeholder: "Short description (optional)" }),
    username: h("input", { type: "text", value: v.username || "", autocomplete: "off" }),
    login_url: h("input", { type: "text", value: v.login_url || "", class: "mono", placeholder: "https://staging.local/login" }),
    password: h("input", { type: "password", autocomplete: "new-password", placeholder: v.has_secret ? "Stored — enter to change" : "" }),
    cookie_domain: h("input", { type: "text", value: v.cookie_domain || "", class: "mono", placeholder: "staging.local" }),
    verify_url: h("input", { type: "text", value: v.verify_url || "", class: "mono", placeholder: "https://staging.local/api/me" }),
    verify_expect_status: h("input", { type: "number", value: v.verify_expect_status || "", placeholder: "200" }),
    verify_expect_text: h("input", { type: "text", value: v.verify_expect_text || "", placeholder: "Expected text (optional)" }),
    notes: h("textarea", { rows: 2, value: v.notes || "", placeholder: "Notes (optional)" }),
  };
  const headers = kvRows(v.header_names, "Authorization"), cookies = kvRows(v.cookie_names, "session");
  const tsel = targetMulti(targets, v.target_ids);
  const blocks = {
    cred: h("div", { class: "fields" }, field("Username", f.username), field("Password", f.password, "Stored encrypted; the agent uses it to submit the login form."), field("Login URL", f.login_url, "Optional.")),
    header: h("div", { class: "field" }, h("div", { class: "label" }, "HTTP headers"), headers.el, h("div", { class: "help" }, "e.g. Authorization: Bearer … · name and value pairs.")),
    cookie: h("div", {}, h("div", { class: "field" }, h("div", { class: "label" }, "Cookies"), cookies.el), field("Cookie domain", f.cookie_domain, "For the Netscape cookie file (optional).")),
    verify: h("div", { class: "fields vbox" }, h("div", { class: "card-subtitle" }, "Skynet pre-check (header/cookie)"),
      field("Verification URL", f.verify_url, "If in scope, Skynet sends one request to check the session."),
      h("div", { class: "field-row two" }, field("Expected HTTP code", f.verify_expect_status), field("Expected text", f.verify_expect_text))),
    anon: h("div", { class: "note" }, "Anonymous profile: no credentials. Used as the unauthenticated role in access-control comparisons."),
  };
  const sync = () => {
    const k = f.kind.value;
    blocks.cred.hidden = k !== "credentials"; blocks.header.hidden = k !== "header";
    blocks.cookie.hidden = k !== "cookie"; blocks.verify.hidden = !["header", "cookie"].includes(k);
    blocks.anon.hidden = k !== "anonymous";
  };
  f.kind.addEventListener("change", sync); sync();
  const collect = () => {
    const k = f.kind.value;
    const body = { name: f.name.value, kind: k, description: f.description.value, notes: f.notes.value, target_ids: tsel.value() };
    if (k === "credentials") { body.username = f.username.value; body.login_url = f.login_url.value; if (f.password.value) body.password = f.password.value; }
    if (k === "header") body.headers = headers.value();
    if (k === "cookie") { body.cookies = cookies.value(); body.cookie_domain = f.cookie_domain.value; }
    if (["header", "cookie"].includes(k)) { body.verify_url = f.verify_url.value; body.verify_expect_status = f.verify_expect_status.value; body.verify_expect_text = f.verify_expect_text.value; }
    return body;
  };
  const foot = [];
  if (p) foot.push(button("Delete", { kind: "danger", ic: "trash", onclick: guard(async () => {
    if (!await confirmDialog("Delete profile?", "Schedules using this profile are paused. Masking in old scans is not affected.", { confirmLabel: "Delete", danger: true })) return;
    const r = await api(`/api/auth-profiles/${p.id}`, { method: "DELETE" }); close(); toast(r.paused_schedules ? `Profile deleted, ${r.paused_schedules} schedules paused` : "Profile deleted"); router();
  }) }));
  if (p && p.verifiable) foot.push(button("Verify", { onclick: guard(async () => {
    const r = await api(`/api/auth-profiles/${p.id}/verify`, { method: "POST" });
    toast(`${VERIFY_TR[r.result.result] || r.result.result}: ${r.result.note || ""}`, r.result.result === "failed");
  }) }));
  foot.push(h("span", { class: "spacer" }), button("Cancel", { onclick: () => close() }),
    button("Save", { kind: "primary", onclick: guard(async () => {
      await api(p ? `/api/auth-profiles/${p.id}` : "/api/auth-profiles", { method: p ? "PUT" : "POST", body: collect() });
      close(); toast("Profile saved"); router();
    }) }));
  const close = dialog(p ? "Edit auth profile" : "New auth profile", [
    h("div", { class: "field-row two" }, field("Name", f.name), h("div", { class: "field" }, h("label", {}, "Method"), f.kind)),
    field("Description", f.description),
    blocks.anon, blocks.cred, blocks.header, blocks.cookie, blocks.verify,
    field("Notes", f.notes),
    h("div", { class: "field" }, h("div", { class: "label" }, "Assigned targets"), tsel.el,
      h("div", { class: "help" }, "A profile can only be used in scans of the targets it is assigned to.")),
  ], foot, { wide: true });
}

// ================================================================== inventory
async function viewInventory(presetTarget) {
  const targets = await api("/api/targets");
  if (!targets.length) {
    app.replaceChildren(pageHead("Inventory", { lead: "Hosts, services, endpoints and technologies discovered in scans." }),
      h("div", { class: "card" }, emptyState("No targets", "Inventory is built from scans. Add a target and scan it first.", [button("New target", { kind: "primary", onclick: () => go("#/targets/new") })])));
    return;
  }
  const st = { target: presetTarget || targets[0].id, kind: "", scope: "", tier: "", q: "" };
  const targetSel = select(targets.map((t) => [String(t.id), `${t.name} · ${ENV_TR[t.environment]}`]), String(st.target));
  const kindSel = select([["", "All kinds"], ...Object.entries(KIND_ASSET_TR)], "");
  const scopeSel = select([["", "All scopes"], ...Object.entries(SCOPE_TR)], "");
  const tierSel = select([["", "All evidence"], ...Object.entries(TIER_TR)], "");
  const search = h("input", { type: "search", placeholder: "Search host, path or name" });
  const summaryBox = h("div", {}), box = h("div", { class: "table-card" }, h("div", { class: "loading" }, "Loading…"));
  const load = guard(async () => {
    const qs = new URLSearchParams({ kind: st.kind, scope: st.scope, tier: st.tier, q: st.q });
    const d = await api(`/api/targets/${st.target}/inventory?${qs}`);
    const diff = d.diff, sum = d.summary || { by_kind: {} };
    summaryBox.replaceChildren(
      h("div", { class: "stats compact" }, Object.entries(KIND_ASSET_TR).map(([k, l]) => h("div", { class: "stat" },
        h("div", { class: "k" }, l), h("div", { class: "v" }, (sum.by_kind[k] || {}).total || 0),
        h("div", { class: "s" }, (sum.by_kind[k] || {}).observed ? `${(sum.by_kind[k] || {}).observed} observed` : "—")))),
      diff ? h("div", { class: "note" }, `Last scan (${MODE_TR[diff.scan_mode] || "?"}, ${diff.complete == null ? "completion unknown" : diff.complete ? "complete" : "partial"}): ` +
        Object.entries(diff.by_kind).filter(([, v]) => v.new || v.changed).map(([k, v]) => `${KIND_ASSET_TR[k]} +${v.new}${v.changed ? ` ~${v.changed}` : ""}`).join(", ") ) : null);
    const rows = d.assets.map((a) => h("tr", { class: "clickable", onclick: () => assetDialog(a) },
      h("td", {}, h("span", { class: "tag" }, KIND_ASSET_TR[a.kind] || a.kind)),
      h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line mono", title: a.key }, assetLabel(a)), a.name && a.kind === "technology" ? h("div", { class: "secondary-line" }, a.version || "") : null)),
      h("td", {}, h("span", { class: `scope-pill ${a.scope}` }, SCOPE_TR[a.scope])),
      h("td", {}, h("span", { class: `tier ${a.tier}` }, TIER_TR[a.tier])),
      h("td", { class: "nowrap muted" }, fmtShort(a.last_seen_at)),
      h("td", { class: "shrink" }, icon("chevron"))));
    box.replaceChildren(table([{ label: "Kind" }, { label: "Asset" }, { label: "Scope" }, { label: "Evidence" }, { label: "Last seen" }, { label: "", cls: "shrink" }], rows,
      emptyState(st.q || st.kind || st.scope || st.tier ? "No assets match the filter" : "No inventory yet", st.q || st.kind ? "Change the filters." : "Assets discovered as this target is scanned are collected here.")));
  });
  targetSel.addEventListener("change", () => { st.target = targetSel.value; location.hash = `#/inventory?target=${st.target}`; load(); });
  [["kind", kindSel], ["scope", scopeSel], ["tier", tierSel]].forEach(([k, el]) => el.addEventListener("change", () => { st[k] = el.value; load(); }));
  let qt; search.addEventListener("input", () => { clearTimeout(qt); qt = setTimeout(() => { st.q = search.value.trim(); load(); }, 200); });
  app.replaceChildren(
    pageHead("Inventory", { lead: "Hosts, services, endpoints and technologies discovered in scans. The scope label follows the target's rules; the inventory never changes scope." }),
    h("div", { class: "toolbar" }, field("Target", targetSel), field("Kind", kindSel), field("Scope", scopeSel), field("Evidence", tierSel), h("div", { class: "field grow" }, h("label", {}, "Search"), search)),
    summaryBox, box);
  load();
}
function assetLabel(a) {
  if (a.kind === "technology") return a.name + (a.version ? ` ${a.version}` : "");
  if (a.kind === "host") return a.host;
  if (a.kind === "service") return `${a.scheme || "tcp"}://${a.host}:${a.port || ""}`;
  return `${a.method || "*"} ${a.host}${a.port ? ":" + a.port : ""}${a.path || ""}`;
}
async function assetDialog(a) {
  const d = await api(`/api/assets/${a.id}/observations`);
  const obs = d.observations || [];
  const close = dialog(assetLabel(a), [
    h("div", { class: "note" }, [KIND_ASSET_TR[a.kind], TIER_TR[a.tier], `first: ${fmtShort(a.first_seen_at)}`, `last: ${fmtShort(a.last_seen_at)}`].filter(Boolean).join(" · ")),
    a.change_note ? alertBox("warn", "Change", `${a.change_note} (${a.changed_run_name || ""})`) : null,
    h("h4", {}, `Observations (${obs.length})`),
    h("div", { class: "occ-list" }, obs.map((o) => h("div", { class: "occ" },
      h("span", { class: `tier ${o.tier}` }, TIER_TR[o.tier]), " ",
      h("span", { class: "tag" }, o.source), " ",
      o.scan_id ? h("a", { href: `#/scans/${o.scan_id}` }, `#${o.scan_id}`) : null, " ",
      h("span", { class: "faint" }, fmtShort(o.observed_at)),
      o.evidence ? h("div", { class: "mono evidence" }, o.evidence) : null)))],
    [button("Close", { onclick: () => close() })], { wide: true });
}

// ================================================================== users (admin)
function usersSection(users) {
  const rows = users.map((u) => h("tr", {},
    h("td", {}, h("div", { class: "primary-line" }, u.display_name || u.username, u.id === ME.id ? [" ", h("span", { class: "tag" }, "You")] : null, u.builtin ? [" ", h("span", { class: "tag accent", title: "SKYNET_USER account from the server configuration; always an active admin." }, "Built-in")] : null),
      h("div", { class: "secondary-line mono" }, u.username)),
    h("td", {}, h("span", { class: `role-chip ${u.role}` }, ROLE_NAMES[u.role] || u.role)),
    h("td", {}, u.active ? h("span", { class: "status active" }, h("span", { class: "dot" }), "Active") : h("span", { class: "status cancelled" }, h("span", { class: "dot" }), "Disabled")),
    h("td", { class: "nowrap" }, u.last_login_at ? fmtShort(u.last_login_at) : h("span", { class: "faint" }, "Never")),
    h("td", { class: "shrink right" }, u.builtin || u.id === ME.id ? h("span", { class: "faint help" }, u.builtin ? "Server-managed" : "") : menu([
      { label: "Change role", icon: "users", need: "admin", onclick: () => userDialog(u) },
      { label: "Reset password", icon: "refresh", need: "admin", onclick: () => resetPasswordDialog(u) },
      { label: u.active ? "Disable" : "Enable account", icon: u.active ? "pause" : "play", need: "admin", onclick: guard(async () => {
        if (u.active && !await confirmDialog("Disable account?", `${u.username} is signed out immediately and can't sign in until re-enabled. Their history stays in the audit log.`, { confirmLabel: "Disable", danger: true })) return;
        await api(`/api/users/${u.id}`, { method: "PUT", body: { active: !u.active } }); toast(u.active ? "Account disabled" : "Account enabled"); router();
      }) }, "-",
      { label: "Delete user", icon: "trash", danger: true, need: "admin", onclick: guard(async () => {
        if (!await confirmDialog("Delete user?", `${u.username} is removed and signed out. Notes and audit entries keep their name. This can't be undone; disabling keeps the account instead.`, { confirmLabel: "Delete", danger: true })) return;
        await api(`/api/users/${u.id}`, { method: "DELETE" }); toast("User deleted"); router();
      }) }]))));
  return section("Users", h("div", {},
    h("div", { class: "table-card" }, table([{ label: "User" }, { label: "Role" }, { label: "Status" }, { label: "Last sign-in" }, { label: "", cls: "shrink" }], rows)),
    h("div", { class: "note roles-note" }, Object.entries(ROLE_HELP).map(([r, t]) => h("div", {}, h("span", { class: `role-chip ${r}` }, ROLE_NAMES[r]), " ", t)))),
  { right: button("Add user", { ic: "plus", size: "sm", need: "admin", onclick: () => userDialog(null) }) });
}

function userDialog(u) {
  const f = {
    username: h("input", { type: "text", autocomplete: "off", value: u ? u.username : "", disabled: !!u, class: "mono" }),
    display_name: h("input", { type: "text", value: u ? u.display_name || "" : "", placeholder: "Optional, e.g. Ayşe Yılmaz" }),
    role: select(Object.entries(ROLE_NAMES), u ? u.role : "analyst"),
    password: h("input", { type: "password", autocomplete: "new-password" }),
  };
  const roleHelp = h("div", { class: "help" }, ROLE_HELP[f.role.value]);
  f.role.addEventListener("change", () => { roleHelp.textContent = ROLE_HELP[f.role.value]; });
  const save = guard(async () => {
    if (u) await api(`/api/users/${u.id}`, { method: "PUT", body: { role: f.role.value, display_name: f.display_name.value } });
    else await api("/api/users", { method: "POST", body: { username: f.username.value, display_name: f.display_name.value, role: f.role.value, password: f.password.value } });
    close(); toast(u ? "User updated" : "User created"); router();
  });
  const close = dialog(u ? `Edit ${u.username}` : "Add user", h("form", { class: "fields", onsubmit: (e) => { e.preventDefault(); save(); } },
    field("Username", f.username, u ? "Usernames can't be changed." : "Used to sign in. Letters, digits and . _ @ -"),
    field("Display name", f.display_name),
    h("div", { class: "field" }, h("label", { for: "userRole" }, "Role"), Object.assign(f.role, { id: "userRole" }), roleHelp),
    u ? null : field("Initial password", f.password, "At least 10 characters. Share it securely; the user can change it under Settings."),
    h("button", { type: "submit", hidden: true })),
  [button("Cancel", { onclick: () => close() }), button(u ? "Save" : "Create user", { kind: "primary", onclick: save })]);
}

function resetPasswordDialog(u) {
  const pw = h("input", { type: "password", autocomplete: "new-password" });
  const save = guard(async () => {
    await api(`/api/users/${u.id}/password`, { method: "POST", body: { password: pw.value } });
    close(); toast(`Password reset; ${u.username}'s sessions were signed out`);
  });
  const close = dialog(`Reset password · ${u.username}`, h("form", { class: "fields", onsubmit: (e) => { e.preventDefault(); save(); } },
    field("New password", pw, "At least 10 characters. Existing sessions of this user are signed out."), h("button", { type: "submit", hidden: true })),
  [button("Cancel", { onclick: () => close() }), button("Reset password", { kind: "primary", onclick: save })]);
}

// ================================================================== audit log (admin)
async function viewAudit(query) {
  const params = new URLSearchParams(query || "");
  const state = { actor: params.get("actor") || "", action: params.get("action") || "", q: params.get("q") || "" };
  const first = await api(`/api/audit?${new URLSearchParams({ ...state, limit: 100 })}`);
  const actorSel = select([["", "All users"], ...first.actors.map((a) => [a, a])], state.actor);
  const groups = [...new Set(first.actions.map(([k]) => k.split(".")[0]))];
  const GROUP_TR = { auth: "Sign-in", account: "Own account", target: "Targets", scan: "Scans", agent: "Agent instructions", schedule: "Schedules", campaign: "Campaigns", auth_profile: "Auth profiles", llm_profile: "LLM connections", finding: "Findings", settings: "Settings", ci_token: "CI token", user: "Users", report: "Reports" };
  const actionSel = select([["", "All actions"], ...groups.map((g) => [g, GROUP_TR[g] || g]), ...first.actions.map(([k, l]) => [k, `· ${l}`])], state.action);
  const search = h("input", { type: "search", value: state.q, placeholder: "Search summary, object id, path" });
  const tbody = h("tbody", {});
  const more = button("Load more", { size: "sm" });
  const OBJ_LINK = { scan: (id) => `#/scans/${id}`, finding: (id) => `#/findings/${id}`, target: (id) => `#/targets/${id}`, schedule: (id) => `#/schedules/${id}`, campaign: (id) => `#/campaigns/${id}` };
  const row = (e) => h("tr", {},
    h("td", { class: "nowrap" }, h("time", { datetime: e.at, title: fmtDateSec(e.at) }, fmtShort(e.at))),
    h("td", {}, h("div", { class: "primary-line" }, e.actor), e.actor_role ? h("div", { class: "secondary-line" }, ROLE_NAMES[e.actor_role] || e.actor_role) : null),
    h("td", {}, h("div", { class: "primary-line" }, e.action_label, e.status >= 400 ? [" ", h("span", { class: "tag danger", title: `HTTP ${e.status}` }, e.status === 403 ? "Denied" : "Failed")] : null),
      h("div", { class: "secondary-line mono" }, e.action)),
    h("td", {}, e.object_type && e.object_id ? (OBJ_LINK[e.object_type] ? h("a", { href: OBJ_LINK[e.object_type](e.object_id) }, `${e.object_type} #${e.object_id}`) : `${e.object_type} #${e.object_id}`) : h("span", { class: "faint" }, "—"),
      e.summary ? h("div", { class: "secondary-line", title: e.summary }, e.summary) : null),
    h("td", { class: "nowrap secondary-line mono" }, e.ip || ""));
  let last = null;
  const fill = (r, append) => {
    if (!append) tbody.replaceChildren();
    r.entries.forEach((e) => tbody.append(row(e)));
    last = r.entries.length ? r.entries[r.entries.length - 1].id : last;
    more.hidden = !r.has_more;
    if (!tbody.childElementCount) tbody.append(h("tr", {}, h("td", { colspan: 5 }, emptyState("No entries", "Nothing matches these filters."))));
  };
  const apply = () => { const qs = new URLSearchParams(Object.entries({ actor: actorSel.value, action: actionSel.value, q: search.value.trim() }).filter(([, v]) => v)); go(`#/audit${qs.toString() ? "?" + qs : ""}`); };
  actorSel.addEventListener("change", apply); actionSel.addEventListener("change", apply);
  search.addEventListener("keydown", (e) => { if (e.key === "Enter") apply(); });
  more.addEventListener("click", guard(async () => fill(await api(`/api/audit?${new URLSearchParams({ ...state, before: last, limit: 100 })}`), true)));
  fill(first, false);
  app.replaceChildren(
    pageHead("Audit log", { lead: "Who did what, and when: sign-ins, scans started or stopped, instructions sent to agents, finding status changes and configuration changes. Append-only; request contents and secrets are never recorded." }),
    h("div", { class: "toolbar audit-filters" }, actorSel, actionSel, search),
    h("div", { class: "table-card" }, h("div", { class: "table-scroll" }, h("table", { class: "t audit-table" },
      h("thead", {}, h("tr", {}, ["Time", "User", "Action", "Object", "IP"].map((x) => h("th", {}, x)))), tbody))),
    h("div", { class: "load-more" }, more));
}

// ================================================================== management report (print → Save as PDF)
const svgEl = (tag, attrs = {}, ...kids) => {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) el.setAttribute(k, v);
  kids.flat().forEach((k) => k != null && el.append(k instanceof Node ? k : document.createTextNode(String(k))));
  return el;
};
const SEVS = ["critical", "high", "medium", "low", "info"];
const dayText = (d) => d == null ? "—" : d < 1 ? "< 1 day" : `${Math.round(d)} day${Math.round(d) === 1 ? "" : "s"}`;

function trendChart(trend) {
  const W = 680, H = 190, L = 34, B = 40, T = 12, R = 8;
  const totals = trend.map((t) => t.counts ? SEVS.reduce((a, k) => a + t.counts[k], 0) : 0);
  const max = Math.max(4, ...totals);
  const step = Math.pow(10, Math.floor(Math.log10(max))) * (max / Math.pow(10, Math.floor(Math.log10(max))) > 5 ? 2 : 1);
  const top = Math.ceil(max / step) * step;
  const y = (v) => T + (H - T - B) * (1 - v / top);
  const slot = (W - L - R) / Math.max(trend.length, 1), bw = Math.min(38, slot * 0.6);
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "rpt-chart", role: "img", "aria-label": "Findings per scan, by severity" });
  for (let v = 0; v <= top; v += step) {
    svg.append(svgEl("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), class: "grid" }), svgEl("text", { x: L - 6, y: y(v) + 3, class: "axis", "text-anchor": "end" }, v));
  }
  trend.forEach((t, i) => {
    const x = L + slot * i + (slot - bw) / 2;
    const g = svgEl("g", { class: t.complete ? "bar" : "bar incomplete" });
    let acc = 0;
    if (t.counts) for (const k of [...SEVS].reverse()) {
      const n = t.counts[k]; if (!n) continue;
      g.append(svgEl("rect", { x, width: bw, y: y(acc + n), height: y(acc) - y(acc + n), class: `sev-${k}` }, svgEl("title", {}, `${SEV_TR[k]}: ${n}`)));
      acc += n;
    }
    if (!totals[i]) g.append(svgEl("line", { x1: x, x2: x + bw, y1: y(0) - 0.5, y2: y(0) - 0.5, class: "zero" }));
    g.append(svgEl("text", { x: x + bw / 2, y: y(acc) - 4, class: "val", "text-anchor": "middle" }, t.counts ? totals[i] : "?"));
    g.append(svgEl("text", { x: x + bw / 2, y: H - B + 14, class: "axis", "text-anchor": "middle" }, dateFmt(t.at, { day: "2-digit", month: "short" })));
    g.append(svgEl("text", { x: x + bw / 2, y: H - B + 26, class: "axis sub", "text-anchor": "middle" }, t.complete ? `#${t.scan_id}` : `#${t.scan_id} ✕`));
    g.append(svgEl("title", {}, `Scan #${t.scan_id}${t.target_name ? ` · ${t.target_name}` : ""} · ${STATUS_TR[t.status] || t.status}${t.complete ? "" : " (incomplete: not comparable)"}`));
    svg.append(g);
  });
  return svg;
}

async function viewReport(kind, id) {
  const r = await api(`/api/${kind}/${id}/report`);
  const f = r.findings, sm = f.summary, sc = r.scans;
  const back = kind === "targets" ? `#/targets/${id}` : `#/campaigns/${id}`;
  const crit = sm.open_counts.critical + sm.open_counts.high;
  const ageCH = [f.open_age.critical, f.open_age.high].filter((a) => a.n);
  const oldestCH = ageCH.length ? Math.max(...ageCH.map((a) => a.max)) : null;
  const tile = (k, v, sub, cls) => h("div", { class: "rpt-tile" + (cls ? " " + cls : "") }, h("div", { class: "k" }, k), h("div", { class: "v" }, v), sub ? h("div", { class: "s" }, sub) : null);
  const sevBars = () => {
    const mx = Math.max(1, ...SEVS.map((k) => sm.open_counts[k]));
    return h("div", { class: "rpt-sevbars" }, SEVS.map((k) => h("div", { class: "row" },
      h("span", { class: "lbl" }, SEV_TR[k]),
      h("span", { class: "track" }, h("span", { class: `fill sev-${k}`, "data-w": Math.round(100 * sm.open_counts[k] / mx) })),
      h("span", { class: "num" }, sm.open_counts[k]))));
  };
  const remChips = h("div", { class: "rpt-chips" }, Object.entries(REMEDIATION_TR).map(([k, l]) => h("span", { class: `rpt-chip rem-${k}${sm.remediation[k] ? "" : " zero"}` }, `${l}: ${sm.remediation[k] || 0}`)),
    sm.seen_after_fix ? h("span", { class: "rpt-chip warn" }, `${sm.seen_after_fix} seen again after being marked fixed`) : null);
  const ageTable = h("table", { class: "rpt-table" },
    h("thead", {}, h("tr", {}, ["Severity", "Open", "Open for (median · oldest)", "Fixed · median time"].map((x) => h("th", {}, x)))),
    h("tbody", {}, SEVS.map((k) => h("tr", {},
      h("td", { class: "nowrap" }, h("span", { class: `rpt-dot sev-${k}` }), SEV_TR[k]),
      h("td", { class: "num" }, sm.open_counts[k]),
      h("td", {}, f.open_age[k].n ? `${dayText(f.open_age[k].median)} · ${dayText(f.open_age[k].max)}` : "—"),
      h("td", {}, f.time_to_fix[k].n ? `${f.time_to_fix[k].n} · ${dayText(f.time_to_fix[k].median)}` : "—")))));
  const cov = r.coverage;
  const coverageBlock = kind === "targets" ? (cov ? h("div", {},
    h("p", { class: "rpt-src" }, `From scan #${cov.scan_id} · ${fmtDate(cov.at)}${cov.complete === false ? " · Strix marked this coverage record incomplete" : ""}`),
    cov.cells ? h("div", { class: "rpt-chips" }, Object.entries(cov.labels).map(([k, l]) => h("span", { class: `rpt-chip cov-${k}` }, `${l}: ${cov.counts[k]}`)))
      : h("p", { class: "rpt-empty" }, "This scan recorded no coverage cells."),
    (cov.gaps || []).length ? h("ul", { class: "rpt-gaps" }, cov.gaps.map((g) => h("li", {}, g))) : null)
    : h("p", { class: "rpt-empty" }, "No completed scan has a readable output folder, so there is no coverage record to report."))
    : h("table", { class: "rpt-table" },
      h("thead", {}, h("tr", {}, ["Target", "Scans (completed / total)", "Open C / H / M / L", "Coverage (tested / partial / not tested / unknown)"].map((x) => h("th", {}, x)))),
      h("tbody", {}, (r.targets || []).length ? r.targets.map((t) => h("tr", {},
        h("td", {}, t.name, t.environment ? h("span", { class: "rpt-env" }, ENV_TR[t.environment] || t.environment) : null),
        h("td", { class: "num" }, `${t.scans.completed} / ${t.scans.total}`),
        h("td", { class: "num" }, ["critical", "high", "medium", "low"].map((k) => t.open_counts[k]).join(" / ")),
        h("td", {}, t.coverage ? `${["tested", "partial", "not_tested", "unknown"].map((k) => t.coverage.counts[k]).join(" / ")} · scan #${t.coverage.scan_id}` : h("span", { class: "rpt-muted" }, t.scans.completed ? "No coverage record" : "No completed scan"))))
        : h("tr", {}, h("td", { colspan: 4, class: "rpt-empty" }, "No targets in this campaign."))));
  const topTable = f.top_open.length ? h("table", { class: "rpt-table rpt-top" },
    h("thead", {}, h("tr", {}, ["Severity", "Finding", kind === "campaigns" ? "Target" : "Location", "First seen", "Open for"].map((x) => h("th", {}, x)))),
    h("tbody", {}, f.top_open.map((g) => h("tr", {},
      h("td", {}, h("span", { class: `rpt-sev sev-${g.severity}` }, SEV_TR[g.severity] || g.severity)),
      h("td", {}, h("span", { class: "t" }, g.title || "Untitled finding"), g.cwe ? h("span", { class: "rpt-muted" }, ` · ${g.cwe}`) : null),
      h("td", { class: "rpt-where", title: g.host || "" }, kind === "campaigns" ? g.target_name || "—" : g.where || "—"),
      h("td", { class: "nowrap" }, dateFmt(g.first_seen_at, { day: "2-digit", month: "short", year: "numeric" })),
      h("td", { class: "nowrap" }, dayText(g.age_days))))))
    : h("p", { class: "rpt-empty" }, sm.unique ? "No open findings." : "No findings were recorded in these scans.");
  const sheet = h("article", { class: "report-sheet" },
    h("header", { class: "rpt-head" },
      h("div", {}, h("div", { class: "rpt-kicker" }, kind === "targets" ? "Security summary · Target" : "Security summary · Campaign"),
        h("h1", {}, r.name),
        h("div", { class: "rpt-meta" }, [r.environment ? ENV_TR[r.environment] || r.environment : null, r.subtitle || null,
          kind === "campaigns" && r.campaign_status ? (CAMP_STATUS_TR[r.campaign_status] || r.campaign_status) : null].filter(Boolean).join(" · "))),
      h("div", { class: "rpt-brand" }, h("div", { class: "b" }, "Skynet"),
        h("div", {}, `Generated ${fmtDate(r.generated_at)}`), h("div", {}, `by ${r.generated_by}`),
        h("div", {}, sc.first_at ? `Period: ${dateFmt(sc.first_at, { day: "2-digit", month: "short", year: "numeric" })} – ${dateFmt(sc.last_at, { day: "2-digit", month: "short", year: "numeric" })}` : "No scans yet"))),
    h("div", { class: "rpt-tiles" },
      tile("Open findings", f.open_total, `${sm.unique} unique finding${sm.unique === 1 ? "" : "s"} in total`),
      tile("Open critical + high", crit, crit ? `${sm.open_counts.critical} critical · ${sm.open_counts.high} high` : "None open", crit ? "hot" : ""),
      tile("Oldest open critical/high", oldestCH == null ? "—" : dayText(oldestCH), "Since first seen"),
      tile("Median time to fix", f.time_to_fix.all.n ? dayText(f.time_to_fix.all.median) : "—", f.time_to_fix.all.n ? `${f.time_to_fix.all.n} with recorded fix time` : sm.remediation.fixed ? "Fix time unavailable" : "Nothing marked fixed yet"),
      tile("Scans", `${sc.completed} / ${sc.total}`, `completed${sc.incomplete ? ` · ${sc.incomplete} incomplete` : ""}${sc.verifications ? ` · ${sc.verifications} verification runs` : ""}`)),
    h("section", { class: "rpt-section rpt-two" },
      h("div", {}, h("h2", {}, "Open findings by severity"), sevBars(), remChips),
      h("div", {}, h("h2", {}, "Findings per scan"), r.trend.length ? [trendChart(r.trend),
        h("div", { class: "rpt-legend" }, SEVS.map((k) => h("span", {}, h("span", { class: `rpt-dot sev-${k}` }), SEV_TR[k])), h("span", { class: "inc" }, "✕ incomplete scan: not comparable"))]
        : h("p", { class: "rpt-empty" }, "No finished scans yet."))),
    ...(() => {
      const age = h("div", {}, h("h2", {}, "Remediation age"),
        h("p", { class: "rpt-src" }, "No deadlines (SLA) are set, so compliance isn't shown. Time is counted from first seen.", f.fixed_time_unknown ? ` ${f.fixed_time_unknown} fixed finding${f.fixed_time_unknown === 1 ? " has" : "s have"} no reliable fix time and ${f.fixed_time_unknown === 1 ? "is" : "are"} excluded.` : ""), ageTable);
      return kind === "targets"
        ? [h("section", { class: "rpt-section rpt-two even" }, age, h("div", {}, h("h2", {}, "Test coverage"), coverageBlock))]
        : [h("section", { class: "rpt-section" }, age), h("section", { class: "rpt-section" }, h("h2", {}, "Targets"), coverageBlock)];
    })(),
    h("section", { class: "rpt-section" }, h("h2", {}, `Open findings${f.top_open.length ? ` · top ${f.top_open.length}` : ""}`), topTable,
      f.open_more ? h("p", { class: "rpt-src" }, `${f.open_more} more open finding${f.open_more === 1 ? "" : "s"} not listed; see Skynet for the full list.`) : null),
    h("footer", { class: "rpt-notes" }, h("h3", {}, "How to read this report"), h("ul", {}, r.notes.map((n) => h("li", {}, n)))));
  sheet.querySelectorAll(".fill[data-w]").forEach((el) => { el.style.width = `${el.dataset.w}%`; });
  const title = `Skynet report - ${r.name} - ${dateFmt(r.generated_at, { year: "numeric", month: "2-digit", day: "2-digit" })}`;
  const print = () => {
    const prev = document.title; document.title = title;
    window.addEventListener("afterprint", () => { document.title = prev; }, { once: true });
    window.print();
  };
  app.replaceChildren(h("div", { class: "report-page" },
    h("div", { class: "report-toolbar" },
      h("a", { href: back, class: "crumb" }, icon("back"), kind === "targets" ? "Back to target" : "Back to campaign"),
      h("span", { class: "hint" }, "In the print dialog choose “Save as PDF”. A4, light theme."),
      button("Download PDF", { kind: "primary", ic: "download", onclick: print })),
    sheet));
}

// ================================================================== boot
(async () => {
  try { ME = await api("/api/me"); TZ = ME.timezone || TZ; } catch { /* redirected or offline */ }
  renderShell();
  router();
  refreshSystem();
  setInterval(refreshSystem, 15000);
})();
