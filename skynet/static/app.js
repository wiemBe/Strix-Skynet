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
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "html") el.innerHTML = v; // server-rendered markdown (raw HTML disabled) only
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, v === true ? "" : v);
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
const fmtTokens = (n) => !n ? "—" : n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? Math.round(n / 1e3) + "K" : String(n);
const modelShort = (m) => m ? m.replace(/^(openrouter|openai)\//, "") : "—";

const SEV = ["critical", "high", "medium", "low", "info"];
const SEV_TR = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const STATUS_TR = { queued: "Queued", running: "Running", stopping: "Stopping", completed: "Completed",
  failed: "Failed", cancelled: "Cancelled", interrupted: "Interrupted" };
const TRIGGER_TR = { manual: "Started manually", schedule: "Schedule", api: "CI / API", cli: "Strix TUI (imported)" };
const MODE_TR = { quick: "Quick", standard: "Standard", deep: "Deep" };
const OUTCOME_TR = { started: "Started", skipped_busy: "Skipped: target had an active scan", missed: "Missed: app was down", error: "Could not start" };
const KIND_TR = { once: "One-time", daily: "Daily", weekly: "Weekly", interval: "Hourly interval", cron: "Custom (cron)" };
const DAYS = [["mon", "Mon"], ["tue", "Tue"], ["wed", "Wed"], ["thu", "Thu"], ["fri", "Fri"], ["sat", "Sat"], ["sun", "Sun"]];
const ENV_TR = { development: "Development", test: "Test", staging: "Staging", production: "Production" };
const CAMP_STATUS_TR = { planned: "Planned", active: "Active", on_hold: "On hold", completed: "Completed" };
const KIND_ASSET_TR = { host: "Host", service: "Service", endpoint: "Endpoint", technology: "Technology" };
const SCOPE_TR = { in: "In scope", out: "Out of scope", unknown: "Unknown" };
const TIER_TR = { observed: "Observed", reported: "Agent-reported" };
const REMEDIATION_TR = { open: "Open", fixed: "Fixed", accepted: "Accepted", false_positive: "False positive" };
const AUTHKIND_TR = { anonymous: "Anonymous", credentials: "Username + password", header: "HTTP header", cookie: "Cookie" };
const VERIFY_TR = { verified: "Verified", failed: "Failed", not_configured: "No URL set", not_verifiable: "Not verifiable",
  not_applicable: "Not applicable", blocked: "Out of scope", not_checked: "Not checked" };

// ================================================================== components
function button(label, { kind = "", ic, onclick, disabled, title, size, type = "button" } = {}) {
  return h("button", { type, class: ["btn", kind, size, !label && ic ? "icon" : ""].filter(Boolean).join(" "), onclick, disabled, title, "aria-label": !label ? title : null },
    ic ? icon(ic) : null, label || null);
}
function errorHeadline(err) {
  if (!err) return "";
  const lines = err.split("\n").map((l) => l.trim()).filter(Boolean);
  return lines.find((l) => /^Error:/.test(l)) || lines.find((l) => /FAILED|Traceback|bulunamadı|çalışmıyor|silinmiş/.test(l)) || lines[lines.length > 1 ? 1 : 0];
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
  for (const it of items.filter(Boolean)) {
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
const field = (label, input, help) => h("div", { class: "field" }, h("label", {}, label), input, help ? h("div", { class: "help" }, help) : null);
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
const NAV = [["overview", "#/", "Overview"], ["targets", "#/targets", "Targets"], ["campaigns", "#/campaigns", "Campaigns"], ["scans", "#/scans", "Scans"], ["schedules", "#/schedules", "Schedules"], ["inventory", "#/inventory", "Inventory"], ["auth", "#/auth-profiles", "Auth profiles"], ["settings", "#/settings", "Settings"]];
$("#nav").replaceChildren(NAV.map(([k, href, label]) => h("a", { href, "data-nav": k }, icon(k), h("span", {}, label), k === "scans" ? h("span", { class: "badge-count", id: "activeCount" }) : null)));
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
      h("span", { class: "dot-bad" }), h("span", { class: "lbl" }, issues.length === 1 ? issues[0] : `${issues.length} system issues`)) : null);
    $("#activeCount").textContent = o.active.length ? String(o.active.length) : "";
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
    parts.push(running.length ? `${running.length} scan(s) running` : "No scans running right now");
    if (queued.length) parts.push(`${queued.length} scan(s) queued`);
    parts.push(problems.length ? `${problems.length} item(s) need attention` : "nothing needs attention");
    const lead = parts.join(", ") + "." + (next ? ` Next scan ${fmtShort(next.next_run_at)} (${next.target_name}).` : "");

    box.replaceChildren(
      pageHead("Overview", { lead, actions: [button("Create schedule", { ic: "schedules", onclick: () => go("#/schedules/new") }), button("New scan", { kind: "primary", ic: "plus", onclick: () => scanDialog(null) })] }),
      problems.length ? alertBox("danger", problems.length === 1 ? "1 item needs attention" : `${problems.length} items need attention`, null,
        h("ul", {}, problems.slice(0, 6).map((p) => h("li", {}, p)))) : null,
      h("div", { class: "stats" },
        h("div", { class: "stat" }, h("div", { class: "k" }, "Active scans"), h("div", { class: "v" }, running.length), h("div", { class: "s" }, `Concurrency limit ${o.max_concurrent}`)),
        h("div", { class: "stat" }, h("div", { class: "k" }, "Queued"), h("div", { class: "v" }, queued.length), h("div", { class: "s" }, queued.length ? "Waiting in line" : "Queue empty")),
        h("div", { class: "stat" + (crit ? " alert" : "") }, h("div", { class: "k" }, "Open critical / high findings"),
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
  return table([{ label: "Target" }, { label: "Schedule" }, { label: "When" }], list.map((u) => h("tr", { class: "clickable", onclick: () => go(`#/schedules/${u.id}`) },
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
    max_budget: h("input", { type: "number", min: "0", step: "any", value: init.max_budget ?? "", placeholder: "Unlimited" }),
    max_turns: h("input", { type: "number", min: "1", step: "1", value: init.max_turns ?? "", placeholder: "Strix default" }),
    fail_on: select([["", "No gate"], ...SEV.map((s) => [s, `${SEV_TR[s]} and above`])], init.fail_on ?? "high"),
  };
  const llmHelp = h("div", { class: "help" });
  const upd = () => {
    const p = profiles.find((x) => String(x.id) === f.llm_profile_id.value);
    llmHelp.textContent = !p ? "" : (p.provider === "openrouter" ? `Model: ${p.strix_model}. Scan content goes to an external provider via OpenRouter.` : `Model: ${p.strix_model}. Content goes to an in-house gateway (${p.base_url}).`) + " On error it does not switch to another connection.";
  };
  f.llm_profile_id.addEventListener("change", upd); upd();
  const fields = [
    h("div", { class: "field" }, h("label", {}, "LLM connection"), f.llm_profile_id, llmHelp),
    field("Scan mode", f.scan_mode),
    h("div", { class: "field-row limits" },
      field("Budget limit (USD)", f.max_budget),
      field("Turns per agent", f.max_turns),
      field("Finding gate", f.fail_on)),
    h("div", { class: "help" }, "Finding gate: if a finding at or above the selected level is found, the result becomes “Gate failed”; used to block a release in CI."),
  ];
  const value = () => ({ llm_profile_id: f.llm_profile_id.value, scan_mode: f.scan_mode.value, max_budget: f.max_budget.value || null, max_turns: f.max_turns.value || null, fail_on: f.fail_on.value });
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
          h("td", {}, t.next_run_at ? whenCell(t.next_run_at) : h("span", { class: "faint" }, "No schedule")),
          h("td", { class: "shrink right", onclick: (e) => e.stopPropagation() },
            button("Scan", { size: "sm", ic: "play", disabled: !!t.active_scan, title: t.active_scan ? "This target has an active scan" : "Scan this target now", onclick: () => scanDialog(t) })));
      }),
      emptyState("No targets yet", "Define the application to scan with its address, environment and scope. Then you can start an on-demand scan or schedule one.",
        [button("New target", { kind: "primary", ic: "plus", onclick: () => go("#/targets/new") })]))));
}

async function viewTarget(id) {
  const [t, schedules, scans, findings] = await Promise.all([api(`/api/targets/${id}`), api(`/api/schedules?target_id=${id}`), api(`/api/scans?target_id=${id}&limit=300`), api(`/api/targets/${id}/findings`)]);
  const del = guard(async () => {
    if (!await confirmDialog("Delete target?", `“${t.name}” and its ${schedules.length} schedule(s) will be deleted. Scan history and Strix report files are kept.`, { confirmLabel: "Delete target", danger: true })) return;
    await api(`/api/targets/${id}`, { method: "DELETE" }); toast("Target deleted"); go("#/targets");
  });
  app.replaceChildren(
    pageHead(t.name, {
      crumb: h("a", { href: "#/targets" }, "Targets"),
      meta: [envTag(t.environment), t.application ? h("span", {}, t.application) : null, h("span", { class: "mono" }, t.base_url)],
      actions: [
        menu([{ label: "Edit", icon: "edit", onclick: () => go(`#/targets/${id}/edit`) },
          { label: "View inventory", icon: "inventory", onclick: () => go(`#/inventory?target=${id}`) }, "-",
          { label: "Delete target", icon: "trash", danger: true, onclick: del }]),
        button("Add schedule", { ic: "schedules", onclick: () => go(`#/schedules/new?target=${id}`) }),
        button(t.active_scan ? "Scan in progress" : "Scan now", { kind: "primary", ic: "play", disabled: !!t.active_scan, onclick: () => scanDialog(t) })] }),
    t.active_scan ? alertBox("info", "This target has an active scan", ["Scan ", h("a", { href: `#/scans/${t.active_scan.id}` }, `#${t.active_scan.id}`), ` is ${STATUS_TR[t.active_scan.status].toLowerCase()}. Back-to-back scans on the same target aren't allowed.`]) : null,
    h("div", { class: "grid-main-side" },
      h("div", {},
        findings.summary && findings.summary.unique ? section("Findings (deduplicated)", findingsCard(findings.summary, id), { hint: `${findings.summary.unique} unique` }) : null,
        section("Scan history", h("div", { class: "table-card" }, scanTable(scans, { showTarget: false, empty: emptyState("This target hasn't been scanned yet", "Start the first scan to see its security posture.", [button("Scan now", { kind: "primary", ic: "play", onclick: () => scanDialog(t) })]) })), { hint: scans.length ? `${scans.length} record(s)` : null }),
        section("Schedules", h("div", { class: "table-card" }, scheduleTable(schedules, { showTarget: false, empty: emptyState("No schedules", "Plan recurring scans for this target.", [button("Add schedule", { onclick: () => go(`#/schedules/new?target=${id}`) })]) })))),
      h("div", {},
        section("Configuration", h("div", { class: "card card-pad" }, h("dl", { class: "dl stacked" },
          h("dt", {}, "Strix targets"), h("dd", { class: "mono" }, t.strix_targets.map((x) => h("div", {}, x))),
          h("dt", {}, "In scope"), h("dd", { class: t.in_scope.length ? "mono" : "faint" }, t.in_scope.length ? t.in_scope.map((x) => h("div", {}, x)) : "Not defined"),
          h("dt", {}, "Out of scope"), h("dd", { class: t.out_of_scope.length ? "mono" : "faint" }, t.out_of_scope.length ? t.out_of_scope.map((x) => h("div", {}, x)) : "Not defined"),
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
      actions: [menu([{ label: "Re-scan the strix_runs folder", icon: "refresh", onclick: guard(async () => { const r = await api("/api/import", { method: "POST" }); toast(`${r.imported} run(s) imported`); load(); }) }]),
        button("New scan", { kind: "primary", ic: "plus", onclick: () => scanDialog(null) })] }),
    h("div", { class: "toolbar" }, seg, h("span", { class: "grow" }), targetSel, search), box);
  await load();
  every(5000, load);
}

async function viewScan(id) {
  let scan = await api(`/api/scans/${id}`);
  let tab = ACTIVE.includes(scan.status) ? "log" : "findings";
  const headBox = h("div", {}), alertsBox = h("div", {}), factsBox = h("div", {}), tabsBox = h("div", { class: "tabs" }), body = h("div", {});
  const log = { source: "strix", offset: -1, box: null, level: "info", follow: null };
  let findingsCount = null;

  const renderHead = () => {
    const active = ACTIVE.includes(scan.status);
    const canResume = ["cancelled", "failed", "interrupted"].includes(scan.status) && scan.run_name && scan.target_id;
    const files = scan.files || {};
    const DL = [["report", "Rapor (Markdown)"], ["sarif", "SARIF"], ["json", "Bulgular (JSON)"], ["csv", "Bulgular (CSV)"], ["coverage", "Kapsam (coverage.json)"], ["log", "Strix logu"]].filter(([k]) => files[k]);
    headBox.replaceChildren(pageHead(scan.target_name || scan.name || `Scan #${scan.id}`, {
      crumb: h("a", { href: "#/scans" }, "Scans"),
      meta: [statusChip(scan.status), envTag(scan.environment || scan.target_environment), h("span", { class: "mono", title: (scan.targets || []).join("\n") }, (scan.targets || [])[0] || ""), h("span", { class: "faint" }, `#${scan.id}`)],
      actions: [
        !active ? menu([{ label: "Delete record", icon: "trash", danger: true, onclick: guard(async () => {
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
      fact("Tokens / requests", `${fmtTokens(sm.tokens || rm.tokens)} / ${sm.requests || rm.requests || "—"}`),
      fact("Finished", scan.finished_at ? fmtDateSec(scan.finished_at) : ACTIVE.includes(scan.status) ? "Ongoing" : "—"),
      fact("Output folder", h("span", { class: "mono" }, scan.run_name || "—"), scan.run_dir || "")));
  };

  const TABS = [["findings", "Findings"], ["log", "Live log"], ["agents", "Agents"], ["telemetry", "Telemetry"], ["report", "Report"], ["details", "Details"]];
  const renderTabs = () => tabsBox.replaceChildren(TABS.map(([k, l]) => h("button", { type: "button", class: tab === k ? "on" : null, onclick: () => { tab = k; renderTabs(); renderBody(); } },
    l, k === "findings" && findingsCount != null ? h("span", { class: "cnt" }, findingsCount) : null)));
  const renderAll = () => { renderHead(); renderAlerts(); renderFacts(); };

  const renderBody = guard(async () => {
    log.box = null;
    if (tab === "findings") body.replaceChildren(await findingsView());
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
    if (v.markdown_html) return h("div", { class: "finding-body" }, h("div", { class: "md", html: v.markdown_html }));
    return h("div", { class: "finding-body" },
      h("div", { class: "note" }, [v.target ? `Target: ${v.target}` : null, v.timestamp ? `Found: ${v.timestamp}` : null, v.confidence ? `Confidence: ${v.confidence}` : null, v.fix_effort ? `Fix effort: ${v.fix_effort}` : null].filter(Boolean).join(" · ")),
      sec("Description", v.description_html), sec("Impact", v.impact_html), sec("Technical analysis", v.technical_analysis_html),
      sec("Evidence", v.evidence_html), sec("Proof of concept (PoC)", v.poc_description_html),
      v.poc_script_code ? h("div", { class: "md" }, h("pre", {}, h("code", {}, v.poc_script_code))) : null,
      sec("Remediation", v.remediation_steps_html), sec("Assumptions", v.assumptions_html), sec("Counterevidence", v.counterevidence_html),
      v.cvss_breakdown ? [h("h4", {}, "CVSS breakdown"), h("dl", { class: "dl" }, Object.entries(v.cvss_breakdown).flatMap(([k, x]) => [h("dt", {}, k), h("dd", {}, x)]))] : null);
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
    const stMap = { running: "running", completed: "completed", failed: "failed" };
    const name = (aid) => (a.agents.find((y) => y.id === aid) || {}).name || aid;
    const byId = {}; ((tel.telemetry || {}).agents || []).forEach((g) => { byId[g.agent_id] = g; });
    return h("div", {}, h("div", { class: "note" }, Object.entries(a.counts).map(([k, n]) => `${n} ${k}`).join(" · ") + " · usage and tool counts from telemetry"),
      h("div", { class: "table-card" }, table([{ label: "Agent" }, { label: "Status" }, { label: "Requests" }, { label: "Tokens" }, { label: "Tool calls" }, { label: "Parent agent" }], a.agents.map((x) => {
        const g = byId[x.id] || {};
        const topTools = Object.entries(g.tools || {}).slice(0, 3).map(([t, n]) => `${t} ${n}`).join(", ");
        return h("tr", {},
          h("td", {}, h("div", { class: "primary-line" }, x.name), g.model ? h("div", { class: "secondary-line mono", title: g.model }, g.model) : null),
          h("td", {}, h("span", { class: `status ${stMap[x.status] || "cancelled"}` }, h("span", { class: "dot" }), x.status)),
          h("td", { class: "num" }, g.requests ?? "—"),
          h("td", { class: "num" }, g.tokens != null ? fmtTokens(g.tokens) : "—"),
          h("td", {}, g.tools_total ? h("div", {}, h("div", {}, g.tools_total), topTools ? h("div", { class: "secondary-line", title: topTools }, topTools) : null) : h("span", { class: "faint" }, "—")),
          h("td", { class: "muted" }, x.parent ? name(x.parent) : "—"));
      }), null)));
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
        stat("Failed requests", req.errors ?? h("span", {}, "0"), null, "Requests that ended with a model/provider error"),
        stat("Retries", ret.total || 0, ret.total ? `rate limit ${ret.rate_limit} · timeout ${ret.timeout} · connection ${ret.connection}` : "none"),
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
    return h("div", { class: "grid-2" },
      h("div", { class: "card card-pad" }, h("div", { class: "card-title" }, "Parameters"), h("dl", { class: "dl" },
        h("dt", {}, "Strix targets"), h("dd", { class: "mono" }, (scan.targets || []).map((t) => h("div", {}, t))),
        h("dt", {}, "Budget limit"), h("dd", {}, scan.max_budget ? `$${scan.max_budget}` : "Unlimited"),
        h("dt", {}, "Turns per agent"), h("dd", {}, scan.max_turns || "Strix default (500)"),
        h("dt", {}, "Finding gate"), h("dd", {}, scan.fail_on ? `${SEV_TR[scan.fail_on]} and above` : "Not defined"),
        h("dt", {}, "Resumed run"), h("dd", { class: scan.resume_run ? "mono" : "faint" }, scan.resume_run || "—"),
        h("dt", {}, "Strix exit code"), h("dd", {}, scan.exit_code ?? "—", scan.exit_code === 2 ? h("span", { class: "faint" }, " · findings found") : scan.exit_code === 1 ? h("span", { class: "faint" }, " · error or interruption") : null),
        h("dt", {}, "Output folder"), h("dd", { class: "mono" }, scan.run_dir || "—"),
        h("dt", {}, "Extra instructions"), h("dd", {}, scan.instruction ? h("pre", { class: "mono", style: null }, scan.instruction) : h("span", { class: "faint" }, "None")))),
      h("div", { class: "card card-pad" }, h("div", { class: "card-title" }, "Executive summary (Strix)"),
        scan.executive_summary_html ? h("div", { class: "md", html: scan.executive_summary_html }) : h("div", { class: "faint" }, "Strix did not write a summary for this run.")));
  }

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
  const cols = [...(showTarget ? [{ label: "Target" }] : []), { label: "Schedule" }, { label: "Next run" }, { label: "Last run" }, { label: "Status" }, { label: "", cls: "shrink" }];
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
        formSection("Schedule", "Choose when and on which target it runs.", [
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
async function viewSettings() {
  const [st, profiles] = await Promise.all([api("/api/settings"), api("/api/llm-profiles")]);
  const f = {
    strix_bin: h("input", { type: "text", value: st.strix_bin, class: "mono" }),
    strix_workdir: h("input", { type: "text", value: st.strix_workdir, class: "mono" }),
    max_concurrent: h("input", { type: "number", min: "1", max: "10", value: st.max_concurrent }),
    default_scan_mode: select([["quick", "Quick"], ["standard", "Standard"], ["deep", "Deep"]], st.default_scan_mode),
    telemetry: h("input", { type: "checkbox", checked: st.telemetry === "1" }),
    webhook_url: h("input", { type: "text", value: st.webhook_url, placeholder: "https://… (Teams or Slack incoming webhook)", class: "mono" }),
  };
  const saveRuntime = guard(async () => {
    await api("/api/settings", { method: "PUT", body: Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.type === "checkbox" ? el.checked : el.value])) });
    toast("Settings saved"); refreshSystem();
  });
  const pw = { current: h("input", { type: "password", autocomplete: "current-password" }), next: h("input", { type: "password", autocomplete: "new-password" }) };
  const llmRows = profiles.map((p) => h("tr", {},
    h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, p.name, p.is_default ? [" ", h("span", { class: "tag accent" }, "Default")] : null),
      h("div", { class: "secondary-line mono", title: p.strix_model }, p.strix_model))),
    h("td", {}, p.provider_label, h("div", { class: "secondary-line mono", title: p.base_url || "" }, p.base_url || "Provider default")),
    h("td", {}, p.has_api_key ? "Stored" : h("span", { class: "faint" }, "None")),
    h("td", {}, p.used_by_schedules ? `${p.used_by_schedules} schedule(s)` : h("span", { class: "faint" }, "—")),
    h("td", { class: "shrink right" }, h("div", { class: "actions" },
      button("Test", { size: "sm", onclick: guard(async () => {
        const r = await api("/api/llm-profiles/test", { method: "POST", body: { id: p.id, provider: p.provider, base_url: p.base_url, model: p.model, ca_cert_path: p.ca_cert_path } });
        toast((r.ok ? "Connection OK. " : "Connection failed. ") + r.message, !r.ok || r.model_found === false);
      }) }),
      menu([!p.is_default ? { label: "Make default", icon: "check", onclick: guard(async () => { await api(`/api/llm-profiles/${p.id}/default`, { method: "POST" }); router(); refreshSystem(); }) } : null,
        { label: "Edit", icon: "edit", onclick: () => llmDialog(p) }, "-",
        { label: "Delete", icon: "trash", danger: true, onclick: guard(async () => {
          if (!await confirmDialog("Delete LLM connection?", `“${p.name}” will be deleted. Deletion is blocked if it is used by schedules.`, { confirmLabel: "Delete", danger: true })) return;
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
    section("Strix runtime environment", h("form", { class: "card card-pad form", onsubmit: (e) => { e.preventDefault(); saveRuntime(); } },
      formSection("Strix", "Installed Strix CLI and output folder.", [
        field("Strix binary", f.strix_bin),
        field("Working folder", f.strix_workdir, "Strix writes output under <folder>/strix_runs/. Scans run with the TUI are also imported from here.")]),
      formSection("Execution", "Queue and defaults.", [
        h("div", { class: "field-row two" }, field("Concurrent scans", f.max_concurrent, "The rest wait in the queue. Only one scan runs on the same target at a time."), field("Default mode", f.default_scan_mode)),
        h("div", { class: "field" }, h("div", { class: "label" }, "Strix telemetry"), h("label", { class: "check" }, f.telemetry, "Telemetry on (STRIX_TELEMETRY=1)"),
          h("div", { class: "help" }, "Strix defaults to on; Skynet starts it off. Keeping it off in-house is recommended."))]),
      formSection("Notification", "A JSON payload is sent to the webhook when a scan finishes.", [field("Webhook URL", f.webhook_url)]),
      h("div", { class: "form-actions" }, button("Save", { kind: "primary", type: "submit" })))),
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
      section("Admin password", st.password_from_env
        ? h("div", { class: "card card-pad muted" }, "The password comes from the SKYNET_PASSWORD environment variable; update the server configuration to change it.")
        : h("form", { class: "card card-pad fields", onsubmit: guard(async (e) => {
          e.preventDefault();
          await api("/api/settings/password", { method: "POST", body: { current: pw.current.value, new: pw.next.value } });
          toast("Password changed. Please sign in again."); setTimeout(() => (location.href = "/login"), 1200);
        }) }, field("Current password", pw.current), field("New password", pw.next, "At least 10 characters."), h("div", {}, button("Change password", { type: "submit" }))))));
  app.querySelectorAll("pre.ci").forEach((p) => { p.style.margin = "14px 0"; p.style.color = "var(--text-2)"; });
  app.querySelectorAll(".section > div > .note").forEach((n) => { n.style.marginTop = "10px"; });
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
        button("New scan", { kind: "primary", ic: "play", onclick: () => scanDialog(null, { campaign_id: id, target_ids: c.target_ids }) })] }),
    c.description ? h("p", { class: "lead-text" }, c.description) : null,
    c.scope ? alertBox("info", "Engagement scope", c.scope) : null,
    h("div", { class: "stats" },
      h("div", { class: "stat" }, h("div", { class: "k" }, "Targets"), h("div", { class: "v" }, c.target_ids.length)),
      h("div", { class: "stat" + (fs.open_counts && (fs.open_counts.critical || fs.open_counts.high) ? " alert" : "") }, h("div", { class: "k" }, "Open critical / high"),
        h("div", { class: "v" }, fs.open_counts ? `${fs.open_counts.critical || 0} / ${fs.open_counts.high || 0}` : "—")),
      h("div", { class: "stat" }, h("div", { class: "k" }, "Unique findings"), h("div", { class: "v" }, fs.unique ?? "—"), fs.seen_after_fix ? h("div", { class: "s alert-text" }, `${fs.seen_after_fix} seen after fix`) : null),
      h("div", { class: "stat" }, h("div", { class: "k" }, "Scans"), h("div", { class: "v" }, c.scan_count), h("div", { class: "s" }, c.active_scans ? `${c.active_scans} active` : "all done"))),
    h("div", { class: "grid-main-side" },
      h("div", {},
        section("Findings", findingsCard(fs, scans.map((s) => s.id), id), { hint: fs.unique ? `${fs.unique} unique, ${fs.occurrences} occurrences` : null }),
        section("Scans", h("div", { class: "table-card" }, scanTable(scans, { empty: emptyState("No scans in this campaign", "Start a scan linked to the campaign.") }))),
        c.schedules && c.schedules.length ? section("Schedules", h("div", { class: "table-card" }, scheduleTable(c.schedules))) : null),
      h("div", {},
        section("Targets", h("div", { class: "card card-pad" }, c.targets.length ? h("ul", { class: "linklist" }, c.targets.map((t) => h("li", {},
          h("a", { href: `#/targets/${t.id}` }, t.name), " ", envTag(t.environment)))) : h("div", { class: "faint" }, "No targets added."))))));
}

// Compact findings summary card with a severity breakdown; links to the full findings table (campaign or target).
function findingsCard(fs, scanIds, campaignId) {
  if (!fs || !fs.unique) return h("div", { class: "card" }, emptyState("No findings", "No deduplicated findings in this scope. They are collected here as scans complete."));
  const openSev = fs.open_counts || {};
  return h("div", { class: "card card-pad" },
    h("div", { class: "sev-bars" }, SEV.map((s) => fs.counts[s] ? h("div", { class: "sev-bar" },
      h("span", { class: `sevpill ${s}` }, SEV_TR[s]), h("span", {}, `${fs.counts[s]} unique`), openSev[s] ? h("span", { class: "faint" }, `${openSev[s]} open`) : null) : null)),
    h("div", { class: "rem-row" }, Object.entries(fs.remediation || {}).map(([k, n]) => n ? h("span", { class: "tag" }, `${REMEDIATION_TR[k]}: ${n}`) : null)),
    h("div", { class: "actions mt" }, button("Review findings", { onclick: () => findingsDialog(scanIds, campaignId) })));
}

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
        h("td", { class: "nowrap muted" }, `${g.runs}× scans`),
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
    api(`/api/findings/${g.id}`).then((full) => {
      occ.replaceChildren(h("div", { class: "occ-list" }, (full.occurrences_list || []).map((o) => h("div", { class: "occ" },
        h("a", { href: `#/scans/${o.scan_id}` }, `#${o.scan_id}`), " ", h("span", { class: "mono" }, o.run_name), " ", h("span", { class: "faint" }, fmtShort(o.observed_at)), " ", h("span", { class: `sevpill ${o.severity}` }, SEV_TR[o.severity] || o.severity)))));
    }).catch(() => occ.replaceChildren(h("div", { class: "faint" }, "Could not load occurrences.")));
    return h("div", { class: "finding-body" },
      h("div", { class: "note" }, [g.cwe, g.host, `first: ${fmtShort(g.first_seen_at)}`, `last: ${fmtShort(g.last_seen_at)}`].filter(Boolean).join(" · ")),
      h("div", { class: "rem-edit" }, h("label", {}, "Remediation status"), remSel, note,
        button("Save", { size: "sm", kind: "primary", onclick: guard(async () => {
          await api(`/api/findings/${g.id}`, { method: "PATCH", body: { remediation: remSel.value, remediation_note: note.value } });
          g.remediation = remSel.value; g.remediation_note = note.value; toast("Updated"); render();
        }) })),
      h("h4", {}, "Occurrences"), occ);
  }
  render();
  const close = dialog("Deduplicated findings", groups.length ? body : emptyState("No findings", "No unique findings recorded in this scope."),
    [button("Close", { onclick: () => close() })], { wide: true });
}

// ================================================================== auth profiles (vault)
function verifyChip(p) {
  if (p.last_verify_ok === 1) return h("span", { class: "status completed", title: p.last_verify_note || "" }, h("span", { class: "dot" }), "Verified");
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
    const r = await api(`/api/auth-profiles/${p.id}`, { method: "DELETE" }); close(); toast(r.paused_schedules ? `Profile deleted, ${r.paused_schedules} schedule(s) paused` : "Profile deleted"); router();
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
      diff ? h("div", { class: "note" }, `Last scan (${diff.scan_mode || "?"}, ${diff.complete ? "complete" : "partial"}): ` +
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

// ================================================================== boot
(async () => {
  try { const st = await api("/api/settings"); TZ = st.timezone || TZ; } catch { /* redirected or offline */ }
  router();
  refreshSystem();
  setInterval(refreshSystem, 15000);
})();
