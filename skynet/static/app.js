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
  try { r = await fetch(path, init); } catch { throw new Error("Sunucuya ulaşılamıyor. Bağlantıyı kontrol edin."); }
  if (r.status === 401) { location.href = "/login"; throw new Error("Oturum sona erdi"); }
  let data = null;
  try { data = await r.json(); } catch { /* no body */ }
  if (!r.ok) {
    const d = data && data.detail;
    throw new Error(typeof d === "string" ? d : Array.isArray(d) ? d.map((x) => x.msg).join("; ") : `İstek başarısız (HTTP ${r.status})`);
  }
  return data;
}

function toast(msg, err = false) {
  const t = h("div", { class: "toast" + (err ? " err" : ""), role: "status" }, msg);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), err ? 8000 : 3500);
}
const guard = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, true); } };

// ================================================================== formatting
let TZ = "Europe/Istanbul";
const dateFmt = (iso, opts) => { if (!iso) return "—"; const d = new Date(iso); return isNaN(d) ? iso : d.toLocaleString("tr-TR", { timeZone: TZ, ...opts }); };
const fmtDate = (iso) => dateFmt(iso, { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
const fmtDateSec = (iso) => dateFmt(iso, { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
const fmtShort = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso), now = new Date();
  const sameDay = d.toLocaleDateString("tr-TR", { timeZone: TZ }) === now.toLocaleDateString("tr-TR", { timeZone: TZ });
  return sameDay ? "Bugün " + dateFmt(iso, { hour: "2-digit", minute: "2-digit" }) : dateFmt(iso, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
};
function relTime(iso) {
  if (!iso) return "";
  const s = (new Date(iso) - Date.now()) / 1000, a = Math.abs(s);
  const rtf = new Intl.RelativeTimeFormat("tr", { numeric: "auto" });
  if (a < 45) return s < 0 ? "az önce" : "birazdan";
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
  return hh ? `${hh} sa ${mm} dk` : mm ? `${mm} dk` : `${ss} sn`;
}
const fmtTokens = (n) => !n ? "—" : n >= 1e6 ? (n / 1e6).toFixed(1).replace(".", ",") + " M" : n >= 1e3 ? Math.round(n / 1e3) + " B" : String(n);
const modelShort = (m) => m ? m.replace(/^(openrouter|openai)\//, "") : "—";

const SEV = ["critical", "high", "medium", "low", "info"];
const SEV_TR = { critical: "Kritik", high: "Yüksek", medium: "Orta", low: "Düşük", info: "Bilgi" };
const STATUS_TR = { queued: "Kuyrukta", running: "Çalışıyor", stopping: "Durduruluyor", completed: "Tamamlandı",
  failed: "Başarısız", cancelled: "İptal edildi", interrupted: "Yarıda kaldı" };
const TRIGGER_TR = { manual: "Elle başlatıldı", schedule: "Zamanlama", api: "CI / API", cli: "Strix TUI (içe aktarıldı)" };
const MODE_TR = { quick: "Hızlı", standard: "Standart", deep: "Derin" };
const OUTCOME_TR = { started: "Başlatıldı", skipped_busy: "Atlandı: hedefte aktif tarama vardı", missed: "Kaçırıldı: uygulama kapalıydı", error: "Başlatılamadı" };
const KIND_TR = { once: "Tek seferlik", daily: "Günlük", weekly: "Haftalık", interval: "Saat aralıklı", cron: "Özel (cron)" };
const DAYS = [["mon", "Pzt"], ["tue", "Sal"], ["wed", "Çar"], ["thu", "Per"], ["fri", "Cum"], ["sat", "Cmt"], ["sun", "Paz"]];
const ENV_TR = { development: "Development", test: "Test", staging: "Staging", production: "Production" };

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
  if (scan.status === "running") sub = `Çalışma süresi: ${durationText(scan)}`;
  else if (scan.status === "queued") sub = "Sırasını bekliyor";
  else if (scan.status === "stopping") sub = "Süreç kapatılıyor";
  else if (scan.status === "failed" && scan.error) sub = errorHeadline(scan.error);
  return h("div", { class: "cell-clip" }, statusChip(scan.status), sub ? h("div", { class: "status-sub", title: scan.error || sub }, sub) : null);
}
const envTag = (e) => e ? h("span", { class: `env ${e}` }, ENV_TR[e] || e) : null;
function sevSummary(counts, { status, max = 3 } = {}) {
  if (!counts) return h("span", { class: "sevsum" }, h("span", { class: "none" }, ACTIVE.includes(status) ? "Henüz yok" : "—"));
  const items = SEV.filter((s) => counts[s]);
  if (!items.length) {
    const txt = ACTIVE.includes(status) ? "Henüz yok" : status && status !== "completed" ? "—" : "Bulgu yok";
    return h("span", { class: "sevsum", title: status && status !== "completed" && !ACTIVE.includes(status) ? "Tarama tamamlanmadı; sonuç eksik olabilir" : null }, h("span", { class: "none" }, txt));
  }
  const shown = items.slice(0, max), rest = items.slice(max).reduce((n, s) => n + counts[s], 0);
  return h("span", { class: "sevsum", title: items.map((s) => `${counts[s]} ${SEV_TR[s]}`).join(", ") },
    shown.map((s) => h("span", { class: "item" }, h("span", { class: `sq ${s}` }), h("span", { class: "n" }, counts[s]), SEV_TR[s].toLowerCase())),
    rest ? h("span", { class: "none" }, `+${rest}`) : null);
}
const VERDICT_HELP = "Bulgu eşiği: seçilen seviye veya üzerinde bulgu varsa sonuç 'Eşik aşıldı' olur. CI'da yayını durdurmak için kullanılır.";
function verdict(scan) {
  const g = scan && scan.summary && scan.summary.gate;
  if (!scan.fail_on) return h("span", { class: "verdict na" }, "Eşik tanımlı değil");
  if (!g || scan.status !== "completed") return h("span", { class: "verdict na", title: VERDICT_HELP }, `${SEV_TR[scan.fail_on]} ve üzeri · sonuç bekleniyor`);
  return h("span", { class: `verdict ${g}`, title: VERDICT_HELP }, icon(g === "pass" ? "check" : "alert"), g === "pass" ? "Eşik aşılmadı" : "Eşik aşıldı",
    h("span", { class: "faint" }, ` (${SEV_TR[scan.fail_on].toLowerCase()} ve üzeri)`));
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
function menu(items, { label = null, title = "Diğer işlemler" } = {}) {
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
    h("div", { class: "dlg-head" }, h("h3", {}, title), button(null, { ic: "plus", kind: "ghost", title: "Kapat", onclick: () => close() })),
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
function confirmDialog(title, desc, { confirmLabel = "Onayla", danger = false } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; close(); resolve(v); } };
    const close = dialog(title, h("div", { class: "muted" }, desc), [
      button("Vazgeç", { onclick: () => finish(false) }),
      button(confirmLabel, { kind: danger ? "danger-solid" : "primary", onclick: () => finish(true) })]);
    const obs = new MutationObserver(() => { if (!document.body.contains($(".dlg-bg"))) { obs.disconnect(); if (!done) { done = true; resolve(false); } } });
    obs.observe($("#dialogs"), { childList: true });
  });
}
const closeDialogs = () => $("#dialogs").replaceChildren();

// ================================================================== shell: navigation + system status
const NAV = [["overview", "#/", "Genel Bakış"], ["targets", "#/targets", "Hedefler"], ["scans", "#/scans", "Taramalar"], ["schedules", "#/schedules", "Zamanlamalar"], ["settings", "#/settings", "Ayarlar"]];
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
    if (!o.docker.ok) issues.push("Docker kapalı");
    if (!o.strix.ok) issues.push("Strix bulunamadı");
    if (!o.llm_default) issues.push("LLM bağlantısı yok");
    box.replaceChildren(issues.length ? h("a", { class: "sys-alert", href: "#/settings", title: issues.join("\n") },
      h("span", { class: "dot-bad" }), h("span", { class: "lbl" }, issues.length === 1 ? issues[0] : `${issues.length} sistem sorunu`)) : null);
    $("#activeCount").textContent = o.active.length ? String(o.active.length) : "";
    return o;
  } catch (e) {
    box.replaceChildren(h("div", { class: "sys-alert", title: e.message }, h("span", { class: "dot-bad" }), h("span", { class: "lbl" }, "Sunucuya ulaşılamıyor")));
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
    app.replaceChildren(h("div", { class: "loading" }, "Yükleniyor…"));
    try { await fn(...m.slice(1)); }
    catch (e) { app.replaceChildren(pageHead("Sayfa yüklenemedi"), alertBox("danger", "Veri alınamadı", e.message, h("div", { class: "actions" }, button("Tekrar dene", { ic: "refresh", onclick: router })))); }
    window.scrollTo(0, 0);
    return;
  }
  location.hash = "#/";
}
window.addEventListener("hashchange", router);
const go = (hash) => { location.hash = hash; };

// ================================================================== shared scan table
function scanTable(list, { empty, showTarget = true } = {}) {
  const cols = [...(showTarget ? [{ label: "Hedef" }] : []), { label: "Durum" }, { label: "Bulgular" }, { label: "Başlangıç" }, { label: "Süre" }, { label: "", cls: "shrink" }];
  return table(cols, list.map((s) => {
    const active = ACTIVE.includes(s.status);
    return h("tr", { class: "clickable", onclick: () => go(`#/scans/${s.id}`) },
      showTarget ? h("td", {}, h("div", { class: "cell-clip" },
        h("div", { class: "primary-line", title: s.target_name || s.name }, s.target_name || s.name || "Adsız"),
        h("div", { class: "secondary-line mono", title: (s.targets || []).join("\n") }, (s.targets || [])[0] || "—"))) : null,
      h("td", {}, statusCell(s)),
      h("td", {}, sevSummary((s.summary || {}).counts, { status: s.status })),
      h("td", {}, whenCell(s.started_at || s.created_at)),
      h("td", { class: "nowrap" }, s.status === "queued" ? h("span", { class: "faint" }, "—") : durationText(s)),
      h("td", { class: "shrink right", onclick: (e) => e.stopPropagation() },
        active && s.status !== "stopping" ? button(s.status === "queued" ? "Kuyruktan çıkar" : "Durdur", { kind: "danger", size: "sm", ic: "stop", onclick: () => stopScan(s, router) }) : null,
        !active ? h("a", { class: "btn ghost sm icon", href: `#/scans/${s.id}`, title: "Ayrıntılar", "aria-label": "Ayrıntılar" }, icon("chevron")) : null));
  }), empty || emptyState("Tarama yok", "Bir hedef seçip tarama başlattığınızda burada görünür."));
}
async function stopScan(s, after) {
  const queued = s.status === "queued";
  const ok = await confirmDialog(queued ? "Tarama kuyruktan çıkarılsın mı?" : "Tarama durdurulsun mu?",
    queued ? "Tarama henüz başlamadı; kuyruktan çıkarılıp iptal edildi olarak işaretlenir."
      : "Strix'e önce kesme sinyali gönderilir ve raporunu yazması beklenir. Yanıt vermezse süreç grubu sonlandırılır ve sandbox konteyneri temizlenir.",
    { confirmLabel: queued ? "Kuyruktan çıkar" : "Taramayı durdur", danger: true });
  if (!ok) return;
  try { await api(`/api/scans/${s.id}/cancel`, { method: "POST" }); toast(queued ? "Tarama kuyruktan çıkarıldı" : "Durdurma isteği gönderildi"); if (after) after(); }
  catch (e) { toast(e.message, true); }
}

// ================================================================== overview
async function viewOverview() {
  const [o, recent] = await Promise.all([refreshSystem(), api("/api/scans?status=completed,failed&limit=6")]);
  if (!o) throw new Error("Sistem durumu alınamadı.");
  const box = h("div", {});
  const render = (o, recent) => {
    const running = o.active.filter((s) => s.status !== "queued"), queued = o.active.filter((s) => s.status === "queued");
    const withScan = o.latest_by_target.filter((r) => r.scan);
    const crit = withScan.reduce((n, r) => n + (((r.scan.summary || {}).counts || {}).critical || 0), 0);
    const high = withScan.reduce((n, r) => n + (((r.scan.summary || {}).counts || {}).high || 0), 0);
    const next = o.upcoming[0];
    const problems = [];
    if (!o.docker.ok) problems.push([h("b", {}, "Docker çalışmıyor."), " Strix sandbox başlatamaz; yeni taramalar başarısız olur."]);
    if (!o.llm_default) problems.push([h("b", {}, "LLM bağlantısı yok."), " ", h("a", { href: "#/settings" }, "Ayarlar'dan ekleyin.")]);
    o.problems.forEach((s) => problems.push([h("a", { href: `#/scans/${s.id}` }, `${s.target_name || s.name}`), ` · tarama ${STATUS_TR[s.status].toLowerCase()} (${fmtShort(s.finished_at || s.created_at)})`, s.error ? h("span", { class: "faint" }, ` · ${errorHeadline(s.error).slice(0, 140)}`) : null]));
    o.schedule_problems.forEach((p) => problems.push([h("a", { href: `#/schedules/${p.id}` }, `${p.target_name} zamanlaması`), ` · ${OUTCOME_TR[p.last_outcome] || p.last_outcome}`, h("span", { class: "faint" }, ` · ${p.last_note || fmtShort(p.event_at)}`)]));

    const parts = [];
    parts.push(running.length ? `${running.length} tarama çalışıyor` : "Şu anda çalışan tarama yok");
    if (queued.length) parts.push(`${queued.length} tarama kuyrukta`);
    parts.push(problems.length ? `${problems.length} konu müdahale bekliyor` : "müdahale gerektiren bir durum yok");
    const lead = parts.join(", ") + "." + (next ? ` Sıradaki tarama ${fmtShort(next.next_run_at)} (${next.target_name}).` : "");

    box.replaceChildren(
      pageHead("Genel Bakış", { lead, actions: [button("Zamanlama oluştur", { ic: "schedules", onclick: () => go("#/schedules/new") }), button("Yeni tarama", { kind: "primary", ic: "plus", onclick: () => scanDialog(null) })] }),
      problems.length ? alertBox("danger", problems.length === 1 ? "Müdahale gereken 1 konu var" : `Müdahale gereken ${problems.length} konu var`, null,
        h("ul", {}, problems.slice(0, 6).map((p) => h("li", {}, p)))) : null,
      h("div", { class: "stats" },
        h("div", { class: "stat" }, h("div", { class: "k" }, "Aktif taramalar"), h("div", { class: "v" }, running.length), h("div", { class: "s" }, `Eşzamanlı limit ${o.max_concurrent}`)),
        h("div", { class: "stat" }, h("div", { class: "k" }, "Kuyruktakiler"), h("div", { class: "v" }, queued.length), h("div", { class: "s" }, queued.length ? "Sıra bekliyor" : "Kuyruk boş")),
        h("div", { class: "stat" + (crit ? " alert" : "") }, h("div", { class: "k" }, "Açık kritik / yüksek bulgu"),
          h("div", { class: "v" }, withScan.length ? `${crit} / ${high}` : "—"),
          h("div", { class: "s", title: "Her hedefin son tamamlanan taramasına göre" }, withScan.length ? "Hedeflerin son taramalarına göre" : "Henüz tamamlanmış tarama yok")),
        h("div", { class: "stat" }, h("div", { class: "k" }, "Sonraki tarama"),
          h("div", { class: "v sm" }, next ? fmtShort(next.next_run_at) : "Planlı tarama yok"),
          h("div", { class: "s", title: next ? next.target_name : "" }, next ? `${next.target_name} · ${relTime(next.next_run_at)}` : h("a", { href: "#/schedules/new" }, "Zamanlama oluştur")))),
      section("Devam eden taramalar", h("div", { class: "table-card" }, scanTable(o.active, {
        empty: emptyState("Şu anda devam eden tarama yok", "Bir hedef seçerek hemen tarama başlatabilir veya düzenli taramalar için zamanlama oluşturabilirsiniz.",
          [button("Yeni tarama", { kind: "primary", ic: "plus", onclick: () => scanDialog(null) })]) })),
      { hint: o.active.length ? "Strix yüzde bazlı ilerleme bildirmez; süre ve canlı bulgular gösterilir." : null }),
      h("div", { class: "grid-2 wide-left" },
        section("Son tamamlanan taramalar", h("div", { class: "table-card" }, recentTable(recent)), { right: h("a", { href: "#/scans" }, "Tümü") }),
        section("Yaklaşan zamanlamalar", h("div", { class: "table-card" }, upcomingTable(o.upcoming)), { right: h("a", { href: "#/schedules" }, "Tümü") })));
  };
  render(o, recent);
  app.replaceChildren(box);
  every(5000, guard(async () => {
    const [n, r] = await Promise.all([refreshSystem(), api("/api/scans?status=completed,failed&limit=6")]);
    if (n) render(n, r);
  }));
}
function recentTable(list) {
  return table([{ label: "Hedef" }, { label: "Sonuç" }, { label: "Bitiş" }], list.map((s) => h("tr", { class: "clickable", onclick: () => go(`#/scans/${s.id}`) },
    h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line", title: s.target_name || s.name }, s.target_name || s.name), h("div", { class: "secondary-line mono", title: (s.targets || [])[0] || "" }, (s.targets || [])[0] || ""))),
    h("td", {}, s.status === "completed" ? sevSummary((s.summary || {}).counts, { status: s.status, max: 2 }) : statusChip(s.status)),
    h("td", {}, whenCell(s.finished_at || s.started_at)))),
  emptyState("Henüz tamamlanan tarama yok", "İlk tarama bittiğinde sonuçları burada görünecek."));
}
function upcomingTable(list) {
  return table([{ label: "Hedef" }, { label: "Plan" }, { label: "Zaman" }], list.map((u) => h("tr", { class: "clickable", onclick: () => go(`#/schedules/${u.id}`) },
    h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, u.target_name), h("div", { class: "secondary-line" }, envTag(u.environment)))),
    h("td", { class: "muted" }, u.describe),
    h("td", {}, whenCell(u.next_run_at)))),
  emptyState("Etkin zamanlama yok", "Hedefleri düzenli taramak için bir plan oluşturun.", [button("Zamanlama oluştur", { onclick: () => go("#/schedules/new") })]));
}

// ================================================================== new scan dialog
function scanOptions(profiles, init) {
  const def = profiles.find((p) => p.is_default);
  const f = {
    llm_profile_id: select(profiles.map((p) => [String(p.id), `${p.name} — ${p.provider_label}${p.is_default ? " (varsayılan)" : ""}`]), String(init.llm_profile_id || (def && def.id) || "")),
    scan_mode: select([["quick", "Hızlı — CI kontrolleri için"], ["standard", "Standart — rutin test"], ["deep", "Derin — kapsamlı, uzun ve maliyetli"]], init.scan_mode || "standard"),
    max_budget: h("input", { type: "number", min: "0", step: "any", value: init.max_budget ?? "", placeholder: "Limitsiz" }),
    max_turns: h("input", { type: "number", min: "1", step: "1", value: init.max_turns ?? "", placeholder: "Strix varsayılanı" }),
    fail_on: select([["", "Eşik yok"], ...SEV.map((s) => [s, `${SEV_TR[s]} ve üzeri`])], init.fail_on ?? "high"),
  };
  const llmHelp = h("div", { class: "help" });
  const upd = () => {
    const p = profiles.find((x) => String(x.id) === f.llm_profile_id.value);
    llmHelp.textContent = !p ? "" : (p.provider === "openrouter" ? `Model: ${p.strix_model}. Tarama içeriği OpenRouter üzerinden dış sağlayıcıya gider.` : `Model: ${p.strix_model}. İçerik kurum içi gateway'e gider (${p.base_url}).`) + " Hata olursa başka bağlantıya geçilmez.";
  };
  f.llm_profile_id.addEventListener("change", upd); upd();
  const fields = [
    h("div", { class: "field" }, h("label", {}, "LLM bağlantısı"), f.llm_profile_id, llmHelp),
    field("Tarama modu", f.scan_mode),
    h("div", { class: "field-row limits" },
      field("Bütçe limiti (USD)", f.max_budget),
      field("Ajan başına tur", f.max_turns),
      field("Bulgu eşiği", f.fail_on)),
    h("div", { class: "help" }, "Bulgu eşiği: seçilen seviye veya üzerinde bulgu çıkarsa sonuç “Eşik aşıldı” olur; CI'da yayını durdurmak için kullanılır."),
  ];
  const value = () => ({ llm_profile_id: f.llm_profile_id.value, scan_mode: f.scan_mode.value, max_budget: f.max_budget.value || null, max_turns: f.max_turns.value || null, fail_on: f.fail_on.value });
  return { fields, value, f };
}

async function scanDialog(target) {
  const [profiles, targets] = await Promise.all([api("/api/llm-profiles"), target ? Promise.resolve(null) : api("/api/targets")]);
  if (!profiles.length) { toast("Önce Ayarlar > LLM bağlantıları bölümünden bir bağlantı ekleyin.", true); return; }
  if (!target && !targets.length) {
    const close = dialog("Yeni tarama", emptyState("Henüz hedef yok", "Tarama başlatmak için önce taranacak uygulamayı hedef olarak tanımlayın."),
      [button("Vazgeç", { onclick: () => close() }), button("Hedef oluştur", { kind: "primary", onclick: () => { close(); go("#/targets/new"); } })]);
    return;
  }
  let t = target || targets.find((x) => !x.active_scan) || targets[0];
  const targetSel = targets ? select(targets.map((x) => [String(x.id), `${x.name} · ${ENV_TR[x.environment]}${x.active_scan ? " (tarama sürüyor)" : ""}`]), String(t.id)) : null;
  const summary = h("div", { class: "target-summary" });
  const optsBox = h("div", { class: "fields" });
  const instruction = h("textarea", { rows: 3, placeholder: "Bu taramaya özel ek talimat (isteğe bağlı)" });
  const prodOk = h("input", { type: "checkbox" });
  const prodRow = h("label", { class: "check" }, prodOk, "Production ortamında aktif test yapılacağını biliyorum ve bu sistem için yetkiliyim.");
  let opts;
  const renderTarget = () => {
    summary.replaceChildren(h("div", { class: "primary-line" }, t.name, " ", envTag(t.environment)), h("div", { class: "mono faint" }, t.base_url),
      t.active_scan ? h("div", { class: "help", style: null }, "Bu hedefte zaten aktif bir tarama var; yenisi başlatılamaz.") : null);
    opts = scanOptions(profiles, { scan_mode: t.default_scan_mode, llm_profile_id: t.llm_profile_id, fail_on: "high" });
    optsBox.replaceChildren(opts.fields);
    prodRow.hidden = t.environment !== "production"; prodOk.checked = false;
  };
  if (targetSel) targetSel.addEventListener("change", () => { t = targets.find((x) => String(x.id) === targetSel.value); renderTarget(); });
  renderTarget();
  const close = dialog("Yeni tarama", [targetSel ? field("Hedef", targetSel) : null, summary, optsBox, field("Ek talimat", instruction), prodRow], [
    button("Vazgeç", { onclick: () => close() }),
    button("Taramayı başlat", { kind: "primary", ic: "play", onclick: guard(async () => {
      if (t.environment === "production" && !prodOk.checked) { toast("Production taraması için onay kutusunu işaretleyin.", true); return; }
      const s = await api(`/api/targets/${t.id}/scan`, { method: "POST", body: { ...opts.value(), instruction: instruction.value } });
      close(); toast("Tarama kuyruğa alındı"); go(`#/scans/${s.id}`);
    }) })], { wide: true });
}

// ================================================================== targets
async function viewTargets() {
  const list = await api("/api/targets");
  app.replaceChildren(
    pageHead("Hedefler", { lead: "Taranan uygulamalar, ortamları ve kapsamları.", actions: [button("Yeni hedef", { kind: "primary", ic: "plus", onclick: () => go("#/targets/new") })] }),
    h("div", { class: "table-card" }, table(
      [{ label: "Hedef" }, { label: "Ortam" }, { label: "Son tarama" }, { label: "Son bulgular" }, { label: "Sonraki tarama" }, { label: "", cls: "shrink" }],
      list.map((t) => {
        const ls = t.active_scan || t.last_scan;
        return h("tr", { class: "clickable", onclick: () => go(`#/targets/${t.id}`) },
          h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line", title: t.name }, t.name), h("div", { class: "secondary-line mono", title: t.base_url }, t.base_url))),
          h("td", {}, envTag(t.environment)),
          h("td", {}, ls ? h("div", {}, statusChip(ls.status), h("div", { class: "status-sub" }, fmtShort(ls.started_at || ls.created_at))) : h("span", { class: "faint" }, "Hiç taranmadı")),
          h("td", {}, t.last_scan ? sevSummary((t.last_scan.summary || {}).counts, { status: t.last_scan.status, max: 2 }) : h("span", { class: "faint" }, "—")),
          h("td", {}, t.next_run_at ? whenCell(t.next_run_at) : h("span", { class: "faint" }, "Plan yok")),
          h("td", { class: "shrink right", onclick: (e) => e.stopPropagation() },
            button("Tara", { size: "sm", ic: "play", disabled: !!t.active_scan, title: t.active_scan ? "Bu hedefte aktif tarama var" : "Bu hedefi şimdi tara", onclick: () => scanDialog(t) })));
      }),
      emptyState("Henüz hedef yok", "Taranacak uygulamayı adresi, ortamı ve kapsamıyla tanımlayın. Ardından anlık tarama başlatabilir veya zamanlayabilirsiniz.",
        [button("Yeni hedef", { kind: "primary", ic: "plus", onclick: () => go("#/targets/new") })]))));
}

async function viewTarget(id) {
  const [t, schedules, scans] = await Promise.all([api(`/api/targets/${id}`), api(`/api/schedules?target_id=${id}`), api(`/api/scans?target_id=${id}&limit=300`)]);
  const authTr = { none: "Yok", credentials: "Kullanıcı adı ve şifre", header: "HTTP başlığı (token)" };
  const del = guard(async () => {
    if (!await confirmDialog("Hedef silinsin mi?", `“${t.name}” ve bağlı ${schedules.length} zamanlama silinir. Tarama geçmişi ve Strix rapor dosyaları korunur.`, { confirmLabel: "Hedefi sil", danger: true })) return;
    await api(`/api/targets/${id}`, { method: "DELETE" }); toast("Hedef silindi"); go("#/targets");
  });
  app.replaceChildren(
    pageHead(t.name, {
      crumb: h("a", { href: "#/targets" }, "Hedefler"),
      meta: [envTag(t.environment), t.application ? h("span", {}, t.application) : null, h("span", { class: "mono" }, t.base_url)],
      actions: [
        menu([{ label: "Düzenle", icon: "edit", onclick: () => go(`#/targets/${id}/edit`) }, "-", { label: "Hedefi sil", icon: "trash", danger: true, onclick: del }]),
        button("Zamanlama ekle", { ic: "schedules", onclick: () => go(`#/schedules/new?target=${id}`) }),
        button(t.active_scan ? "Tarama sürüyor" : "Şimdi tara", { kind: "primary", ic: "play", disabled: !!t.active_scan, onclick: () => scanDialog(t) })] }),
    t.active_scan ? alertBox("info", "Bu hedefte aktif bir tarama var", ["Tarama ", h("a", { href: `#/scans/${t.active_scan.id}` }, `#${t.active_scan.id}`), ` ${STATUS_TR[t.active_scan.status].toLowerCase()}. Aynı hedefte üst üste tarama başlatılmaz.`]) : null,
    h("div", { class: "grid-main-side" },
      h("div", {},
        section("Tarama geçmişi", h("div", { class: "table-card" }, scanTable(scans, { showTarget: false, empty: emptyState("Bu hedef henüz taranmadı", "İlk taramayı başlatarak güvenlik durumunu görün.", [button("Şimdi tara", { kind: "primary", ic: "play", onclick: () => scanDialog(t) })]) })), { hint: scans.length ? `${scans.length} kayıt` : null }),
        section("Zamanlamalar", h("div", { class: "table-card" }, scheduleTable(schedules, { showTarget: false, empty: emptyState("Zamanlama yok", "Bu hedef için düzenli tarama planlayın.", [button("Zamanlama ekle", { onclick: () => go(`#/schedules/new?target=${id}`) })]) })))),
      h("div", {},
        section("Yapılandırma", h("div", { class: "card card-pad" }, h("dl", { class: "dl stacked" },
          h("dt", {}, "Strix hedefleri"), h("dd", { class: "mono" }, t.strix_targets.map((x) => h("div", {}, x))),
          h("dt", {}, "Kapsam içi"), h("dd", { class: t.in_scope.length ? "mono" : "faint" }, t.in_scope.length ? t.in_scope.map((x) => h("div", {}, x)) : "Tanımlı değil"),
          h("dt", {}, "Kapsam dışı"), h("dd", { class: t.out_of_scope.length ? "mono" : "faint" }, t.out_of_scope.length ? t.out_of_scope.map((x) => h("div", {}, x)) : "Tanımlı değil"),
          h("dt", {}, "Kimlik doğrulama"), h("dd", {}, authTr[t.auth_type], t.has_auth_secret ? h("div", { class: "faint" }, "Gizli değer şifreli kayıtlı") : null),
          h("dt", {}, "Varsayılan mod"), h("dd", {}, MODE_TR[t.default_scan_mode])))),
        section("Strix'e iletilecek talimat", h("div", { class: "card card-pad" },
          h("div", { class: "note", style: null }, "Strix'te ayrı kapsam veya kimlik doğrulama seçeneği yoktur; bu bilgiler talimat dosyasıyla iletilir ve seçilen LLM sağlayıcısına gider. Gizli değerler burada maskelenir."),
          h("pre", { class: "mono", style: null }, t.instruction_preview))))));
  app.querySelectorAll(".card pre").forEach((p) => { p.style.whiteSpace = "pre-wrap"; p.style.margin = "12px 0 0"; p.style.color = "var(--text-2)"; });
}

async function viewTargetForm(id) {
  const [t, profiles] = await Promise.all([id ? api(`/api/targets/${id}`) : null, api("/api/llm-profiles")]);
  const v = t || { environment: "test", auth_type: "none", default_scan_mode: "standard", in_scope: [], out_of_scope: [], extra_targets: [] };
  const f = {
    name: h("input", { type: "text", value: v.name || "", placeholder: "Örn. Mobil Bankacılık API" }),
    application: h("input", { type: "text", value: v.application || "", placeholder: "Proje veya uygulama adı" }),
    environment: select(Object.entries(ENV_TR), v.environment),
    base_url: h("input", { type: "text", value: v.base_url || "", placeholder: "https://staging.uygulama.local", class: "mono" }),
    extra_targets: h("textarea", { rows: 2, value: (v.extra_targets || []).join("\n"), placeholder: "https://github.com/kurum/repo\n./openapi.yaml" }),
    in_scope: h("textarea", { rows: 3, value: (v.in_scope || []).join("\n"), placeholder: "staging.uygulama.local\napi.staging.uygulama.local" }),
    out_of_scope: h("textarea", { rows: 3, value: (v.out_of_scope || []).join("\n"), placeholder: "/admin/delete\nodeme.uygulama.local" }),
    instruction: h("textarea", { rows: 4, value: v.instruction || "", placeholder: "Örn. Kimlik doğrulama, IDOR ve iş mantığı hatalarına odaklan." }),
    auth_type: select([["none", "Yok"], ["credentials", "Kullanıcı adı ve şifre"], ["header", "HTTP başlığı (token)"]], v.auth_type),
    auth_login_url: h("input", { type: "text", value: v.auth_login_url || "", placeholder: "https://staging.uygulama.local/login", class: "mono" }),
    auth_username: h("input", { type: "text", value: v.auth_username || "", autocomplete: "off" }),
    auth_header_name: h("input", { type: "text", value: v.auth_header_name || "", placeholder: "Authorization" }),
    auth_secret: h("input", { type: "password", value: "", autocomplete: "new-password", placeholder: v.has_auth_secret ? "Kayıtlı — değiştirmek için yeni değer girin" : "" }),
    auth_notes: h("textarea", { rows: 2, value: v.auth_notes || "", placeholder: "Örn. OTP için test numarası kullanılır." }),
    default_scan_mode: select([["quick", "Hızlı"], ["standard", "Standart"], ["deep", "Derin"]], v.default_scan_mode),
    llm_profile_id: select([["", "Varsayılan bağlantı"], ...profiles.map((p) => [String(p.id), `${p.name} — ${p.provider_label}`])], v.llm_profile_id ? String(v.llm_profile_id) : ""),
  };
  const authBlocks = {
    login: field("Giriş adresi", f.auth_login_url), user: field("Kullanıcı adı", f.auth_username), header: field("Başlık adı", f.auth_header_name),
    secret: field("Şifre / token", f.auth_secret, "Sunucuda şifreli saklanır, tarayıcıya geri gönderilmez."), notes: field("Notlar", f.auth_notes),
  };
  const syncAuth = () => {
    const a = f.auth_type.value;
    authBlocks.login.hidden = authBlocks.secret.hidden = authBlocks.notes.hidden = a === "none";
    authBlocks.user.hidden = a !== "credentials"; authBlocks.header.hidden = a !== "header";
    authBlocks.secret.querySelector("label").textContent = a === "header" ? "Başlık değeri (token)" : "Şifre";
  };
  f.auth_type.addEventListener("change", syncAuth);
  const save = guard(async () => {
    const body = Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.value]));
    if (!body.auth_secret) delete body.auth_secret;
    const r = await api(id ? `/api/targets/${id}` : "/api/targets", { method: id ? "PUT" : "POST", body });
    toast("Hedef kaydedildi"); go(`#/targets/${r.id}`);
  });
  app.replaceChildren(
    pageHead(id ? "Hedefi düzenle" : "Yeni hedef", { crumb: id ? h("a", { href: `#/targets/${id}` }, v.name) : h("a", { href: "#/targets" }, "Hedefler") }),
    h("form", { class: "card card-pad form", onsubmit: (e) => { e.preventDefault(); save(); } },
      formSection("Genel", "Taranacak uygulamayı ve ortamını tanımlayın.", [
        field("Hedef adı", f.name), field("Uygulama / proje", f.application),
        field("Ortam", f.environment, "Production hedeflerde tarama başlatılmadan önce ayrıca onay istenir."),
        field("Hedef adresi", f.base_url, "Strix'e hedef olarak verilir: URL, alan adı, IP, git deposu veya yerel klasör."),
        field("Ek hedefler", f.extra_targets, "İsteğe bağlı, her satıra bir tane: kaynak kod deposu, OpenAPI/Postman dosyası veya ek host.")]),
      formSection("Kapsam", "Strix'te teknik kapsam kısıtı yoktur; bu liste talimat olarak iletilir ve ajanların uyması istenir.", [
        field("Kapsam içi", f.in_scope, "Her satıra bir host veya URL."), field("Kapsam dışı", f.out_of_scope, "Trafik gönderilmemesi gereken host, URL veya yollar.")]),
      formSection("Kimlik doğrulama", "Yalnızca test hesabı kullanın. Bilgiler tarama sırasında talimat olarak Strix'e ve seçilen LLM sağlayıcısına iletilir.", [
        field("Yöntem", f.auth_type), authBlocks.login, authBlocks.user, authBlocks.header, authBlocks.secret, authBlocks.notes]),
      formSection("Varsayılanlar", "Tarama başlatırken değiştirilebilir.", [
        field("Tarama talimatı", f.instruction, "Strix talimat dosyasına eklenir."),
        h("div", { class: "field-row two" }, field("Varsayılan mod", f.default_scan_mode), field("LLM bağlantısı", f.llm_profile_id))]),
      h("div", { class: "form-actions" }, button("Vazgeç", { onclick: () => history.back() }), button("Kaydet", { kind: "primary", type: "submit" }))));
  syncAuth();
}

// ================================================================== scans
async function viewScans() {
  const targets = await api("/api/targets");
  const st = { tab: "all", target: "", q: "", limit: 50 };
  const TABS = [["all", "Tümü", ""], ["active", "Aktif", "queued,running,stopping"], ["completed", "Tamamlanan", "completed"], ["failed", "Başarısız", "failed"], ["stopped", "İptal / yarıda", "cancelled,interrupted"]];
  const seg = h("div", { class: "seg" });
  const targetSel = select([["", "Tüm hedefler"], ...targets.map((t) => [String(t.id), t.name])], "");
  const search = h("input", { type: "search", placeholder: "Hedef, adres veya çalıştırma adı ara" });
  const box = h("div", { class: "table-card" }, h("div", { class: "loading" }, "Yükleniyor…"));
  const renderSeg = () => seg.replaceChildren(TABS.map(([k, l]) => h("button", { type: "button", class: st.tab === k ? "on" : null, onclick: () => { st.tab = k; st.limit = 50; renderSeg(); load(); } }, l)));
  targetSel.addEventListener("change", () => { st.target = targetSel.value; st.limit = 50; load(); });
  let qt; search.addEventListener("input", () => { clearTimeout(qt); qt = setTimeout(() => { st.q = search.value.trim().toLowerCase(); st.limit = 50; load(); }, 200); });
  const load = guard(async () => {
    const status = TABS.find((x) => x[0] === st.tab)[2];
    let list = await api(`/api/scans?limit=1000${status ? "&status=" + status : ""}${st.target ? "&target_id=" + st.target : ""}`);
    if (st.q) list = list.filter((s) => [s.target_name, s.name, s.run_name, ...(s.targets || [])].join(" ").toLowerCase().includes(st.q));
    const shown = list.slice(0, st.limit);
    box.replaceChildren(scanTable(shown, { empty: emptyState(st.q || st.target || status ? "Filtreye uyan tarama yok" : "Henüz tarama yok", st.q || st.target || status ? "Filtreleri değiştirmeyi deneyin." : "Bir hedef seçip tarama başlattığınızda burada görünür.") }),
      list.length > 0 ? h("div", { class: "table-foot" }, h("span", {}, `${list.length} taramadan ${shown.length} tanesi gösteriliyor`),
        list.length > shown.length ? button("Daha fazla göster", { size: "sm", onclick: () => { st.limit += 50; load(); } }) : null) : null);
  });
  renderSeg();
  app.replaceChildren(
    pageHead("Taramalar", { lead: "Elle, zamanlamayla, CI'dan veya Strix TUI'den başlatılan tüm çalıştırmalar.",
      actions: [menu([{ label: "strix_runs klasörünü yeniden tara", icon: "refresh", onclick: guard(async () => { const r = await api("/api/import", { method: "POST" }); toast(`${r.imported} çalıştırma içe aktarıldı`); load(); }) }]),
        button("Yeni tarama", { kind: "primary", ic: "plus", onclick: () => scanDialog(null) })] }),
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
    headBox.replaceChildren(pageHead(scan.target_name || scan.name || `Tarama #${scan.id}`, {
      crumb: h("a", { href: "#/scans" }, "Taramalar"),
      meta: [statusChip(scan.status), envTag(scan.environment || scan.target_environment), h("span", { class: "mono", title: (scan.targets || []).join("\n") }, (scan.targets || [])[0] || ""), h("span", { class: "faint" }, `#${scan.id}`)],
      actions: [
        !active ? menu([{ label: "Kaydı sil", icon: "trash", danger: true, onclick: guard(async () => {
          if (!await confirmDialog("Tarama kaydı silinsin mi?", "Kayıt listeden kaldırılır. Diskteki Strix çıktı klasörü silinmez.", { confirmLabel: "Kaydı sil", danger: true })) return;
          await api(`/api/scans/${id}`, { method: "DELETE" }); go("#/scans");
        }) }]) : null,
        DL.length ? menu(DL.map(([k, l]) => ({ label: l, icon: "download", onclick: () => { location.href = `/api/scans/${id}/download/${k}`; } })), { label: "İndir" }) : null,
        canResume ? button("Kaldığı yerden devam et", { ic: "play", title: "strix --resume ile aynı çalıştırmayı sürdürür", onclick: guard(async () => { const n = await api(`/api/scans/${id}/resume`, { method: "POST" }); go(`#/scans/${n.id}`); }) }) : null,
        scan.target_id && !active ? button("Yeniden tara", { onclick: guard(async () => { const t = await api(`/api/targets/${scan.target_id}`); scanDialog(t); }) }) : null,
        active ? button(scan.status === "stopping" ? "Durduruluyor…" : scan.status === "queued" ? "Kuyruktan çıkar" : "Taramayı durdur", { kind: "danger", ic: "stop", disabled: scan.status === "stopping", onclick: () => stopScan(scan, async () => { scan = await api(`/api/scans/${id}`); renderAll(); }) }) : null] }));
  };

  const renderAlerts = () => {
    alertsBox.replaceChildren(
      scan.error ? alertBox(scan.status === "failed" ? "danger" : "warn", scan.status === "failed" ? "Tarama başarısız oldu" : "Not", null, h("pre", { class: "mono" }, scan.error)) : null,
      scan.trigger === "cli" ? alertBox("info", "Strix TUI'den içe aktarılan çalıştırma", "Kullanılan model Strix logundan okundu. LLM bağlantısı ve bulgu eşiği bilgisi yok.") : null);
  };

  const renderFacts = () => {
    const sm = scan.summary || {}, rm = scan.run_meta || {};
    const cost = sm.cost || rm.cost;
    const fact = (k, v, title) => h("div", { title }, h("div", { class: "k" }, k), h("div", { class: "v" }, v));
    factsBox.replaceChildren(h("div", { class: "facts" },
      fact("Bulgular", sevSummary(sm.counts, { status: scan.status, max: 5 })),
      fact("Bulgu eşiği", verdict(scan), VERDICT_HELP),
      fact("Başlangıç", fmtDateSec(scan.started_at)),
      fact("Süre", ACTIVE.includes(scan.status) && scan.status !== "queued" ? `${durationText(scan)} (sürüyor)` : durationText(scan)),
      fact("Model", h("span", { class: "mono" }, scan.model || "—")),
      fact("LLM bağlantısı", scan.llm_profile_name ? `${scan.llm_profile_name} · ${scan.llm_provider === "litellm" ? "LiteLLM" : "OpenRouter"}` : "—"),
      fact("Tarama modu", MODE_TR[scan.scan_mode] || scan.scan_mode || "—"),
      fact("Başlatan", TRIGGER_TR[scan.trigger] || scan.trigger),
      fact("LLM maliyeti", cost ? `$${Number(cost) < 0.01 ? Number(cost).toFixed(4) : Number(cost).toFixed(2)}` : h("span", { class: "faint" }, "Strix bildirmedi"), cost ? null : "Strix model fiyatını bilmediğinde maliyeti 0 yazar"),
      fact("Token / istek", `${fmtTokens(sm.tokens || rm.tokens)} / ${sm.requests || rm.requests || "—"}`),
      fact("Bitiş", scan.finished_at ? fmtDateSec(scan.finished_at) : ACTIVE.includes(scan.status) ? "Sürüyor" : "—"),
      fact("Çıktı klasörü", h("span", { class: "mono" }, scan.run_name || "—"), scan.run_dir || "")));
  };

  const TABS = [["findings", "Bulgular"], ["log", "Canlı log"], ["agents", "Ajanlar"], ["report", "Rapor"], ["details", "Ayrıntılar"]];
  const renderTabs = () => tabsBox.replaceChildren(TABS.map(([k, l]) => h("button", { type: "button", class: tab === k ? "on" : null, onclick: () => { tab = k; renderTabs(); renderBody(); } },
    l, k === "findings" && findingsCount != null ? h("span", { class: "cnt" }, findingsCount) : null)));
  const renderAll = () => { renderHead(); renderAlerts(); renderFacts(); };

  const renderBody = guard(async () => {
    log.box = null;
    if (tab === "findings") body.replaceChildren(await findingsView());
    else if (tab === "log") body.replaceChildren(logView());
    else if (tab === "agents") body.replaceChildren(await agentsView());
    else if (tab === "report") {
      const r = await api(`/api/scans/${id}/report`);
      body.replaceChildren(r.available ? h("div", { class: "card card-pad" }, h("div", { class: "md report", html: r.html }))
        : h("div", { class: "card" }, emptyState("Rapor yok", ACTIVE.includes(scan.status) ? "Strix raporu tarama sonunda yazar." : "Strix bu çalıştırma için rapor dosyası oluşturmadı.")));
    } else body.replaceChildren(detailsView());
  });

  async function findingsView() {
    const r = await api(`/api/scans/${id}/findings`);
    findingsCount = r.items.length; renderTabs();
    if (!r.items.length) return h("div", { class: "card" }, emptyState(
      ACTIVE.includes(scan.status) ? "Henüz bulgu raporlanmadı" : scan.status === "completed" ? "Strix bu taramada bulgu raporlamadı" : "Bulgu yok",
      ACTIVE.includes(scan.status) ? "Strix doğruladığı bulguları tarama sürerken yazar; bu liste otomatik güncellenir." : scan.status === "completed" ? "Bu, hedefin güvenli olduğunu garanti etmez; tarama kapsamı ve modunu Ayrıntılar sekmesinde görebilirsiniz." : "Tarama tamamlanmadığı için sonuç eksik olabilir."));
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
    tbody.querySelectorAll(".cell-clip").forEach((c) => { c.style.maxWidth = "min(900px, 60vw)"; });
    return h("div", {},
      r.source === "vulnerabilities/*.md" ? alertBox("info", "Ön bulgular", "Tarama sürerken Strix'in yazdığı tekil bulgu dosyalarından okunuyor. Nihai liste tarama bitince oluşur.") : null,
      h("div", { class: "table-card" }, h("div", { class: "table-scroll" }, h("table", { class: "t" },
        h("thead", {}, h("tr", {}, ["Önem", "Bulgu", "CVSS", "CWE", ""].map((c) => h("th", {}, c)))), tbody))),
      r.source === "vulnerabilities.json" ? h("div", { class: "note", style: null }, "Kaynak: Strix vulnerabilities.json. Satıra tıklayarak ayrıntıları açın.") : null);
  }

  function findingDetail(v) {
    const sec = (t, html) => html ? [h("h4", {}, t), h("div", { class: "md", html })] : null;
    if (v.markdown_html) return h("div", { class: "finding-body" }, h("div", { class: "md", html: v.markdown_html }));
    return h("div", { class: "finding-body" },
      h("div", { class: "note" }, [v.target ? `Hedef: ${v.target}` : null, v.timestamp ? `Bulunma: ${v.timestamp}` : null, v.confidence ? `Güven: ${v.confidence}` : null, v.fix_effort ? `Düzeltme eforu: ${v.fix_effort}` : null].filter(Boolean).join(" · ")),
      sec("Açıklama", v.description_html), sec("Etki", v.impact_html), sec("Teknik analiz", v.technical_analysis_html),
      sec("Kanıt", v.evidence_html), sec("Kavram kanıtı (PoC)", v.poc_description_html),
      v.poc_script_code ? h("div", { class: "md" }, h("pre", {}, h("code", {}, v.poc_script_code))) : null,
      sec("Düzeltme önerisi", v.remediation_steps_html), sec("Varsayımlar", v.assumptions_html), sec("Karşı kanıt", v.counterevidence_html),
      v.cvss_breakdown ? [h("h4", {}, "CVSS kırılımı"), h("dl", { class: "dl" }, Object.entries(v.cvss_breakdown).flatMap(([k, x]) => [h("dt", {}, k), h("dd", {}, x)]))] : null);
  }

  function logView() {
    const box = h("div", { class: "logbox", role: "log", "aria-live": "off" });
    log.box = box; log.offset = -1;
    const src = select([["strix", "Strix logu"], ["process", "Süreç çıktısı"]], log.source);
    const lvl = select([["all", "Tüm satırlar"], ["info", "DEBUG gizli"], ["warn", "Uyarı ve hatalar"]], log.level);
    const follow = h("input", { type: "checkbox", checked: true });
    log.follow = follow;
    [src, lvl].forEach((s) => s.addEventListener("change", () => { log.source = src.value; log.level = lvl.value; log.offset = -1; box.replaceChildren(); pollLog(); }));
    pollLog();
    return h("div", { class: "log-card" }, h("div", { class: "log-toolbar" }, src, lvl, h("label", { class: "check" }, follow, "Sona kaydır"),
      h("span", { class: "note" }, "Strix yüzde bazlı ilerleme bildirmez; ilerleme log ve ajan durumlarından izlenir.")), box);
  }
  const pollLog = guard(async () => {
    const box = log.box;
    if (!box) return;
    const r = await api(`/api/scans/${id}/log?source=${log.source}&offset=${log.offset}`);
    if (!r.available) {
      if (!box.childNodes.length) box.append(h("span", { class: "d" }, scan.status === "queued" ? "Tarama kuyrukta bekliyor.\n" : log.source === "strix" ? "Strix logu henüz oluşmadı; sandbox hazırlanıyor olabilir.\n" : "Süreç çıktısı yok.\n"));
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
    const a = await api(`/api/scans/${id}/agents`);
    if (!a.agents.length) return h("div", { class: "card" }, emptyState("Ajan bilgisi yok", "Strix ajan durumlarını tarama başladıktan sonra yazar."));
    const stMap = { running: "running", completed: "completed", failed: "failed" };
    const name = (aid) => (a.agents.find((y) => y.id === aid) || {}).name || aid;
    return h("div", {}, h("div", { class: "note", style: null }, Object.entries(a.counts).map(([k, n]) => `${n} ${k}`).join(" · ")),
      h("div", { class: "table-card" }, table([{ label: "Ajan" }, { label: "Durum" }, { label: "Üst ajan" }], a.agents.map((x) => h("tr", {},
        h("td", {}, h("div", { class: "primary-line" }, x.name)),
        h("td", {}, h("span", { class: `status ${stMap[x.status] || "cancelled"}` }, h("span", { class: "dot" }), x.status)),
        h("td", { class: "muted" }, x.parent ? name(x.parent) : "—"))), null)));
  }

  function detailsView() {
    return h("div", { class: "grid-2" },
      h("div", { class: "card card-pad" }, h("div", { class: "card-title" }, "Parametreler"), h("dl", { class: "dl" },
        h("dt", {}, "Strix hedefleri"), h("dd", { class: "mono" }, (scan.targets || []).map((t) => h("div", {}, t))),
        h("dt", {}, "Bütçe limiti"), h("dd", {}, scan.max_budget ? `$${scan.max_budget}` : "Limitsiz"),
        h("dt", {}, "Ajan başına tur"), h("dd", {}, scan.max_turns || "Strix varsayılanı (500)"),
        h("dt", {}, "Bulgu eşiği"), h("dd", {}, scan.fail_on ? `${SEV_TR[scan.fail_on]} ve üzeri` : "Tanımlı değil"),
        h("dt", {}, "Devam edilen çalıştırma"), h("dd", { class: scan.resume_run ? "mono" : "faint" }, scan.resume_run || "—"),
        h("dt", {}, "Strix çıkış kodu"), h("dd", {}, scan.exit_code ?? "—", scan.exit_code === 2 ? h("span", { class: "faint" }, " · bulgu bulundu") : scan.exit_code === 1 ? h("span", { class: "faint" }, " · hata veya kesinti") : null),
        h("dt", {}, "Çıktı klasörü"), h("dd", { class: "mono" }, scan.run_dir || "—"),
        h("dt", {}, "Ek talimat"), h("dd", {}, scan.instruction ? h("pre", { class: "mono", style: null }, scan.instruction) : h("span", { class: "faint" }, "Yok")))),
      h("div", { class: "card card-pad" }, h("div", { class: "card-title" }, "Yönetici özeti (Strix)"),
        scan.executive_summary_html ? h("div", { class: "md", html: scan.executive_summary_html }) : h("div", { class: "faint" }, "Strix bu çalıştırma için özet yazmadı.")));
  }

  renderAll(); renderTabs();
  app.replaceChildren(headBox, alertsBox, factsBox, tabsBox, body);
  await renderBody();
  every(3000, guard(async () => {
    const wasActive = ACTIVE.includes(scan.status);
    if (wasActive) {
      scan = await api(`/api/scans/${id}`);
      renderAll();
      if (!ACTIVE.includes(scan.status)) { toast(`Tarama ${STATUS_TR[scan.status].toLowerCase()}`); if (tab !== "log") renderBody(); }
      else if (tab === "findings" || tab === "agents") renderBody();
    }
    if (log.box) pollLog();
  }));
}

// ================================================================== schedules
function scheduleTable(list, { showTarget = true, empty } = {}) {
  const cols = [...(showTarget ? [{ label: "Hedef" }] : []), { label: "Plan" }, { label: "Sonraki çalışma" }, { label: "Son çalışma" }, { label: "Durum" }, { label: "", cls: "shrink" }];
  return table(cols, list.map((s) => {
    const done = !s.enabled && s.kind === "once" && s.last_outcome;
    const last = s.last_scan && s.last_outcome === "started"
      ? h("div", {}, statusChip(s.last_scan.status), h("div", { class: "status-sub" }, fmtShort(s.last_run_at)))
      : s.last_outcome ? h("div", { class: "cell-clip" }, h("span", { class: "status failed" }, h("span", { class: "dot" }), s.last_outcome === "missed" ? "Kaçırıldı" : s.last_outcome === "skipped_busy" ? "Atlandı" : "Başlatılamadı"), h("div", { class: "status-sub", title: s.last_note || "" }, OUTCOME_TR[s.last_outcome]))
        : h("span", { class: "faint" }, "Henüz çalışmadı");
    return h("tr", { class: "clickable", onclick: () => go(`#/schedules/${s.id}`) },
      showTarget ? h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, s.target_name), h("div", { class: "secondary-line" }, envTag(s.environment)))) : null,
      h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, s.name || KIND_TR[s.kind]), h("div", { class: "secondary-line" }, s.describe + (s.timezone !== TZ ? ` · ${s.timezone}` : "")))),
      h("td", {}, s.enabled && s.next_run_at ? whenCell(s.next_run_at) : h("span", { class: "faint" }, "—")),
      h("td", {}, last),
      h("td", {}, h("span", { class: `status ${s.enabled ? "active" : "paused"}` }, h("span", { class: "dot" }), s.enabled ? "Etkin" : done ? "Tamamlandı" : "Duraklatıldı"),
        !s.llm_profile_name ? h("div", { class: "status-sub" }, "LLM bağlantısı silinmiş") : null),
      h("td", { class: "shrink right", onclick: (e) => e.stopPropagation() },
        button(showTarget ? (s.enabled ? "Duraklat" : "Etkinleştir") : null, { size: "sm", ic: s.enabled ? "pause" : "play", title: s.enabled ? "Duraklat" : "Etkinleştir", disabled: done, onclick: guard(async () => {
          await api(`/api/schedules/${s.id}/${s.enabled ? "pause" : "resume"}`, { method: "POST" });
          toast(s.enabled ? "Zamanlama duraklatıldı" : "Zamanlama etkinleştirildi"); router();
        }) })));
  }), empty || emptyState("Zamanlama yok", "Hedefleri düzenli taramak için bir plan oluşturun.", [button("Zamanlama oluştur", { kind: "primary", ic: "plus", onclick: () => go("#/schedules/new") })]));
}

async function viewSchedules() {
  const list = await api("/api/schedules");
  app.replaceChildren(
    pageHead("Zamanlamalar", { lead: `Tekrarlayan ve ileri tarihli taramalar. Saat dilimi: ${TZ}.`, actions: [button("Zamanlama oluştur", { kind: "primary", ic: "plus", onclick: () => go("#/schedules/new") })] }),
    alertBox("info", "Zamanlamalar nasıl çalışır?", "Uygulama kapalıyken zamanı geçen çalıştırmalar sonradan başlatılmaz, “Kaçırıldı” olarak kaydedilir. Hedefte aktif tarama varken gelen çalıştırma atlanır. Başarısız taramalar otomatik olarak tekrarlanmaz."),
    h("div", { class: "table-card" }, scheduleTable(list)));
}

async function viewScheduleForm(id, presetTarget) {
  const [s, targets, profiles] = await Promise.all([id ? api(`/api/schedules/${id}`) : null, api("/api/targets"), api("/api/llm-profiles")]);
  if (!targets.length || !profiles.length) {
    app.replaceChildren(pageHead("Zamanlama oluştur", { crumb: h("a", { href: "#/schedules" }, "Zamanlamalar") }), h("div", { class: "card" },
      !targets.length ? emptyState("Önce bir hedef oluşturun", "Zamanlama bir hedefe bağlıdır.", [button("Yeni hedef", { kind: "primary", onclick: () => go("#/targets/new") })])
        : emptyState("LLM bağlantısı yok", "Taramalar için bir LLM bağlantısı gerekir.", [button("Ayarlara git", { kind: "primary", onclick: () => go("#/settings") })])));
    return;
  }
  const v = s || { kind: "weekly", time_of_day: "02:00", weekdays: ["mon"], timezone: TZ, enabled: 1, target_id: presetTarget || targets[0].id, fail_on: "high" };
  const tgt0 = targets.find((t) => t.id === v.target_id) || targets[0];
  let kind = v.kind;
  const f = {
    target_id: select(targets.map((t) => [String(t.id), `${t.name} · ${ENV_TR[t.environment]}`]), String(v.target_id)),
    name: h("input", { type: "text", value: v.name || "", placeholder: "Örn. Haftalık staging taraması" }),
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
  const kindSeg = h("div", { class: "seg" });
  const kf = {
    once: field("Tarih ve saat", f.run_at), time: field("Saat", f.time_of_day), days: h("div", { class: "field" }, h("div", { class: "label" }, "Günler"), daySeg),
    interval: field("Kaç saatte bir", f.interval_hours, "İlk çalışma kayıttan bir dakika sonra yapılır, ardından bu aralıkla devam eder."),
    cron: field("Cron ifadesi", f.cron_expr, "Beş alanlı standart cron: dakika saat gün ay haftanın-günü."),
  };
  const renderKind = () => {
    kindSeg.replaceChildren(Object.entries(KIND_TR).map(([k, l]) => h("button", { type: "button", class: kind === k ? "on" : null, onclick: () => { kind = k; renderKind(); preview(); } }, l)));
    kf.once.hidden = kind !== "once"; kf.time.hidden = !["daily", "weekly"].includes(kind); kf.days.hidden = kind !== "weekly";
    kf.interval.hidden = kind !== "interval"; kf.cron.hidden = kind !== "cron";
  };
  const nextBox = h("div", {});
  const collect = () => ({ target_id: f.target_id.value, name: f.name.value, kind, run_at: f.run_at.value, time_of_day: f.time_of_day.value,
    weekdays: [...days], interval_hours: f.interval_hours.value, cron_expr: f.cron_expr.value, timezone: f.timezone.value, enabled: f.enabled.checked, ...opts.value() });
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
    toast("Zamanlama kaydedildi"); if (id) router(); else go(`#/schedules/${r.id}`);
  });
  app.replaceChildren(
    pageHead(id ? (s.name || `${KIND_TR[s.kind]} zamanlama`) : "Zamanlama oluştur", {
      crumb: h("a", { href: "#/schedules" }, "Zamanlamalar"),
      meta: id ? [h("span", { class: `status ${s.enabled ? "active" : "paused"}` }, h("span", { class: "dot" }), s.enabled ? "Etkin" : "Duraklatıldı"), h("span", {}, s.target_name), envTag(s.environment)] : null,
      actions: id ? [
        menu([{ label: "Zamanlamayı sil", icon: "trash", danger: true, onclick: guard(async () => {
          if (!await confirmDialog("Zamanlama silinsin mi?", "Plan ve geçmişi silinir. Bu plandan başlatılmış taramalar korunur.", { confirmLabel: "Zamanlamayı sil", danger: true })) return;
          await api(`/api/schedules/${id}`, { method: "DELETE" }); go("#/schedules");
        }) }]),
        button(s.enabled ? "Duraklat" : "Etkinleştir", { ic: s.enabled ? "pause" : "play", onclick: guard(async () => { await api(`/api/schedules/${id}/${s.enabled ? "pause" : "resume"}`, { method: "POST" }); router(); }) })] : null }),
    h("div", { class: "grid-main-side" },
      h("form", { class: "card card-pad form", onsubmit: (e) => { e.preventDefault(); save(); } },
        formSection("Plan", "Ne zaman ve hangi hedefte çalışacağını seçin.", [
          field("Hedef", f.target_id), field("Ad (isteğe bağlı)", f.name),
          h("div", { class: "field" }, h("div", { class: "label" }, "Tekrar"), kindSeg),
          kf.once, kf.time, kf.days, kf.interval, kf.cron,
          h("div", { class: "field-row two" }, field("Saat dilimi", f.timezone, "IANA adı, varsayılan Europe/Istanbul."), h("div", { class: "field" }, h("div", { class: "label" }, "Durum"), h("label", { class: "check" }, f.enabled, "Kaydedince etkin olsun")))]),
        formSection("Tarama ayarları", "Her çalıştırmada bu ayarlar kullanılır. LLM bağlantısı sabittir; hata durumunda başka bağlantıya geçilmez.", opts.fields),
        h("div", { class: "form-actions" }, button("Vazgeç", { onclick: () => history.back() }), button("Kaydet", { kind: "primary", type: "submit" }))),
      h("div", {},
        h("div", { class: "card card-pad" }, h("div", { class: "card-title" }, "Sonraki 5 çalışma"), nextBox),
        id ? h("div", { class: "card card-pad" }, h("div", { class: "card-title" }, "Plan geçmişi"),
          s.events.length ? h("ol", { class: "events" }, s.events.map((e) => h("li", {},
            h("div", {}, OUTCOME_TR[e.outcome] || e.outcome, e.scan_id ? [" · ", h("a", { href: `#/scans/${e.scan_id}` }, `tarama #${e.scan_id}`)] : null),
            h("div", { class: "faint" }, fmtDate(e.at)), e.note && e.outcome !== "started" ? h("div", { class: "faint" }, e.note) : null)))
            : h("div", { class: "faint" }, "Bu plan henüz tetiklenmedi.")) : null)));
  [opts.f.llm_profile_id, opts.f.scan_mode, f.target_id].forEach((el) => el.addEventListener("change", preview));
  renderKind(); preview();
}

// ================================================================== settings
async function viewSettings() {
  const [st, profiles] = await Promise.all([api("/api/settings"), api("/api/llm-profiles")]);
  const f = {
    strix_bin: h("input", { type: "text", value: st.strix_bin, class: "mono" }),
    strix_workdir: h("input", { type: "text", value: st.strix_workdir, class: "mono" }),
    max_concurrent: h("input", { type: "number", min: "1", max: "10", value: st.max_concurrent }),
    default_scan_mode: select([["quick", "Hızlı"], ["standard", "Standart"], ["deep", "Derin"]], st.default_scan_mode),
    telemetry: h("input", { type: "checkbox", checked: st.telemetry === "1" }),
    webhook_url: h("input", { type: "text", value: st.webhook_url, placeholder: "https://… (Teams veya Slack gelen webhook)", class: "mono" }),
  };
  const saveRuntime = guard(async () => {
    await api("/api/settings", { method: "PUT", body: Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.type === "checkbox" ? el.checked : el.value])) });
    toast("Ayarlar kaydedildi"); refreshSystem();
  });
  const pw = { current: h("input", { type: "password", autocomplete: "current-password" }), next: h("input", { type: "password", autocomplete: "new-password" }) };
  const llmRows = profiles.map((p) => h("tr", {},
    h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, p.name, p.is_default ? [" ", h("span", { class: "tag accent" }, "Varsayılan")] : null),
      h("div", { class: "secondary-line mono", title: p.strix_model }, p.strix_model))),
    h("td", {}, p.provider_label, h("div", { class: "secondary-line mono", title: p.base_url || "" }, p.base_url || "Sağlayıcı varsayılanı")),
    h("td", {}, p.has_api_key ? "Kayıtlı" : h("span", { class: "faint" }, "Yok")),
    h("td", {}, p.used_by_schedules ? `${p.used_by_schedules} zamanlama` : h("span", { class: "faint" }, "—")),
    h("td", { class: "shrink right" }, h("div", { class: "actions" },
      button("Test et", { size: "sm", onclick: guard(async () => {
        const r = await api("/api/llm-profiles/test", { method: "POST", body: { id: p.id, provider: p.provider, base_url: p.base_url, model: p.model, ca_cert_path: p.ca_cert_path } });
        toast((r.ok ? "Bağlantı başarılı. " : "Bağlantı başarısız. ") + r.message, !r.ok || r.model_found === false);
      }) }),
      menu([!p.is_default ? { label: "Varsayılan yap", icon: "check", onclick: guard(async () => { await api(`/api/llm-profiles/${p.id}/default`, { method: "POST" }); router(); refreshSystem(); }) } : null,
        { label: "Düzenle", icon: "edit", onclick: () => llmDialog(p) }, "-",
        { label: "Sil", icon: "trash", danger: true, onclick: guard(async () => {
          if (!await confirmDialog("LLM bağlantısı silinsin mi?", `“${p.name}” silinir. Zamanlamalarda kullanılıyorsa silme engellenir.`, { confirmLabel: "Sil", danger: true })) return;
          await api(`/api/llm-profiles/${p.id}`, { method: "DELETE" }); router(); refreshSystem();
        }) }])))));
  const o = lastOverview || await api("/api/overview");
  const d = o.llm_default;
  const health = (ok, name, value, detail) => h("div", { class: "health" },
    h("div", { class: "health-head" }, h("span", { class: ok ? "dot-ok" : "dot-bad" }), h("span", { class: "name" }, name)),
    h("div", { class: "value" }, value), detail ? h("div", { class: "detail mono", title: detail }, detail) : null);
  app.replaceChildren(
    pageHead("Ayarlar", { lead: "Sistem durumu, LLM bağlantıları, Strix çalışma ortamı ve entegrasyonlar." }),
    section("Sistem durumu", h("div", { class: "health-grid" },
      health(o.docker.ok, "Docker", o.docker.ok ? "Çalışıyor" : "Erişilemiyor", o.docker.ok ? `Engine ${o.docker.version}` : (o.docker.error || "").slice(0, 160)),
      health(o.strix.ok, "Strix", o.strix.ok ? o.strix.version : "Bulunamadı", st.strix_bin),
      health(!!d, "Varsayılan LLM", d ? `${d.name} · ${d.provider_label}` : "Tanımlı değil", d ? d.strix_model : null),
      health(true, "Zamanlama", `Saat dilimi ${o.timezone}`, `Strix telemetrisi ${o.telemetry ? "açık" : "kapalı"} · eşzamanlı limit ${o.max_concurrent}`))),
    section("LLM bağlantıları", h("div", {},
      h("div", { class: "table-card" }, table([{ label: "Bağlantı" }, { label: "Sağlayıcı" }, { label: "API anahtarı" }, { label: "Kullanım" }, { label: "", cls: "shrink" }], llmRows,
        emptyState("LLM bağlantısı yok", "Taramalar için OpenRouter veya kurum içi LiteLLM bağlantısı ekleyin.", [button("Bağlantı ekle", { kind: "primary", ic: "plus", onclick: () => llmDialog(null) })]))),
      h("div", { class: "note", style: null }, "Bağlantılar Strix'e STRIX_LLM, LLM_API_KEY ve LLM_API_BASE ortam değişkenleriyle iletilir. API anahtarları sunucuda şifreli saklanır ve tarayıcıya gönderilmez.")),
    { right: button("Bağlantı ekle", { ic: "plus", size: "sm", onclick: () => llmDialog(null) }) }),
    section("Strix çalışma ortamı", h("form", { class: "card card-pad form", onsubmit: (e) => { e.preventDefault(); saveRuntime(); } },
      formSection("Strix", "Kurulu Strix CLI ve çıktı klasörü.", [
        field("Strix binary", f.strix_bin),
        field("Çalışma klasörü", f.strix_workdir, "Strix çıktıları <klasör>/strix_runs/ altına yazar. TUI ile yapılan taramalar da buradan içe aktarılır.")]),
      formSection("Çalıştırma", "Kuyruk ve varsayılanlar.", [
        h("div", { class: "field-row two" }, field("Eşzamanlı tarama", f.max_concurrent, "Fazlası kuyrukta bekler. Aynı hedefte aynı anda tek tarama çalışır."), field("Varsayılan mod", f.default_scan_mode)),
        h("div", { class: "field" }, h("div", { class: "label" }, "Strix telemetrisi"), h("label", { class: "check" }, f.telemetry, "Telemetri açık (STRIX_TELEMETRY=1)"),
          h("div", { class: "help" }, "Strix'in varsayılanı açıktır; Skynet kapalı başlatır. Kurum içinde kapalı tutulması önerilir."))]),
      formSection("Bildirim", "Tarama bittiğinde webhook'a JSON gönderilir.", [field("Webhook URL", f.webhook_url)]),
      h("div", { class: "form-actions" }, button("Kaydet", { kind: "primary", type: "submit" })))),
    h("div", { class: "grid-2" },
      section("CI / pipeline erişimi", h("div", { class: "card card-pad" },
        h("div", { class: "muted" }, "Prod öncesi pipeline'dan tarama başlatmak için X-API-Token başlığı kullanılır. Token yalnızca oluşturulduğu anda gösterilir."),
        h("pre", { class: "mono ci" }, "POST /api/ci/targets/<hedef_id>/scan\nGET  /api/ci/scans/<tarama_id>\n     → status, finished, gate (pass | fail)"),
        button(st.has_api_token ? "Token'ı yenile" : "Token oluştur", { onclick: guard(async () => {
          if (st.has_api_token && !await confirmDialog("Token yenilensin mi?", "Eski token hemen geçersiz olur; onu kullanan pipeline'lar güncellenmelidir.", { confirmLabel: "Yenile", danger: true })) return;
          const r = await api("/api/settings/api-token", { method: "POST" });
          const inp = h("input", { type: "text", value: r.api_token, readonly: true, class: "mono" });
          dialog("Yeni CI token", [alertBox("warn", "Bu değer bir daha gösterilmeyecek", "CI sistemindeki gizli değişkene kaydedin."), inp],
            [button("Kopyala", { kind: "primary", onclick: guard(async () => { await navigator.clipboard.writeText(r.api_token); toast("Kopyalandı"); }) })]);
          inp.select(); st.has_api_token = true;
        }) }))),
      section("Yönetici şifresi", st.password_from_env
        ? h("div", { class: "card card-pad muted" }, "Şifre SKYNET_PASSWORD ortam değişkeninden geliyor; değiştirmek için sunucu yapılandırmasını güncelleyin.")
        : h("form", { class: "card card-pad fields", onsubmit: guard(async (e) => {
          e.preventDefault();
          await api("/api/settings/password", { method: "POST", body: { current: pw.current.value, new: pw.next.value } });
          toast("Şifre değişti. Yeniden giriş yapın."); setTimeout(() => (location.href = "/login"), 1200);
        }) }, field("Mevcut şifre", pw.current), field("Yeni şifre", pw.next, "En az 10 karakter."), h("div", {}, button("Şifreyi değiştir", { type: "submit" }))))));
  app.querySelectorAll("pre.ci").forEach((p) => { p.style.margin = "14px 0"; p.style.color = "var(--text-2)"; });
  app.querySelectorAll(".section > div > .note").forEach((n) => { n.style.marginTop = "10px"; });
}

function llmDialog(p) {
  const v = p || { provider: "openrouter", api_type: "", reasoning_effort: "" };
  const f = {
    name: h("input", { type: "text", value: v.name || "", placeholder: "Örn. OpenRouter – DeepSeek" }),
    provider: select([["openrouter", "OpenRouter"], ["litellm", "LiteLLM (kurum içi gateway)"]], v.provider),
    base_url: h("input", { type: "text", value: v.base_url || "", class: "mono" }),
    api_key: h("input", { type: "password", value: "", autocomplete: "new-password", placeholder: v.has_api_key ? "Kayıtlı — değiştirmek için yeni anahtar girin" : "" }),
    model: h("input", { type: "text", value: v.model || "", class: "mono", list: "modelList" }),
    api_type: select([["", "Strix varsayılanı"], ["chat_completions", "chat_completions"], ["responses", "responses"]], v.api_type),
    reasoning_effort: select([["", "Strix varsayılanı"], ...["none", "minimal", "low", "medium", "high", "xhigh", "max"].map((x) => [x, x])], v.reasoning_effort),
    ca_cert_path: h("input", { type: "text", value: v.ca_cert_path || "", class: "mono", placeholder: "/etc/ssl/kurum-ca.pem" }),
    is_default: h("input", { type: "checkbox", checked: !!v.is_default }),
  };
  const dl = h("datalist", { id: "modelList" });
  const providerHelp = h("div", { class: "help" }), modelHelp = h("div", { class: "help" });
  const testOut = h("div", {});
  const sync = () => {
    const lit = f.provider.value === "litellm";
    f.base_url.placeholder = lit ? "http://litellm.kurum.local:4000" : "Boş bırakın (https://openrouter.ai/api/v1)";
    f.model.placeholder = lit ? "gateway'deki model adı" : "deepseek/deepseek-v4.1-flash-1017";
    providerHelp.textContent = lit ? "Strix'e openai/<model> ve LLM_API_BASE olarak verilir (OpenAI uyumlu gateway yöntemi). Gateway yalnızca chat completions destekliyorsa API tipini chat_completions seçin." : "Strix'e openrouter/<sağlayıcı>/<model> olarak verilir.";
    modelHelp.textContent = `Strix'e giden değer: ${lit ? "openai/" : "openrouter/"}${f.model.value.replace(/^(openai|openrouter)\//, "") || "<model>"}`;
  };
  f.provider.addEventListener("change", sync); f.model.addEventListener("input", sync); sync();
  const body = () => ({ id: p && p.id, ...Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.type === "checkbox" ? el.checked : el.value])) });
  const close = dialog(p ? "LLM bağlantısını düzenle" : "Yeni LLM bağlantısı", [
    h("div", { class: "field-row two" }, field("Bağlantı adı", f.name), h("div", { class: "field" }, h("label", {}, "Sağlayıcı"), f.provider)),
    providerHelp,
    field("Base URL", f.base_url),
    field("API anahtarı", f.api_key, "Şifreli saklanır; kaydedildikten sonra görüntülenemez. LiteLLM'de genellikle virtual key; gateway anahtar istemiyorsa boş bırakılabilir."),
    h("div", { class: "field" }, h("label", {}, "Model"), f.model, dl, modelHelp),
    h("div", { class: "field-row two" }, field("API tipi", f.api_type), field("Reasoning effort", f.reasoning_effort)),
    field("Özel CA sertifikası", f.ca_cert_path, "Kurum içi TLS için; Strix'e SSL_CERT_FILE olarak verilir."),
    h("label", { class: "check" }, f.is_default, "Varsayılan bağlantı yap"),
    testOut], [
    button("Bağlantıyı test et", { onclick: guard(async () => {
      testOut.replaceChildren(h("div", { class: "faint" }, "Test ediliyor…"));
      const r = await api("/api/llm-profiles/test", { method: "POST", body: body() });
      dl.replaceChildren(r.models.map((m) => h("option", { value: m })));
      testOut.replaceChildren(alertBox(r.ok ? (r.model_found === false ? "warn" : "info") : "danger", r.ok ? "Bağlantı başarılı" : "Bağlantı başarısız", r.message + (r.models.length ? " Model alanında öneriler listelenir." : "")));
    }) }),
    h("span", { class: "spacer" }),
    button("Vazgeç", { onclick: () => close() }),
    button("Kaydet", { kind: "primary", onclick: guard(async () => {
      await api(p ? `/api/llm-profiles/${p.id}` : "/api/llm-profiles", { method: p ? "PUT" : "POST", body: body() });
      close(); toast("Bağlantı kaydedildi"); router(); refreshSystem();
    }) })], { wide: true });
}

// ================================================================== boot
(async () => {
  try { const st = await api("/api/settings"); TZ = st.timezone || TZ; } catch { /* redirected or offline */ }
  router();
  refreshSystem();
  setInterval(refreshSystem, 15000);
})();
