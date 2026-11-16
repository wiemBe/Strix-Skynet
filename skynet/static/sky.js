/* Skynet – evidence views (docs/FEATURE_BACKLOG.md SKY-01..07). Loaded after app.js and uses its helpers.
 * Every recorded request/response, agent text and note is inserted as a text node, never as HTML. */
"use strict";

const SKY_STATUS_CLS = { tested: "completed", partial: "queued", blocked: "failed", not_tested: "neutral", not_applicable: "neutral", unknown: "neutral",
  verified: "completed", lost: "failed", not_applicable_s: "neutral" };
const TIME_SRC = { caido: "Caido request time", date_header: "Response Date header", source: "Source time", skynet: "Skynet record", session_store: "Stored in agent session", viewed: "When the agent viewed it" };
const ROLE_TR = { attack: "Attack", control: "Control", context: "Context", unassigned: "Role not assigned" };
const ROLE_SRC_TR = { strix_link: "Linked by the Strix finding", assessment: "Per verification assessment (agent-reported)", analyst: "Assigned by analyst" };
const chip = (cls, label, title) => h("span", { class: `status ${cls}`, title: title || null }, h("span", { class: "dot" }), label);
const whenSrc = (at, src, block = false) => at ? h("span", { class: "when-src" + (block ? " block" : "") }, h("span", { class: "nowrap" }, fmtDateSec(at)), h("span", { class: "faint" }, block ? TIME_SRC[src] || src || "time source unknown" : ` · ${TIME_SRC[src] || src || "time source unknown"}`)) : h("span", { class: "faint" }, "Timestamp unavailable");
const alive = (el) => document.body.contains(el);
function selfPoll(el, ms, fn) {           // stops by itself when the element leaves the page
  const t = setInterval(() => { if (!alive(el)) { clearInterval(t); return; } fn(); }, ms);
  timers.push(t);
}

// ------------------------------------------------------------------ recorded exchange viewer
function exchangePanel(x, title) {
  const part = (name, p) => h("div", { class: "ex-part" },
    h("div", { class: "ex-part-head" }, h("span", { class: "live-code-label" }, name.toUpperCase()),
      !p ? h("span", { class: "tag" }, "Not recorded") : p.complete ? h("span", { class: "tag" }, "Complete") : h("span", { class: "tag danger" }, p.clipped ? "Clipped" : "Incomplete page"),
      p ? h("span", { class: "faint" }, `viewed by ${p.agent_id} · ${p.stored_at ? fmtShort(p.stored_at) : "time unavailable"}`) : null),
    p ? h("pre", { class: "ex-text" }, p.text || "(empty)") : h("div", { class: "faint ex-missing" }, `The agent did not view the full ${name}.`));
  if (x.missing) return h("div", { class: "ex-panel" }, h("div", { class: "ex-head" }, h("strong", {}, title || `Request ${x.request_id}`)), alertBox("warn", "Evidence missing", x.reason));
  return h("div", { class: "ex-panel" },
    h("div", { class: "ex-head" }, h("strong", {}, title || `Caido request ${x.request_id}`),
      x.status != null ? h("span", { class: "tag" }, `HTTP ${x.status}`) : null,
      h("span", { class: "faint mono" }, x.run_name),
      x.source_time ? h("span", { class: "faint" }, `Caido time ${fmtDateSec(x.source_time)}`) : null),
    part("request", x.request), part("response", x.response));
}
async function scanExchangeDialog(sid, rid) {
  const x = await api(`/api/scans/${sid}/exchanges/${encodeURIComponent(rid)}`);
  const close = dialog(`Recorded exchange · request ${rid}`, [h("div", { class: "help" }, "Masked with this scan's known secrets and credential patterns. Read-only; opening it sends nothing."), exchangePanel(x)],
    [button("Close", { onclick: () => close() })], { wide: true });
}

// ------------------------------------------------------------------ SKY-02 session health
async function skySessionTab(sid, scan) {
  const root = h("div", { class: "sky-tab" });
  const render = (d, names) => {
    const profs = d.profiles || [];
    if (!profs.length) return root.replaceChildren(h("div", { class: "card" }, emptyState("No authentication profiles", "This scan ran without Vault profiles, so there is no session to track.")));
    root.replaceChildren(
      h("div", { class: "note sky-lead" }, "A state is evidence for one agent at one moment. It is never spread to other agents or carried forward. ",
        "“Recorded by” is the agent that viewed the exchange in Strix's shared proxy; Strix does not record which agent sent it. ", d.method),
      profs.map((p) => {
        const agents = p.agents || [];
        return h("section", { class: "card card-pad sky-profile" },
          h("div", { class: "sky-row-head" }, h("h3", {}, p.name), h("span", { class: "tag" }, AUTHKIND_TR[p.kind] || p.kind),
            p.state === "not_applicable" ? chip("neutral", "Not applicable") : null,
            h("span", { class: "faint" }, p.binding_source === "scan_start" ? "Credential compared from the scan-start snapshot" : p.binding_source === "current_profile_unchanged" ? "Credential compared with the current profile (unchanged since the scan started)" : p.binding_source === "unavailable" ? "Credential not available for comparison" : "")),
          p.precheck ? h("div", { class: "sky-precheck" }, h("span", { class: "faint" }, p.precheck.label, ": "), VERIFY_TR[p.precheck.result] || p.precheck.result, p.precheck.at ? h("span", { class: "faint" }, ` · ${fmtShort(p.precheck.at)}`) : null) : null,
          p.reason ? h("div", { class: "help" }, p.reason) : null,
          agents.length ? h("div", { class: "table-scroll" }, h("table", { class: "t" },
            h("thead", {}, h("tr", {}, ["Recorded by", "State", "Evidence time", "Evidence", ""].map((c) => h("th", {}, c)))),
            h("tbody", {}, agents.map((a) => {
              const ev = a.evidence || a.last_signal;
              return h("tr", {},
                h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line", title: names[a.agent_id] || a.agent_name || a.agent_id }, names[a.agent_id] || a.agent_name || a.agent_id), h("div", { class: "secondary-line mono" }, a.agent_id))),
                h("td", {}, chip(SKY_STATUS_CLS[a.state] || "neutral", a.state_label, a.reason || null), a.reason ? h("div", { class: "status-sub wrap" }, a.reason) : null),
                h("td", {}, ev ? whenSrc(ev.at, ev.time_source, true) : "—"),
                h("td", {}, ev ? h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, ev.label), h("div", { class: "secondary-line mono", title: `${ev.method} ${ev.path}` }, `${ev.method} ${ev.path} · HTTP ${ev.status} · ${a.count} record${a.count === 1 ? "" : "s"}`)) : "—"),
                h("td", { class: "shrink" }, ev ? button("Open", { size: "sm", onclick: guard(() => scanExchangeDialog(sid, ev.request_id)) }) : null));
            })))) : null,
          (p.signals || []).length ? h("details", { class: "sky-details" }, h("summary", {}, `All session signals · ${p.signals.length}`),
            h("ol", { class: "sky-signals" }, p.signals.map((s) => h("li", {}, whenSrc(s.at, s.time_source), " ", h("strong", {}, s.label), " ",
              h("span", { class: "mono faint" }, `${s.method} ${s.path} · HTTP ${s.status} · ${names[s.agent_id] || s.agent_id}`), " ",
              h("a", { href: "#", onclick: (e) => { e.preventDefault(); guard(() => scanExchangeDialog(sid, s.request_id))(); } }, "evidence"))))) : null);
      }));
  };
  const load = async () => {
    const [d, a] = await Promise.all([api(`/api/scans/${sid}/session-health`), api(`/api/scans/${sid}/agents`)]);
    if (!alive(root) && root.childElementCount) return;
    render(d, Object.fromEntries((a.agents || []).map((x) => [x.id, x.name])));
  };
  await load();
  if (ACTIVE.includes(scan.status)) selfPoll(root, 5000, pollGuard(load));
  return root;
}

// ------------------------------------------------------------------ SKY-03 coverage matrix
async function skyCoverageTab(sid) {
  const m = await api(`/api/scans/${sid}/coverage-matrix`);
  if (!m.available) return h("div", { class: "card" }, emptyState("No coverage data", m.reason || "This run has no output folder."));
  const roleLabel = Object.fromEntries((m.roles || []).map((r) => [r.id, r.label]));
  roleLabel["*"] = "Any role";
  const st = { q: "", role: "", type: "", status: "" };
  const q = h("input", { type: "search", placeholder: "Filter endpoints" });
  const roleSel = select([["", "All roles"], ...Object.entries(roleLabel)], "");
  const typeSel = select([["", "All test types"], ...(m.types || []).map((t) => [t.id, t.id === "NONE" ? "No test record" : `${t.id} · ${t.label}`])], "");
  const statusSel = select([["", "All statuses"], ...Object.entries(m.statuses)], "");
  const counts = h("div", { class: "sky-counts" }), tbl = h("div", { class: "table-card" }), detail = h("div", {});
  const showCell = (c) => {
    detail.replaceChildren(h("section", { class: "card card-pad sky-cell" },
      h("div", { class: "sky-row-head" }, h("h3", { class: "mono" }, c.endpoint), h("span", { class: "tag" }, c.origin), h("span", { class: "tag" }, roleLabel[c.role] || c.role),
        h("span", { class: "tag" }, c.test_type === "NONE" ? "No test record" : `${c.test_type} · ${c.test_type_label}`), chip(SKY_STATUS_CLS[c.status], c.status_label)),
      h("h4", {}, "Skynet evaluation"), h("ul", { class: "sky-reasons" }, c.reasons.map((r) => h("li", {}, r))),
      c.verification_id ? h("a", { href: `#/scans/${sid}` }, `Accepted verification #${c.verification_id} in this scan`) : null,
      c.claims.length ? [h("h4", {}, c.claims.length > 1 ? `Strix coverage records (${c.claims.length}, source claims, unmodified)` : "Strix coverage record (source claim, unmodified)"), c.claims.map((i) => {
        const cl = m.claims[i] || {}, res = (c.claim_results || []).find((x) => x.claim === i);
        return h("div", { class: "sky-claim" }, h("div", {}, h("strong", {}, cl.outcome_label || cl.outcome), h("span", { class: "faint" }, ` · ${cl.recorded_by || "agent"} · ${cl.recorded_at || "time unavailable"}`)),
          res ? h("div", { class: "sky-claim-eval" }, chip(SKY_STATUS_CLS[res.status], `Skynet: ${res.status_label}`), " ", h("span", { class: "faint" }, res.reason)) : null,
          h("div", { class: "mono faint" }, cl.surface, " — ", cl.risk_area), cl.evidence ? h("div", { class: "sky-claim-text" }, cl.evidence) : null);
      })] : null,
      h("h4", {}, `Recorded evidence · ${c.evidence_count}`),
      c.evidence.length ? h("div", { class: "occ-list" }, c.evidence.map((e) => h("div", { class: "occ" },
        h("span", { class: "mono" }, `request ${e.request_id}`), " ", e.status != null ? h("span", { class: "tag" }, `HTTP ${e.status}`) : null, " ",
        whenSrc(e.at, e.time_source), " ", h("span", { class: "faint" }, e.agent_id), " ",
        button("Open", { size: "sm", onclick: guard(() => scanExchangeDialog(sid, e.request_id)) })))) : h("div", { class: "faint" }, "No full request/response was recorded for this cell.")));
    detail.scrollIntoView({ block: "nearest" });
  };
  const render = () => {
    const sel = m.cells.filter((c) => (!st.q || c.endpoint.toLowerCase().includes(st.q)) && (!st.role || c.role === st.role)
      && (!st.type || c.test_type === st.type) && (!st.status || c.status === st.status));
    const n = {}; sel.forEach((c) => { n[c.status] = (n[c.status] || 0) + 1; });
    counts.replaceChildren(Object.entries(m.statuses).map(([k, l]) => h("button", { type: "button", class: "sky-count" + (st.status === k ? " on" : ""), "aria-pressed": st.status === k,
      onclick: () => { st.status = st.status === k ? "" : k; statusSel.value = st.status; render(); } }, chip(SKY_STATUS_CLS[k], l), h("span", { class: "n" }, n[k] || 0))));
    tbl.replaceChildren(table([{ label: "Endpoint" }, { label: "Role" }, { label: "Test type" }, { label: "Status" }, { label: "Evidence", cls: "num" }, { label: "", cls: "shrink" }],
      sel.map((c) => h("tr", { class: "clickable", onclick: () => showCell(c) },
        h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line mono", title: c.endpoint }, c.endpoint),
          h("div", { class: "secondary-line mono", title: c.origin }, c.origin))),
        h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line", title: roleLabel[c.role] || c.role }, roleLabel[c.role] || c.role))),
        h("td", { class: "nowrap" }, c.test_type === "NONE" ? h("span", { class: "faint" }, "No test record") : h("span", { title: c.test_type_label }, c.test_type)),
        h("td", {}, chip(SKY_STATUS_CLS[c.status], c.status_label)),
        h("td", { class: "num" }, c.evidence_count),
        h("td", { class: "shrink" }, icon("chevron")))),
      emptyState("No cells match the filter", "Change the filters.")));
  };
  q.addEventListener("input", () => { st.q = q.value.trim().toLowerCase(); render(); });
  [["role", roleSel], ["type", typeSel], ["status", statusSel]].forEach(([k, el]) => el.addEventListener("change", () => { st[k] = el.value; render(); }));
  render();
  return h("div", { class: "sky-tab" },
    h("div", { class: "note sky-lead" }, m.rule, " Test types are ", h("a", { href: m.wstg_url, target: "_blank", rel: "noopener noreferrer" }, m.wstg_version),
      " categories mapped heuristically from Strix's free-text risk area; this is not an OWASP compliance statement."),
    m.complete === false ? alertBox("warn", "Strix marked this run's coverage incomplete", null) : null,
    (m.gaps || []).length ? alertBox("info", "Coverage gaps reported by Strix", null, h("ul", { class: "sky-reasons" }, m.gaps.map((g) => h("li", {}, g)))) : null,
    counts,
    h("div", { class: "toolbar" }, h("div", { class: "field grow" }, h("label", {}, "Endpoint"), q), field("Role", roleSel), field("Test type", typeSel), field("Status", statusSel)),
    tbl, detail,
    h("details", { class: "sky-details" }, h("summary", {}, `Strix coverage records (${m.claims.length}, from ${m.source || "—"}, unmodified)`),
      h("ol", { class: "sky-signals" }, m.claims.map((c) => h("li", {}, h("strong", {}, c.outcome_label || c.outcome), " · ", h("span", { class: "mono" }, c.surface), h("span", { class: "faint" }, ` · ${c.risk_area} · ${c.test_type}`))))));
}

// ------------------------------------------------------------------ SKY-04 instruction center
async function skyInstructionsTab(sid, scan) {
  const root = h("div", { class: "sky-tab" });
  const st = { agent: "", open: new Set() };
  const agentSel = select([["", "All agents"]], "");
  agentSel.addEventListener("change", () => { st.agent = agentSel.value; load(); });
  const list = h("div", {}), head = h("div", {});
  const followItem = (i) => h("li", {},
    h("span", { class: "faint" }, i.at ? fmtDateSec(i.at) : "time unavailable", " · "), h("span", { class: "tag" }, i.kind === "message" ? "Agent message" : i.kind === "tool_call" ? `Call · ${i.tool || "tool"}` : `Result · ${i.tool || "tool"}`), " ",
    h("span", { class: "sky-follow-text" }, (i.text || "").slice(0, 300)));
  const follow = async (m, box) => {
    box.replaceChildren(h("div", { class: "faint" }, "Loading…"));
    const r = await api(`/api/scans/${sid}/messages/${m.id}/activity?limit=60`);
    const ol = h("ol", { class: "sky-follow" }, (r.items || []).map(followItem));
    const more = h("div", {});
    let cursor = r.cursor;
    const moreBtn = () => more.replaceChildren(button("Load more", { size: "sm", onclick: guard(async () => {
      const n = await api(`/api/scans/${sid}/messages/${m.id}/activity?limit=60&after=${cursor}`);
      (n.items || []).forEach((i) => ol.append(followItem(i))); cursor = n.cursor;
      if (n.has_more) moreBtn(); else more.replaceChildren();
    }) }));
    if (r.has_more || (r.items || []).length >= 60) moreBtn();
    box.replaceChildren(
      h("div", { class: "help" }, r.application.method),
      !r.marker_found ? h("div", { class: "faint" }, r.reason) : (r.items || []).length ? [ol, more] : h("div", { class: "faint" }, "No visible activity from this agent after the instruction yet."));
  };
  const render = (d) => {
    const agents = new Map();
    (d.agents || []).forEach((a) => agents.set(a.id, a.name));
    (d.messages || []).forEach((m) => { if (!agents.has(m.agent_id)) agents.set(m.agent_id, m.agent_name || m.agent_id); });
    if (agentSel.options.length !== agents.size + 1) {
      const keep = agentSel.value;
      agentSel.replaceChildren(h("option", { value: "" }, "All agents"), [...agents].map(([id, n]) => h("option", { value: id }, n)));
      agentSel.value = [...agents.keys()].includes(keep) ? keep : "";
    }
    head.replaceChildren(!d.available ? alertBox("info", ACTIVE.includes(scan.status) ? "Messaging is not available for this scan" : "This scan is not running", ACTIVE.includes(scan.status) ? d.reason : "Instructions can only be sent while a scan runs (from Live activity). The history below is read-only.") : null);
    const msgs = (d.messages || []).filter((m) => !st.agent || m.agent_id === st.agent);
    list.replaceChildren(msgs.length ? msgs.map((m) => {
      const box = h("div", { class: "sky-follow-box" });
      const det = h("details", { class: "sky-details", open: st.open.has(m.id) || null, ontoggle: (e) => { if (e.target.open) { st.open.add(m.id); guard(() => follow(m, box))(); } else st.open.delete(m.id); } },
        h("summary", {}, "Agent activity after this instruction"), box);
      if (st.open.has(m.id)) guard(() => follow(m, box))();
      const cls = { delivered: "completed", queued: "queued", sending: "neutral", expired: "neutral", rejected: "failed", unknown: "queued" }[m.state] || "neutral";
      return h("article", { class: "card card-pad sky-instr" },
        h("div", { class: "sky-row-head" }, h("strong", {}, m.agent_name || m.agent_id), chip(cls, m.stage_label, m.stage_help),
          m.application ? chip("neutral", m.application.label, m.application.method) : null, h("span", { class: "faint" }, `by ${m.created_by || "—"}`)),
        h("div", { class: "compose-msg-text" }, m.content || h("span", { class: "faint" }, "Content unavailable")),
        h("ol", { class: "sky-stages" }, [["Sent", m.created_at], ["Accepted by Strix", m.accepted_at], ["Added to agent context", m.delivered_at]].map(([l, at]) =>
          h("li", { class: at ? "done" : null }, h("span", {}, l), h("span", { class: "faint" }, at ? fmtDateSec(at) : "—")))),
        m.reason ? h("div", { class: "help" }, m.reason) : h("div", { class: "help" }, m.stage_help),
        m.state === "delivered" ? det : null);
    }) : h("div", { class: "card" }, emptyState("No instructions", st.agent ? "No instruction was sent to this agent." : "No operator instruction was sent during this scan.")));
  };
  const load = pollGuard(async () => {
    const d = await api(`/api/scans/${sid}/messages${st.agent ? "?agent_id=" + encodeURIComponent(st.agent) : ""}`);
    render(d);
  });
  root.append(h("div", { class: "note sky-lead" }, "Accepted, in context and applied are different things. Skynet records the first two; it does not judge whether an agent followed an instruction, and an agent saying so is not execution evidence."),
    h("div", { class: "toolbar" }, field("Agent", agentSel)), head, list);
  await load();
  if (ACTIVE.includes(scan.status)) selfPoll(root, 3000, load);
  return root;
}

// ------------------------------------------------------------------ SKY-05 browser view
async function skyBrowserTab(sid, scan) {
  const a = await api(`/api/scans/${sid}/agents`);
  const agents = a.agents || [];
  const root = h("div", { class: "sky-tab" });
  if (!agents.length) return h("div", { class: "card" }, emptyState("No agents yet", "Strix writes agent states after the scan starts."));
  const sel = select(agents.map((x) => [x.id, x.name]), agents[0].id);
  const box = h("div", {});
  let gen = 0;
  const conn = h("div", { role: "status" });
  const load = async () => {
    const my = ++gen, agent = sel.value;
    let d;
    try { d = await api(`/api/scans/${sid}/browser?agent_id=${encodeURIComponent(agent)}`); }
    catch (e) {
      if (my !== gen) return;
      const last = box.querySelector(".sky-browser") ? "The view below is the last answer received; it may be out of date." : "";
      conn.replaceChildren(alertBox("warn", "Connection lost", `Skynet could not be reached (${e.message}). ${last} Retrying…`));
      return;
    }
    if (my !== gen || agent !== sel.value) return;          // a slow answer for the previous agent is dropped
    conn.replaceChildren();
    const cap = d.capability, l = d.latest;
    const fcls = { latest: "completed", stale: "queued", recorded: "neutral", unavailable: "neutral" }[d.freshness];
    box.replaceChildren(
      h("section", { class: "card card-pad sky-browser" },
        h("div", { class: "sky-row-head" }, h("h3", {}, (agents.find((x) => x.id === agent) || {}).name || agent), chip(fcls, d.freshness_label),
          h("span", { class: "faint" }, `checked ${fmtDateSec(d.checked_at)}`)),
        h("div", { class: "sky-frame", role: "img", "aria-label": "Screenshot withheld" },
          h("div", { class: "sky-frame-title" }, l ? "Screenshot withheld" : "No screenshot to show"),
          h("div", { class: "faint" }, l ? cap.policy : "This agent has not loaded a screenshot into its context.")),
        l ? h("dl", { class: "dl" },
          h("dt", {}, "Agent"), h("dd", { class: "mono" }, l.agent_id),
          h("dt", {}, "Stored"), h("dd", {}, whenSrc(l.stored_at, l.time_source)),
          h("dt", {}, "Freshness rule"), h("dd", {}, `Latest screenshot within ${cap.fresh_seconds} s while the scan runs; Stale after that; Recorded once the scan has ended.`),
          h("dt", {}, "Sandbox file"), h("dd", { class: "mono" }, l.sandbox_path || "—"),
          h("dt", {}, "Size"), h("dd", {}, l.approx_bytes ? `${Math.round(l.approx_bytes / 1024)} KB ${l.media_type || ""}` : "—")) : null),
      h("div", { class: "note" }, cap.reason),
      (d.screenshots || []).length ? h("details", { class: "sky-details" }, h("summary", {}, `Screenshot records for this agent · ${d.screenshots.length}`),
        h("ol", { class: "sky-signals" }, d.screenshots.map((s) => h("li", {}, whenSrc(s.stored_at, s.time_source), " ", h("span", { class: "tag" }, s.state === "stored" ? "Stored (withheld)" : s.state === "elided" ? "Elided by Strix" : "Not recorded"), " ", h("span", { class: "mono faint" }, s.call_id))))) : null);
  };
  sel.addEventListener("change", () => { box.replaceChildren(h("div", { class: "faint" }, "Loading…")); guard(load)(); });
  root.append(h("div", { class: "note sky-lead" }, "Read-only. Checking for screenshots never navigates the browser or sends a request."), h("div", { class: "toolbar" }, field("Agent", sel)), conn, box);
  await load();
  if (ACTIVE.includes(scan.status)) selfPoll(root, 5000, load);
  return root;
}

// ------------------------------------------------------------------ SKY-06 timeline & replay
async function skyTimelineTab(sid, scan) {
  const root = h("div", { class: "sky-tab" });
  const st = { kinds: new Set(), agent: "", q: "", events: [], keys: new Set(), total: 0, offset: 0, replay: null, seenAt: null, maskingRevision: null };
  const live = ACTIVE.includes(scan.status);
  const a = await api(`/api/scans/${sid}/agents`);
  const names = Object.fromEntries((a.agents || []).map((x) => [x.id, x.name]));
  const agentSel = select([["", "All agents"], ...(a.agents || []).map((x) => [x.id, x.name])], "");
  const q = h("input", { type: "search", placeholder: "Search event text" });
  const kindBox = h("div", { class: "sky-kinds" });
  const list = h("ol", { class: "sky-timeline" }), info = h("div", { class: "note" }), more = h("div", {});
  const follow = h("input", { type: "checkbox", checked: live });
  const slider = h("input", { type: "range", min: "0", max: "1000", value: "1000", "aria-label": "Replay position" });
  const speed = select([["1", "1×"], ["10", "10×"], ["60", "60×"], ["600", "600×"]], "60");
  const pos = h("span", { class: "mono" }, "—");
  const playBtn = button("Play", { size: "sm", ic: "play" });
  let KINDS = {};
  const sortKey = (e) => [e.at ? 0 : 1, e.at || "", e.kind, e.seq || 0, e.key];
  const cmp = (x, y) => { const a1 = sortKey(x), b1 = sortKey(y); for (let i = 0; i < a1.length; i++) { if (a1[i] < b1[i]) return -1; if (a1[i] > b1[i]) return 1; } return 0; };
  const range = () => { const t = st.events.filter((e) => e.at).map((e) => Date.parse(e.at)); return t.length ? [Math.min(...t), Math.max(...t)] : null; };
  const cursor = () => { const r = range(); return r ? r[0] + (r[1] - r[0]) * (+slider.value / 1000) : null; };
  const row = (e) => h("li", { class: "sky-ev " + e.kind + (e.same_time ? " tie" : "") },
    h("div", { class: "sky-ev-time", title: e.skynet_seen_at ? `First seen by Skynet ${fmtDateSec(e.skynet_seen_at)}` : null }, e.at ? fmtDateSec(e.at) : "Timestamp unavailable", h("div", { class: "faint" }, e.at ? TIME_SRC[e.time_source] || e.time_source : (e.time_note || ""))),
    h("div", { class: "sky-ev-body" },
      h("div", { class: "sky-ev-head" }, h("span", { class: "tag" }, e.kind_label), e.agent_id ? h("span", { class: "faint" }, names[e.agent_id] || e.agent_id) : null,
        e.same_time ? h("span", { class: "tag", title: "Another event has the same timestamp; their order is not established." }, "Same time") : null),
      h("div", { class: "sky-ev-text" }, e.summary),
      e.request_id && (e.kind === "http_request" || e.kind === "session") ? h("a", { href: "#", onclick: (ev) => { ev.preventDefault(); guard(() => scanExchangeDialog(sid, e.request_id))(); } }, e.full === false ? "View list record" : "Open recorded exchange") : null));
  let lastSig = "";
  const render = () => {
    const cur = st.replay ? cursor() : null;
    const shown = st.replay ? st.events.filter((e) => e.at && Date.parse(e.at) <= cur) : st.events;
    const view = st.replay ? shown.slice(-500) : shown;     // replay keeps the DOM bounded: the latest 500 up to the position
    const sig = `${st.replay ? 1 : 0}:${shown.length}:${st.events.length}:${view.length ? view[view.length - 1].key : ""}`;
    if (sig !== lastSig) {
      lastSig = sig;
      list.replaceChildren(view.length ? view.map(row) : h("li", { class: "faint" }, st.replay ? "No recorded events before this position." : "No events match the filters."));
    }
    pos.textContent = st.replay && cur != null ? fmtDateSec(new Date(cur).toISOString()) : "—";
    info.textContent = `${st.events.length} of ${st.total} events loaded` + (st.replay ? ` · replay shows ${shown.length} recorded up to the position${shown.length > 500 ? " (latest 500 listed)" : ""}; events without a timestamp are hidden during replay` + (st.events.length < st.total ? " · replay covers the first 5000 events" : "") : "")
      + (live && !st.replay ? (follow.checked ? " · following live" : " · live updates paused") : "");
    more.replaceChildren(st.events.length < st.total ? button(`Load more (${st.total - st.events.length} left)`, { size: "sm", onclick: guard(() => load(false)) }) : null);
    if (!st.replay && live && follow.checked) list.lastElementChild?.scrollIntoView({ block: "nearest" });
  };
  const qs = () => new URLSearchParams({ kinds: [...st.kinds].join(","), agent_id: st.agent, q: st.q });
  const merge = (events, removed = []) => {
    if (!events.length && !removed.some((key) => st.keys.has(key))) return;
    const byKey = new Map(st.events.map((e) => [e.key, e]));
    for (const key of removed) byKey.delete(key);
    for (const e of events) byKey.set(e.key, e);  // updates include corrected times and newly masked text
    st.events = [...byKey.values()]; st.keys = new Set(byKey.keys());
    lastSig = "";
  };
  let generation = 0;
  const load = async (reset) => {
    if (reset) { generation++; st.events = []; st.keys = new Set(); st.offset = 0; lastSig = ""; }
    const gen = generation;
    const p = new URLSearchParams(qs()); p.set("offset", String(st.offset)); p.set("limit", "200");
    const d = await api(`/api/scans/${sid}/timeline?${p}`);
    if (gen !== generation) return;
    if (!reset && st.maskingRevision && st.maskingRevision !== d.masking_revision) {
      list.replaceChildren(); return load(true);
    }
    st.maskingRevision = d.masking_revision;
    KINDS = d.kinds;
    if (!kindBox.childElementCount) kindBox.replaceChildren(Object.entries(KINDS).map(([k, l]) => h("label", { class: "check" },
      h("input", { type: "checkbox", onchange: (e) => { e.target.checked ? st.kinds.add(k) : st.kinds.delete(k); guard(() => load(true))(); } }), l)));
    merge(d.events);
    st.events.sort(cmp);
    st.total = d.total; st.offset = d.offset + d.events.length;
    if (reset || st.seenAt == null) st.seenAt = d.now;
    render();
  };
  let refreshing = false;
  const refreshLive = pollGuard(async () => {      // events Skynet first saw since the last poll, wherever they sort
    if (refreshing || st.replay || !follow.checked || st.seenAt == null) return;
    refreshing = true;
    try {
    const gen = generation;
    const p = new URLSearchParams(qs()); if (st.seenAt) p.set("seen_after", st.seenAt); p.set("limit", "500");
    const d = await api(`/api/scans/${sid}/timeline?${p}`);
    if (gen !== generation) return;
    if (d.reset_required || st.maskingRevision !== d.masking_revision) { list.replaceChildren(); return load(true); }
    merge(d.events, d.removed_keys);
    st.seenAt = d.now;
    st.events.sort(cmp); st.total = d.total; render();
    // The cursor stops at the last returned event; remaining batch pages are read on subsequent polls.
    } finally { refreshing = false; }
  });
  let timer = null;
  const stop = () => { if (timer) clearInterval(timer); timer = null; playBtn.replaceChildren(icon("play"), "Play"); };
  playBtn.addEventListener("click", () => {
    if (timer) return stop();
    const r = range(); if (!r) return toast("No timed events to replay.", true);
    if (!st.replay) { st.replay = true; slider.value = "0"; }
    playBtn.replaceChildren(icon("pause"), "Pause");
    timer = setInterval(() => {
      if (!alive(root)) return stop();
      const span = Math.max(1, r[1] - r[0]), step = (250 * +speed.value) / span * 1000;
      slider.value = String(Math.min(1000, +slider.value + Math.max(1, step)));
      render();
      if (+slider.value >= 1000) stop();
    }, 250);
    timers.push(timer);
  });
  const loadAll = async () => {          // replay needs the whole recorded history (bounded)
    while (st.events.length < st.total && st.events.length < 5000) { const n = st.offset; await load(false); if (st.offset === n) break; }
  };
  const replayToggle = h("input", { type: "checkbox", onchange: guard(async (e) => {
    st.replay = e.target.checked || null; if (!st.replay) stop(); controls.hidden = !st.replay;
    if (st.replay) await loadAll();
    render();
  }) });
  const controls = h("div", { class: "sky-replay", hidden: true }, playBtn, button("", { size: "sm", ic: "back", title: "Step back", onclick: () => { slider.value = String(Math.max(0, +slider.value - 20)); render(); } }),
    slider, button("", { size: "sm", ic: "chevron", title: "Step forward", onclick: () => { slider.value = String(Math.min(1000, +slider.value + 20)); render(); } }),
    h("label", { class: "check" }, "Speed ", speed), h("span", {}, "Position: ", pos));
  slider.addEventListener("input", () => { st.replay = true; render(); });
  agentSel.addEventListener("change", () => { st.agent = agentSel.value; guard(() => load(true))(); });
  let qt; q.addEventListener("input", () => { clearTimeout(qt); qt = setTimeout(() => { st.q = q.value.trim(); guard(() => load(true))(); }, 250); });
  follow.addEventListener("change", render);
  root.append(
    h("div", { class: "note sky-lead" }, "Recorded events from Strix's files, Caido and Skynet's own records. Times keep their source; events with the same time are not ordered, and order does not show cause. ",
      h("strong", {}, "Replay only re-reads these records: it never re-sends a request, re-runs a tool, messages an agent or starts a scan.")),
    h("div", { class: "toolbar" }, field("Agent", agentSel), h("div", { class: "field grow" }, h("label", {}, "Search"), q),
      live ? h("label", { class: "check sky-inline" }, follow, "Follow live") : null, h("label", { class: "check sky-inline" }, replayToggle, live ? "Replay recorded so far" : "Replay")),
    kindBox, controls, info, list, more);
  await load(true);
  if (live) selfPoll(root, 3000, refreshLive);
  return root;
}

// ------------------------------------------------------------------ SKY-07 evidence workspace
async function viewWorkspace(gid, query) {
  const params = new URLSearchParams(query || "");
  const ctxQs = params.get("verification") ? `verification_id=${params.get("verification")}` : params.get("occurrence") ? `occurrence_id=${params.get("occurrence")}` : "";
  const w = await api(`/api/findings/${gid}/workspace${ctxQs ? "?" + ctxQs : ""}`);
  const g = w.group, ctx = w.context || {};
  const pick = { left: null, right: null };
  const exs = ctx.exchanges || [];
  const attack = exs.find((x) => x.role === "attack"), control = exs.find((x) => x.role === "control");
  pick.left = (attack || exs.find((x) => x.key !== control?.key) || exs[0] || {}).key || null;
  pick.right = ((control && control.key !== pick.left ? control : exs.find((x) => x.key !== pick.left)) || {}).key || null;
  const sideBox = h("div", { class: "ex-sides" }), diffBox = h("div", {}), notesBox = h("div", {});
  const label = (x) => `${ROLE_TR[x.role] || x.role} · request ${x.request_id}${x.status != null ? ` · HTTP ${x.status}` : ""}`;
  const sideSel = (side) => {
    const s = select(exs.map((x) => [x.key, label(x)]), pick[side] || "");
    s.addEventListener("change", () => { pick[side] = s.value; renderSides(); diffBox.replaceChildren(); });
    return s;
  };
  const renderSides = () => {
    const byKey = Object.fromEntries(exs.map((x) => [x.key, x]));
    sideBox.replaceChildren(["left", "right"].map((side) => {
      const x = byKey[pick[side]];
      return h("div", { class: "ex-side" }, field(side === "left" ? "Left" : "Right", sideSel(side)),
        x ? h("div", { class: "help" }, `${ROLE_TR[x.role] || x.role} — ${ROLE_SRC_TR[x.role_source] || x.role_source}${x.role_by ? ` (${x.role_by}, ${fmtShort(x.role_at)})` : ""}`) : null,
        x ? exchangePanel(x, label(x)) : h("div", { class: "faint" }, "Nothing selected."),
        x && !x.missing ? h("div", { class: "actions ex-actions" },
          menu(["attack", "control", "context", "clear"].map((r) => ({ need: "analyst", label: r === "clear" ? "Clear my role" : `Mark as ${ROLE_TR[r].toLowerCase()}`, onclick: guard(async () => {
            await api(`/api/findings/${gid}/labels`, { method: "POST", body: { run_name: x.run_name, request_id: x.request_id, label: r, occurrence_id: ctx.occurrence_id || null } });
            toast("Role saved (original evidence unchanged)"); router();
          }) })), { label: "Assign role" }),
          button("Download masked", { size: "sm", ic: "download", onclick: () => { location.href = `/api/findings/${gid}/exchanges/${encodeURIComponent(x.run_name)}/${encodeURIComponent(x.request_id)}/download`; } })) : null);
    }));
  };
  const showDiff = guard(async (part) => {
    if (!pick.left || !pick.right || pick.left === pick.right) return toast("Select two different exchanges.", true);
    const d = await api(`/api/findings/${gid}/diff?left=${encodeURIComponent(pick.left)}&right=${encodeURIComponent(pick.right)}&part=${part}`);
    diffBox.replaceChildren(h("section", { class: "card card-pad" }, h("div", { class: "sky-row-head" }, h("h3", {}, `Difference · ${part}`), h("span", { class: "faint" }, d.note || "")),
      !d.available ? h("div", { class: "faint" }, d.reason) : [d.complete ? null : alertBox("warn", "One side is incomplete", "The difference covers only what was recorded."),
        h("pre", { class: "ex-diff" }, d.ops.map((o) => h("span", { class: o.op === "+" ? "add" : o.op === "-" ? "del" : null }, `${o.op === " " ? " " : o.op} ${o.text}\n`)))]));
  });
  const renderNotes = (notes) => {
    const ta = h("textarea", { rows: 3, maxlength: 8000, placeholder: "Analyst note (kept separate from the evidence; never changes remediation or verification)", "aria-label": "New analyst note" });
    notesBox.replaceChildren(h("section", { class: "card card-pad" }, h("div", { class: "sky-row-head" }, h("h3", {}, "Analyst notes"), h("span", { class: "faint" }, "Edits add a revision; history is kept.")),
      can("analyst") ? ta : null, can("analyst") ? h("div", { class: "actions ex-actions" }, button("Add note", { need: "analyst", kind: "primary", size: "sm", onclick: guard(async () => {
        const r = await api(`/api/findings/${gid}/notes`, { method: "POST", body: { body: ta.value, occurrence_id: ctx.occurrence_id || null, verification_id: ctx.verification_id || null } });
        toast("Note added"); renderNotes(r.notes);
      }) })) : h("p", { class: "faint" }, "Read-only access. Analyst access is required to add or edit notes."),
      notes.length ? h("ol", { class: "sky-notes" }, notes.map((n) => {
        const edit = h("textarea", { rows: 3, maxlength: 8000, hidden: true, "aria-label": "Edit note" }); edit.value = n.body || "";
        const save = button("Save revision", { need: "analyst", size: "sm", kind: "primary", onclick: guard(async () => { const r = await api(`/api/findings/${gid}/notes/${n.id}`, { method: "PUT", body: { body: edit.value } }); toast("Revision saved"); renderNotes(r.notes); }) });
        save.hidden = true;
        return h("li", { class: "sky-note" }, h("div", { class: "sky-row-head" }, h("strong", {}, n.created_by || "analyst"), h("span", { class: "faint" }, fmtDateSec(n.updated_at)),
          n.occurrence_id ? h("span", { class: "tag" }, `occurrence #${n.occurrence_id}`) : n.verification_id ? h("span", { class: "tag" }, `verification #${n.verification_id}`) : null,
          h("span", { class: "tag" }, "Analyst note — not machine evidence"),
          button("Edit", { need: "analyst", size: "sm", onclick: () => { edit.hidden = !edit.hidden; save.hidden = edit.hidden; } })),
          h("div", { class: "sky-note-body" }, n.body == null ? h("span", { class: "faint" }, "Could not be decrypted") : n.body), edit, save,
          n.revisions.length > 1 ? h("details", { class: "sky-details" }, h("summary", {}, `Revision history · ${n.revisions.length}`),
            h("ol", { class: "sky-signals" }, n.revisions.map((r) => h("li", {}, h("span", { class: "faint" }, `${fmtDateSec(r.created_at)} · ${r.author} — `), r.body)))) : null);
      })) : h("div", { class: "faint" }, "No notes yet.")));
  };
  const ctxList = h("div", { class: "card card-pad sky-ctx" }, h("div", { class: "card-title" }, "Evidence context"),
    h("div", { class: "card-subtitle" }, "Finding occurrences"),
    w.occurrences.map((o) => h("div", { class: "sky-ctx-item" + (ctx.kind === "occurrence" && ctx.occurrence_id === o.id ? " on" : "") },
      h("a", { href: `#/findings/${gid}?occurrence=${o.id}` }, `${o.strix_id} · scan #${o.scan_id}`),
      h("div", { class: "faint mono" }, o.run_name), h("div", { class: "faint" }, `${fmtShort(o.observed_at)} · ${o.scan_trigger === "verify" ? "verification run" : "scan"}`),
      h("div", {}, chip(o.correlation.state === "analyst_confirmed" ? "completed" : o.correlation.state === "analyst_rejected" ? "failed" : "neutral", o.correlation.label)),
      h("div", { class: "actions" }, ["confirmed", "rejected", "cleared"].map((d) => button(d === "confirmed" ? "Confirm match" : d === "rejected" ? "Reject match" : "Clear", { need: "analyst", size: "sm", onclick: guard(async () => {
        await api(`/api/findings/${gid}/occurrences/${o.id}/review`, { method: "POST", body: { decision: d } }); toast("Correlation review saved"); router();
      }) }))))),
    h("div", { class: "card-subtitle sky-gap" }, "Verification runs"),
    w.verifications.length ? w.verifications.map((v) => h("div", { class: "sky-ctx-item" + (ctx.kind === "verification" && ctx.verification_id === v.id ? " on" : "") },
      h("a", { href: `#/findings/${gid}?verification=${v.id}` }, `Verification #${v.id} · scan #${v.scan_id}`),
      h("div", { class: "faint" }, `${v.result_label} · ${fmtShort(v.finished_at || v.created_at)}`))) : h("div", { class: "faint" }, "None."));
  app.replaceChildren(
    pageHead(g.title || `Finding #${gid}`, { crumb: h("a", { href: "#/scans" }, "Evidence workspace"),
      meta: [h("span", { class: `sevpill ${g.severity}` }, SEV_TR[g.severity] || g.severity), h("span", { class: `rem ${g.remediation}` }, REMEDIATION_TR[g.remediation]), h("span", { class: "mono" }, [g.method, g.host, g.endpoint].filter(Boolean).join(" ")), g.cwe ? h("span", { class: "faint" }, g.cwe) : null] }),
    h("div", { class: "grid-main-side sky-ws" },
      h("div", {},
        h("div", { class: "note sky-lead" }, ctx.kind === "verification" ? `Verification #${ctx.verification_id} · ${ctx.result_label || ""} — ${ctx.result_note || ""}` : ctx.kind === "occurrence" ? `Original Strix finding ${ctx.strix_id} in run ${ctx.run_name}.` : "No evidence context.", " ", w.masking_note),
        (ctx.gaps || []).map((x) => alertBox("warn", "Evidence gap", x)),
        ctx.pairing_note ? alertBox("info", ctx.kind === "verification" ? "Roles from the verification assessment" : "Roles are not assigned by Strix", ctx.pairing_note) : null,
        ctx.assessment ? h("div", { class: "card card-pad sky-claim" }, h("div", { class: "card-subtitle" }, "Agent assessment (agent-reported, not proof)"), h("div", {}, `${ctx.assessment.outcome || "—"} · test completed: ${ctx.assessment.test_completed === true ? "yes" : "not stated"}`), ctx.assessment.reason ? h("div", { class: "sky-claim-text" }, ctx.assessment.reason) : null) : null,
        exs.length ? [sideBox, h("div", { class: "actions ex-actions" }, button("Compare requests", { size: "sm", onclick: () => showDiff("request") }), button("Compare responses", { size: "sm", onclick: () => showDiff("response") })), diffBox] : null,
        h("div", { class: "note" }, ctx.screenshots || ""),
        notesBox),
      h("div", {}, ctxList)));
  renderSides(); renderNotes(w.notes || []);
}

// ------------------------------------------------------------------ SKY-01 scan comparison
async function viewCompare(tid, query) {
  const params = new URLSearchParams(query || "");
  const [t, scans] = await Promise.all([api(`/api/targets/${tid}`), api(`/api/scans?target_id=${tid}&limit=300`)]);
  const usable = scans.filter((s) => s.run_name);
  const opt = (s) => [String(s.id), `#${s.id} · ${fmtShort(s.started_at || s.created_at)} · ${STATUS_TR[s.status] || s.status} · ${MODE_TR[s.scan_mode] || s.scan_mode || "—"}${s.trigger === "verify" ? " · verification" : ""}`];
  const done = usable.filter((s) => s.status === "completed");
  const refSel = select(usable.map(opt), params.get("ref") || (done[1] || usable[1] || {}).id);
  const cmpSel = select(usable.map(opt), params.get("cmp") || (done[0] || usable[0] || {}).id);
  const out = h("div", {});
  const run = guard(async () => {
    location.hash = `#/targets/${tid}/compare?ref=${refSel.value}&cmp=${cmpSel.value}`;
  });
  app.replaceChildren(pageHead("Compare scans", { crumb: h("a", { href: `#/targets/${tid}` }, t.name), lead: "What changed between two scans of this target, and where the comparison is uncertain. “New” is relative to the reference you select." }),
    usable.length < 2 ? h("div", { class: "card" }, emptyState("Not enough scans", "Two scans of this target with an output folder are needed.")) :
      h("div", { class: "toolbar" }, field("Reference scan", refSel), field("Comparison scan", cmpSel), h("div", { class: "field" }, h("label", {}, " "), button("Compare", { kind: "primary", onclick: run }))),
    out);
  if (usable.length < 2 || !params.get("ref") || !params.get("cmp")) {
    if (usable.length >= 2) out.append(h("div", { class: "note" }, "Select a reference and a comparison scan."));
    return;
  }
  let d;
  try { d = await api(`/api/compare?reference=${params.get("ref")}&comparison=${params.get("cmp")}`); }
  catch (e) { out.replaceChildren(alertBox("danger", "Cannot compare these scans", e.message)); return; }
  const ws = (f) => h("a", { href: `#/findings/${f.group_id}?occurrence=${f.occurrence_id}` }, f.title);
  const fTable = (rows, extra) => table([{ label: "Severity" }, { label: "Finding" }, { label: "Remediation" }, { label: extra[0] }],
    rows.map((f) => h("tr", {}, h("td", { class: "shrink" }, h("span", { class: `sevpill ${f.severity}` }, SEV_TR[f.severity] || f.severity)),
      h("td", {}, h("div", { class: "cell-clip" }, h("div", { class: "primary-line" }, ws(f)), h("div", { class: "secondary-line mono" }, f.endpoint))),
      h("td", { class: "nowrap" }, h("span", { class: `rem ${f.remediation}` }, REMEDIATION_TR[f.remediation])),
      h("td", {}, extra[1](f)))), h("div", { class: "sky-none faint" }, "None."));
  const eTable = (rows, showState) => table([{ label: "Endpoint" }, { label: "Evidence" }, { label: showState ? "State" : "Coverage in this run" }],
    rows.map((e) => h("tr", { class: "clickable", onclick: guard(async () => { const a = (await api(`/api/assets/${e.asset_id}/observations`)).asset; assetDialog(a); }) },
      h("td", {}, h("span", { class: "mono" }, e.label)), h("td", {}, h("span", { class: `tier ${e.tier}` }, TIER_TR[e.tier])),
      h("td", {}, showState ? [chip(e.state === "not_tested_in_run" ? "queued" : "neutral", e.state_label), h("div", { class: "status-sub" }, e.reason)] : e.coverage ? chip(SKY_STATUS_CLS[e.coverage.status], e.coverage.status_label) : h("span", { class: "faint" }, "No coverage cell")))),
    h("div", { class: "sky-none faint" }, "None."));
  const side = (s, l) => h("div", { class: "card card-pad" }, h("div", { class: "card-subtitle" }, l),
    h("div", {}, h("a", { href: `#/scans/${s.id}` }, `Scan #${s.id}`), " · ", STATUS_TR[s.status] || s.status, " · ", MODE_TR[s.scan_mode] || s.scan_mode || "—"),
    h("div", { class: "faint" }, `${fmtDateSec(s.started_at)} · profiles: ${(s.auth_profile_names || []).join(", ") || "none"}`),
    h("div", { class: "faint" }, `Coverage record: ${s.coverage_complete == null ? "completeness unknown" : s.coverage_complete ? "complete" : "incomplete"} · release / build: not recorded`));
  const fe = d.findings, ee = d.endpoints;
  out.replaceChildren(
    h("div", { class: "note sky-lead" }, d.label, ". ", d.note),
    h("div", { class: "grid-2 sky-sides" }, side(d.reference, "Reference"), side(d.comparison, "Comparison")),
    d.caveats.map((c) => alertBox(c.level === "warn" ? "warn" : "info", c.text, null)),
    section("Findings", h("div", {},
      h("h4", { class: "sky-sub" }, `New observations · ${fe.new.length}`), h("div", { class: "table-card" }, fTable(fe.new, ["Note", (f) => f.seen_before_reference ? "Seen in scans before the reference" : h("span", { class: "faint" }, "Not seen before the reference")])),
      h("h4", { class: "sky-sub" }, `Seen again · ${fe.seen_again.length}`), h("div", { class: "table-card" }, fTable(fe.seen_again, ["Match", (f) => chip(f.match === "analyst_confirmed" ? "completed" : f.match === "analyst_rejected" ? "failed" : "neutral", f.match_label)])),
      h("h4", { class: "sky-sub" }, `Not observed in this run · ${fe.not_observed.length}`), h("div", { class: "table-card" }, fTable(fe.not_observed, ["Why", (f) => h("div", { class: "status-sub wrap" }, f.reason)]))),
      { hint: "Remediation is never changed by a comparison" }),
    section("Endpoints", h("div", {},
      h("h4", { class: "sky-sub" }, `New in the comparison scan · ${ee.new.length}`), h("div", { class: "table-card" }, eTable(ee.new, false)),
      h("h4", { class: "sky-sub" }, `Not observed / not tested in this run · ${ee.not_observed.length}`), h("div", { class: "table-card" }, eTable(ee.not_observed, true)),
      h("div", { class: "note" }, `${ee.both} endpoints observed in both scans.`))),
    section("Test coverage changes", h("div", { class: "table-card" }, table([{ label: "Endpoint" }, { label: "Role" }, { label: "Test type" }, { label: "Reference" }, { label: "Comparison" }],
      d.coverage_changes.map((c) => h("tr", {}, h("td", {}, h("div", { class: "mono" }, c.endpoint), h("div", { class: "secondary-line mono" }, c.origin)), h("td", {}, c.role === "*" ? "Any role" : c.role), h("td", {}, c.test_type === "NONE" ? "No test record" : c.test_type),
        h("td", {}, c.reference_status ? chip(SKY_STATUS_CLS[c.reference_status], c.reference) : h("span", { class: "faint" }, "No cell")),
        h("td", {}, c.comparison_status ? chip(SKY_STATUS_CLS[c.comparison_status], c.comparison) : h("span", { class: "faint" }, "No cell")))),
      h("div", { class: "sky-none faint" }, "No coverage cell changed."))), { hint: d.wstg_version + " (heuristic mapping)" }),
    d.against_all_prior ? h("div", { class: "note" }, "Comparison scan relative to everything known before it (inventory): " +
      Object.entries(d.against_all_prior.by_kind).map(([k, v]) => `${KIND_ASSET_TR[k] || k} +${v.new} new, ${v.not_observed} not observed`).join(" · ")) : null);
}
