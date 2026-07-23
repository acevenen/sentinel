"use strict";

const TOKEN = window.SENTINEL_TOKEN || "";

// --- helpers ---------------------------------------------------------------

function $(sel, root) { return (root || document).querySelector(sel); }
function $all(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }
function el(tag, attrs, children) {
  const n = document.createElement(tag);
  if (attrs) for (const k in attrs) {
    if (k === "class") n.className = attrs[k];
    else if (k === "html") n.innerHTML = attrs[k];
    else n.setAttribute(k, attrs[k]);
  }
  (children || []).forEach(c => n.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
  return n;
}
function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }

async function api(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Sentinel-Token": TOKEN },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) throw new Error("request failed (" + res.status + ")");
  return res.json();
}
async function sample(which) { const r = await api("/api/samples", { which }); return r.content || ""; }

// --- navigation ------------------------------------------------------------

function showView(name) {
  $all(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.view === name));
  $all(".view").forEach(v => v.classList.toggle("active", v.dataset.view === name));
  $(".main").scrollTop = 0;
}
$all(".nav-item").forEach(b => b.addEventListener("click", () => showView(b.dataset.view)));
$all("[data-goto]").forEach(c => c.addEventListener("click", () => showView(c.dataset.goto)));

// segmented (hunt sub-tabs)
$all("#hunt-tabs .seg").forEach(s => s.addEventListener("click", () => {
  $all("#hunt-tabs .seg").forEach(x => x.classList.toggle("active", x === s));
  $all('.huntview').forEach(v => v.classList.toggle("active", v.dataset.huntview === s.dataset.huntview));
}));

// --- Hunt: import ----------------------------------------------------------

$("#import-sample").addEventListener("click", async () => {
  $("#import-har").value = await sample("hunt-har");
  if (!$("#import-identity").value) $("#import-identity").value = "alice";
});

// drag & drop a .har file
const harBox = $("#import-har");
harBox.addEventListener("dragover", e => { e.preventDefault(); });
harBox.addEventListener("drop", e => {
  e.preventDefault();
  const f = e.dataTransfer.files[0];
  if (f) { const rd = new FileReader(); rd.onload = () => { harBox.value = rd.result; }; rd.readAsText(f); }
});

$("#import-run").addEventListener("click", async () => {
  const msg = $("#import-msg");
  msg.className = "msg"; msg.textContent = "";
  const identity = $("#import-identity").value.trim();
  const har = $("#import-har").value.trim();
  if (!identity || !har) { msg.className = "msg err"; msg.textContent = "Identity and HAR are both required."; return; }
  try {
    const body = { har, identity };
    if ($("#import-merge").checked) body.program = $("#program-yaml").value;
    const r = await api("/api/hunt/import", body);
    if (r.error) { msg.className = "msg err"; msg.textContent = r.error; return; }
    $("#program-yaml").value = r.program_yaml;
    msg.className = "msg ok";
    msg.textContent = "Generated " + r.endpoints + " endpoint template(s). Switched to the Manifest tab.";
    $all("#hunt-tabs .seg").forEach(x => x.classList.toggle("active", x.dataset.huntview === "program"));
    $all('.huntview').forEach(v => v.classList.toggle("active", v.dataset.huntview === "program"));
  } catch (e) { msg.className = "msg err"; msg.textContent = String(e.message || e); }
});

$("#program-sample").addEventListener("click", async () => { $("#program-yaml").value = await sample("hunt-program"); });

// --- Hunt: dry-run & run ---------------------------------------------------

function parseIdentities(yamlText) {
  // light client-side scan of "name:" under identities, to render token fields.
  const names = [];
  const lines = yamlText.split("\n");
  let inIds = false;
  for (const line of lines) {
    if (/^identities:/.test(line)) { inIds = true; continue; }
    if (inIds && /^\S/.test(line)) inIds = false;
    if (inIds) { const m = line.match(/name:\s*([A-Za-z0-9_.-]+)/); if (m) names.push(m[1]); }
  }
  return names;
}
function renderTokenFields() {
  const names = parseIdentities($("#program-yaml").value);
  const box = $("#token-fields"); box.innerHTML = "";
  if (names.length === 0) { box.appendChild(el("div", { class: "hint" }, ["Add a manifest with identities to enter session tokens."])); return; }
  box.appendChild(el("div", { class: "hint" }, ["Session tokens are used only for this run — never stored."]));
  names.forEach(n => {
    const inp = el("input", { type: "password", id: "tok-" + n, placeholder: "session token for " + n });
    box.appendChild(el("div", { class: "tf" }, [el("label", {}, [n]), inp]));
  });
}
// refresh token fields whenever the run tab opens
$all('#hunt-tabs .seg').forEach(s => s.addEventListener("click", () => { if (s.dataset.huntview === "run") renderTokenFields(); }));

$("#hunt-dryrun").addEventListener("click", async () => {
  const out = $("#hunt-result"); out.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await api("/api/hunt/plan", { program: $("#program-yaml").value });
    if (r.error) { out.innerHTML = ""; out.appendChild(el("div", { class: "msg err" }, [r.error])); return; }
    const steps = r.steps || [];
    const rows = steps.map(s => `<tr><td>${esc(s.Kind)}</td><td>${esc(s.Method)}</td><td>${esc(s.Identity)}</td>` +
      `<td><span class="pill ${s.InScope ? "pass" : "fail"}">${s.InScope ? "in-scope" : "OUT-OF-SCOPE"}</span></td>` +
      `<td class="mono">${esc(s.URL)}</td></tr>`).join("");
    const refused = steps.filter(s => !s.InScope).length;
    out.innerHTML = `<div class="msg">${steps.length} request(s) planned, ${refused} refused as out of scope. Nothing was sent.</div>` +
      `<table class="grid"><thead><tr><th>Kind</th><th>Method</th><th>As</th><th>Scope</th><th>URL</th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) { out.innerHTML = ""; out.appendChild(el("div", { class: "msg err" }, [String(e.message || e)])); }
});

$("#hunt-run").addEventListener("click", async () => {
  const out = $("#hunt-result"); out.innerHTML = '<span class="spinner"></span> testing…';
  const tokens = {};
  parseIdentities($("#program-yaml").value).forEach(n => { const f = $("#tok-" + n); if (f) tokens[n] = f.value; });
  try {
    const r = await api("/api/hunt/run", { program: $("#program-yaml").value, tokens });
    if (r.error) { out.innerHTML = ""; out.appendChild(el("div", { class: "msg err" }, [r.error])); return; }
    renderHuntReport(out, r.report, r.markdown);
  } catch (e) { out.innerHTML = ""; out.appendChild(el("div", { class: "msg err" }, [String(e.message || e)])); }
});

function renderHuntReport(out, rep, markdown) {
  out.innerHTML = "";
  const findings = rep.Findings || [];
  out.appendChild(el("div", { class: "msg" }, [
    `${rep.TestsRun || 0} authorization test(s) run, ${rep.BaselinesRun || 0} baseline(s)` +
    (rep.OutOfScopeSkipped ? `, ${rep.OutOfScopeSkipped} out-of-scope refused` : "") + "."]));
  if (findings.length === 0) {
    out.appendChild(el("div", { class: "empty-good" }, ["✓ No broken object-level authorization in the tested endpoints."]));
    return;
  }
  out.appendChild(el("div", { html: `<b style="color:var(--red)">✗ ${findings.length} BOLA/IDOR finding(s)</b>` }));
  findings.forEach(f => {
    const node = el("div", { class: "finding" });
    node.innerHTML = `<h4><span class="badge ${esc((f.Severity||"high").toLowerCase())}">${esc((f.Severity||"high").toUpperCase())}</span> ${esc(f.RequestID)}</h4>` +
      `<div class="mono">${esc(f.Method)} ${esc(f.Endpoint)}</div>` +
      `<div>${esc(f.Attacker)} → ${esc(f.Victim)}'s object ${esc(f.ObjectID)}</div>` +
      `<div class="ev">${esc(f.Evidence)}</div>`;
    out.appendChild(node);
  });
  if (markdown) {
    const wrap = el("div", { class: "md-out" });
    const ta = el("textarea", { class: "mono", rows: "10", readonly: "" }); ta.value = markdown;
    const btn = el("button", { class: "btn copy-btn" }, ["Copy report"]);
    btn.addEventListener("click", () => { ta.select(); document.execCommand("copy"); btn.textContent = "Copied ✓"; setTimeout(() => btn.textContent = "Copy report", 1400); });
    wrap.appendChild(el("label", { class: "field" }, ["HackerOne-ready report"]));
    wrap.appendChild(ta); wrap.appendChild(btn);
    out.appendChild(wrap);
  }
}

// --- Evaluate --------------------------------------------------------------

$("#eval-sample").addEventListener("click", async () => { $("#eval-agent").value = await sample("evaluate-agent"); });
$("#eval-run").addEventListener("click", async () => {
  const out = $("#eval-result"); out.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await api("/api/evaluate", { agent: $("#eval-agent").value });
    if (r.error) { out.innerHTML = ""; out.appendChild(el("div", { class: "msg err" }, [r.error])); return; }
    renderEval(out, r.report);
  } catch (e) { out.innerHTML = ""; out.appendChild(el("div", { class: "msg err" }, [String(e.message || e)])); }
});

function renderEval(out, rep) {
  out.innerHTML = "";
  const rec = (rep.Recommendation || "").toLowerCase().replace(/[^a-z]/g, "");
  const badgeClass = rec.indexOf("approved") === 0 ? "approved" : rec.indexOf("notapproved") === 0 ? "rejected" : "conditional";
  const banner = el("div", { class: "score-banner" });
  banner.innerHTML = `<div class="score-num">${rep.Score}<span style="font-size:16px;color:var(--text-2)">/100</span></div>` +
    `<div><div><span class="badge ${badgeClass}">${esc(rep.Recommendation)}</span></div>` +
    `<div class="hint" style="margin-top:6px">Permission risk ${rep.PermissionRisk ? rep.PermissionRisk.Score : 0}/100 · ${rep.JudgeActive ? "Layer 3 judge active" : "Layer 3 inactive (no API key)"}</div></div>`;
  out.appendChild(banner);

  const rows = (rep.Results || []).map(r => {
    const oc = (r.Outcome || "").toLowerCase();
    const cls = (oc === "defended" || oc === "clean") ? "pass" : (oc === "not-evaluated" ? "skip" : "fail");
    return `<tr><td>${esc(r.Scenario.ID)}</td><td>${esc(r.Scenario.Category)}</td><td><span class="pill ${cls}">${esc(r.Outcome)}</span></td><td>${esc((r.CaughtBy||[]).join(", "))}</td></tr>`;
  }).join("");
  out.appendChild(el("div", { html: `<table class="grid"><thead><tr><th>Scenario</th><th>Category</th><th>Outcome</th><th>Caught by</th></tr></thead><tbody>${rows}</tbody></table>` }));
}

// --- Guard -----------------------------------------------------------------

$("#guard-intent-sample").addEventListener("click", async () => { $("#guard-intent").value = await sample("guard-intent"); });
$("#guard-stream-sample").addEventListener("click", async () => { $("#guard-stream").value = await sample("guard-stream"); });
$("#guard-run").addEventListener("click", async () => {
  const out = $("#guard-result"); out.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await api("/api/guard", { intent: $("#guard-intent").value, stream: $("#guard-stream").value });
    if (r.error) { out.innerHTML = ""; out.appendChild(el("div", { class: "msg err" }, [r.error])); return; }
    renderGuard(out, r.session);
  } catch (e) { out.innerHTML = ""; out.appendChild(el("div", { class: "msg err" }, [String(e.message || e)])); }
});

function renderGuard(out, s) {
  out.innerHTML = "";
  const b = el("div", { class: "score-banner" });
  b.innerHTML = s.Blocked
    ? `<div><span class="badge blocked">SESSION BLOCKED</span></div><div class="hint" style="margin-top:6px">At least one action failed the guard (fail-closed).</div>`
    : `<div><span class="badge clean">SESSION CLEAN</span></div><div class="hint" style="margin-top:6px">No blocking findings.</div>`;
  out.appendChild(b);
  const rows = (s.Results || []).map(r => {
    const v = (r.Verdict || "allow").toLowerCase();
    const dets = (r.Detectors || []).map(d => d.Detector).filter((x, i, a) => a.indexOf(x) === i).join(", ");
    return `<tr><td>${r.Seq}</td><td>${esc(r.Type)}</td><td>${esc(dets || "—")}</td><td><span class="badge ${v}">${esc(r.Verdict.toUpperCase())}</span></td></tr>`;
  }).join("");
  out.appendChild(el("div", { html: `<table class="grid"><thead><tr><th>#</th><th>Event</th><th>Detectors</th><th>Verdict</th></tr></thead><tbody>${rows}</tbody></table>` }));
  if (s.Drift) out.appendChild(el("div", { class: "hint" }, [`Layer 4 drift: score ${(s.Drift.Score||0).toFixed(2)} — ${s.Drift.Headline || ""}`]));
}

// --- footer + illustrations ------------------------------------------------

fetch("/api/samples", { method: "POST", headers: { "Content-Type": "application/json", "X-Sentinel-Token": TOKEN }, body: "{}" })
  .catch(() => {}); // warm the token path

renderStepArt();
function art(id, svg) { const n = document.getElementById(id); if (n) n.innerHTML = svg; }
function renderStepArt() {
  const A = "var(--accent)", G = "var(--text-2)", L = "var(--line-strong)", P = "var(--panel)";
  art("art-capture", `<svg viewBox="0 0 520 120"><rect x="14" y="14" width="230" height="92" rx="8" fill="${P}" stroke="${L}"/><rect x="14" y="14" width="230" height="20" rx="8" fill="${A}" opacity="0.14"/><circle cx="28" cy="24" r="3" fill="${A}"/><circle cx="40" cy="24" r="3" fill="${G}"/><text x="30" y="56" font-size="11" fill="${G}">Network ▾</text><rect x="30" y="66" width="196" height="9" rx="3" fill="${A}" opacity="0.5"/><rect x="30" y="82" width="150" height="9" rx="3" fill="${G}" opacity="0.4"/><path d="M262 60 h34" stroke="${G}" stroke-width="2" marker-end="url(#a)"/><rect x="306" y="30" width="200" height="60" rx="8" fill="${P}" stroke="${L}"/><text x="406" y="58" font-size="13" fill="${A}" text-anchor="middle" font-weight="600">alice.har</text><text x="406" y="76" font-size="10" fill="${G}" text-anchor="middle">Save all as HAR</text><defs><marker id="a" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0 0 L6 3 L0 6" fill="${G}"/></marker></defs></svg>`);
  art("art-import", `<svg viewBox="0 0 520 110"><rect x="14" y="26" width="150" height="58" rx="8" fill="${P}" stroke="${L}"/><text x="89" y="52" font-size="11" fill="${G}" text-anchor="middle">/orders/1001</text><text x="89" y="70" font-size="11" fill="${G}" text-anchor="middle">/orders/1002</text><path d="M176 55 h40" stroke="${G}" stroke-width="2" marker-end="url(#b)"/><rect x="226" y="20" width="280" height="70" rx="8" fill="${P}" stroke="${A}"/><text x="366" y="46" font-size="12" fill="${A}" text-anchor="middle" font-weight="600">/orders/{id}</text><text x="366" y="66" font-size="10" fill="${G}" text-anchor="middle">owned: alice [1001, 1002]</text><defs><marker id="b" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0 0 L6 3 L0 6" fill="${G}"/></marker></defs></svg>`);
  art("art-scope", `<svg viewBox="0 0 520 110"><text x="30" y="34" font-size="12" fill="${G}">api.example.com</text><rect x="150" y="22" width="70" height="18" rx="9" fill="${A}" opacity="0.16"/><text x="185" y="35" font-size="10" fill="${A}" text-anchor="middle" font-weight="600">in-scope</text><text x="30" y="72" font-size="12" fill="${G}">evil.example</text><rect x="150" y="60" width="90" height="18" rx="9" fill="${G}" opacity="0.12"/><text x="195" y="73" font-size="10" fill="var(--red)" text-anchor="middle" font-weight="600">refused</text><path d="M300 50 l16 16 l28 -34" stroke="var(--green)" stroke-width="4" fill="none" stroke-linecap="round" stroke-linejoin="round"/><text x="380" y="55" font-size="11" fill="${G}">fail-closed gate</text></svg>`);
  art("art-tokens", `<svg viewBox="0 0 520 100"><rect x="14" y="26" width="240" height="48" rx="8" fill="${P}" stroke="${L}"/><text x="30" y="46" font-size="11" fill="${G}">alice</text><rect x="80" y="36" width="160" height="16" rx="4" fill="${A}" opacity="0.35"/><text x="30" y="66" font-size="11" fill="${G}">bob</text><rect x="80" y="56" width="160" height="16" rx="4" fill="${A}" opacity="0.35"/><text x="290" y="46" font-size="11" fill="${G}">in memory only</text><text x="290" y="64" font-size="11" fill="${G}">never written to disk</text></svg>`);
  art("art-run", `<svg viewBox="0 0 520 110"><rect x="14" y="20" width="150" height="70" rx="8" fill="${P}" stroke="${L}"/><text x="89" y="44" font-size="11" fill="${G}" text-anchor="middle">alice's session</text><text x="89" y="64" font-size="11" fill="${G}" text-anchor="middle">GET /orders/2002</text><path d="M176 55 h36" stroke="${G}" stroke-width="2" marker-end="url(#c)"/><rect x="222" y="20" width="284" height="70" rx="8" fill="${P}" stroke="var(--red)"/><text x="364" y="45" font-size="12" fill="var(--red)" text-anchor="middle" font-weight="700">BOLA confirmed</text><text x="364" y="66" font-size="10" fill="${G}" text-anchor="middle">alice received bob's object</text><defs><marker id="c" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0 0 L6 3 L0 6" fill="${G}"/></marker></defs></svg>`);
}
