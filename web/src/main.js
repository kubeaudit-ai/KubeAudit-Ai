// KubeAudit AI web app: UI wiring. Scanning runs entirely in the browser.
import YAML from "https://cdn.jsdelivr.net/npm/yaml@2.5.1/browser/index.js";
import { createEngine, RULES, SEVERITY_ORDER } from "./engine.js";
import { createFixer, isAutoFixable } from "./fixer.js";
import { SAMPLES } from "./samples.js";

const engine = createEngine(YAML);
const fixer = createFixer(YAML, engine);

const SEVS = ["critical", "high", "medium", "low"];
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const WEIGHT = { critical: 25, high: 10, medium: 4, low: 1 };
const STORE_KEY = "kubeaudit.files.v1";
const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
// Inline `code` in rule text -> <code>
const md = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
const isTopLevel = (() => { try { return window.self === window.top; } catch { return false; } })();

// ---------------------------------------------------------------- state

const state = {
  files: [],          // [{ name, text }]
  active: 0,
  results: [],        // per file: { findings, resources, error, helm }
  selected: null,     // { file, line }
  tab: "findings",
  fixed: null,        // per active file: { text, changes, error }
};

function loadStored() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw);
    if (Array.isArray(v.files) && v.files.length && v.files.every((f) => typeof f.name === "string" && typeof f.text === "string")) return v;
  } catch { /* storage unavailable */ }
  return null;
}
function store() {
  try { localStorage.setItem(STORE_KEY, JSON.stringify({ files: state.files, active: state.active })); } catch { /* ignore */ }
}

// ---------------------------------------------------------------- scanning

function scanFile(f) {
  if (/\{\{/.test(f.text)) return { findings: [], resources: 0, helm: true };
  try {
    const r = engine.scanText(f.text, f.name);
    return { findings: r.findings, resources: r.resources };
  } catch (e) {
    return { findings: [], resources: 0, error: { message: e.message, line: e.line || 1 } };
  }
}

function scanAll() {
  state.results = state.files.map(scanFile);
  state.fixed = null;
  render();
}

function totals() {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  let resources = 0, findings = 0, errors = 0;
  state.results.forEach((r) => {
    resources += r.resources;
    if (r.error) errors++;
    r.findings.forEach((f) => { counts[f.rule.severity]++; findings++; });
  });
  const score = Math.max(0, 100 - SEVS.reduce((s, k) => s + counts[k] * WEIGHT[k], 0));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { counts, resources, findings, errors, score, grade };
}

// ---------------------------------------------------------------- editor

const editor = $("#editor");
const gutter = $("#gutter");
const band = $("#band");
let LINE_H = 20;

function measure() {
  const cs = getComputedStyle(editor);
  LINE_H = parseFloat(cs.lineHeight) || 20;
}

function renderGutter() {
  const f = state.files[state.active];
  const r = state.results[state.active] || { findings: [] };
  const lines = (f ? f.text : "").split("\n").length;
  const worst = new Map();
  r.findings.forEach((x) => {
    const cur = worst.get(x.line);
    if (!cur || SEVERITY_ORDER[x.rule.severity] > SEVERITY_ORDER[cur]) worst.set(x.line, x.rule.severity);
  });
  if (r.error) worst.set(r.error.line, "error");
  let html = "";
  for (let i = 1; i <= lines; i++) {
    const s = worst.get(i);
    html += s ? `<button type="button" class="ln mark ${s}" data-line="${i}" aria-label="Line ${i}: ${s} issue">${i}</button>` : `<span class="ln">${i}</span>`;
  }
  gutter.innerHTML = html;
  syncScroll();
  positionBand();
}

function syncScroll() {
  gutter.style.transform = `translateY(${-editor.scrollTop}px)`;
  positionBand();
}

function positionBand() {
  const sel = state.selected;
  if (!sel || sel.file !== state.active) { band.hidden = true; return; }
  band.hidden = false;
  const padTop = parseFloat(getComputedStyle(editor).paddingTop) || 0;
  band.style.transform = `translateY(${padTop + (sel.line - 1) * LINE_H - editor.scrollTop}px)`;
  band.style.height = `${LINE_H}px`;
}

function goToLine(fileIdx, line) {
  if (fileIdx !== state.active) { state.active = fileIdx; renderFileTabs(); editor.value = state.files[fileIdx].text; renderGutter(); }
  state.selected = { file: fileIdx, line };
  const target = Math.max(0, (line - 4) * LINE_H);
  editor.scrollTop = target;
  syncScroll();
  document.querySelectorAll(".finding.sel").forEach((n) => n.classList.remove("sel"));
  document.querySelectorAll(`.finding[data-file="${fileIdx}"][data-line="${line}"]`).forEach((n) => n.classList.add("sel"));
  if (window.matchMedia("(max-width: 980px)").matches) $("#manifest").scrollIntoView({ behavior: "smooth", block: "start" });
}

let timer = null;
editor.addEventListener("input", () => {
  state.files[state.active].text = editor.value;
  state.selected = null;
  renderGutter();
  clearTimeout(timer);
  timer = setTimeout(() => { scanAll(); store(); }, 220);
});
editor.addEventListener("scroll", syncScroll);
editor.addEventListener("keydown", (e) => {
  if (e.key === "Tab" && !e.shiftKey && !e.altKey && !e.metaKey && !e.ctrlKey) {
    e.preventDefault();
    const { selectionStart: s, selectionEnd: t } = editor;
    editor.setRangeText("  ", s, t, "end");
    editor.dispatchEvent(new Event("input"));
  }
});
gutter.addEventListener("click", (e) => {
  const b = e.target.closest(".mark");
  if (!b) return;
  const line = Number(b.dataset.line);
  goToLine(state.active, line);
  const row = document.querySelector(`.finding[data-file="${state.active}"][data-line="${line}"]`);
  if (row) { setTab("findings"); row.scrollIntoView({ behavior: "smooth", block: "nearest" }); row.querySelector("summary")?.focus(); }
});

// ---------------------------------------------------------------- files

function renderFileTabs() {
  const wrap = $("#filetabs");
  wrap.innerHTML = state.files.map((f, i) => {
    const r = state.results[i] || { findings: [] };
    const n = r.error ? "!" : r.findings.length;
    return `<div class="ftab${i === state.active ? " on" : ""}" role="presentation">
      <button type="button" class="fname" data-i="${i}" role="tab" aria-selected="${i === state.active}">${esc(f.name)}<span class="fcount">${n}</span></button>
      ${state.files.length > 1 ? `<button type="button" class="fclose" data-close="${i}" aria-label="Close ${esc(f.name)}">×</button>` : ""}
    </div>`;
  }).join("");
}

$("#filetabs").addEventListener("click", (e) => {
  const close = e.target.closest("[data-close]");
  if (close) {
    const i = Number(close.dataset.close);
    state.files.splice(i, 1);
    state.active = Math.min(state.active, state.files.length - 1);
    if (state.active > i) state.active--;
    state.selected = null;
    openActive(); scanAll(); store();
    return;
  }
  const b = e.target.closest("[data-i]");
  if (!b) return;
  state.active = Number(b.dataset.i);
  state.selected = null;
  openActive(); render();
});

function openActive() {
  editor.value = state.files[state.active]?.text ?? "";
  editor.scrollTop = 0;
  renderFileTabs(); renderGutter();
}

function setFiles(files) {
  state.files = files;
  state.active = 0;
  state.selected = null;
  state.tab = "findings";
  openActive(); scanAll(); store();
}

async function readFiles(list) {
  const picked = [...list].filter((f) => /\.(ya?ml|json)$/i.test(f.name) || f.type.includes("yaml"));
  if (!picked.length) { toast("Choose .yaml or .yml files."); return; }
  const tooBig = picked.find((f) => f.size > 5 * 1024 * 1024);
  if (tooBig) { toast(`${tooBig.name} is larger than 5 MB.`); return; }
  const files = await Promise.all(picked.map(async (f) => ({ name: f.name, text: await f.text() })));
  setFiles(files);
  toast(`Loaded ${files.length} file${files.length > 1 ? "s" : ""}.`);
}

$("#upload").addEventListener("change", (e) => { readFiles(e.target.files); e.target.value = ""; });
const dropzone = $("#manifest");
["dragenter", "dragover"].forEach((t) => dropzone.addEventListener(t, (e) => { e.preventDefault(); dropzone.classList.add("drag"); }));
["dragleave", "drop"].forEach((t) => dropzone.addEventListener(t, (e) => { e.preventDefault(); if (t === "dragleave" && dropzone.contains(e.relatedTarget)) return; dropzone.classList.remove("drag"); }));
dropzone.addEventListener("drop", (e) => { if (e.dataTransfer?.files?.length) readFiles(e.dataTransfer.files); });

$("#sample").addEventListener("change", (e) => {
  const s = SAMPLES.find((x) => x.id === e.target.value);
  if (s) setFiles([{ name: s.name, text: s.text }]);
  e.target.value = "";
});
$("#clear").addEventListener("click", () => {
  setFiles([{ name: "manifest.yaml", text: "" }]);
  editor.focus();
});

// ---------------------------------------------------------------- results

function renderSummary() {
  const t = totals();
  const empty = !state.files.some((f) => f.text.trim());
  const fail = t.counts.critical + t.counts.high > 0;
  $("#score").textContent = empty ? "–" : String(t.score);
  $("#grade").textContent = empty ? "" : t.grade;
  $("#scorecard").dataset.grade = empty ? "" : t.grade;
  $("#meter-fill").style.width = `${empty ? 0 : t.score}%`;
  $("#chips").innerHTML = SEVS.map((s) =>
    `<li class="chip ${s}${t.counts[s] ? "" : " zero"}"><span class="n">${t.counts[s]}</span> ${SEV_LABEL[s]}</li>`).join("");
  const verdict = $("#verdict");
  if (empty) {
    verdict.className = "verdict idle";
    verdict.innerHTML = `<span class="v-k">status</span><span class="v-v">waiting for YAML</span>`;
  } else if (t.errors) {
    verdict.className = "verdict warn";
    verdict.innerHTML = `<span class="v-k">status</span><span class="v-v">fix the YAML error to finish scanning</span>`;
  } else {
    verdict.className = `verdict ${fail ? "fail" : "pass"}`;
    verdict.innerHTML = `<span class="v-k">PR check (fail-on: high)</span><span class="v-v">${fail ? "would fail" : "would pass"}</span>`;
  }
  $("#scanned").textContent = empty ? "Paste or upload Kubernetes YAML to start."
    : `${t.resources} resource${t.resources === 1 ? "" : "s"} in ${state.files.length} file${state.files.length === 1 ? "" : "s"} · ${t.findings} finding${t.findings === 1 ? "" : "s"}`;
}

function renderFindings() {
  const box = $("#findings");
  const parts = [];
  state.results.forEach((r, fi) => {
    const f = state.files[fi];
    if (r.helm) parts.push(`<div class="notice">${esc(f.name)} looks like a Helm template (it contains <code>{{ }}</code>). Render it first with <code>helm template</code>, or use the GitHub Action, which renders charts for you.</div>`);
    if (r.error) parts.push(`<div class="notice err"><strong>${esc(f.name)}, line ${r.error.line}:</strong> ${esc(r.error.message)}<button type="button" class="linkbtn" data-goto="${fi}:${r.error.line}">Show line</button></div>`);
  });
  const all = state.results.flatMap((r, fi) => r.findings.map((x) => ({ ...x, fi })));
  if (!all.length) {
    const any = state.files.some((f) => f.text.trim());
    const ok = any && !state.results.some((r) => r.error || r.helm) && state.results.some((r) => r.resources);
    if (ok) parts.push(`<div class="clean"><strong>No issues found.</strong> Every workload follows all 15 rules.</div>`);
    else if (any && !state.results.some((r) => r.resources || r.error || r.helm)) parts.push(`<div class="notice">No Kubernetes resources found. Each document needs <code>apiVersion</code> and <code>kind</code>.</div>`);
    box.innerHTML = parts.join("");
    return;
  }
  const groups = new Map();
  for (const x of all) {
    const key = `${x.fi}\u0000${x.resource}`;
    if (!groups.has(key)) groups.set(key, { fi: x.fi, resource: x.resource, items: [] });
    groups.get(key).items.push(x);
  }
  const sorted = [...groups.values()].sort((a, b) =>
    Math.max(...b.items.map((i) => SEVERITY_ORDER[i.rule.severity])) - Math.max(...a.items.map((i) => SEVERITY_ORDER[i.rule.severity])));
  for (const g of sorted) {
    const [kind, ...rest] = g.resource.split("/");
    parts.push(`<section class="res"><h3><span><span class="kind">${esc(kind)}</span>/${esc(rest.join("/"))}</span>${state.files.length > 1 ? `<span class="infile">${esc(state.files[g.fi].name)}</span>` : ""}</h3><ul>`);
    for (const x of g.items) {
      const auto = isAutoFixable(x.rule.id);
      parts.push(`<li class="finding ${x.rule.severity}" data-file="${g.fi}" data-line="${x.line}">
        <details>
          <summary>
            <span class="sev">${SEV_LABEL[x.rule.severity]}</span>
            <span class="rid">${x.rule.id}</span>
            <span class="ttl">${md(x.rule.title)}</span>
            <button type="button" class="lnk" data-goto="${g.fi}:${x.line}" aria-label="Show line ${x.line}">L${x.line}</button>
          </summary>
          <div class="body">
            <p class="msg">${md(x.message)}</p>
            <p>${md(x.rule.remediation)}</p>
            <pre class="snip"><code>${esc(x.rule.fix)}</code></pre>
            <p class="meta"><span class="tag ${auto ? "auto" : "manual"}">${auto ? "Auto-fix available" : "Needs your decision"}</span>
            <a href="${esc(x.rule.docs)}" target="_blank" rel="noopener">Kubernetes docs</a></p>
          </div>
        </details>
      </li>`);
    }
    parts.push(`</ul></section>`);
  }
  box.innerHTML = parts.join("");
}

document.addEventListener("click", (e) => {
  const g = e.target.closest("[data-goto]");
  if (!g) return;
  e.preventDefault();
  e.stopPropagation();
  const [fi, line] = g.dataset.goto.split(":").map(Number);
  goToLine(fi, line);
});

// ---------------------------------------------------------------- fixed YAML

function lineDiff(a, b) {
  // Marks lines of b that are not part of the longest common subsequence with a.
  const n = a.length, m = b.length;
  if (n * m > 4e7) return null;
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--)
    dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const changed = new Set();
  let i = 0, j = 0;
  while (j < m) {
    if (i < n && a[i] === b[j]) { i++; j++; }
    else if (i < n && dp[i + 1][j] >= dp[i][j + 1]) i++;
    else { changed.add(j); j++; }
  }
  return changed;
}

function computeFix() {
  const f = state.files[state.active];
  const r = state.results[state.active];
  if (!f || !f.text.trim() || r?.error || r?.helm) { state.fixed = { text: "", changes: [], error: r?.error ? "Fix the YAML error first." : r?.helm ? "Helm templates can't be fixed here. Render the chart first." : "Nothing to fix yet." }; return; }
  try {
    const out = fixer.fixText(f.text);
    const after = engine.scanText(out.text, f.name);
    state.fixed = { ...out, after, before: r };
  } catch (e) {
    state.fixed = { text: "", changes: [], error: e.message };
  }
}

function renderFixed() {
  if (!state.fixed) computeFix();
  const fx = state.fixed;
  const box = $("#fixed");
  if (fx.error) { box.innerHTML = `<div class="notice">${esc(fx.error)}</div>`; return; }
  const f = state.files[state.active];
  const remaining = fx.after.findings;
  const scoreOf = (list) => Math.max(0, 100 - list.reduce((s, x) => s + WEIGHT[x.rule.severity], 0));
  const before = scoreOf(fx.before.findings), after = scoreOf(remaining);
  const changed = lineDiff(f.text.split("\n"), fx.text.split("\n"));
  const lines = fx.text.replace(/\n$/, "").split("\n");
  const manual = [...new Map(remaining.map((x) => [x.rule.id, x.rule])).values()];
  box.innerHTML = `
    <div class="fixhead">
      <div class="delta"><span class="b">${before}</span><span class="arrow" aria-hidden="true">→</span><span class="a">${after}</span><span class="cap">score for ${esc(f.name)}</span></div>
      <div class="actions">
        <button type="button" class="btn primary" id="apply">Use fixed version</button>
        <button type="button" class="btn" id="copyfix">Copy YAML</button>
        ${isTopLevel ? `<button type="button" class="btn" id="dlfix">Download</button>` : ""}
      </div>
    </div>
    ${fx.changes.length ? `<details class="changes"><summary>${fx.changes.length} change${fx.changes.length === 1 ? "" : "s"} applied</summary><ul>${fx.changes.map((c) => `<li>${esc(c)}</li>`).join("")}</ul></details>` : `<p class="muted">No automatic changes were needed.</p>`}
    ${manual.length ? `<div class="manual"><strong>Still needs your decision:</strong><ul>${manual.map((r) => `<li><span class="rid">${r.id}</span> ${md(r.title)}. ${md(r.remediation)}</li>`).join("")}</ul></div>` : ""}
    <div class="codeview" role="region" aria-label="Fixed YAML" tabindex="0"><pre>${lines.map((l, i) =>
      `<span class="cl${changed && changed.has(i) ? " add" : ""}"><span class="cn">${i + 1}</span>${esc(l) || " "}</span>`).join("\n")}</pre></div>
    <p class="muted small">Highlighted lines were added or changed. Comments and the rest of your file are kept as they were. Review resource sizes and read-only filesystems before deploying.</p>`;
  $("#apply").addEventListener("click", () => {
    state.files[state.active].text = fx.text;
    openActive(); scanAll(); store(); setTab("findings");
    toast("Fixed version loaded into the editor.");
  });
  $("#copyfix").addEventListener("click", (e) => copyText(fx.text, e.currentTarget));
  $("#dlfix")?.addEventListener("click", () => download(fx.text, f.name.replace(/(\.ya?ml)?$/i, ".fixed.yaml")));
}

// ---------------------------------------------------------------- rules tab

function renderRules() {
  $("#rules").innerHTML = `<div class="tablewrap"><table><thead><tr><th>ID</th><th>Severity</th><th>Checks for</th><th>Fix</th></tr></thead><tbody>${
    Object.values(RULES).map((r) => `<tr><td class="rid">${r.id}</td><td><span class="pill ${r.severity}">${SEV_LABEL[r.severity]}</span></td><td><strong>${md(r.title)}</strong><br><span class="muted">${md(r.remediation)}</span></td><td>${isAutoFixable(r.id) ? "Automatic" : "Manual"}</td></tr>`).join("")
  }</tbody></table></div>
  <p class="muted small">Skip a rule for one resource with the annotation <code>kubeaudit.ai/ignore: "KA010"</code> (or <code>"all"</code>).</p>`;
}

// ---------------------------------------------------------------- report, copy, download

function markdownReport() {
  const t = totals();
  const lines = [`# KubeAudit AI report`, ``, `Score **${t.score}/100 (${t.grade})** · ${t.resources} resources · ${t.findings} findings`, ``,
    `| Severity | Count |`, `|---|---:|`, ...SEVS.map((s) => `| ${SEV_LABEL[s]} | ${t.counts[s]} |`), ``];
  state.results.forEach((r, fi) => {
    if (!r.findings.length) return;
    lines.push(`## ${state.files[fi].name}`, "");
    for (const x of r.findings) lines.push(`- **${x.rule.id}** ${SEV_LABEL[x.rule.severity]}, line ${x.line}: ${x.message}  \n  Fix: ${x.rule.remediation}`);
    lines.push("");
  });
  return lines.join("\n");
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    toast("Copied.");
    if (btn) { const o = btn.textContent; btn.textContent = "Copied"; setTimeout(() => (btn.textContent = o), 1400); }
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text; ta.setAttribute("readonly", ""); ta.className = "copybuf";
    document.body.appendChild(ta); ta.select();
    toast("Press Ctrl+C (or ⌘C) to copy.");
    setTimeout(() => ta.remove(), 8000);
  }
}

function download(text, name) {
  const url = URL.createObjectURL(new Blob([text], { type: "application/yaml" }));
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

$("#copyreport").addEventListener("click", (e) => copyText(markdownReport(), e.currentTarget));

let toastTimer = null;
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), 2600);
}

// ---------------------------------------------------------------- tabs + render

function setTab(tab) {
  state.tab = tab;
  document.querySelectorAll(".tabs [role=tab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === tab)));
  document.querySelectorAll(".panel").forEach((p) => (p.hidden = p.id !== tab));
  if (tab === "fixed") renderFixed();
}
document.querySelector(".tabs").addEventListener("click", (e) => {
  const b = e.target.closest("[data-tab]");
  if (b) setTab(b.dataset.tab);
});

function render() {
  renderFileTabs(); renderGutter(); renderSummary(); renderFindings();
  if (state.tab === "fixed") renderFixed();
}

// ---------------------------------------------------------------- boot

$("#sample").innerHTML = `<option value="">Examples…</option>` + SAMPLES.map((s) => `<option value="${s.id}">${esc(s.label)}</option>`).join("");
renderRules();
measure();
window.addEventListener("resize", () => { measure(); positionBand(); });
const saved = loadStored();
if (saved) {
  state.files = saved.files;
  state.active = Math.min(saved.active || 0, saved.files.length - 1);
  openActive(); scanAll();
} else {
  setFiles([{ name: SAMPLES[0].name, text: SAMPLES[0].text }]);
}
document.body.classList.add("ready");
