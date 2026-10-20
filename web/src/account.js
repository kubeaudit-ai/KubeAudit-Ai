// Accounts: sign-in (GitHub, email link), Pro upgrade, API key, saved history, shared reports, rule settings.
// The API address is fixed at build time (never read from the URL) so a crafted link
// can't redirect sign-in tokens to another server.
/* global __API_URL__ */
const API = typeof __API_URL__ === "string" ? __API_URL__ : "https://kubeaudit-ai-production.up.railway.app";
const TOKEN_KEY = "kubeaudit.session.v1";
const SEVS = ["critical", "high", "medium", "low"];

export function initAccount(app) {
  const { esc, md, toast, copyText, RULES, SEV_LABEL } = app;
  const $ = (s, root = document) => root.querySelector(s);
  const acct = { token: null, me: null, providers: null };

  // ---------------------------------------------------------------- storage + API

  const getToken = () => { try { return localStorage.getItem(TOKEN_KEY); } catch { return null; } };
  const setToken = (t) => { acct.token = t; try { t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ } };

  async function api(path, { method = "GET", body } = {}) {
    let res;
    try {
      res = await fetch(API + path, {
        method,
        headers: { ...(body ? { "Content-Type": "application/json" } : {}), ...(acct.token ? { Authorization: `Bearer ${acct.token}` } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch {
      const err = new Error("Can't reach the KubeAudit server. Check your connection and try again.");
      err.status = 0;
      throw err;
    }
    if (res.status === 204) return null;
    let data = null;
    try { data = await res.json(); } catch { /* empty body */ }
    if (!res.ok) {
      const d = data && data.detail;
      const msg = Array.isArray(d) ? d.map((x) => (x.msg || "").replace(/^Value error, /, "")).join(" ") : (d || `Request failed (${res.status}).`);
      const err = new Error(msg);
      err.status = res.status;
      if (res.status === 401 && acct.token) { setToken(null); acct.me = null; renderHeader(); }
      throw err;
    }
    return data;
  }

  // ---------------------------------------------------------------- header button

  const slot = $("#acct");
  function renderHeader() {
    if (!acct.me) {
      slot.innerHTML = `<button type="button" class="btn" id="signin">Sign in</button>`;
      $("#signin").addEventListener("click", openSignIn);
      return;
    }
    const m = acct.me;
    const initial = esc((m.name || m.email || "?").trim().charAt(0).toUpperCase());
    slot.innerHTML = `<button type="button" class="acctbtn" id="openacct" aria-label="Account">
      ${m.avatar_url ? `<img src="${esc(m.avatar_url)}" alt="" width="28" height="28">` : `<span class="avatar">${initial}</span>`}
      <span class="who">${esc(m.name || m.email)}</span>${m.plan === "pro" ? `<span class="pro">Pro</span>` : ""}</button>`;
    $("#openacct").addEventListener("click", () => openAccount());
  }

  // ---------------------------------------------------------------- dialogs

  function dialog(id, html, { wide = false } = {}) {
    let d = document.getElementById(id);
    if (!d) {
      d = document.createElement("dialog");
      d.id = id;
      d.className = `dlg${wide ? " wide" : ""}`;
      d.addEventListener("click", (e) => { if (e.target === d) d.close(); });
      document.body.appendChild(d);
    }
    d.innerHTML = `<div class="dlg-in"><button type="button" class="x" aria-label="Close">×</button>${html}</div>`;
    $(".x", d).addEventListener("click", () => d.close());
    if (!d.open) d.showModal();
    return d;
  }

  async function providers() {
    if (!acct.providers) {
      try { acct.providers = await api("/v1/auth/providers"); } catch { acct.providers = { github: false, email: false, billing: false }; }
    }
    return acct.providers;
  }

  async function openSignIn(reason) {
    const p = await providers();
    const d = dialog("dlg-signin", `
      <h2>Sign in to KubeAudit AI</h2>
      <p class="muted">${esc(typeof reason === "string" ? reason : "Save your scans, share reports with your team, and get an API key for CI.")}</p>
      <div class="stack">
        ${p.github ? `<a class="btn gh" href="${esc(API)}/v1/auth/github/start"><svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8a8 8 0 0 0 5.47 7.59c.4.07.55-.17.55-.38v-1.33c-2.23.48-2.7-1.07-2.7-1.07-.36-.92-.89-1.17-.89-1.17-.73-.5.06-.49.06-.49.8.06 1.23.83 1.23.83.72 1.22 1.88.87 2.34.66.07-.52.28-.87.5-1.07-1.78-.2-3.65-.89-3.65-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48v2.2c0 .21.15.46.55.38A8 8 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>Continue with GitHub</a>` : ""}
        ${p.github && p.email ? `<div class="or"><span>or</span></div>` : ""}
        ${p.email ? `<form id="emailform" class="stack" novalidate>
          <label for="email-in">Email</label>
          <input id="email-in" type="email" autocomplete="email" required placeholder="you@company.com">
          <button type="submit" class="btn primary">Email me a sign-in link</button>
          <p class="err" id="email-err" hidden></p>
        </form>` : ""}
        ${!p.github && !p.email ? `<p class="notice">Sign-in isn't available right now. You can keep using the scanner without an account.</p>` : ""}
      </div>
      <p class="muted small">Scanning stays in your browser. An account only stores what you choose to save.</p>`);
    const form = $("#emailform", d);
    if (form) form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const input = $("#email-in", d), err = $("#email-err", d), btn = $("button[type=submit]", form);
      err.hidden = true;
      if (!input.value.includes("@")) { err.textContent = "Enter a valid email address."; err.hidden = false; return; }
      btn.disabled = true; btn.textContent = "Sending…";
      try {
        await api("/v1/auth/email/start", { method: "POST", body: { email: input.value.trim() } });
        form.outerHTML = `<div class="sent"><strong>Check your inbox.</strong><p>We sent a sign-in link to <b>${esc(input.value.trim())}</b>. It works once, for 15 minutes.</p></div>`;
      } catch (ex) {
        err.textContent = ex.message; err.hidden = false; btn.disabled = false; btn.textContent = "Email me a sign-in link";
      }
    });
  }

  // ---------------------------------------------------------------- account page

  async function openAccount(focus) {
    try { acct.me = await api("/v1/me"); } catch (e) { if (e.status === 401) return openSignIn(); toast(e.message); return; }
    renderHeader();
    const m = acct.me;
    const pro = m.plan === "pro";
    const renew = m.current_period_end ? new Date(m.current_period_end).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : null;
    const usage = m.usage;
    const pct = Math.min(100, Math.round((usage.api_scans_this_month / Math.max(1, usage.monthly_limit)) * 100));
    const d = dialog("dlg-account", `
      <header class="acct-head">
        ${m.avatar_url ? `<img src="${esc(m.avatar_url)}" alt="" width="44" height="44">` : `<span class="avatar big">${esc((m.name || m.email).charAt(0).toUpperCase())}</span>`}
        <div><h2>${esc(m.name || "Your account")}</h2><p class="muted">${esc(m.email)}</p></div>
        <span class="plan ${pro ? "pro" : ""}">${pro ? "Pro" : "Free"}</span>
      </header>

      <section class="acard" id="sec-plan">
        <h3>Plan</h3>
        ${pro ? `<p><strong>KubeAudit AI Pro</strong>, $9/month${renew ? `. Renews ${esc(renew)}.` : "."}</p>
          ${m.billing_enabled ? `<button type="button" class="btn" id="portal">Manage billing</button>` : ""}`
        : `<p>You're on the free plan: unlimited scanning in the browser and ${usage.monthly_limit} API scans a month.</p>
          <ul class="perks"><li>Saved scan history you can reopen</li><li>Shareable report links for your team or clients</li><li>Your own rule settings, applied everywhere</li><li>2,500 API scans a month for CI and the CLI</li></ul>
          ${m.billing_enabled ? `<button type="button" class="btn primary" id="upgrade">Upgrade to Pro · $9/month</button>` : `<p class="notice">Upgrades open soon.</p>`}
          ${m.subscription_status === "past_due" ? `<p class="err">Your last payment failed. Update your card in Manage billing to keep Pro.</p>` : ""}
          ${m.has_billing_account && m.billing_enabled ? `<button type="button" class="btn" id="portal">Manage billing</button>` : ""}`}
      </section>

      <section class="acard" id="sec-key">
        <h3>API key</h3>
        <div class="meterline"><span>${usage.api_scans_this_month} of ${usage.monthly_limit.toLocaleString()} API scans this month</span><div class="meter"><div style="width:${pct}%"></div></div></div>
        <p>${m.api_key_last4 ? `Current key: <code>ka_live_…${esc(m.api_key_last4)}</code>` : "No API key yet."}</p>
        <div id="newkey"></div>
        <button type="button" class="btn" id="genkey">${m.api_key_last4 ? "Replace key" : "Create API key"}</button>
        <details class="howto"><summary>Use it from the command line</summary>
<pre class="snip"><code>curl -X POST ${esc(API)}/audit \\
  -H "X-API-Key: $KUBEAUDIT_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"manifest": "apiVersion: v1\\nkind: Pod\\n..."}'</code></pre></details>
      </section>

      <section class="acard" id="sec-history">
        <h3>Saved scans</h3>
        ${pro ? `<div id="history"><p class="muted">Loading…</p></div>` : `<p class="locked">Save scans and come back to them later with Pro.</p>`}
      </section>

      <section class="acard" id="sec-rules">
        <h3>Rule settings</h3>
        ${pro ? `<p class="muted small">Turn rules off or change their severity. Applies to scans in this app and to saved reports.</p><div id="rulesettings"></div>`
          : `<p class="locked">Choose which rules apply and how severe they are with Pro.</p>`}
      </section>

      <footer class="acct-foot">
        <button type="button" class="btn" id="signout">Sign out</button>
        <span class="danger" id="deletewrap"><button type="button" class="linkbtn" id="delacct">Delete account</button></span>
      </footer>`, { wide: true });

    $("#upgrade", d)?.addEventListener("click", (e) => goBilling("/v1/billing/checkout", e.currentTarget));
    $("#portal", d)?.addEventListener("click", (e) => goBilling("/v1/billing/portal", e.currentTarget));
    $("#genkey", d).addEventListener("click", async (e) => {
      const b = e.currentTarget;
      if (m.api_key_last4 && b.dataset.confirm !== "1") { b.dataset.confirm = "1"; b.textContent = "Replace key? The old one stops working"; return; }
      b.disabled = true;
      try {
        const r = await api("/v1/me/api-key", { method: "POST" });
        acct.me.api_key_last4 = r.api_key_last4;
        $("#newkey", d).innerHTML = `<div class="keybox"><code id="fullkey">${esc(r.api_key)}</code><button type="button" class="btn" id="copykey">Copy</button></div>
          <p class="small warn-text">Copy it now. For your security it won't be shown again.</p>`;
        $("#copykey", d).addEventListener("click", (ev) => copyText(r.api_key, ev.currentTarget));
        b.remove();
      } catch (ex) { toast(ex.message); b.disabled = false; }
    });
    $("#signout", d).addEventListener("click", async () => {
      try { await api("/v1/auth/logout", { method: "POST" }); } catch { /* signing out locally anyway */ }
      setToken(null); acct.me = null; app.setSettings(null); renderHeader(); d.close(); toast("Signed out.");
    });
    $("#delacct", d).addEventListener("click", () => {
      $("#deletewrap", d).innerHTML = `This deletes your account and saved scans. <button type="button" class="btn dangerbtn" id="delyes">Delete my account</button> <button type="button" class="linkbtn" id="delno">Keep it</button>`;
      $("#delno", d).addEventListener("click", () => openAccount());
      $("#delyes", d).addEventListener("click", async () => {
        try { await api("/v1/me", { method: "DELETE" }); setToken(null); acct.me = null; app.setSettings(null); renderHeader(); d.close(); toast("Account deleted."); }
        catch (ex) { toast(ex.message); }
      });
    });
    if (pro) { loadHistory(d); renderRuleSettings(d); }
    if (focus) $(`#sec-${focus}`, d)?.scrollIntoView({ block: "start" });
  }

  async function goBilling(path, btn) {
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = "Opening…";
    try { const r = await api(path, { method: "POST" }); window.location.assign(r.url); }
    catch (e) { toast(e.message); btn.disabled = false; btn.textContent = label; }
  }

  // ---------------------------------------------------------------- history

  const shareUrl = (id) => `${location.origin}${location.pathname}?r=${encodeURIComponent(id)}`;

  async function loadHistory(d) {
    const box = $("#history", d);
    try {
      const r = await api("/v1/scans?limit=50");
      if (!r.items.length) { box.innerHTML = `<p class="muted">No saved scans yet. Use <b>Save</b> next to the score to keep one.</p>`; return; }
      box.innerHTML = `<ul class="hist">${r.items.map((s) => `
        <li data-id="${esc(s.id)}">
          <span class="hscore g-${esc(s.grade)}">${s.score}</span>
          <span class="hmain"><strong>${esc(s.title)}</strong><span class="muted small">${new Date(s.created_at).toLocaleString()} · ${SEVS.map((k) => `${s.counts[k] || 0} ${k}`).join(", ")}${s.verified ? " · verified" : ""}</span></span>
          <span class="hact">
            <button type="button" class="btn" data-act="open">Open</button>
            <button type="button" class="btn" data-act="share">${s.shared ? "Copy link" : "Share"}</button>
            ${s.shared ? `<button type="button" class="linkbtn" data-act="unshare">Stop sharing</button>` : ""}
            <button type="button" class="linkbtn" data-act="delete">Delete</button>
          </span>
        </li>`).join("")}</ul>`;
      box.querySelectorAll("[data-act]").forEach((b) => b.addEventListener("click", async (e) => {
        const li = e.currentTarget.closest("li"), id = li.dataset.id, act = e.currentTarget.dataset.act;
        try {
          if (act === "open") {
            const s = await api(`/v1/scans/${id}`);
            if (s.files && s.files.length) { app.setFiles(s.files); d.close(); toast(`Opened “${s.title}”.`); }
            else showReport(s, { owner: false });
          } else if (act === "share") {
            const r2 = await api(`/v1/scans/${id}/share`, { method: "POST" });
            await copyText(shareUrl(r2.share_id), e.currentTarget);
            loadHistory(d);
          } else if (act === "unshare") {
            await api(`/v1/scans/${id}/share`, { method: "DELETE" }); toast("The link no longer works."); loadHistory(d);
          } else if (act === "delete") {
            if (e.currentTarget.dataset.confirm !== "1") { e.currentTarget.dataset.confirm = "1"; e.currentTarget.textContent = "Confirm delete"; return; }
            await api(`/v1/scans/${id}`, { method: "DELETE" }); loadHistory(d);
          }
        } catch (ex) { toast(ex.message); }
      }));
    } catch (e) { box.innerHTML = `<p class="err">${esc(e.message)}</p>`; }
  }

  // ---------------------------------------------------------------- rule settings

  function renderRuleSettings(d) {
    const s = acct.me.rule_settings || { disabled: [], severity: {} };
    const box = $("#rulesettings", d);
    box.innerHTML = `<div class="tablewrap"><table class="rset"><thead><tr><th>On</th><th>Rule</th><th>Severity</th></tr></thead><tbody>${
      Object.values(RULES).map((r) => `<tr>
        <td><input type="checkbox" id="on-${r.id}" ${s.disabled.includes(r.id) ? "" : "checked"} aria-label="Enable ${r.id}"></td>
        <td><label for="on-${r.id}"><span class="rid">${r.id}</span> ${md(r.title)}</label></td>
        <td><select id="sev-${r.id}" aria-label="Severity for ${r.id}">${SEVS.map((k) => `<option value="${k}" ${(s.severity[r.id] || r.severity) === k ? "selected" : ""}>${SEV_LABEL[k]}${k === r.severity ? " (default)" : ""}</option>`).join("")}</select></td>
      </tr>`).join("")}</tbody></table></div>
      <div class="row"><button type="button" class="btn primary" id="saverules">Save rule settings</button><button type="button" class="linkbtn" id="resetrules">Reset to defaults</button></div>`;
    const collect = () => ({
      disabled: Object.keys(RULES).filter((id) => !$(`#on-${id}`, d).checked),
      severity: Object.fromEntries(Object.keys(RULES).map((id) => [id, $(`#sev-${id}`, d).value])),
    });
    const save = async (body) => {
      try {
        const saved = await api("/v1/me/settings", { method: "PUT", body });
        acct.me.rule_settings = saved; app.setSettings(saved); toast("Rule settings saved."); renderRuleSettings(d);
      } catch (e) { toast(e.message); }
    };
    $("#saverules", d).addEventListener("click", () => save(collect()));
    $("#resetrules", d).addEventListener("click", () => save({ disabled: [], severity: {} }));
  }

  // ---------------------------------------------------------------- save current scan

  async function saveCurrent() {
    if (!acct.me) return openSignIn("Sign in to save scans to your history.");
    if (acct.me.plan !== "pro") { toast("Saved history is part of Pro."); return openAccount("plan"); }
    const files = app.currentFiles().filter((f) => f.text.trim());
    if (!files.length) { toast("Add some YAML first."); return; }
    const def = `${files[0].name}${files.length > 1 ? ` +${files.length - 1}` : ""} · ${new Date().toLocaleDateString()}`;
    const d = dialog("dlg-save", `
      <h2>Save this scan</h2>
      <form id="saveform" class="stack">
        <label for="save-title">Name</label>
        <input id="save-title" maxlength="200" value="${esc(def)}" required>
        <label class="check"><input type="checkbox" id="save-yaml" checked> Save the YAML too</label>
        <p class="muted small">With the YAML saved you can reopen the files later, and the server re-checks them, so shared reports show as <b>verified</b>. Without it, only the findings are stored.</p>
        <button type="submit" class="btn primary">Save to history</button>
      </form>`);
    $("#saveform", d).addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = $("button[type=submit]", d);
      btn.disabled = true; btn.textContent = "Saving…";
      const includeYaml = $("#save-yaml", d).checked;
      const findings = app.currentResults().flatMap((r) => r.findings.map((x) => ({
        rule_id: x.rule.id, severity: x.rule.severity, message: x.message, resource: x.resource,
        container: x.container, file: x.file, line: x.line })));
      try {
        await api("/v1/scans", { method: "POST", body: {
          title: $("#save-title", d).value.trim() || def,
          findings: findings.slice(0, 5000),
          resource_count: app.currentResults().reduce((n, r) => n + r.resources, 0),
          ...(includeYaml ? { files: files.slice(0, 20).map((f) => ({ name: f.name.slice(0, 255), text: f.text })) } : {}),
        } });
        d.close(); toast("Saved to your history.");
      } catch (ex) { toast(ex.message); btn.disabled = false; btn.textContent = "Save to history"; }
    });
  }
  $("#savescan").addEventListener("click", saveCurrent);

  // ---------------------------------------------------------------- report view (shared or saved without YAML)

  function showReport(s, { owner = true } = {}) {
    const byFile = new Map();
    const rank = { critical: 0, high: 1, medium: 2, low: 3 };
    const sorted = [...s.findings].sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9) || a.line - b.line);
    for (const f of sorted) {
      if (!byFile.has(f.file)) byFile.set(f.file, []);
      byFile.get(f.file).push(f);
    }
    dialog("dlg-report", `
      <p class="eyebrow">${owner ? `Shared by ${esc(s.owner)}` : "Saved scan"} · ${new Date(s.created_at).toLocaleString()}</p>
      <h2>${esc(s.title)}</h2>
      <div class="rephead">
        <span class="repscore">${s.score}<small>/100</small></span><span class="grade g-${esc(s.grade)}">${esc(s.grade)}</span>
        <ul class="chips">${SEVS.map((k) => `<li class="chip ${k}${s.counts[k] ? "" : " zero"}"><span class="n">${s.counts[k] || 0}</span> ${SEV_LABEL[k]}</li>`).join("")}</ul>
      </div>
      <p class="muted small">${s.resource_count} resources${s.files && s.files.length ? ` in ${s.files.map((f) => esc(f.name)).join(", ")}` : ""}.
        ${s.verified ? `<span class="tag auto">Verified</span> The server re-checked the YAML for this report.` : `Findings as reported by the scanner in the author's browser.`}</p>
      ${s.findings.length ? [...byFile.entries()].map(([file, items]) => `<h3 class="repfile">${esc(file)}</h3><ul class="replist">${
        items.map((f) => `<li class="${esc(f.severity)}"><span class="sev">${SEV_LABEL[f.severity] || esc(f.severity)}</span><span class="rid">${esc(f.rule_id)}</span><span>${md(f.title || "")}<br><span class="muted small">${md(f.message)} · line ${f.line}</span></span></li>`).join("")}</ul>`).join("")
        : `<div class="clean"><strong>No issues found.</strong></div>`}
      <p class="small"><a href="${esc(location.origin + location.pathname)}">Scan your own Kubernetes YAML with KubeAudit AI</a></p>`, { wide: true });
  }

  // ---------------------------------------------------------------- boot

  async function loadMe() {
    try {
      acct.me = await api("/v1/me");
      app.setSettings(acct.me.plan === "pro" ? acct.me.rule_settings : null);
    } catch { acct.me = null; }
    renderHeader();
  }

  async function boot() {
    acct.token = getToken();
    const params = new URLSearchParams(location.search);
    const strip = ["login", "magic", "login_error", "billing", "r"];
    const take = Object.fromEntries(strip.map((k) => [k, params.get(k)]));
    if (strip.some((k) => params.has(k))) {
      strip.forEach((k) => params.delete(k));
      const q = params.toString();
      history.replaceState(null, "", location.pathname + (q ? `?${q}` : "") + location.hash);
    }
    renderHeader();
    if (take.r) {
      try { showReport(await api(`/v1/shared/${encodeURIComponent(take.r)}`)); }
      catch (e) { toast(e.message); }
    }
    try {
      if (take.login) { const r = await api("/v1/auth/exchange", { method: "POST", body: { code: take.login } }); setToken(r.token); toast("Signed in."); }
      else if (take.magic) { const r = await api("/v1/auth/email/verify", { method: "POST", body: { token: take.magic } }); setToken(r.token); toast("Signed in."); }
    } catch (e) { toast(e.message); }
    if (take.login_error) toast(take.login_error);
    if (acct.token) await loadMe();
    if (take.billing === "success") {
      toast("Payment received. Activating Pro…");
      for (let i = 0; i < 10 && acct.me && acct.me.plan !== "pro"; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        await loadMe();
      }
      if (acct.me?.plan === "pro") { toast("Welcome to KubeAudit AI Pro."); openAccount(); }
      else toast("Payment received. Pro will appear in a minute; refresh the page if it doesn't.");
    } else if (take.billing === "cancelled") toast("Checkout cancelled. You weren't charged.");
  }

  boot();
}
