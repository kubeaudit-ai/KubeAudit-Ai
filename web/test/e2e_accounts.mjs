// End-to-end: real backend (uvicorn + SQLite) + built web app + headless Chromium.
// Usage: node web/test/e2e_accounts.mjs [screenshot-dir]
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import os from "node:os";
import net from "node:net";
import { spawn, execFileSync } from "node:child_process";
import { chromium } from "playwright-core";

const here = path.dirname(new URL(import.meta.url).pathname);
const repo = path.resolve(here, "../..");
const shots = process.argv[2] || os.tmpdir();
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ka-e2e-"));
const outbox = path.join(tmp, "outbox.jsonl");
const dbFile = path.join(tmp, "e2e.db");

const freePort = () => new Promise((res) => { const s = net.createServer().listen(0, () => { const p = s.address().port; s.close(() => res(p)); }); });
const apiPort = await freePort(), sitePort = await freePort();
const API = `http://127.0.0.1:${apiPort}`, SITE = `http://127.0.0.1:${sitePort}/`;

// ---- build the app against the local API
execFileSync("node", [path.join(here, "..", "build.mjs")], { env: { ...process.env, KUBEAUDIT_API_URL: API }, stdio: "inherit" });

// ---- start the backend
const api = spawn("python", ["-m", "uvicorn", "app.main:app", "--port", String(apiPort), "--log-level", "warning"], {
  cwd: repo,
  env: { ...process.env, DATABASE_URL: `sqlite:///${dbFile}`, EMAIL_BACKEND: `file:${outbox}`, APP_URL: SITE, API_URL: API,
         CORS_ORIGINS: `http://127.0.0.1:${sitePort}`, GITHUB_CLIENT_ID: "test-client", GITHUB_CLIENT_SECRET: "test-secret" },
  stdio: ["ignore", "inherit", "inherit"],
});
for (let i = 0; i < 100; i++) {
  try { if ((await fetch(`${API}/health`)).ok) break; } catch { /* starting */ }
  await new Promise((r) => setTimeout(r, 150));
}

// ---- serve the site
const site = path.join(here, "..", "dist", "site");
const server = http.createServer((req, res) => {
  const p = path.join(site, req.url.split("?")[0] === "/" ? "index.html" : decodeURIComponent(req.url.split("?")[0]));
  if (!fs.existsSync(p) || fs.statSync(p).isDirectory()) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { "content-type": p.endsWith(".html") ? "text/html" : p.endsWith(".js") ? "text/javascript" : "application/octet-stream" });
  fs.createReadStream(p).pipe(res);
}).listen(sitePort);

const exe = process.env.CHROME_PATH || (fs.existsSync("/opt/pw-browsers") ? fs.readdirSync("/opt/pw-browsers")
  .map((d) => path.join("/opt/pw-browsers", d, "chrome-linux", "headless_shell")).find(fs.existsSync) : undefined);
const browser = await chromium.launch(exe ? { executablePath: exe } : {});
const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); console.log(`${cond ? "PASS" : "FAIL"}  ${msg}`); };
const sql = (q) => execFileSync("python", ["-c", `import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute(sys.argv[2]).fetchall(); c.commit(); print(r)`, dbFile, q]).toString().trim();

async function context() {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: "block" });
  await ctx.route(/cdn\.jsdelivr\.net\/npm\/yaml@2\.5\.1\/(.*)$/, (route) => route.fulfill({
    path: path.join(here, "..", "node_modules", "yaml", route.request().url().match(/yaml@2\.5\.1\/(.*)$/)[1]), contentType: "text/javascript" }));
  await ctx.route(/fonts\.(googleapis|gstatic)\.com/, (r) => r.fulfill({ status: 200, body: "", contentType: "text/css" }));
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  return { ctx, page, errors };
}
const waitToast = (page, text) => page.waitForFunction((t) => document.querySelector("#toast")?.textContent.includes(t), text, { timeout: 8000 }).then(() => true, () => false);

try {
  const { ctx, page, errors } = await context();
  await page.goto(SITE);
  await page.waitForSelector("body.ready");

  // 1. Sign in by email
  await page.click("#signin");
  await page.waitForSelector("#dlg-signin[open]");
  const gh = await page.getAttribute("#dlg-signin a.gh", "href");
  check(gh === `${API}/v1/auth/github/start`, "GitHub button goes to the API's GitHub sign-in");
  await page.fill("#email-in", "Sai@Example.com");
  await page.click("#emailform button[type=submit]");
  await page.waitForSelector("#dlg-signin .sent");
  check(true, "email form confirms the link was sent");
  const link = JSON.parse(fs.readFileSync(outbox, "utf8").trim().split("\n").pop()).link;
  check(link.startsWith(`${SITE}?magic=`), "sign-in email links back to the web app");
  await page.goto(link);
  await page.waitForSelector("#openacct", { timeout: 8000 });
  check(!page.url().includes("magic="), "sign-in token is removed from the address bar");
  check((await page.textContent("#openacct")).includes("sai@example.com"), "header shows the signed-in account");
  const reuse = await (await fetch(`${API}/v1/auth/email/verify`, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: new URL(link).searchParams.get("magic") }) })).status;
  check(reuse === 400, "the emailed link can't be used twice");

  // 2. Account: free plan, API key
  await page.click("#openacct");
  await page.waitForSelector("#dlg-account[open]");
  check((await page.textContent("#sec-plan")).includes("free plan"), "account shows the free plan");
  check((await page.textContent("#sec-plan")).includes("Upgrades open soon"), "upgrade is hidden while billing isn't configured");
  await page.click("#genkey");
  await page.waitForSelector("#fullkey");
  const key = (await page.textContent("#fullkey")).trim();
  const audit = await fetch(`${API}/audit`, { method: "POST", headers: { "content-type": "application/json", "X-API-Key": key },
    body: JSON.stringify({ manifest: "apiVersion: v1\nkind: Pod\nmetadata: {name: p}" }) });
  check(audit.status === 200 && key.startsWith("ka_live_"), "new API key works against the API");
  await page.screenshot({ path: `${shots}/account-free.png` });
  await page.click("#dlg-account .x");

  // 3. Free user can't save
  await page.click("#savescan");
  check(await waitToast(page, "part of Pro"), "saving explains it's a Pro feature");
  await page.click("#dlg-account .x");

  // 4. Become Pro (what the Stripe webhook does) and reload
  sql("UPDATE users SET subscription_tier='PRO', subscription_status='active' WHERE email='sai@example.com'");
  await page.reload();
  await page.waitForSelector("#openacct .pro", { timeout: 8000 });
  check(true, "header shows the Pro badge");

  // 5. Save a scan with YAML
  await page.click("#savescan");
  await page.waitForSelector("#dlg-save[open]");
  await page.fill("#save-title", "payments release 4.2");
  await page.click("#saveform button[type=submit]");
  check(await waitToast(page, "Saved to your history"), "scan saved to history");
  await page.click("#openacct");
  await page.waitForSelector("#history .hist li");
  const histText = await page.textContent("#history");
  check(histText.includes("payments release 4.2") && histText.includes("verified"), "history lists the scan as verified");
  await page.screenshot({ path: `${shots}/account-pro.png` });

  // 6. Share and open the link signed out
  await page.click("#history [data-act=share]");
  await page.waitForSelector("#history [data-act=unshare]");
  const token = await page.evaluate(() => localStorage.getItem("kubeaudit.session.v1"));
  const list = await (await fetch(`${API}/v1/scans`, { headers: { Authorization: `Bearer ${token}` } })).json();
  const shareId = list.items[0].share_id;
  check(!!shareId, "sharing creates a link");
  const anon = await context();
  await anon.page.goto(`${SITE}?r=${shareId}`);
  await anon.page.waitForSelector("#dlg-report[open]", { timeout: 8000 });
  const rep = await anon.page.textContent("#dlg-report");
  check(rep.includes("payments release 4.2") && rep.includes("Verified") && rep.includes("KA001"), "shared report opens for someone signed out");
  check(!rep.includes("sk_live_example_do_not_commit"), "shared report doesn't expose the YAML or its secrets");
  await anon.page.screenshot({ path: `${shots}/shared-report.png` });
  await anon.ctx.close();

  // 7. Rule settings change the results
  const before = await page.$$eval(".finding", (n) => n.length);
  await page.uncheck("#on-KA015");
  await page.selectOption("#sev-KA009", "critical");
  await page.click("#saverules");
  check(await waitToast(page, "Rule settings saved"), "rule settings save");
  await page.click("#dlg-account .x");
  const after = await page.$$eval(".finding", (n) => n.length);
  const crit = await page.$$eval(".finding.critical .rid", (n) => n.map((x) => x.textContent));
  check(after < before && crit.includes("KA009"), `rule settings apply to scanning (${before} → ${after} findings, KA009 now critical)`);
  check(await page.isVisible("#settings-note"), "the page says custom rule settings are on");

  // 8. Reopen the saved scan
  await page.selectOption("#sample", "hardened");
  await page.click("#openacct");
  await page.waitForSelector("#history [data-act=open]");
  await page.click("#history [data-act=open]");
  check(await waitToast(page, "Opened"), "opening a saved scan loads its files");
  check((await page.inputValue("#editor")).includes("payments-api"), "the editor shows the saved YAML");

  // Phone layout of the account dialog
  await page.setViewportSize({ width: 390, height: 844 });
  await page.click("#openacct");
  await page.waitForSelector("#dlg-account[open] #history .hist li");
  const over = await page.evaluate(() => { const d = document.querySelector("#dlg-account"); return d.scrollWidth - d.clientWidth; });
  check(over <= 0, `account dialog fits a phone screen (overflow ${over}px)`);
  await page.screenshot({ path: `${shots}/account-phone.png` });
  await page.click("#dlg-account .x");
  await page.setViewportSize({ width: 1280, height: 900 });

  // 9. Sign out
  await page.click("#openacct");
  await page.click("#signout");
  await page.waitForSelector("#signin");
  const me = await fetch(`${API}/v1/me`, { headers: { Authorization: `Bearer ${token}` } });
  check(me.status === 401, "signing out ends the session on the server");
  check(errors.length === 0, `no page errors (${errors.join(" | ")})`);
  await ctx.close();
} catch (e) {
  failures.push(String(e));
  console.log("ERROR", e);
} finally {
  await browser.close(); server.close(); api.kill();
}
console.log(failures.length ? `\n${failures.length} FAILED` : "\nALL PASSED");
process.exit(failures.length ? 1 : 0);
