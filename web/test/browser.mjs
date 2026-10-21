// End-to-end check of the built site in headless Chromium.
// The YAML library CDN request is served from node_modules so the test runs offline.
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { chromium } from "playwright-core";
import { execFileSync } from "node:child_process";

const here = path.dirname(new URL(import.meta.url).pathname);
const site = path.join(here, "..", "dist", "site");
const shots = process.argv[2] || "/tmp";
const exe = process.env.CHROME_PATH || ["/opt/pw-browsers"].flatMap((root) => fs.existsSync(root) ? fs.readdirSync(root).flatMap((d) => [
  path.join(root, d, "chrome-linux", "headless_shell"), path.join(root, d, "chrome-headless-shell-linux64", "chrome-headless-shell")]) : [])
  .find(fs.existsSync);

const server = http.createServer((req, res) => {
  const p = path.join(site, decodeURIComponent(req.url.split("?")[0]) === "/" ? "index.html" : decodeURIComponent(req.url.split("?")[0]));
  if (!fs.existsSync(p) || fs.statSync(p).isDirectory()) { res.writeHead(404); return res.end(); }
  const type = p.endsWith(".html") ? "text/html" : p.endsWith(".js") ? "text/javascript" : p.endsWith(".svg") ? "image/svg+xml" : p.endsWith(".webmanifest") ? "application/manifest+json" : "application/octet-stream";
  res.writeHead(200, { "content-type": type }); fs.createReadStream(p).pipe(res);
}).listen(0);
const base = `http://127.0.0.1:${server.address().port}/`;

const browser = await chromium.launch(exe ? { executablePath: exe } : {});
const failures = [];
const check = (cond, msg) => { if (!cond) failures.push(msg); console.log(`${cond ? "PASS" : "FAIL"}  ${msg}`); };

async function newPage(opts = {}) {
  const ctx = await browser.newContext({ serviceWorkers: "block", ...opts });
  await ctx.route(/cdn\.jsdelivr\.net\/npm\/yaml@2\.5\.1\/(.*)$/, (route) => {
    const rel = route.request().url().match(/yaml@2\.5\.1\/(.*)$/)[1];
    route.fulfill({ path: path.join(here, "..", "node_modules", "yaml", rel), contentType: "text/javascript" });
  });
  await ctx.route(/fonts\.(googleapis|gstatic)\.com/, (r) => r.fulfill({ status: 200, body: "", contentType: "text/css" }));
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  await page.goto(base);
  await page.waitForSelector("body.ready", { timeout: 15000 });
  return { page, ctx, errors };
}

// ---- desktop
{
  const { page, ctx, errors } = await newPage({ viewport: { width: 1360, height: 900 } });
  const score = await page.textContent("#score");
  check(score === "0", `sample scan shows score 0 for the insecure sample (got ${score})`);
  const findings = await page.$$eval(".finding", (n) => n.length);
  check(findings === 19, `insecure sample lists 19 findings (got ${findings})`);
  check((await page.textContent("#verdict")).includes("would fail"), "verdict says the PR check would fail");
  const marks = await page.$$eval("button.ln.mark", (n) => n.length);
  check(marks > 5, `gutter marks lines with findings (${marks})`);
  await page.screenshot({ path: `${shots}/desktop-light.png`, fullPage: false });

  // click a finding's line link -> band shown
  await page.click(".finding.critical .lnk");
  check(await page.isVisible("#band"), "clicking a finding highlights its line in the editor");
  await page.click(".finding.critical summary .ttl");
  check(await page.isVisible(".finding.critical .body"), "finding expands to show the fix");

  // fixed tab
  await page.click('[data-tab="fixed"]');
  const delta = await page.textContent(".delta");
  check(/0\s*→\s*\d+/.test(delta), `fixed tab shows score improvement (${delta.replace(/\s+/g, " ").trim()})`);
  const added = await page.$$eval(".cl.add", (n) => n.length);
  check(added > 10, `fixed YAML highlights changed lines (${added})`);
  await page.screenshot({ path: `${shots}/desktop-fixed.png` });
  await page.click("#apply");
  await page.waitForTimeout(400);
  const after = Number(await page.textContent("#score"));
  check(after > 0, `after applying the fix the score rises (now ${after})`);
  const auto = await page.$$eval(".tag.auto", (n) => n.length);
  check(auto === 0, `no auto-fixable findings remain after applying (${auto})`);

  // hardened sample -> 100
  await page.selectOption("#sample", "hardened");
  await page.waitForTimeout(400);
  check((await page.textContent("#score")) === "100", "hardened sample scores 100");
  check(await page.isVisible(".clean"), "hardened sample shows 'No issues found'");

  // invalid YAML
  await page.fill("#editor", "apiVersion: v1\nkind: Pod\n  bad: [indent\n");
  await page.waitForTimeout(500);
  check(await page.isVisible(".notice.err"), "invalid YAML shows an error with its line");

  // helm template
  await page.fill("#editor", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {{ .Release.Name }}\n");
  await page.waitForTimeout(500);
  check((await page.textContent("#findings")).includes("Helm template"), "Helm templates get an explanation");

  // upload two files
  const tmp = fs.mkdtempSync("/tmp/ka-up-");
  fs.writeFileSync(path.join(tmp, "a.yaml"), fs.readFileSync(path.join(here, "../../tests/fixtures/repo/k8s/insecure.yaml")));
  fs.writeFileSync(path.join(tmp, "b.yml"), fs.readFileSync(path.join(here, "../../tests/fixtures/repo/k8s/secure.yaml")));
  await page.setInputFiles("#upload", [path.join(tmp, "a.yaml"), path.join(tmp, "b.yml")]);
  await page.waitForTimeout(500);
  const tabs = await page.$$eval(".ftab", (n) => n.length);
  check(tabs === 2, `uploading two files opens two tabs (${tabs})`);
  const total = await page.$$eval(".finding", (n) => n.length);
  const pyCount = Number(execFileSync("python", ["-c", `
import sys; sys.path.insert(0, ${JSON.stringify(path.join(here, "../.."))})
from pathlib import Path
from app.scanner import Config, scan_text
print(sum(len(scan_text(Path(f).read_text(), f, Config())[0]) for f in sys.argv[1:]))`, path.join(tmp, "a.yaml"), path.join(tmp, "b.yml")]).toString().trim());
  check(total === pyCount, `uploaded files are all scanned (${total} findings in the app, ${pyCount} from the Python engine)`);

  // rules tab
  await page.click('[data-tab="rules"]');
  check((await page.$$eval("#rules tbody tr", (n) => n.length)) === 15, "rules tab lists 15 rules");

  // persistence
  await page.reload(); await page.waitForSelector("body.ready");
  check((await page.$$eval(".ftab", (n) => n.length)) === 2, "files are kept after a reload");
  check(errors.length === 0, `no console errors (${errors.join(" | ")})`);
  await ctx.close();
}

// ---- phone + dark
{
  const { page, ctx, errors } = await newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, colorScheme: "dark", isMobile: true, hasTouch: true });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check(overflow <= 0, `no horizontal scroll on a phone (overflow ${overflow}px)`);
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  check(bg === "rgb(11, 18, 24)", `dark theme applies (${bg})`);
  await page.screenshot({ path: `${shots}/phone-dark.png`, fullPage: true });
  check(errors.length === 0, `no console errors on phone (${errors.join(" | ")})`);
  await ctx.close();
}

// ---- installable app: manifest + service worker
{
  const { page, ctx } = await newPage({ viewport: { width: 1200, height: 800 }, serviceWorkers: "allow" });
  const manifest = await page.evaluate(async () => (await fetch(document.querySelector('link[rel=manifest]').href)).json());
  check(manifest.display === "standalone" && manifest.icons.some((i) => i.sizes === "512x512"), "web app manifest is valid for install");
  const ok = await page.evaluate(async () => {
    const reg = await navigator.serviceWorker.ready;
    for (let i = 0; i < 50; i++) {
      const c = await caches.open("kubeaudit-v2");
      const keys = (await c.keys()).map((r) => new URL(r.url).pathname);
      if (keys.some((k) => k.endsWith("/index.html")) && keys.some((k) => k.endsWith("icon-512.png"))) return !!reg.active;
      await new Promise((r) => setTimeout(r, 100));
    }
    return false;
  });
  check(ok, "service worker installs and caches the app for offline use");
  await ctx.close();
}

await browser.close(); server.close();
console.log(failures.length ? `\n${failures.length} FAILED` : "\nALL PASSED");
process.exit(failures.length ? 1 : 0);
