// Build the web app.
//   dist/app.html      page body for publishing as a Claude artifact
//   dist/site/         full static site for GitHub Pages (installable PWA)
import fs from "node:fs";
import path from "node:path";
import { build } from "esbuild";

const here = path.dirname(new URL(import.meta.url).pathname);
const out = path.join(here, "dist");
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(path.join(out, "site"), { recursive: true });

const result = await build({
  entryPoints: [path.join(here, "src/main.js")],
  bundle: true, format: "esm", minify: true, write: false, target: "es2020",
  external: ["https://*"],
  define: { __API_URL__: JSON.stringify(process.env.KUBEAUDIT_API_URL || "https://kubeaudit-ai-production.up.railway.app") },
  legalComments: "none",
});
const bundle = result.outputFiles[0].text.replace(/<\/script/gi, "<\\/script");
const body = fs.readFileSync(path.join(here, "src/app.html"), "utf8").replace("/*__BUNDLE__*/", () => bundle);
fs.writeFileSync(path.join(out, "app.html"), body);

// Full document for the static site.
const titleEnd = body.indexOf("</style>") + "</style>".length;
const head = body.slice(0, titleEnd);
const rest = body.slice(titleEnd);
const site = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0b6a86">
<link rel="manifest" href="manifest.webmanifest">
<link rel="icon" href="icon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="icon-192.png">
<meta property="og:title" content="KubeAudit AI">
<meta property="og:description" content="Scan Kubernetes YAML for security problems and get a fixed file. Runs in your browser.">
<style>:root{padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}body{margin:0}[hidden]{display:none!important}</style>
${head}
</head>
<body>
${rest}
<script>if ("serviceWorker" in navigator) addEventListener("load", () => navigator.serviceWorker.register("sw.js").catch(() => {}));</script>
</body>
</html>
`;
fs.writeFileSync(path.join(out, "site", "index.html"), site);
for (const f of ["manifest.webmanifest", "sw.js", "icon.svg", "icon-192.png", "icon-512.png"]) {
  const src = path.join(here, "public", f);
  if (fs.existsSync(src)) fs.copyFileSync(src, path.join(out, "site", f));
}
console.log(`app.html ${(body.length / 1024).toFixed(1)} KB, bundle ${(bundle.length / 1024).toFixed(1)} KB`);
