// Compare the JS engine with the Python engine on every YAML file under a directory.
// Usage: node web/test/parity.mjs <dir> <python-results.json>
import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { createEngine } from "../src/engine.js";

const [dir, pyFile] = process.argv.slice(2);
const py = JSON.parse(fs.readFileSync(pyFile, "utf8"));
const engine = createEngine(YAML);

let files = 0, same = 0, findings = 0, parseDisagree = [], diffs = [];
for (const [rel, ref] of Object.entries(py)) {
  const text = fs.readFileSync(path.join(dir, rel), "utf8");
  let js;
  try {
    const r = engine.scanText(text, rel);
    js = { resources: r.resources, findings: r.findings.map((f) => [f.rule.id, f.line, f.resource, f.container, f.message]) };
  } catch (e) {
    js = { error: true, msg: String(e.message) };
  }
  files++;
  if (ref.error || js.error) {
    if (!(ref.error && js.error)) parseDisagree.push({ rel, py: ref.error ? "error" : "ok", js: js.error ? js.msg : "ok" });
    else same++;
    continue;
  }
  const key = (a) => JSON.stringify(a);
  const a = ref.findings.map(key).sort(), b = js.findings.map(key).sort();
  findings += a.length;
  if (key(a) === key(b) && ref.resources === js.resources) { same++; continue; }
  const onlyPy = a.filter((x) => !b.includes(x)), onlyJs = b.filter((x) => !a.includes(x));
  diffs.push({ rel, resources: [ref.resources, js.resources], onlyPy: onlyPy.slice(0, 3), onlyJs: onlyJs.slice(0, 3) });
}
console.log(`files compared: ${files}, identical: ${same}, python findings: ${findings}`);
console.log(`finding mismatches: ${diffs.length}, parse-status mismatches: ${parseDisagree.length}`);
for (const x of diffs.slice(0, 15)) console.log("DIFF", JSON.stringify(x));
for (const x of parseDisagree.slice(0, 15)) console.log("PARSE", JSON.stringify(x));
// Parsers may disagree on rare YAML edge cases; that only matters if it hides findings.
const hidden = parseDisagree.filter((x) => x.js !== "ok" && (py[x.rel].findings || []).length);
if (hidden.length) console.log("JS rejected files where Python found issues:", hidden.length);
process.exit(diffs.length || hidden.length ? 1 : 0);
