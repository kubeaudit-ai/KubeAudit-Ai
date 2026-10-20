// Apply the fixer to every YAML file under <dir>, writing results to <outdir> (same relative paths).
import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { createEngine } from "../src/engine.js";
import { createFixer } from "../src/fixer.js";

const [dir, outdir, list] = process.argv.slice(2);
const engine = createEngine(YAML);
const fixer = createFixer(YAML, engine);
const files = JSON.parse(fs.readFileSync(list, "utf8"));
let fixed = 0, failed = 0, changes = 0;
for (const rel of files) {
  const text = fs.readFileSync(path.join(dir, rel), "utf8");
  try {
    const r = fixer.fixText(text);
    fs.mkdirSync(path.dirname(path.join(outdir, rel)), { recursive: true });
    fs.writeFileSync(path.join(outdir, rel), r.text);
    fixed++; changes += r.changes.length;
  } catch (e) { failed++; console.log("FIX FAILED", rel, e.message); }
}
console.log(`fixed files: ${fixed}, failed: ${failed}, changes applied: ${changes}`);
