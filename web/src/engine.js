// KubeAudit AI scanning engine for the browser (and Node, for tests).
//
// A line-for-line port of app/rules.py + the parsing/line-mapping parts of
// app/scanner.py. CI checks it against the Python engine (web/test/parity.mjs),
// so both report the same rules on the same lines.
//
// The YAML library is injected so the same file runs in the browser (CDN build)
// and in Node (npm package): createEngine(YAML).

import { DATA } from "./rules.js";
import { PARSE_OPTIONS } from "./yamlopts.js";

export const RULES = DATA.RULES;
export const SEVERITY_ORDER = DATA.SEVERITY_ORDER;
const DANGEROUS_CAPS = new Set(DATA.DANGEROUS_CAPS);
const SECRET_NAME = new RegExp(DATA.SECRET_NAME, "i");
const LONG_RUNNING = new Set(DATA.LONG_RUNNING);
const POD_SPEC_PATHS = DATA.POD_SPEC_PATHS;
const IGNORE_ANNOTATION = DATA.IGNORE_ANNOTATION;

// ---------------------------------------------------------------- Python semantics helpers

const isDict = (v) => v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof Date);
const d = (v) => (isDict(v) ? v : {});
// Python truthiness
function truthy(v) {
  if (v === null || v === undefined || v === false || v === 0 || v === "") return false;
  if (Array.isArray(v)) return v.length > 0;
  if (isDict(v)) return Object.keys(v).length > 0;
  return true;
}
// Python str()
function pyStr(v) {
  if (v === null || v === undefined) return "None";
  if (v === true) return "True";
  if (v === false) return "False";
  if (Array.isArray(v) || isDict(v)) return JSON.stringify(v);
  return String(v);
}
// Python `for x in (value or [])` over a list or string; dict iterates keys
function iterItems(v) {
  if (!truthy(v)) return [];
  if (Array.isArray(v)) return v;
  if (typeof v === "string") return [...v];
  if (isDict(v)) return Object.keys(v);
  return [];
}
// Python `isinstance(v, int) and v > 0` (bool counts as int in Python)
const positiveInt = (v) => v === true || (typeof v === "number" && Number.isInteger(v) && v > 0);
// Python `"*" in value`
function containsStar(v) {
  if (!truthy(v)) return false;
  if (typeof v === "string") return v.includes("*");
  if (Array.isArray(v)) return v.some((x) => x === "*");
  if (isDict(v)) return Object.prototype.hasOwnProperty.call(v, "*");
  return false;
}
function get(obj, path) {
  for (const part of path) {
    if (isDict(obj)) obj = obj[part];
    else if (Array.isArray(obj) && typeof part === "number" && part < obj.length) obj = obj[part];
    else return undefined;
  }
  return obj;
}

export function imageIsPinned(image) {
  if (!image) return false;
  if (image.includes("@sha256:")) return true;
  const last = image.split("/").pop();
  if (!last.includes(":")) return false;
  const tag = last.slice(last.indexOf(":") + 1);
  return tag !== "" && tag !== "latest";
}

export function severityAtLeast(sev, threshold) {
  return (SEVERITY_ORDER[sev] ?? 0) >= (SEVERITY_ORDER[threshold] ?? 99);
}

function ignoredRules(obj) {
  const ann = d(d(obj.metadata).annotations);
  const raw = Object.prototype.hasOwnProperty.call(ann, IGNORE_ANNOTATION) ? ann[IGNORE_ANNOTATION] : "";
  return new Set(pyStr(raw).split(",").map((s) => s.trim().toUpperCase()).filter(Boolean));
}

// ---------------------------------------------------------------- rules

function finding(ruleId, message, path, resource, container = null) {
  return { rule: RULES[ruleId], message, path, resource, container };
}

function checkPod(obj, kind, resource) {
  const base = POD_SPEC_PATHS[kind];
  const pod = get(obj, base);
  if (!isDict(pod)) return [];
  const out = [];
  const podSc = d(pod.securityContext);

  for (const flag of ["hostNetwork", "hostPID", "hostIPC"]) {
    if (pod[flag] === true) out.push(finding("KA004", `${resource} sets \`${flag}: true\`.`, [...base, flag], resource));
  }
  iterItems(pod.volumes).forEach((vol, i) => {
    if (isDict(vol) && Object.prototype.hasOwnProperty.call(vol, "hostPath")) {
      const hp = d(vol.hostPath);
      const hpPath = Object.prototype.hasOwnProperty.call(hp, "path") ? pyStr(hp.path) : "?";
      const volName = Object.prototype.hasOwnProperty.call(vol, "name") ? pyStr(vol.name) : String(i);
      out.push(finding("KA005", `${resource} mounts host path \`${hpPath}\` (volume \`${volName}\`).`,
        [...base, "volumes", i, "hostPath"], resource));
    }
  });
  if (pod.automountServiceAccountToken !== false) {
    out.push(finding("KA015", `${resource} mounts its service account token automatically.`,
      [...base, "automountServiceAccountToken"], resource));
  }
  const podNonRoot = podSc.runAsNonRoot === true || positiveInt(podSc.runAsUser);

  for (const group of ["initContainers", "containers", "ephemeralContainers"]) {
    iterItems(pod[group]).forEach((c, i) => {
      if (!isDict(c)) return;
      const cpath = [...base, group, i];
      const name = Object.prototype.hasOwnProperty.call(c, "name") ? pyStr(c.name) : "unnamed";
      const label = group === "containers" ? `container \`${name}\`` : `${group.slice(0, -1)} \`${name}\``;
      const sc = d(c.securityContext);
      const caps = d(sc.capabilities);
      const res = d(c.resources);
      const F = (id, msg, p) => out.push(finding(id, msg, p, resource, name));

      if (sc.privileged === true) F("KA001", `${label} in ${resource} runs privileged.`, [...cpath, "securityContext", "privileged"]);
      if (sc.allowPrivilegeEscalation !== false) {
        F("KA002", `${label} in ${resource} does not set \`allowPrivilegeEscalation: false\`.`,
          [...cpath, "securityContext", "allowPrivilegeEscalation"]);
      }
      const cNonRoot = sc.runAsNonRoot === true || positiveInt(sc.runAsUser);
      if (!(podNonRoot || cNonRoot) || sc.runAsNonRoot === false || sc.runAsUser === 0 || sc.runAsUser === false) {
        F("KA003", `${label} in ${resource} may run as root.`, [...cpath, "securityContext", "runAsNonRoot"]);
      }
      const added = new Set(iterItems(caps.add).map((x) => pyStr(x).toUpperCase()));
      const bad = [...added].filter((x) => DANGEROUS_CAPS.has(x)).sort();
      if (bad.length) F("KA006", `${label} in ${resource} adds ${bad.join(", ")}.`, [...cpath, "securityContext", "capabilities", "add"]);
      const dropped = new Set(iterItems(caps.drop).map((x) => pyStr(x).toUpperCase()));
      if (!dropped.has("ALL")) {
        F("KA012", `${label} in ${resource} does not drop ALL capabilities.`, [...cpath, "securityContext", "capabilities", "drop"]);
      }
      const image = Object.prototype.hasOwnProperty.call(c, "image") ? pyStr(c.image) : "";
      if (!imageIsPinned(image)) {
        F("KA009", `${label} in ${resource} uses image \`${image || "<none>"}\` without a pinned version.`, [...cpath, "image"]);
      }
      if (sc.readOnlyRootFilesystem !== true) {
        F("KA010", `${label} in ${resource} has a writable root filesystem.`, [...cpath, "securityContext", "readOnlyRootFilesystem"]);
      }
      if (group === "ephemeralContainers") return;
      if (!truthy(d(res.limits).memory)) F("KA011", `${label} in ${resource} has no memory limit.`, [...cpath, "resources", "limits", "memory"]);
      const req = d(res.requests);
      if (!truthy(req.cpu) || !truthy(req.memory)) {
        F("KA013", `${label} in ${resource} is missing CPU or memory requests.`, [...cpath, "resources", "requests"]);
      }
      if (group === "containers" && LONG_RUNNING.has(kind) && !(truthy(c.readinessProbe) || truthy(c.livenessProbe))) {
        F("KA014", `${label} in ${resource} has no readiness or liveness probe.`, cpath);
      }
      iterItems(c.env).forEach((env, j) => {
        if (!isDict(env)) return;
        const val = env.value;
        const envName = Object.prototype.hasOwnProperty.call(env, "name") ? pyStr(env.name) : "";
        if (typeof val === "string" && val.trim() && SECRET_NAME.test(envName)) {
          F("KA007", `${label} in ${resource} sets \`${pyStr(env.name)}\` to a literal value.`, [...cpath, "env", j, "value"]);
        }
      });
    });
  }
  return out;
}

function checkRbac(obj, resource) {
  const out = [];
  iterItems(obj.rules).forEach((rule, i) => {
    if (!isDict(rule)) return;
    const wild = ["verbs", "resources", "apiGroups"].filter((k) => containsStar(rule[k]));
    if (wild.length) out.push(finding("KA008", `${resource} rule ${i + 1} uses \`*\` in ${wild.join(", ")}.`, ["rules", i], resource));
  });
  return out;
}

export function checkObject(obj) {
  if (!isDict(obj)) return [];
  const kind = Object.prototype.hasOwnProperty.call(obj, "kind") ? pyStr(obj.kind) : "";
  const meta = d(obj.metadata);
  const name = Object.prototype.hasOwnProperty.call(meta, "name") ? pyStr(meta.name) : "unnamed";
  const resource = `${kind}/${name}`;
  let findings = [];
  if (Object.prototype.hasOwnProperty.call(POD_SPEC_PATHS, kind)) findings = findings.concat(checkPod(obj, kind, resource));
  if (kind === "Role" || kind === "ClusterRole") findings = findings.concat(checkRbac(obj, resource));
  const skip = ignoredRules(obj);
  if (skip.has("ALL")) return [];
  return findings.filter((f) => !skip.has(f.rule.id) && !skip.has(f.rule.name.toUpperCase()));
}

// ---------------------------------------------------------------- parsing + line mapping

export function createEngine(YAML) {
  const PARSE_OPTS = PARSE_OPTIONS;

  function parse(text) {
    const lineCounter = new YAML.LineCounter();
    const docs = YAML.parseAllDocuments(text, { ...PARSE_OPTS, lineCounter });
    const list = Array.isArray(docs) ? docs : [docs]; // EmptyStream when text has no documents
    const errors = [];
    for (const doc of list) for (const e of doc.errors || []) errors.push(e);
    if (errors.length) {
      const e = errors[0];
      const line = e.linePos?.[0]?.line ?? (e.pos ? lineCounter.linePos(e.pos[0]).line : 1);
      const err = new Error(e.message.split("\n")[0]);
      err.line = line;
      throw err;
    }
    const lineOf = (offset) => lineCounter.linePos(offset).line;
    const out = [];
    for (const doc of list) {
      const value = doc.toJS({ maxAliasCount: -1 });
      if (!isDict(value)) continue;
      if (value.kind === "List" && Array.isArray(value.items)) {
        value.items.forEach((item, i) => {
          if (isDict(item) && truthy(item.kind)) out.push({ obj: item, doc, prefix: ["items", i] });
        });
      } else if (truthy(value.apiVersion) && truthy(value.kind)) {
        out.push({ obj: value, doc, prefix: [] });
      }
    }
    return { objects: out, lineOf };
  }

  function resolve(node, doc) {
    let guard = 0;
    while (node && YAML.isAlias(node) && guard++ < 50) node = node.resolve(doc);
    return node;
  }

  // Same walk as scanner._line_for: the deepest node along `path` that exists;
  // a mapping hit reports the key's line, a sequence hit the item's line.
  function lineFor(doc, path, lineOf) {
    let node = resolve(doc.contents, doc);
    if (!node || !node.range) return 1;
    let best = lineOf(node.range[0]);
    for (const part of path) {
      let next = null;
      if (YAML.isMap(node)) {
        for (const pair of node.items) {
          const k = pair.key;
          const kv = YAML.isScalar(k) ? (k.source ?? pyStr(k.value)) : null;
          if (kv !== null && kv === String(part)) {
            next = resolve(pair.value, doc);
            best = lineOf(k.range[0]);
            break;
          }
        }
      } else if (YAML.isSeq(node) && typeof part === "number" && part < node.items.length) {
        next = resolve(node.items[part], doc);
        if (next && next.range) best = lineOf(next.range[0]);
      }
      if (!next || !next.range) break;
      node = next;
    }
    return best;
  }

  /** Scan YAML text. Returns { findings:[{rule,message,resource,container,file,line}], resources } */
  function scanText(text, file = "manifest.yaml") {
    const { objects, lineOf } = parse(text);
    const located = [];
    for (const { obj, doc, prefix } of objects) {
      for (const f of checkObject(obj)) {
        located.push({ ...f, file, line: lineFor(doc, [...prefix, ...f.path], lineOf) });
      }
    }
    located.sort((a, b) => (SEVERITY_ORDER[b.rule.severity] - SEVERITY_ORDER[a.rule.severity])
      || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || (a.line - b.line)
      || (a.rule.id < b.rule.id ? -1 : a.rule.id > b.rule.id ? 1 : 0));
    return { findings: located, resources: objects.length, objects };
  }

  return { scanText, parse, checkObject, RULES, POD_SPEC_PATHS };
}
