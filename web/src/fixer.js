import { PARSE_OPTIONS } from "./yamlopts.js";

// Auto-fix for the settings that have one safe, standard answer.
//
// Edits the YAML in place through the `yaml` Document API, so comments, key
// order and formatting are kept. Anything that needs a human decision (image
// versions, secrets, host access, RBAC, probes) is left alone and reported.

const AUTO_FIXED = new Set(["KA001", "KA002", "KA003", "KA010", "KA011", "KA012", "KA013", "KA015"]);
export const MANUAL_RULES = new Set(["KA004", "KA005", "KA006", "KA007", "KA008", "KA009", "KA014"]);
export const isAutoFixable = (ruleId) => AUTO_FIXED.has(ruleId);

const isDict = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

export function createFixer(YAML, engine) {
  const POD_SPEC_PATHS = engine.POD_SPEC_PATHS;

  // Set a value at `path`, creating plain block maps for missing parents.
  // (doc.setIn would create `!!omap` collections under the YAML 1.1 schema.)
  function setPath(doc, path, value) {
    let node = doc.contents;
    for (let i = 0; i < path.length - 1; i++) {
      const part = path[i];
      let child = node.get(part, true);
      if (child === undefined || child === null || (YAML.isScalar(child) && (child.value === null || child.value === undefined))) {
        child = new YAML.YAMLMap();
        node.set(doc.createNode(part), child);
      }
      if (YAML.isAlias(child)) throw new Error("uses a YAML alias here; fix by hand");
      if (!YAML.isMap(child) && !YAML.isSeq(child)) throw new Error(`\`${part}\` is not a map`);
      node = child;
    }
    const last = path[path.length - 1];
    const v = YAML.isNode(value) ? value : doc.createNode(value);
    if (YAML.isSeq(node)) node.set(last, v);
    else if (node.has(last)) node.set(last, v);
    else node.add(doc.createPair(last, v));
  }

  function present(v) {
    return v !== null && v !== undefined && v !== "" && v !== false && v !== 0;
  }

  function setIfMissing(doc, path, value, changes, label) {
    if (present(doc.getIn(path))) return;
    setPath(doc, path, value);
    changes.push(label);
  }

  function forceValue(doc, path, value, changes, label) {
    if (doc.getIn(path) === value) return;
    setPath(doc, path, value);
    changes.push(label);
  }

  function fixPod(doc, base, kind, resource, changes) {
    const pod = doc.getIn(base);
    if (!YAML.isMap(pod)) return;
    const podJs = pod.toJSON();

    forceValue(doc, [...base, "automountServiceAccountToken"], false, changes,
      `${resource}: set automountServiceAccountToken: false`);

    const psc = isDict(podJs.securityContext) ? podJs.securityContext : {};
    if (psc.runAsNonRoot !== true) {
      setPath(doc, [...base, "securityContext", "runAsNonRoot"], true);
      changes.push(`${resource}: set securityContext.runAsNonRoot: true`);
    }
    if (psc.runAsUser === 0 || psc.runAsUser === undefined || psc.runAsUser === null) {
      setPath(doc, [...base, "securityContext", "runAsUser"], 10001);
      changes.push(`${resource}: set securityContext.runAsUser: 10001`);
    }

    for (const group of ["initContainers", "containers", "ephemeralContainers"]) {
      const list = podJs[group];
      if (!Array.isArray(list)) continue;
      list.forEach((c, i) => {
        if (!isDict(c)) return;
        const p = [...base, group, i];
        const name = c.name ?? "unnamed";
        const who = `${resource} ${group === "containers" ? "container" : group.slice(0, -1)} ${name}`;
        const sc = isDict(c.securityContext) ? c.securityContext : {};
        if (sc.privileged === true) forceValue(doc, [...p, "securityContext", "privileged"], false, changes, `${who}: set privileged: false`);
        forceValue(doc, [...p, "securityContext", "allowPrivilegeEscalation"], false, changes, `${who}: set allowPrivilegeEscalation: false`);
        if (sc.runAsNonRoot === false) forceValue(doc, [...p, "securityContext", "runAsNonRoot"], true, changes, `${who}: set runAsNonRoot: true`);
        if (sc.runAsUser === 0) forceValue(doc, [...p, "securityContext", "runAsUser"], 10001, changes, `${who}: set runAsUser: 10001`);
        forceValue(doc, [...p, "securityContext", "readOnlyRootFilesystem"], true, changes,
          `${who}: set readOnlyRootFilesystem: true (mount an emptyDir for any path the app writes to)`);

        const caps = isDict(sc.capabilities) ? sc.capabilities : {};
        const drop = Array.isArray(caps.drop) ? caps.drop.map((x) => String(x).toUpperCase()) : [];
        if (!drop.includes("ALL")) {
          if (Array.isArray(caps.drop)) {
            doc.getIn([...p, "securityContext", "capabilities", "drop"], true).add(doc.createNode("ALL"));
          } else {
            const seq = new YAML.YAMLSeq();
            seq.flow = true;
            seq.add(doc.createNode("ALL"));
            setPath(doc, [...p, "securityContext", "capabilities", "drop"], seq);
          }
          changes.push(`${who}: drop ALL capabilities`);
        }
        if (group === "ephemeralContainers") return;
        setIfMissing(doc, [...p, "resources", "limits", "memory"], "512Mi", changes, `${who}: set memory limit 512Mi (adjust to your app)`);
        setIfMissing(doc, [...p, "resources", "requests", "cpu"], "100m", changes, `${who}: set CPU request 100m (adjust to your app)`);
        setIfMissing(doc, [...p, "resources", "requests", "memory"], "128Mi", changes, `${who}: set memory request 128Mi (adjust to your app)`);
      });
    }
  }

  /** Returns { text, changes } where text is the fixed YAML. Throws on invalid YAML. */
  function fixText(text) {
    const docs = YAML.parseAllDocuments(text, PARSE_OPTIONS);
    const list = Array.isArray(docs) ? docs : [docs];
    for (const doc of list) if (doc.errors && doc.errors.length) throw new Error(doc.errors[0].message.split("\n")[0]);
    const changes = [];
    for (const doc of list) {
      const value = doc.toJS({ maxAliasCount: -1 });
      if (!isDict(value)) continue;
      const targets = value.kind === "List" && Array.isArray(value.items)
        ? value.items.map((item, i) => ({ obj: item, prefix: ["items", i] }))
        : [{ obj: value, prefix: [] }];
      for (const { obj, prefix } of targets) {
        if (!isDict(obj)) continue;
        const kind = String(obj.kind ?? "");
        if (!Object.prototype.hasOwnProperty.call(POD_SPEC_PATHS, kind)) continue;
        const name = isDict(obj.metadata) && obj.metadata.name != null ? obj.metadata.name : "unnamed";
        try {
          fixPod(doc, [...prefix, ...POD_SPEC_PATHS[kind]], kind, `${kind}/${name}`, changes);
        } catch (e) {
          changes.push(`${kind}/${name}: skipped automatic fixes (${e.message})`);
        }
      }
    }
    const out = list.map((doc, i) => {
      let s = doc.toString({ lineWidth: 0 });
      if (i > 0 && !s.startsWith("---")) s = "---\n" + s;
      return s;
    }).join("");
    return { text: out, changes };
  }

  return { fixText };
}
