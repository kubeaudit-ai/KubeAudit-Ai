// Parser options shared by the engine and the fixer.
//
// Kubernetes YAML follows YAML 1.1 (booleans like `yes`, octal `0644`), so we
// parse as 1.1, with two corrections so values survive an edit unchanged:
//  - timestamps stay strings (otherwise `...T09:15:16Z` is rewritten without its `Z`)
//  - a bare `.` stays a string (the 1.1 float rule would turn the key `.` into `.nan`),
//    matching how PyYAML and Kubernetes read it.
const FLOAT_TAG = "tag:yaml.org,2002:float";
const TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp";
const STRICT_FLOAT = /^[-+]?(?:[0-9][0-9_]*\.[0-9_]*|\.[0-9][0-9_]*)(?:[eE][-+]?[0-9]+)?$/;

function customTags(tags) {
  return tags
    .filter((t) => t.tag !== TIMESTAMP_TAG)
    .map((t) => {
      if (t.tag === FLOAT_TAG && !t.format && t.test && t.test.test(".")) {
        return { ...t, test: STRICT_FLOAT };
      }
      return t;
    });
}

export const PARSE_OPTIONS = { version: "1.1", merge: true, uniqueKeys: false, strict: false, prettyErrors: false, customTags };
