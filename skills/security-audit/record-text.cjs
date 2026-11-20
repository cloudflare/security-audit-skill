"use strict";

/**
 * Record text: the line-oriented, escape-free authoring format that
 * audit-state.cjs compiles into the skill's JSON contracts.
 *
 *   # comment                      ignored
 *   [section]                      starts a new item (a unit, a check, a trace step, ...)
 *   key: text to end of line       never quote or escape the text
 *   key: <<<                       multi-line text, ended by a line containing only >>>
 *   key = <JSON value>             exact value when needed: null, "", "\u0000"
 *   key:                           an empty value means "not provided"
 *   - item                         list items directly under an empty `key:` line
 *
 * Repeating a list key appends another item. Dotted keys address nested objects
 * (`severity.impact.score`). Every section and field is checked against a spec,
 * and every error names the source line.
 */

const KEY_LINE = /^([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)[ \t]*(:|=)(.*)$/;
const SECTION_LINE = /^\[[ \t]*([A-Za-z_][A-Za-z0-9_.-]*)(?:[ \t:#-][^\]]*)?\][ \t]*$/;
const LIST_ITEM = /^[ \t]*-(?:[ \t]+(.*))?$/;
const OPEN_FENCE = /^[ \t]*```[A-Za-z0-9_-]*[ \t]*$/;
const CLOSE_FENCE = /^[ \t]*```[ \t]*$/;
const BLOCK_OPEN = /^<<<([A-Za-z0-9_]*)[ \t]*$/;
const UNSAFE_SINGLE_LINE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Default_Ignorable_Code_Point}]/u;

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

function tokenize(text) {
  const errors = [];
  let source = String(text);
  if (source.charCodeAt(0) === 0xfeff) source = source.slice(1);
  const lines = source.replace(/\r\n?/g, "\n").split("\n");

  // Tolerate one Markdown code fence wrapped around the whole document.
  const first = lines.findIndex((line) => line.trim() !== "");
  let last = lines.length - 1;
  while (last >= 0 && lines[last].trim() === "") last--;
  if (first !== -1 && last > first && OPEN_FENCE.test(lines[first]) && CLOSE_FENCE.test(lines[last])) {
    lines[first] = "";
    lines[last] = "";
  }

  const entries = [];
  let pendingList = null;
  let index = 0;
  while (index < lines.length) {
    const lineNo = index + 1;
    const line = lines[index++];
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;

    const section = SECTION_LINE.exec(trimmed);
    if (section) {
      entries.push({ type: "section", name: section[1], line: lineNo });
      pendingList = null;
      continue;
    }

    const item = LIST_ITEM.exec(line);
    if (item && pendingList) {
      entries.push({ type: "field", key: pendingList, op: ":", value: item[1] === undefined ? "" : item[1], line: lineNo });
      continue;
    }

    const field = KEY_LINE.exec(trimmed);
    if (field) {
      const [, key, op, rest] = field;
      if (op === "=") {
        entries.push({ type: "field", key, op, value: rest.trim(), line: lineNo });
        pendingList = null;
        continue;
      }
      const value = rest.replace(/^[ \t]+/, "");
      const open = BLOCK_OPEN.exec(value);
      if (open) {
        const terminator = open[1] || ">>>";
        const body = [];
        let closed = false;
        while (index < lines.length) {
          const blockLine = lines[index++];
          if (blockLine.trim() === terminator) {
            closed = true;
            break;
          }
          body.push(blockLine);
        }
        if (!closed) {
          errors.push({ line: lineNo, message: `the multi-line value of "${key}" is never closed; end it with a line containing only ${terminator}` });
        }
        entries.push({ type: "field", key, op, value: body.join("\n"), block: true, line: lineNo });
        pendingList = null;
        continue;
      }
      entries.push({ type: "field", key, op, value, line: lineNo });
      pendingList = value.trim() === "" ? key : null;
      continue;
    }

    if (item) {
      errors.push({ line: lineNo, message: "a \"- item\" line must follow a list field written as \"key:\" with nothing after the colon" });
    } else {
      errors.push({ line: lineNo, message: "cannot read this line; expected \"key: value\", \"[section]\", \"# comment\", or a blank line (for text over several lines write \"key: <<<\" and end it with a line \">>>\")" });
    }
  }
  return { entries, errors };
}

// ---------------------------------------------------------------------------
// Spec-driven builder
// ---------------------------------------------------------------------------

/**
 * A spec set maps names to section specs:
 *   { fields: { "dotted.key": FieldSpec }, sections: { name: specName },
 *     aliases: { alias: "dotted.key" }, into: "json.path", single: bool,
 *     label: "display name", open: bool }
 * FieldSpec: { type: text|raw|plain|token|int|bool|enum, list, split, values, nullable, help }
 */

function levenshtein(a, b) {
  const row = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i++) {
    let previous = row[0];
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const saved = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1));
      previous = saved;
    }
  }
  return row[b.length];
}

function suggest(word, candidates) {
  let best = null;
  let bestScore = Infinity;
  for (const candidate of candidates) {
    const score = levenshtein(word, candidate);
    const tail = candidate.split(".").pop();
    const tailScore = tail === word ? 0 : Infinity;
    const effective = Math.min(score, tailScore);
    if (effective < bestScore) {
      best = candidate;
      bestScore = effective;
    }
  }
  return best !== null && bestScore <= Math.max(2, Math.floor(word.length / 3)) ? best : null;
}

function normalizeSectionName(name) {
  return name.toLowerCase().replace(/-/g, "_");
}

function resolveSection(spec, name) {
  const wanted = normalizeSectionName(name);
  for (const key of Object.keys(spec.sections || {})) {
    if (normalizeSectionName(key) === wanted) return spec.sections[key];
  }
  return null;
}

function resolveField(spec, key) {
  const wanted = key.toLowerCase();
  if (hasOwn(spec.fields, wanted)) return wanted;
  if (spec.aliases && hasOwn(spec.aliases, wanted)) return spec.aliases[wanted];
  return null;
}

function getPath(object, dotted) {
  let current = object;
  for (const part of dotted.split(".")) {
    if (current === null || typeof current !== "object" || !hasOwn(current, part)) return undefined;
    current = current[part];
  }
  return current;
}

function containerFor(object, dotted, lineInfo, line) {
  const parts = dotted.split(".");
  let current = object;
  for (const part of parts.slice(0, -1)) {
    if (!hasOwn(current, part) || current[part] === null || typeof current[part] !== "object") {
      current[part] = {};
      lineInfo.set(current[part], { line, fields: new Map() });
      const parentInfo = lineInfo.get(current);
      if (parentInfo && !parentInfo.fields.has(part)) parentInfo.fields.set(part, line);
    }
    current = current[part];
  }
  return { container: current, leaf: parts[parts.length - 1] };
}

function stripWrappingQuotes(value) {
  const match = /^(["'`])([\s\S]*)\1$/.exec(value);
  return match ? match[2] : value;
}

function coerceText(spec, raw) {
  switch (spec.type) {
    case "raw":
      return { values: [raw] };
    case "text":
      return { values: [raw.trim()] };
    case "plain":
      return { values: [stripWrappingQuotes(raw.trim()).trim()] };
    case "token": {
      const cleaned = stripWrappingQuotes(raw.trim()).trim();
      if (spec.split) return { values: cleaned.split(/[\s,]+/).filter((part) => part !== "").map(stripWrappingQuotes) };
      return { values: [cleaned] };
    }
    case "int": {
      const cleaned = stripWrappingQuotes(raw.trim());
      if (!/^[+-]?\d+$/.test(cleaned)) return { error: `expected a whole number, got ${JSON.stringify(cleaned)}` };
      return { values: [Number(cleaned)] };
    }
    case "bool": {
      const cleaned = stripWrappingQuotes(raw.trim()).toLowerCase();
      if (["true", "yes"].includes(cleaned)) return { values: [true] };
      if (["false", "no"].includes(cleaned)) return { values: [false] };
      return { error: `expected true or false, got ${JSON.stringify(cleaned)}` };
    }
    case "enum": {
      const cleaned = stripWrappingQuotes(raw.trim()).trim();
      const match = spec.values.find((allowed) => allowed.toLowerCase() === cleaned.toLowerCase());
      if (match === undefined) return { error: `expected one of ${spec.values.join(" | ")}, got ${JSON.stringify(cleaned)}` };
      return { values: [match] };
    }
    default:
      return { error: `internal: unknown field type ${spec.type}` };
  }
}

function coerceJson(spec, rawJson) {
  let parsed;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    return { error: "after \"=\" write one JSON value such as null, \"\", 12, or \"text with \\n escapes\"; for ordinary text write \"key: value\" instead" };
  }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  if (Array.isArray(parsed) && !spec.list) return { error: "a JSON list is only allowed for list fields" };
  const values = [];
  for (const item of items) {
    if (item === null) {
      if (!spec.nullable) return { error: "null is not allowed for this field" };
      values.push(null);
    } else if (typeof item === "string") {
      if (spec.type === "int" || spec.type === "bool") return { error: `expected a ${spec.type === "int" ? "whole number" : "true or false"}, got a string` };
      if (spec.type === "enum" && !spec.values.includes(item)) return { error: `expected one of ${spec.values.join(" | ")}` };
      values.push(item);
    } else if (typeof item === "number") {
      if (spec.type !== "int" || !Number.isInteger(item)) return { error: "a number is only allowed for whole-number fields" };
      values.push(item);
    } else if (typeof item === "boolean") {
      if (spec.type !== "bool") return { error: "true/false is only allowed for true-or-false fields" };
      values.push(item);
    } else {
      return { error: "only strings, numbers, true/false, and null are allowed after \"=\"" };
    }
  }
  return { values, exact: true };
}

/**
 * Builds a JSON value from record text according to `specs[rootName]`.
 * Returns { value, errors, lineInfo }. lineInfo maps every built object to
 * { line, fields: Map<key, line>, section } so validator paths can be traced
 * back to the source line that produced them.
 */
function parseRecordText(text, specs, rootName) {
  const { entries, errors } = tokenize(text);
  const lineInfo = new WeakMap();
  const rootSpec = specs[rootName];
  const root = {};
  lineInfo.set(root, { line: 1, fields: new Map(), section: rootSpec.label || rootName });
  const nodes = [];
  const rootNode = { spec: rootSpec, specName: rootName, obj: root, line: 1, filled: false, parent: null, seen: new Map() };
  const stack = [rootNode];

  for (const entry of entries) {
    if (entry.type === "section") {
      let depth = stack.length - 1;
      let childName = null;
      while (depth >= 0) {
        childName = resolveSection(stack[depth].spec, entry.name);
        if (childName) break;
        depth--;
      }
      if (!childName) {
        const allowed = new Set();
        for (const node of stack) for (const key of Object.keys(node.spec.sections || {})) allowed.add(`[${key}]`);
        errors.push({ line: entry.line, message: `unknown section [${entry.name}] here; allowed: ${[...allowed].join(", ") || "none"}` });
        // Push an inert node so its fields are reported once, not misplaced.
        stack.push({ spec: { fields: {}, sections: {}, inert: true }, obj: {}, line: entry.line, filled: false, parent: null, seen: new Map() });
        continue;
      }
      stack.length = depth + 1;
      const parentNode = stack[depth];
      const childSpec = specs[childName];
      const child = {};
      lineInfo.set(child, { line: entry.line, fields: new Map(), section: childSpec.label || childName });
      const node = { spec: childSpec, specName: childName, obj: child, line: entry.line, filled: false, parent: parentNode, seen: new Map() };
      if (childSpec.single) {
        const existing = getPath(parentNode.obj, childSpec.into);
        if (existing !== undefined) {
          errors.push({ line: entry.line, message: `[${entry.name}] may appear only once` });
        }
        const { container, leaf } = containerFor(parentNode.obj, childSpec.into, lineInfo, entry.line);
        container[leaf] = child;
        lineInfo.get(container).fields.set(leaf, entry.line);
      } else {
        const { container, leaf } = containerFor(parentNode.obj, childSpec.into, lineInfo, entry.line);
        if (!Array.isArray(container[leaf])) container[leaf] = [];
        container[leaf].push(child);
        const containerInfo = lineInfo.get(container);
        if (containerInfo && !containerInfo.fields.has(leaf)) containerInfo.fields.set(leaf, entry.line);
      }
      node.container = getPath(parentNode.obj, childSpec.into);
      nodes.push(node);
      stack.push(node);
      continue;
    }

    // Field: the innermost open section that defines the key receives it.
    if (stack[stack.length - 1].spec.inert) continue;
    let target = null;
    let key = null;
    for (let depth = stack.length - 1; depth >= 0; depth--) {
      key = resolveField(stack[depth].spec, entry.key);
      if (key) {
        target = stack[depth];
        break;
      }
    }
    let fieldSpec = target ? target.spec.fields[key] : null;
    if (!target) {
      const top = stack[stack.length - 1];
      if (top.spec.open) {
        target = top;
        key = entry.key;
        fieldSpec = { type: "text", list: false, extra: true };
      } else {
        const known = new Set();
        for (const node of stack) Object.keys(node.spec.fields).forEach((name) => known.add(name));
        const hint = suggest(entry.key.toLowerCase(), known);
        const where = top === rootNode ? "at the top level" : `in [${top.spec.label || top.specName}]`;
        errors.push({ line: entry.line, message: `unknown field "${entry.key}" ${where}${hint ? `; did you mean "${hint}"?` : ""}` });
        continue;
      }
    }

    if (entry.op === ":" && !entry.block && entry.value.trim() === "") continue;
    const coerced = entry.op === "=" ? coerceJson(fieldSpec, entry.value) : (fieldSpec.nullable && /^(null|none)$/i.test(entry.value.trim()) ? { values: [null] } : coerceText(fieldSpec, entry.value));
    if (coerced.error) {
      errors.push({ line: entry.line, message: `${key}: ${coerced.error}` });
      continue;
    }
    if (!fieldSpec.list && coerced.values.length !== 1) {
      errors.push({ line: entry.line, message: `${key}: expected exactly one value` });
      continue;
    }

    const { container, leaf } = containerFor(target.obj, key, lineInfo, entry.line);
    const info = lineInfo.get(container);
    if (fieldSpec.list) {
      if (!Array.isArray(container[leaf])) container[leaf] = [];
      container[leaf].push(...coerced.values);
      if (!info.fields.has(leaf)) info.fields.set(leaf, entry.line);
    } else {
      if (target.seen.has(key)) {
        const where = target === rootNode ? "at the top level" : `in this [${target.spec.label || target.specName}] item`;
        errors.push({ line: entry.line, message: `${key}: given twice ${where} (first on line ${target.seen.get(key)}); start a new section for a new item, or remove one` });
        continue;
      }
      target.seen.set(key, entry.line);
      container[leaf] = coerced.values[0];
      info.fields.set(leaf, entry.line);
    }
    for (let node = target; node; node = node.parent) node.filled = true;
  }

  // Drop sections that were left completely empty (unused template skeletons).
  for (let index = nodes.length - 1; index >= 0; index--) {
    const node = nodes[index];
    if (node.filled) continue;
    const parentObj = node.parent.obj;
    if (node.spec.single) {
      const { container, leaf } = containerFor(parentObj, node.spec.into, lineInfo, node.line);
      if (container[leaf] === node.obj) delete container[leaf];
    } else if (Array.isArray(node.container)) {
      const position = node.container.indexOf(node.obj);
      if (position !== -1) node.container.splice(position, 1);
      if (node.container.length === 0) {
        const { container, leaf } = containerFor(parentObj, node.spec.into, lineInfo, node.line);
        if (container[leaf] === node.container) delete container[leaf];
      }
    }
  }
  pruneEmptyObjects(root);

  errors.sort((left, right) => left.line - right.line);
  return { value: root, errors, lineInfo };
}

function pruneEmptyObjects(value) {
  if (Array.isArray(value)) {
    value.forEach(pruneEmptyObjects);
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const key of Object.keys(value)) {
    const child = value[key];
    if (child !== null && typeof child === "object" && !Array.isArray(child)) {
      pruneEmptyObjects(child);
      if (Object.keys(child).length === 0) delete value[key];
    } else if (Array.isArray(child)) {
      pruneEmptyObjects(child);
    }
  }
}

// ---------------------------------------------------------------------------
// Validator path -> source line
// ---------------------------------------------------------------------------

function parseValidatorPath(text) {
  const tokens = [];
  const pattern = /\.([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]|\[("(?:[^"\\]|\\.)*")\]|\{(\d+)\}/gy;
  let index = text.startsWith("$data") ? 5 : text.startsWith("$") ? 1 : 0;
  pattern.lastIndex = index;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    if (match[1] !== undefined) tokens.push(match[1]);
    else if (match[2] !== undefined) tokens.push(Number(match[2]));
    else if (match[3] !== undefined) tokens.push(JSON.parse(match[3]));
    index = pattern.lastIndex;
  }
  return { tokens, rest: text.slice(index) };
}

/** Returns the most specific source line for a validator path below `root`. */
function locate(root, tokens, lineInfo) {
  let current = root;
  let line = null;
  for (const token of tokens) {
    if (current === null || typeof current !== "object") break;
    const info = lineInfo.get(current);
    if (info) {
      if (line === null) line = info.line;
      if (typeof token === "string" && info.fields.has(token)) line = info.fields.get(token);
    }
    if (!hasOwn(current, token)) break;
    current = current[token];
    const childInfo = current !== null && typeof current === "object" ? lineInfo.get(current) : null;
    if (childInfo) line = childInfo.line;
  }
  if (line === null && root && lineInfo.get(root)) line = lineInfo.get(root).line;
  return line;
}

/**
 * Converts "$[0].trace[1].kind: message" from a validator run on `root` into
 * { line, message } with a readable relative path.
 */
function mapValidatorMessage(message, root, lineInfo, options = {}) {
  const { dropTokens = 0, label = "" } = options;
  const separator = message.indexOf(": ");
  const pathText = separator === -1 ? message : message.slice(0, separator);
  const detail = separator === -1 ? "" : message.slice(separator + 2);
  if (!pathText.startsWith("$")) return { line: null, message };
  const { tokens } = parseValidatorPath(pathText);
  const relative = tokens.slice(dropTokens);
  const line = locate(root, tokens, lineInfo);
  const readable = relative.map((token, position) => typeof token === "number" ? `[${token}]` : `${position === 0 ? "" : "."}${token}`).join("");
  const prefix = [label, readable].filter(Boolean).join(" ");
  return { line, message: prefix ? `${prefix}: ${detail}` : detail };
}

// ---------------------------------------------------------------------------
// Serializer
// ---------------------------------------------------------------------------

function chooseTerminator(value) {
  const lines = new Set(value.split("\n").map((line) => line.trim()));
  if (!lines.has(">>>")) return { open: "<<<", close: ">>>" };
  for (let index = 1; ; index++) {
    const tag = `END${index}`;
    if (!lines.has(tag)) return { open: `<<<${tag}`, close: tag };
  }
}

function formatScalar(key, value, type) {
  if (value === null) return `${key} = null`;
  if (typeof value === "number" || typeof value === "boolean") return `${key}: ${value}`;
  const text = String(value);
  const trimmedType = type !== "raw";
  if (text === "") return `${key} = ""`;
  const edgesTrimmed = text.trim() === text;
  if (!text.includes("\n")) {
    if (UNSAFE_SINGLE_LINE.test(text.replace(/\t/g, "")) || !edgesTrimmed || /^<<</.test(text) || (!trimmedType && text !== text.replace(/^[ \t]+/, ""))) {
      return `${key} = ${JSON.stringify(text)}`;
    }
    if ((type === "plain" || type === "token" || type === "enum") && /^(["'`]).*\1$/.test(text)) return `${key} = ${JSON.stringify(text)}`;
    return `${key}: ${text}`;
  }
  const withoutNewlines = text.replace(/[\t\n]/g, "");
  if (UNSAFE_SINGLE_LINE.test(withoutNewlines) || (trimmedType && !edgesTrimmed)) return `${key} = ${JSON.stringify(text)}`;
  const { open, close } = chooseTerminator(text);
  return `${key}: ${open}\n${text}\n${close}`;
}

function sectionEntries(specs, specName) {
  const spec = specs[specName];
  const seen = new Set();
  const result = [];
  for (const [name, childName] of Object.entries(spec.sections || {})) {
    if (seen.has(childName)) continue;
    seen.add(childName);
    result.push({ name, childName });
  }
  return result;
}

/**
 * Serializes `value` with `specs[specName]`. In skeleton mode every field is
 * written (empty when absent), help comments are added, and each section with
 * no items gets one empty item to fill in.
 */
function serializeRecordText(value, specs, specName, options = {}) {
  const { skeleton = false, comments = skeleton, onlyFields = null, header = null } = options;
  const out = [];
  if (header) for (const line of header) out.push(line === "" ? "" : `# ${line}`);
  writeNode(value || {}, specs, specName, out, { skeleton, comments, onlyFields });
  return `${out.join("\n").replace(/\n{3,}/g, "\n\n").replace(/^\n+/, "")}\n`;
}

function writeNode(value, specs, specName, out, options) {
  const spec = specs[specName];
  const { skeleton, comments, onlyFields } = options;
  const fieldFilter = onlyFields && onlyFields[specName];
  for (const [key, fieldSpec] of Object.entries(spec.fields)) {
    if (fieldSpec.hidden) continue;
    if (fieldFilter && !fieldFilter.has(key)) continue;
    const current = getPath(value, key);
    if (comments && fieldSpec.help) for (const line of [].concat(fieldSpec.help)) out.push(`# ${line}`);
    if (fieldSpec.list) {
      const items = Array.isArray(current) ? current : [];
      if (items.length === 0 && skeleton) out.push(`${key}:`);
      for (const item of items) out.push(formatScalar(key, item, fieldSpec.type));
    } else if (current === undefined) {
      if (skeleton) out.push(`${key}:`);
    } else {
      out.push(formatScalar(key, current, fieldSpec.type));
    }
  }
  for (const { name, childName } of sectionEntries(specs, specName)) {
    const childSpec = specs[childName];
    if (fieldFilter && !fieldFilter.has(`[${name}]`)) continue;
    const current = getPath(value, childSpec.into);
    const items = childSpec.single ? (current === undefined ? [] : [current]) : (Array.isArray(current) ? current : []);
    if (items.length === 0 && !(skeleton && !childSpec.noSkeleton)) continue;
    for (const item of items.length === 0 ? [{}] : items) {
      out.push("");
      if (comments && childSpec.help) for (const line of childSpec.help) out.push(`# ${line}`);
      out.push(`[${name}]`);
      writeNode(item, specs, childName, out, options);
    }
  }
}

/** Generic, spec-less display of any JSON value as record-text-like lines. */
function displayText(value, prefix = "", out = []) {
  if (Array.isArray(value)) {
    if (value.every((item) => item === null || typeof item !== "object")) {
      if (value.length === 0) out.push(`${prefix}: (none)`);
      for (const item of value) out.push(formatScalar(prefix, item, "text"));
      return out;
    }
    value.forEach((item, index) => {
      out.push(`[${prefix} #${index + 1}]`);
      displayText(item, "", out);
    });
    return out;
  }
  if (value !== null && typeof value === "object") {
    const nested = [];
    for (const [key, child] of Object.entries(value)) {
      const name = prefix ? `${prefix}.${key}` : key;
      if (Array.isArray(child) && child.some((item) => item !== null && typeof item === "object")) {
        nested.push([name, child]);
      } else {
        displayText(child, name, out);
      }
    }
    for (const [name, child] of nested) displayText(child, name, out);
    return out;
  }
  out.push(formatScalar(prefix || "value", value, "text"));
  return out;
}

// ---------------------------------------------------------------------------
// Spec helpers
// ---------------------------------------------------------------------------

const field = (type, extra = {}) => ({ type, ...extra });
const list = (type, extra = {}) => ({ type, list: true, ...extra });

/**
 * Derives finding-record specs from report-schema.json so the authoring format
 * can never drift from the schema. Returns a spec set whose `record` entry
 * accepts the union of the selected verdict branches.
 */
function recordSpecsFromSchema(schema, options = {}) {
  const { verdictKey = "verdict", verdicts = null, recordName = "record", into = "record", single = true, label = recordName } = options;
  const branches = schema.items.oneOf.filter((branch) => verdicts === null || verdicts.includes(branch.properties.verdict.const));
  const specs = {};
  const record = { fields: {}, sections: {}, aliases: {}, into, single, label, branchInfo: {} };
  specs[recordName] = record;

  function typeOf(sub) {
    if (sub.type === "integer") return field("int");
    if (hasOwn(sub, "const")) return field("enum", { values: [sub.const] });
    if (hasOwn(sub, "enum")) return field("enum", { values: sub.enum.slice() });
    if (hasOwn(sub, "pattern")) return field("token");
    if (sub.visibleContent) return field("text");
    if (hasOwn(sub, "minLength")) return field("plain");
    return field("raw");
  }

  function mergeField(target, key, spec, verdict, required) {
    if (!hasOwn(target.fields, key)) {
      target.fields[key] = { ...spec, verdicts: new Set(), requiredIn: new Set() };
    } else if (spec.type === "enum" && key === verdictKey) {
      for (const value of spec.values) if (!target.fields[key].values.includes(value)) target.fields[key].values.push(value);
    }
    target.fields[key].verdicts.add(verdict);
    if (required) target.fields[key].requiredIn.add(verdict);
  }

  function walkObject(properties, requiredList, prefix, target, verdict, required, specNamePrefix) {
    for (const [name, sub] of Object.entries(properties)) {
      const key = prefix ? `${prefix}.${name}` : name;
      const isRequired = required && (requiredList || []).includes(name);
      if (sub.description && !(target.descriptions || (target.descriptions = {}))[key]) target.descriptions[key] = sub.description;
      if (sub.type === "object" && sub.properties) {
        walkObject(sub.properties, sub.required, key, target, verdict, isRequired, specNamePrefix);
      } else if (sub.type === "array" && sub.items && sub.items.type === "object") {
        const childName = `${specNamePrefix}.${name}`;
        if (!specs[childName]) {
          specs[childName] = { fields: {}, sections: {}, aliases: {}, into: key, label: name, verdicts: new Set(), requiredIn: new Set(), minItems: sub.minItems || 0 };
        }
        const child = specs[childName];
        child.verdicts.add(verdict);
        if (isRequired && (sub.minItems || 0) > 0) child.requiredIn.add(verdict);
        target.sections[name] = childName;
        const singular = name.endsWith("ies") ? `${name.slice(0, -3)}y` : name.endsWith("s") ? name.slice(0, -1) : null;
        if (singular) target.sections[singular] = childName;
        if (prefix) target.sections[key] = childName;
        walkObject(sub.items.properties, sub.items.required, "", child, verdict, true, childName);
      } else if (sub.type === "array") {
        mergeField(target, key, { ...typeOf(sub.items || {}), list: true, minItems: sub.minItems || 0 }, verdict, isRequired);
      } else {
        const renamed = key === "verdict" ? verdictKey : key;
        mergeField(target, renamed, typeOf(sub), verdict, isRequired);
      }
    }
  }

  record.verdictDescriptions = {};
  for (const branch of branches) {
    const verdict = branch.properties.verdict.const;
    if (branch.description) record.verdictDescriptions[verdict] = branch.description;
    walkObject(branch.properties, branch.required, "", record, verdict, true, recordName);
  }
  if (verdictKey !== "verdict") record.aliases.verdict = verdictKey;
  // Allow `file: src/a.c:10` in trace/evidence without a separate line field.
  for (const spec of Object.values(specs)) {
    if (spec.fields.file && spec.fields.line) spec.fileLine = true;
  }
  addRecordHelp(specs, recordName, branches.map((branch) => branch.properties.verdict.const), verdictKey);
  return specs;
}

function describeVerdicts(set, all) {
  const values = [...set];
  if (values.length === all.length) return "every verdict";
  return values.join(" and ") + " only";
}

function addRecordHelp(specs, recordName, allVerdicts, verdictKey) {
  const record = specs[recordName];
  const groups = new Map();
  for (const [key, spec] of Object.entries(record.fields)) {
    const parts = [];
    if (key === verdictKey) {
      parts.push(`${key}: ${spec.values.join(" | ")}`);
    } else {
      parts.push(key);
      const applies = describeVerdicts(spec.verdicts, allVerdicts);
      const requiredIn = [...spec.requiredIn];
      if (requiredIn.length > 0) {
        parts.push(requiredIn.length === spec.verdicts.size ? `required (${applies})` : `required for ${requiredIn.join(", ")} (${applies})`);
      } else {
        parts.push(`optional (${applies})`);
      }
      if (spec.type === "enum") parts.push(spec.values.join(" | "));
      if (spec.type === "token") parts.push("pattern ^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$, no line/wave/agent/severity/verdict");
      if (spec.list) parts.push(spec.minItems ? `one per line, at least ${spec.minItems}` : "one per line");
      if (spec.type === "raw") parts.push("exact text; use <<< >>> for several lines");
    }
    // Carry the schema's own descriptions: verdict meanings, then the field's and its parent object's.
    const lines = [];
    if (key === verdictKey) {
      for (const [verdict, text] of Object.entries(record.verdictDescriptions || {})) lines.push(`  ${verdict}: ${text}`);
    }
    const descriptions = record.descriptions || {};
    const parent = key.includes(".") ? key.slice(0, key.indexOf(".")) : null;
    const firstOfParent = parent && Object.keys(record.fields).find((name) => name.startsWith(`${parent}.`)) === key;
    if (firstOfParent && descriptions[parent]) lines.unshift(`${parent} — ${descriptions[parent]}`);
    const ownDescription = key === verdictKey ? null : descriptions[key];
    spec.help = [...lines.filter((line) => !line.startsWith("  ")), parts.join(" — ") + (ownDescription ? ` — ${ownDescription}` : ""), ...lines.filter((line) => line.startsWith("  "))];
    const groupKey = key === verdictKey ? "" : [...spec.verdicts].sort().join(",");
    if (!groups.has(groupKey)) groups.set(groupKey, []);
    groups.get(groupKey).push(key);
  }
  // Reorder fields: verdict first, then fields shared by every verdict, then per-verdict groups.
  const order = [...groups.keys()].sort((left, right) => {
    const rank = (key) => key === "" ? -1 : key.split(",").length === allVerdicts.length ? 0 : 1;
    return rank(left) - rank(right) || allVerdicts.indexOf(left.split(",")[0]) - allVerdicts.indexOf(right.split(",")[0]) || right.split(",").length - left.split(",").length;
  });
  const reordered = {};
  for (const groupKey of order) for (const key of groups.get(groupKey)) reordered[key] = record.fields[key];
  record.fields = reordered;
  for (const [name, childName] of Object.entries(record.sections)) {
    const child = specs[childName];
    if (child.help || name !== child.label) continue;
    const applies = describeVerdicts(child.verdicts, allVerdicts);
    const required = child.requiredIn.size > 0 ? `at least ${child.minItems} required (${applies})` : `optional (${applies})`;
    child.help = [`[${name}] — one section per item, ${required}`];
    for (const [key, spec] of Object.entries(child.fields)) {
      const extras = [];
      if (spec.type === "enum") extras.push(spec.values.join(" | "));
      if (key === "file" && child.fields.line) extras.push("repository-relative; \"file: path:line\" also works");
      if (spec.type === "raw") extras.push("exact text; use <<< >>> for several lines");
      if (extras.length > 0) spec.help = `${key} — ${extras.join(" — ")}`;
    }
  }
}

/** Splits `file: path:12` into file and line after parsing. */
function splitFileLines(value, specs, specName) {
  const spec = specs[specName];
  if (!spec) return;
  if (spec.fileLine && value && typeof value === "object" && typeof value.file === "string" && value.line === undefined) {
    const match = /^(.*\S):(\d+)$/.exec(value.file);
    if (match) {
      value.file = match[1];
      value.line = Number(match[2]);
    }
  }
  for (const childName of new Set(Object.values(spec.sections || {}))) {
    const childSpec = specs[childName];
    const current = getPath(value, childSpec.into);
    const items = childSpec.single ? (current ? [current] : []) : (Array.isArray(current) ? current : []);
    for (const item of items) splitFileLines(item, specs, childName);
  }
}

module.exports = {
  displayText,
  field,
  formatScalar,
  getPath,
  list,
  mapValidatorMessage,
  parseRecordText,
  parseValidatorPath,
  locate,
  recordSpecsFromSchema,
  serializeRecordText,
  splitFileLines,
  tokenize,
};
