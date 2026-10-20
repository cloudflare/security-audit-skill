#!/usr/bin/env node

/**
 * Validates run-metadata.json against the documented run-state contract.
 * Usage: node validate-run-metadata.cjs <path-to-run-metadata.json>
 *
 * When run_status is "complete", sibling coverage-ledger.json in the same
 * directory is required. Candidate fingerprints on that ledger must each
 * appear in sibling findings.json (treated as empty if that file is absent).
 */

const fs = require("node:fs");
const path = require("node:path");
const { TextDecoder } = require("node:util");

const LIMITS = Object.freeze({
  inputBytes: 5 * 1024 * 1024,
  collectionItems: 1000,
  objectFields: 1000,
  nestingDepth: 64,
  preflightValues: 500000,
  validationErrors: 100,
});
const MAX_INPUT_BYTES = LIMITS.inputBytes;
const MAX_LIST_ITEMS = LIMITS.collectionItems;
const MAX_TEXT_LENGTH = 4096;
const REQUIRED_FIELDS = [
  "run_id",
  "repo",
  "target",
  "source_ref",
  "profile",
  "scope_paths",
  "budget",
  "execution_policy",
  "run_status",
];
const PROFILES = new Set(["quick", "standard", "deep"]);
const RUN_STATUSES = new Set(["in_progress", "complete", "incomplete"]);
const INCOMPLETE_REASONS = new Set([
  "budget_cannot_fund_reconnaissance_and_reserves",
  "critic_budget_exhausted",
  "validation_budget_exhausted",
]);
const EXECUTION_POLICY = "sandboxed-source-and-local-only";
const VISIBLE_CONTENT = /[^\p{White_Space}\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}]/u;
const PATH_FORBIDDEN_CHARACTER = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u;
const WINDOWS_RESERVED_COMPONENT = /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\.|$)/iu;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const UNSAFE_DIAGNOSTIC_CHARACTER = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu;
const MAX_DIAGNOSTIC_STRING_LENGTH = 256;

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

class JsonStructureError extends Error {}
class SafeInputError extends Error {}

function escapeUnsafeDiagnosticCharacters(value) {
  return String(value).replace(UNSAFE_DIAGNOSTIC_CHARACTER, (character) => {
    const codePoint = character.codePointAt(0);
    return codePoint <= 0xffff
      ? `\\u${codePoint.toString(16).padStart(4, "0")}`
      : `\\u{${codePoint.toString(16)}}`;
  });
}

function safeQuote(value) {
  let serialized;
  if (typeof value === "string") {
    const clipped = value.length > MAX_DIAGNOSTIC_STRING_LENGTH
      ? `${value.slice(0, MAX_DIAGNOSTIC_STRING_LENGTH)}...`
      : value;
    serialized = JSON.stringify(clipped);
  } else if (value === null || typeof value === "boolean") {
    serialized = String(value);
  } else if (typeof value === "number" && Number.isFinite(value)) {
    serialized = String(value);
  } else {
    serialized = `"<${Array.isArray(value) ? "array" : typeof value}>"`;
  }
  return escapeUnsafeDiagnosticCharacters(serialized);
}

function createErrorList() {
  const errors = [];
  Object.defineProperty(errors, "push", {
    value(...messages) {
      const remaining = LIMITS.validationErrors - this.length;
      if (remaining > 0) {
        Array.prototype.push.apply(this, messages.slice(0, remaining).map(escapeUnsafeDiagnosticCharacters));
      }
      return this.length;
    },
  });
  return errors;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function preflightJsonText(contents) {
  const containers = [];
  let rootState = "value";
  let inString = false;
  let escaped = false;
  let totalValues = 0;

  function fail(message) {
    throw new JsonStructureError(`input ${message}`);
  }

  function currentContainer() {
    return containers[containers.length - 1];
  }

  function countValue() {
    totalValues++;
    if (totalValues > LIMITS.preflightValues) {
      fail(`exceeds ${LIMITS.preflightValues} total value limit`);
    }
  }

  function beginValue() {
    const container = currentContainer();
    if (!container) {
      if (rootState !== "value") fail("has malformed JSON structure");
      rootState = "end";
    } else if (container.type === "array") {
      if (container.state !== "firstValueOrEnd" && container.state !== "value") {
        fail("has malformed JSON array structure");
      }
      container.items++;
      if (container.items > LIMITS.collectionItems) {
        fail(`exceeds ${LIMITS.collectionItems} item array limit`);
      }
      container.state = "commaOrEnd";
    } else {
      if (container.state !== "value") fail("has malformed JSON object structure");
      container.state = "commaOrEnd";
    }
    countValue();
  }

  function beginString() {
    const container = currentContainer();
    if (container && container.type === "object" &&
        (container.state === "firstKeyOrEnd" || container.state === "key")) {
      container.fields++;
      if (container.fields > LIMITS.objectFields) {
        fail(`exceeds ${LIMITS.objectFields} field object limit`);
      }
      container.state = "colon";
    } else {
      beginValue();
    }
    inString = true;
  }

  function beginContainer(type) {
    beginValue();
    if (containers.length >= LIMITS.nestingDepth) {
      fail(`exceeds nesting depth limit ${LIMITS.nestingDepth}`);
    }
    containers.push(type === "array"
      ? { type, state: "firstValueOrEnd", items: 0 }
      : { type, state: "firstKeyOrEnd", fields: 0 });
  }

  function closeContainer(type) {
    const container = currentContainer();
    if (!container || container.type !== type) fail("has mismatched JSON containers");
    const canClose = type === "array"
      ? container.state === "firstValueOrEnd" || container.state === "commaOrEnd"
      : container.state === "firstKeyOrEnd" || container.state === "commaOrEnd";
    if (!canClose) fail(`has malformed JSON ${type} structure`);
    containers.pop();
  }

  function isWhitespace(character) {
    return character === " " || character === "\t" || character === "\r" || character === "\n";
  }

  function isTokenDelimiter(character) {
    return isWhitespace(character) || character === "," || character === ":" ||
      character === "[" || character === "]" || character === "{" ||
      character === "}" || character === "\"";
  }

  for (let index = 0; index < contents.length; index++) {
    const character = contents[index];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === "\"") {
        inString = false;
      }
      continue;
    }
    if (isWhitespace(character)) continue;

    if (character === "\"") {
      beginString();
    } else if (character === "[") {
      beginContainer("array");
    } else if (character === "{") {
      beginContainer("object");
    } else if (character === "]") {
      closeContainer("array");
    } else if (character === "}") {
      closeContainer("object");
    } else if (character === ":") {
      const container = currentContainer();
      if (!container || container.type !== "object" || container.state !== "colon") {
        fail("has malformed JSON object structure");
      }
      container.state = "value";
    } else if (character === ",") {
      const container = currentContainer();
      if (!container || container.state !== "commaOrEnd") fail("has malformed JSON collection structure");
      container.state = container.type === "array" ? "value" : "key";
    } else {
      beginValue();
      while (index + 1 < contents.length && !isTokenDelimiter(contents[index + 1])) index++;
    }
  }

  if (inString) fail("has an unterminated JSON string");
  if (containers.length > 0) fail("has truncated JSON structure");
  if (rootState !== "end") fail("has no JSON value");
}

function preflightDocument(root) {
  const errors = createErrorList();
  const stack = [{ value: root, depth: 0, location: "$" }];
  let visited = 0;

  while (stack.length > 0) {
    const { value, depth, location } = stack.pop();
    visited++;
    if (visited > LIMITS.preflightValues) {
      errors.push(`$: exceeds ${LIMITS.preflightValues} total values`);
      return errors;
    }
    if (value === null || typeof value !== "object") continue;
    if (depth >= LIMITS.nestingDepth) {
      errors.push(`${location}: exceeds nesting depth limit ${LIMITS.nestingDepth}`);
      return errors;
    }

    if (Array.isArray(value)) {
      if (value.length > MAX_LIST_ITEMS) {
        errors.push(`${location}: exceeds ${MAX_LIST_ITEMS} entries`);
        return errors;
      }
      for (let index = value.length - 1; index >= 0; index--) {
        stack.push({ value: value[index], depth: depth + 1, location: `${location}[${index}]` });
      }
      continue;
    }

    const keys = Object.keys(value);
    if (keys.length > LIMITS.objectFields) {
      errors.push(`${location}: exceeds ${LIMITS.objectFields} object fields`);
      return errors;
    }
    for (let index = keys.length - 1; index >= 0; index--) {
      const key = keys[index];
      stack.push({ value: value[key], depth: depth + 1, location: `${location}{${index}}` });
    }
  }

  return errors;
}

function hasValidUnicodeScalarValues(value) {
  let index = 0;
  while (index < value.length) {
    const first = value.charCodeAt(index++);
    if (first >= 0xd800 && first <= 0xdbff) {
      if (index >= value.length) return false;
      const second = value.charCodeAt(index++);
      if (second < 0xdc00 || second > 0xdfff) return false;
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function hasVisibleProse(value) {
  return hasValidUnicodeScalarValues(value) && VISIBLE_CONTENT.test(value);
}

function isVisibleText(value, maxLength = MAX_TEXT_LENGTH) {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= maxLength &&
    value.trim() === value &&
    hasVisibleProse(value);
}

function isSafeRelativePath(value) {
  if (typeof value !== "string" || value.length === 0 || !hasValidUnicodeScalarValues(value) || value.trim() !== value || PATH_FORBIDDEN_CHARACTER.test(value) || value.includes("\\") || value.includes(":")) return false;
  if (path.posix.isAbsolute(value) || path.win32.isAbsolute(value) || /^[A-Za-z]:/.test(value) || value.startsWith("~")) return false;
  return value.split("/").every((segment) =>
    segment !== "" &&
    segment !== "." &&
    segment !== ".." &&
    !/[ .]$/u.test(segment) &&
    !WINDOWS_RESERVED_COMPONENT.test(segment));
}

function validateStringArray(value, location, errors, options = {}) {
  const { allowEmpty = true, pathValue = false } = options;
  if (!Array.isArray(value)) {
    errors.push(`${location}: expected array`);
    return;
  }
  if (!allowEmpty && value.length === 0) errors.push(`${location}: must not be empty`);
  if (value.length > MAX_LIST_ITEMS) errors.push(`${location}: exceeds ${MAX_LIST_ITEMS} entries`);
  const seen = new Set();
  value.slice(0, MAX_LIST_ITEMS).forEach((entry, index) => {
    const entryLocation = `${location}[${index}]`;
    const valid = pathValue ? isSafeRelativePath(entry) : isVisibleText(entry);
    if (!valid) errors.push(`${entryLocation}: invalid ${pathValue ? "repository-relative path" : "text"}`);
    if (typeof entry === "string" && seen.has(entry)) errors.push(`${entryLocation}: duplicate entry`);
    if (typeof entry === "string") seen.add(entry);
  });
}

function collectFindingFingerprints(findings) {
  const fingerprints = new Set();
  if (!Array.isArray(findings)) return fingerprints;
  for (const finding of findings) {
    if (isObject(finding) && typeof finding.fingerprint === "string") {
      fingerprints.add(finding.fingerprint);
    }
  }
  return fingerprints;
}

function validateCompleteCrossCheck(metadata, options, errors) {
  if (metadata.run_status !== "complete") return;

  if (options.completeRequiresLedger && options.ledger === undefined) {
    errors.push("$: complete run requires sibling coverage-ledger.json");
    return;
  }
  if (options.ledger === undefined) return;

  if (!Array.isArray(options.ledger)) {
    errors.push("coverage-ledger.json: expected a top-level array");
    return;
  }

  const findings = options.findings;
  if (findings !== undefined && !Array.isArray(findings)) {
    errors.push("findings.json: expected a top-level array");
    return;
  }
  const fingerprints = collectFindingFingerprints(findings === undefined ? [] : findings);

  options.ledger.forEach((unit, index) => {
    if (!isObject(unit) || unit.status !== "candidate") return;
    if (!Array.isArray(unit.result_fingerprints)) return;
    unit.result_fingerprints.forEach((fingerprint, fingerprintIndex) => {
      if (typeof fingerprint !== "string") return;
      if (!fingerprints.has(fingerprint)) {
        errors.push(
          `coverage-ledger.json[${index}].result_fingerprints[${fingerprintIndex}]: complete run cannot leave candidate fingerprint ${safeQuote(fingerprint)} absent from findings.json`,
        );
      }
    });
  });
}

function validateDocument(metadata, options = {}) {
  const errors = createErrorList();
  if (!isObject(metadata)) {
    errors.push("$: expected a top-level object");
    return errors;
  }

  errors.push(...preflightDocument(metadata));
  if (errors.length > 0) return errors;

  for (const field of REQUIRED_FIELDS) {
    if (!hasOwn(metadata, field)) errors.push(`$: missing required field ${safeQuote(field)}`);
  }

  for (const field of ["run_id", "repo", "target", "source_ref"]) {
    if (hasOwn(metadata, field) && !isVisibleText(metadata[field])) {
      errors.push(`$.${field}: invalid text`);
    }
  }

  if (hasOwn(metadata, "profile") && !PROFILES.has(metadata.profile)) {
    errors.push(`$.profile: expected "quick", "standard", or "deep", got ${safeQuote(metadata.profile)}`);
  }

  if (hasOwn(metadata, "scope_paths")) {
    validateStringArray(metadata.scope_paths, "$.scope_paths", errors, { pathValue: true });
  }

  if (hasOwn(metadata, "budget") && metadata.budget !== null &&
      !(Number.isInteger(metadata.budget) && metadata.budget >= 1)) {
    errors.push("$.budget: expected null or a positive integer");
  }

  if (hasOwn(metadata, "execution_policy") && metadata.execution_policy !== EXECUTION_POLICY) {
    errors.push(`$.execution_policy: expected ${safeQuote(EXECUTION_POLICY)}, got ${safeQuote(metadata.execution_policy)}`);
  }

  if (hasOwn(metadata, "run_status") && !RUN_STATUSES.has(metadata.run_status)) {
    errors.push(`$.run_status: expected "in_progress", "complete", or "incomplete", got ${safeQuote(metadata.run_status)}`);
  }

  const hasReason = hasOwn(metadata, "incomplete_reason");
  if (metadata.run_status === "incomplete") {
    if (!hasReason) {
      errors.push('$.incomplete_reason: required when run_status is "incomplete"');
    } else if (!INCOMPLETE_REASONS.has(metadata.incomplete_reason)) {
      errors.push('$.incomplete_reason: expected "budget_cannot_fund_reconnaissance_and_reserves", "critic_budget_exhausted", or "validation_budget_exhausted", got ' +
        safeQuote(metadata.incomplete_reason));
    }
  } else if (hasReason) {
    errors.push('$.incomplete_reason: allowed only when run_status is "incomplete"');
  }

  if (hasOwn(metadata, "selected_companion_files")) {
    validateStringArray(metadata.selected_companion_files, "$.selected_companion_files", errors);
  }
  if (hasOwn(metadata, "prior_run_paths")) {
    validateStringArray(metadata.prior_run_paths, "$.prior_run_paths", errors);
  }

  validateCompleteCrossCheck(metadata, options, errors);
  return errors;
}

function readFileWithinLimit(file) {
  const noFollow = fs.constants.O_NOFOLLOW;
  const nonBlock = fs.constants.O_NONBLOCK;
  if (!Number.isInteger(noFollow) || noFollow === 0 || !Number.isInteger(nonBlock) || nonBlock === 0) {
    throw new SafeInputError("OS no-follow and nonblocking input protection is unavailable");
  }

  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | noFollow | nonBlock);
  } catch (error) {
    if (error && (error.code === "ELOOP" || error.code === "EMLINK")) throw new SafeInputError("input must not be a symlink");
    throw error;
  }
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) throw new SafeInputError("input must be a regular file");
    if (stat.size > MAX_INPUT_BYTES) throw new SafeInputError(`input exceeds ${MAX_INPUT_BYTES} byte limit`);

    const chunks = [];
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let bytesRead = 0;
    while (true) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      bytesRead += count;
      if (bytesRead > MAX_INPUT_BYTES) throw new SafeInputError(`input exceeds ${MAX_INPUT_BYTES} byte limit`);
      chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    try {
      return UTF8_DECODER.decode(Buffer.concat(chunks, bytesRead));
    } catch {
      throw new SafeInputError("input is not valid UTF-8");
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function parseJsonFile(file, label) {
  let contents;
  try {
    contents = readFileWithinLimit(file);
  } catch (error) {
    if (error && error.code === "ENOENT") return { missing: true };
    const reason = error instanceof SafeInputError ? error.message : "input could not be opened or read safely";
    return { error: `Failed to read ${label}: ${reason}` };
  }

  try {
    preflightJsonText(contents);
  } catch (error) {
    const reason = error instanceof JsonStructureError ? error.message : "invalid JSON structure";
    return { error: `Failed to parse ${label}: ${reason}` };
  }

  try {
    return { value: JSON.parse(contents) };
  } catch {
    return { error: `Failed to parse ${label}: invalid JSON syntax` };
  }
}

function run(file) {
  if (!file) {
    console.error("Usage: node validate-run-metadata.cjs <path-to-run-metadata.json>");
    return 1;
  }

  const metadataResult = parseJsonFile(file, "run metadata");
  if (metadataResult.missing) {
    console.error("Failed to read run metadata: input could not be opened or read safely");
    return 1;
  }
  if (metadataResult.error) {
    console.error(metadataResult.error);
    return 1;
  }

  const directory = path.dirname(file);
  const ledgerResult = parseJsonFile(path.join(directory, "coverage-ledger.json"), "coverage ledger");
  if (ledgerResult.error) {
    console.error(ledgerResult.error);
    return 1;
  }
  const findingsResult = parseJsonFile(path.join(directory, "findings.json"), "findings JSON");
  if (findingsResult.error) {
    console.error(findingsResult.error);
    return 1;
  }

  let errors;
  try {
    errors = validateDocument(metadataResult.value, {
      ledger: ledgerResult.missing ? undefined : ledgerResult.value,
      findings: findingsResult.missing ? undefined : findingsResult.value,
      completeRequiresLedger: true,
    });
  } catch {
    console.error("Failed to validate run metadata: unexpected validation error");
    return 1;
  }

  for (const message of errors) console.error("ERROR:", message);
  if (errors.length > 0) {
    const cap = errors.length === LIMITS.validationErrors ? `; output capped at ${LIMITS.validationErrors}` : "";
    console.error(`FAIL: ${errors.length} validation error(s)${cap}`);
    return 1;
  }
  console.log("PASS: run metadata valid");
  return 0;
}

module.exports = {
  INCOMPLETE_REASONS,
  LIMITS,
  PATH_FORBIDDEN_CHARACTER,
  PROFILES,
  RUN_STATUSES,
  UNSAFE_DIAGNOSTIC_CHARACTER,
  VISIBLE_CONTENT,
  WINDOWS_RESERVED_COMPONENT,
  hasVisibleProse,
  isSafeRelativePath,
  preflightJsonText,
  readFileWithinLimit,
  safeQuote,
  validateDocument,
};

if (require.main === module) process.exit(run(process.argv[2]));
