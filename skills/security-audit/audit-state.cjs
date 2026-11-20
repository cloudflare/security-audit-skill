#!/usr/bin/env node
"use strict";

/**
 * audit-state.cjs — builds and maintains every JSON file of a full-audit run so
 * that no agent writes JSON by hand, and regenerates progress.html on every
 * change.
 *
 * Agents author record text (see record-text.cjs and AUDIT-STATE-TOOL.md); this
 * tool compiles it, enforces the ledger state table and verdict contracts with
 * the skill's own validators, and writes atomically.
 *
 * Usage: node audit-state.cjs help
 */

const fs = require("fs");
const path = require("path");
const RT = require("./record-text.cjs");
const ledgerValidator = require("./validate-coverage-ledger.cjs");
const findingsValidator = require("./validate-findings.cjs");
const { renderProgressHtml } = require("./progress-report.cjs");

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const SKILL_DIR = __dirname;
/** Quotes a path for printed commands when it contains spaces (works in sh, PowerShell, and cmd). */
const shellPath = (value) => (/\s/.test(value) ? `"${value}"` : value);
const TOOL = `node ${shellPath(path.join(SKILL_DIR, "audit-state.cjs"))}`;
const MAX_INPUT_BYTES = 5 * 1024 * 1024;
const MAX_STATE_BYTES = 64 * 1024 * 1024;
const STATE_VERSION = 1;
const ROLES = ["recon", "hunter", "critic", "final-critic", "verifier", "record-verifier", "triager"];
const RESULT_ROLES = new Set(["hunter", "critic", "final-critic", "verifier", "record-verifier", "triager"]);
const EXECUTING_ROLES = new Set(["hunter", "verifier", "record-verifier"]);
const ROLE_PHASE = { recon: 1, hunter: 2, critic: 2, "final-critic": 2, verifier: 3, "record-verifier": 5, triager: 5 };
const SHARED_FILES = ["run-metadata.json", "architecture.md", "coverage-ledger.json", "findings.json", "REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md", "state/", "progress.html"];
const VERDICT_RANK = { rejected: 0, needs_validation: 1, confirmed: 2 };
const SEED_STATUSES = ["planned", "deferred", "out_of_scope", "not_applicable"];
const PRIOR_STATUSES = ["new", "prior_confirmed_same_source", "prior_confirmed_changed_source", "prior_needs_validation", "prior_deferred", "prior_blocked", "prior_out_of_scope", "prior_covered_same_source", "prior_covered_changed_source", "prior_rejected_claim_changed", "none"];
const REF_FIELDS = ["surface", "boundary", "subsystem", "attack_class"];
const UNIT_KEY_ORDER = ["coverage_id", "canonical_refs", "surface", "boundary", "subsystem", "attack_class", "lifecycle", "starting_paths", "ordinary_attack_class_block", "selected_companion_blocks", "excluded_blocks", "prior_status", "attempts", "wave", "status", "agent_id", "reviewed_paths", "local_checks", "result_fingerprints", "unresolved", "bookkeeping"];
const FINGERPRINT = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/;

class UserError extends Error {
  constructor(message, details = []) {
    super(message);
    this.details = details;
  }
}

const SCHEMA = (() => {
  const schema = JSON.parse(fs.readFileSync(path.join(SKILL_DIR, "report-schema.json"), "utf8"));
  const errors = findingsValidator.collectSchemaErrors(schema);
  if (errors.length > 0) throw new Error(`report-schema.json is invalid:\n${errors.join("\n")}`);
  return schema;
})();

// ---------------------------------------------------------------------------
// Record-text specs
// ---------------------------------------------------------------------------

const { field, list } = RT;

function checkFields(extra = {}) {
  return {
    ...extra,
    invariant: field("text", { help: "invariant — required: the specific control checked for this unit" }),
    method: field("enum", { values: ["source", "local"], help: "method: source | local" }),
    reviewed_paths: list("plain", { help: "reviewed_paths — required: repository-relative paths this check reviewed, one per line" }),
    result: field("text", { help: "result — required: what source or the bounded check established" }),
    artifact: field("plain", { nullable: true, help: "artifact — local checks only: agents/<agent-id>/artifacts/<file> promoted by the parent; leave empty for source checks" }),
    agent_id: field("token", { help: "agent_id — leave empty: it defaults to your own agent ID" }),
  };
}

const EXCLUDED_BLOCK = {
  label: "excluded_block",
  into: "excluded_blocks",
  fields: {
    block: field("plain", { help: "block — FILE.md#exact class or section name" }),
    reason: field("text", { help: "reason — the source fact that excludes it" }),
  },
};

const HUNTER_SPECS = {
  ...RT.recordSpecsFromSchema(SCHEMA, { verdictKey: "proposed_verdict", verdicts: ["confirmed", "needs_validation"], recordName: "candidate", into: "candidates", single: false, label: "candidate" }),
  result: {
    label: "hunter result",
    fields: { hardening: list("text", { help: "hardening — concrete non-finding notes, one per line (optional)" }) },
    sections: { unit: "unit", units: "unit", candidate: "candidate", candidates: "candidate", uncovered: "uncovered" },
  },
  unit: {
    label: "unit",
    into: "units",
    fields: {
      coverage_id: field("token", { help: "coverage_id — the assigned unit (alias such as U3, or the full coverage ID)" }),
      disposition: field("enum", { values: ["covered", "candidate", "blocked"], help: "disposition: covered | candidate | blocked" }),
      candidate_fingerprints: list("token", { split: true, help: "candidate_fingerprints — only for disposition candidate: fingerprints of the [candidate] sections below" }),
      unresolved: list("text", { help: "unresolved — required for blocked, optional for candidate: one exact unresolved fact per line" }),
      reviewed_paths: list("plain", { hidden: true }),
    },
    aliases: { fingerprints: "candidate_fingerprints", result_fingerprints: "candidate_fingerprints", id: "coverage_id", unit: "coverage_id" },
    sections: { check: "check", checks: "check", local_checks: "check" },
    help: ["[unit] — exactly one per assigned coverage unit; give each at least one [check]"],
  },
  check: { label: "check", into: "checks", fields: checkFields(), aliases: { paths: "reviewed_paths" }, help: ["[check] — one per invariant checked for the unit above"] },
  uncovered: {
    label: "uncovered",
    into: "uncovered",
    fields: {
      surface: field("text"),
      boundary: field("text"),
      subsystem: field("text"),
      attack_class: field("text"),
      starting_paths: list("plain", { help: "starting_paths — repository-relative, one per line" }),
      reason: field("text", { help: "reason — why this needs its own deterministic coverage unit" }),
    },
    help: ["[uncovered] — optional: a different boundary you found that no assigned unit covers"],
  },
};

const CRITIC_SPECS = {
  result: {
    label: "critic result",
    fields: {
      reassign_ids: list("token", { split: true, help: "reassign_ids — existing units that did not close (aliases or coverage IDs), one or more per line" }),
      resolved_prior_leads: list("token", { split: true, help: "resolved_prior_leads — prior-lead fingerprints that current coverage resolves" }),
      stop: field("bool", { help: "stop: true only when you accept no missing units and no reassignments, otherwise false" }),
    },
    sections: { missing_unit: "missing_unit", missing_units: "missing_unit" },
  },
  missing_unit: {
    label: "missing_unit",
    into: "missing_units",
    fields: {
      surface: field("text"),
      boundary: field("text"),
      subsystem: field("text"),
      attack_class: field("text"),
      starting_paths: list("plain", { help: "starting_paths — repository-relative, one per line" }),
      selected_companion_blocks: list("plain", { help: "selected_companion_blocks — FILE.md#section, one per line" }),
      reason: field("text", { help: "reason — the source-backed coverage gap" }),
    },
    sections: { excluded_block: "excluded_block", excluded_blocks: "excluded_block" },
    help: ["[missing_unit] — one per source-backed coverage gap (optional)"],
  },
  excluded_block: EXCLUDED_BLOCK,
};

const RECORD_SPECS = RT.recordSpecsFromSchema(SCHEMA, { verdictKey: "verdict", recordName: "record", into: "record", single: true, label: "record" });
RECORD_SPECS.record.fields.verdict.help = [].concat(RECORD_SPECS.record.fields.verdict.help).map((line) => (line.startsWith("verdict:") ? `${line} (leave empty to use the decision)` : line));

/** Hints the schema cannot express, shared by every record-shaped section. */
function addRecordHints(specs, recordName) {
  const record = specs[recordName];
  for (const key of ["validation_plan.local", "validation_plan.deployment"]) {
    if (record.fields[key]) record.fields[key].help = `${key} — needs_validation: give local, deployment, or both (at least one)`;
  }
  const trace = specs[`${recordName}.trace`];
  if (trace && trace.fields.kind) trace.fields.kind.help = "kind — entrypoint | propagation | sink (may stay empty in a multi-step trace: first step entrypoint, last sink, others propagation)";
  // The validation priority is derived, never authored: hide it and say so.
  if (record.fields["triage.priority"]) record.fields["triage.priority"].hidden = true;
  const firstTriage = record.fields["triage.potential_impact.score"];
  if (firstTriage) firstTriage.help = [].concat(firstTriage.help, TRIAGE_HINT);
}

const TRIAGE_HINT = ["the tool computes triage.priority (P1-P4) from the two triage scores; do not write it"];

addRecordHints(RECORD_SPECS, "record");
addRecordHints(HUNTER_SPECS, "candidate");

const TRIAGE_FIELDS = Object.fromEntries(Object.entries(RECORD_SPECS.record.fields)
  .filter(([key]) => key.startsWith("triage.") && key !== "triage.priority")
  .map(([key, spec]) => [key, { ...spec }]));

const TRIAGER_SPECS = {
  result: { label: "triage result", fields: {}, sections: { lead: "lead", leads: "lead" } },
  lead: {
    label: "lead",
    into: "leads",
    fields: { fingerprint: field("token", { help: "fingerprint — the assigned lead (already filled in)" }), ...TRIAGE_FIELDS },
    help: ["[lead] — one per assigned needs_validation record"],
  },
};

const VERIFIER_SPECS = {
  ...RECORD_SPECS,
  result: {
    label: "verifier result",
    fields: { decision: field("enum", { values: ["confirmed", "needs_validation", "rejected"], help: "decision: confirmed | needs_validation | rejected" }) },
    sections: { record: "record", check: "vcheck", checks: "vcheck" },
  },
  vcheck: {
    label: "check",
    into: "checks",
    fields: checkFields({ coverage_id: field("token", { help: "coverage_id — the linked unit this check belongs to (required when the candidate links several units)" }) }),
    aliases: { paths: "reviewed_paths", unit: "coverage_id" },
    help: ["[check] — your own evidence for a linked unit; required for a carried prior record's unit"],
    noSkeleton: false,
  },
};

const RECORD_VERIFIER_SPECS = {
  ...RECORD_SPECS,
  result: {
    label: "record-verifier result",
    fields: {
      decision: field("enum", { values: ["verified", "replace"], help: "decision: verified | replace" }),
      fingerprint: field("token", { help: "fingerprint — for verified: the fingerprint of the record you verified" }),
      reason: field("text", { help: "reason — for replace: why the record must change" }),
    },
    sections: { record: "record" },
  },
};

const UNIT_SPECS = {
  root: { label: "units file", fields: {}, sections: { unit: "seed", units: "seed" } },
  seed: {
    label: "unit",
    into: "units",
    fields: {
      surface: field("text", { help: "surface / boundary / subsystem / attack_class / lifecycle — human labels" }),
      boundary: field("text"),
      subsystem: field("text"),
      attack_class: field("text"),
      lifecycle: field("text", { help: "lifecycle — optional; give canonical_refs.lifecycle too when set" }),
      "canonical_refs.surface": field("plain", { help: "canonical_refs.* — stable source-derived references; the tool derives coverage_id from them" }),
      "canonical_refs.boundary": field("plain"),
      "canonical_refs.subsystem": field("plain"),
      "canonical_refs.attack_class": field("plain"),
      "canonical_refs.lifecycle": field("plain"),
      starting_paths: list("plain", { help: "starting_paths — repository-relative, one per line" }),
      ordinary_attack_class_block: field("plain", { nullable: true, help: "ordinary_attack_class_block — ATTACK-CLASSES.md#<class>; leave empty when none applies" }),
      selected_companion_blocks: list("plain", { help: "selected_companion_blocks — FILE.md#section, one per line" }),
      prior_status: field("enum", { values: PRIOR_STATUSES, help: `prior_status — optional (defaults to none without prior runs, new with prior runs): ${PRIOR_STATUSES.join(" | ")}` }),
      status: field("enum", { values: SEED_STATUSES, help: "status — optional, default planned: planned | deferred | out_of_scope | not_applicable" }),
      unresolved: list("text", { help: "unresolved — the reason, required for deferred, out_of_scope, and not_applicable" }),
      wave: field("int", { help: "wave — optional; defaults to the next unassigned wave" }),
      priority_rationale: field("text", { help: "priority_rationale — optional ordering rationale kept in bookkeeping" }),
      from_proposal: field("token", { help: "from_proposal — optional proposal ID (P1, P2, ...) this unit accepts" }),
    },
    aliases: { "ref.surface": "canonical_refs.surface", "ref.boundary": "canonical_refs.boundary", "ref.subsystem": "canonical_refs.subsystem", "ref.attack_class": "canonical_refs.attack_class", "ref.lifecycle": "canonical_refs.lifecycle" },
    sections: { excluded_block: "excluded_block", excluded_blocks: "excluded_block" },
    help: ["[unit] — one per coverage unit"],
  },
  excluded_block: EXCLUDED_BLOCK,
};

const METADATA_SPECS = {
  root: {
    label: "run metadata",
    open: true,
    fields: {
      run_id: field("text", { help: "run_id — e.g. run-3" }),
      repo: field("text", { help: "repo — stable repository identifier" }),
      target: field("plain", { help: "target — absolute repository root under review" }),
      "source_ref.commit": field("plain", { help: "source_ref.commit — the reviewed commit" }),
      "source_ref.dirty": field("bool", { help: "source_ref.dirty — true when the worktree has uncommitted changes" }),
      profile: field("enum", { values: ["quick", "standard", "deep"], help: "profile: quick | standard | deep" }),
      scope_paths: list("plain", { help: "scope_paths — in-scope repository-relative paths, one per line (empty: whole repository)" }),
      budget: field("int", { nullable: true, help: "budget — maximum agent invocations; leave empty when unset" }),
      selected_companions: list("plain", { help: "selected_companions — companion files selected in reconnaissance, one per line" }),
      prior_runs: list("plain", { help: "prior_runs — absolute paths of compatible prior run directories, one per line" }),
      run_status: field("enum", { values: ["in_progress", "complete", "incomplete"], help: "run_status — managed by the tool; use finish" }),
      incomplete_reason: field("text", { help: "incomplete_reason — exact reason when run_status is incomplete" }),
    },
  },
};

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

const now = () => new Date().toISOString();
const clone = (value) => JSON.parse(JSON.stringify(value));
const uniq = (values) => [...new Set(values)];

function runPaths(run) {
  return {
    run,
    metadata: path.join(run, "run-metadata.json"),
    ledger: path.join(run, "coverage-ledger.json"),
    findings: path.join(run, "findings.json"),
    architecture: path.join(run, "architecture.md"),
    html: path.join(run, "progress.html"),
    stateDir: path.join(run, "state"),
    state: path.join(run, "state", "audit-state.json"),
    events: path.join(run, "state", "events.jsonl"),
    results: path.join(run, "state", "results"),
    lock: path.join(run, "state", ".lock"),
    agentDir: (id) => path.join(run, "agents", id),
    result: (id) => path.join(run, "agents", id, "result.txt"),
  };
}

function relativeResultPath(id) {
  return `agents/${id}/result.txt`;
}

function readTextLimited(file, limit = MAX_INPUT_BYTES, label = file) {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch {
    throw new UserError(`cannot read ${label}: file not found`);
  }
  if (stat.isSymbolicLink()) throw new UserError(`refusing to read ${label}: it is a symlink`);
  if (!stat.isFile()) throw new UserError(`refusing to read ${label}: not a regular file`);
  if (stat.size > limit) throw new UserError(`refusing to read ${label}: larger than ${limit} bytes`);
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  const descriptor = fs.openSync(file, flags);
  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile() || opened.size > limit) throw new UserError(`refusing to read ${label}: changed while opening`);
    const buffer = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < buffer.length) {
      const count = fs.readSync(descriptor, buffer, offset, buffer.length - offset, offset);
      if (count === 0) break;
      offset += count;
    }
    return buffer.subarray(0, offset).toString("utf8");
  } finally {
    fs.closeSync(descriptor);
  }
}

function readJson(file, fallback, limit = MAX_STATE_BYTES) {
  if (!fs.existsSync(file)) return fallback;
  const text = readTextLimited(file, limit, path.basename(file));
  try {
    return JSON.parse(text);
  } catch {
    throw new UserError(`${path.basename(file)} is not valid JSON; it was not written by this tool or was edited by hand`);
  }
}

function writeAtomic(file, contents) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(temp, contents, { flag: "wx" });
  for (let attempt = 0; ; attempt++) {
    try {
      fs.renameSync(temp, file);
      return;
    } catch (error) {
      if (attempt >= 20 || !["EPERM", "EACCES", "EBUSY"].includes(error.code)) {
        try { fs.unlinkSync(temp); } catch { /* ignore */ }
        throw error;
      }
      sleep(50);
    }
  }
}

function writeJson(file, value) {
  writeAtomic(file, `${JSON.stringify(value, null, 2)}\n`);
}

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function withLock(P, fn) {
  fs.mkdirSync(P.stateDir, { recursive: true });
  const deadline = Date.now() + 30000;
  let descriptor = null;
  while (descriptor === null) {
    try {
      descriptor = fs.openSync(P.lock, "wx");
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      try {
        if (Date.now() - fs.statSync(P.lock).mtimeMs > 120000) fs.unlinkSync(P.lock);
      } catch { /* raced with another release */ }
      if (Date.now() > deadline) throw new UserError(`another audit-state command holds ${P.lock}; retry, or delete the lock if no command is running`);
      sleep(100);
    }
  }
  try {
    fs.writeSync(descriptor, `${process.pid} ${now()}\n`);
    return fn();
  } finally {
    fs.closeSync(descriptor);
    try { fs.unlinkSync(P.lock); } catch { /* ignore */ }
  }
}

function parseArgs(argv) {
  const booleans = new Set(["write", "force", "json", "non-material", "allow-over-budget", "new-root-cause", "allow-inside-target", "help"]);
  const repeatable = new Set(["set"]);
  const positionals = [];
  const options = {};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg.startsWith("--")) {
      let key = arg.slice(2);
      let value;
      const equals = key.indexOf("=");
      if (equals !== -1) {
        value = key.slice(equals + 1);
        key = key.slice(0, equals);
      } else if (booleans.has(key)) {
        value = true;
      } else {
        if (index + 1 >= argv.length) throw new UserError(`--${key} needs a value`);
        value = argv[++index];
      }
      if (key === "id") key = "agent";
      if (repeatable.has(key)) (options[key] = options[key] || []).push(value);
      else options[key] = value;
    } else {
      positionals.push(arg);
    }
  }
  return { positionals, options };
}

function requireOption(options, key, hint = "") {
  if (options[key] === undefined || options[key] === true || options[key] === "") {
    throw new UserError(`missing --${key}${hint ? ` ${hint}` : ""}`);
  }
  return options[key];
}

function splitList(value) {
  if (value === undefined || value === true) return [];
  return String(value).split(/[\s,]+/).filter(Boolean);
}

function readInputText(options) {
  const file = requireOption(options, "file", "<record-text file, or - for stdin>");
  if (file === "-") return { text: fs.readFileSync(0, "utf8"), label: "stdin" };
  return { text: readTextLimited(path.resolve(file), MAX_INPUT_BYTES, file), label: file };
}

function readReason(options, key = "reason", required = true) {
  if (options[`${key}-file`]) return readTextLimited(path.resolve(options[`${key}-file`])).trim();
  if (typeof options[key] === "string" && options[key].trim() !== "") return options[key].trim();
  if (required) throw new UserError(`missing --${key} "<text>" (or --${key}-file <file> for text with quotes)`);
  return null;
}

function formatErrors(errors, label) {
  const sorted = errors.slice().sort((left, right) => (left.line || Infinity) - (right.line || Infinity));
  return sorted.map((error) => (error.line ? `${label}:${error.line}: ${error.message}` : `${label}: ${error.message}`));
}

// ---------------------------------------------------------------------------
// Run context
// ---------------------------------------------------------------------------

function newState() {
  return {
    version: STATE_VERSION,
    created_at: now(),
    updated_at: now(),
    phase: 1,
    wave: 0,
    next_alias: 1,
    next_proposal: 1,
    agents: [],
    candidates: [],
    proposals: [],
    validation: {},
    findings_written_at: null,
  };
}

function openRun(options, { requireMetadata = true } = {}) {
  const run = path.resolve(requireOption(options, "run", "<output directory>"));
  const P = runPaths(run);
  if (requireMetadata && !fs.existsSync(P.metadata)) throw new UserError(`no run-metadata.json in ${run}; run "init" first`);
  const state = readJson(P.state, null) || newState();
  return {
    run,
    P,
    options,
    metadata: readJson(P.metadata, null, MAX_INPUT_BYTES),
    ledger: readJson(P.ledger, null, MAX_INPUT_BYTES),
    findings: readJson(P.findings, null, MAX_INPUT_BYTES),
    state,
    changed: new Set(),
    events: [],
    output: [],
  };
}

function event(ctx, command, message, extra = {}) {
  ctx.events.push({ at: now(), command, message, ...extra });
}

function ensureLedger(ctx) {
  if (!Array.isArray(ctx.ledger)) ctx.ledger = [];
  return ctx.ledger;
}

function alias(unit) {
  return (unit.bookkeeping && unit.bookkeeping.alias) || unit.coverage_id;
}

function bookkeeping(unit) {
  if (!unit.bookkeeping || typeof unit.bookkeeping !== "object") unit.bookkeeping = {};
  return unit.bookkeeping;
}

function findUnit(ctx, ref) {
  const ledger = ensureLedger(ctx);
  const wanted = String(ref).trim();
  return ledger.find((unit) => unit.coverage_id === wanted) ||
    ledger.find((unit) => unit.bookkeeping && typeof unit.bookkeeping.alias === "string" && unit.bookkeeping.alias.toLowerCase() === wanted.toLowerCase()) ||
    null;
}

function requireUnit(ctx, ref) {
  const unit = findUnit(ctx, ref);
  if (!unit) {
    const known = ensureLedger(ctx).map(alias).slice(0, 20).join(", ");
    throw new UserError(`unknown coverage unit ${JSON.stringify(ref)}${known ? `; known units: ${known}` : ""}`);
  }
  return unit;
}

function findAgent(ctx, id) {
  return ctx.state.agents.find((agent) => agent.id === id) || null;
}

function requireAgent(ctx, id) {
  const agent = findAgent(ctx, id);
  if (!agent) throw new UserError(`unknown agent ${JSON.stringify(id)}; start it with "agent start" first`);
  return agent;
}

function findCandidate(ctx, fingerprint) {
  return ctx.state.candidates.find((candidate) => candidate.fingerprint === fingerprint) || null;
}

function requireCandidate(ctx, fingerprint) {
  const candidate = findCandidate(ctx, fingerprint);
  if (!candidate) throw new UserError(`unknown candidate ${JSON.stringify(fingerprint)}`);
  return candidate;
}

function linkedUnits(ctx, fingerprint) {
  return ensureLedger(ctx).filter((unit) =>
    (unit.result_fingerprints || []).includes(fingerprint) ||
    (unit.attempts || []).some((attempt) => (attempt.result_fingerprints || []).includes(fingerprint)) ||
    ((unit.bookkeeping && unit.bookkeeping.carried_fingerprints) || []).includes(fingerprint));
}

function orderedUnit(unit) {
  const out = {};
  for (const key of UNIT_KEY_ORDER) if (hasOwn(unit, key)) out[key] = unit[key];
  for (const key of Object.keys(unit)) if (!hasOwn(out, key)) out[key] = unit[key];
  return out;
}

function sortLedger(ledger) {
  ledger.sort((left, right) => (left.coverage_id < right.coverage_id ? -1 : left.coverage_id > right.coverage_id ? 1 : 0));
  for (let index = 0; index < ledger.length; index++) ledger[index] = orderedUnit(ledger[index]);
}

function describeLedgerError(message, ledger, unitLines = new Map()) {
  const match = /^\$\[(\d+)\]/.exec(message);
  if (!match) return message;
  const unit = ledger[Number(match[1])];
  if (!unit) return message;
  const line = unitLines.get(unit.coverage_id);
  return `${line ? `line ${line}: ` : ""}unit ${alias(unit)}${message.slice(match[0].length)}`;
}

function profile(ctx) {
  return (ctx.metadata && ctx.metadata.profile) || "standard";
}

function raisePhase(ctx, phase) {
  if (phase > ctx.state.phase) {
    ctx.state.phase = phase;
    event(ctx, "phase", `phase ${phase} started`);
  }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

function branchFor(verdict) {
  return SCHEMA.items.oneOf.find((branch) => branch.properties.verdict.const === verdict) || null;
}

/** Orders keys as the schema lists them and defaults required empty-allowed arrays. */
function normalizeAgainstSchema(value, node, lineInfo) {
  if (node && node.type === "object" && value && typeof value === "object" && !Array.isArray(value)) {
    const out = {};
    const properties = node.properties || {};
    for (const key of Object.keys(properties)) {
      if (hasOwn(value, key)) {
        out[key] = normalizeAgainstSchema(value[key], properties[key], lineInfo);
      } else if ((node.required || []).includes(key) && properties[key].type === "array" && !(properties[key].minItems > 0)) {
        out[key] = [];
      }
    }
    for (const key of Object.keys(value)) if (!hasOwn(out, key) && !hasOwn(properties, key)) out[key] = value[key];
    if (lineInfo && lineInfo.has(value)) lineInfo.set(out, lineInfo.get(value));
    return out;
  }
  if (node && node.type === "array" && Array.isArray(value) && node.items) {
    const out = value.map((item) => normalizeAgainstSchema(item, node.items, lineInfo));
    if (lineInfo && lineInfo.has(value)) lineInfo.set(out, lineInfo.get(value));
    return out;
  }
  return value;
}

function inferTraceKinds(record) {
  if (!Array.isArray(record.trace) || record.trace.length < 2) return;
  const last = record.trace.length - 1;
  record.trace.forEach((step, index) => {
    if (step && typeof step === "object" && !hasOwn(step, "kind")) {
      step.kind = index === 0 ? "entrypoint" : index === last ? "sink" : "propagation";
    }
  });
}

/**
 * Sets triage.priority from the two triage scores of a needs_validation record
 * (replacing any authored value) and returns it, or null when a score is missing.
 */
function applyTriagePriority(record) {
  if (record.verdict !== "needs_validation" || !record.triage || typeof record.triage !== "object") return null;
  const score = (entry) => (entry && typeof entry === "object" ? entry.score : undefined);
  const priority = findingsValidator.triagePriority(score(record.triage.potential_impact), score(record.triage.plausibility));
  if (priority) record.triage.priority = priority;
  else delete record.triage.priority;
  return priority;
}

function needsTriage(record) {
  return Boolean(record) && record.verdict === "needs_validation" && !(record.triage && record.triage.priority);
}

/** Builds a schema-ordered record and returns schema/semantic errors mapped to lines. */
function finalizeRecord(raw, verdict, lineInfo, label) {
  const draft = { ...raw };
  delete draft.proposed_verdict;
  const ordered = { verdict, ...draft };
  if (lineInfo && lineInfo.has(raw)) lineInfo.set(ordered, lineInfo.get(raw));
  inferTraceKinds(ordered);
  const derivedPriority = applyTriagePriority(ordered);
  const branch = branchFor(verdict);
  const record = branch ? normalizeAgainstSchema(ordered, branch, lineInfo) : ordered;
  let messages = findingsValidator.validateDocument([record], SCHEMA);
  // A missing priority only echoes a missing score, which is reported on its own.
  if (!derivedPriority) messages = messages.filter((message) => !/triage: missing required field "priority"/.test(message));
  // The oneOf summary line only repeats that the branch errors below exist.
  if (messages.length > 1) messages = messages.filter((message) => !message.includes("must match exactly one schema in oneOf"));
  const errors = messages.map((message) => (lineInfo
    ? RT.mapValidatorMessage(message, [record], lineInfo, { dropTokens: 1, label })
    : { line: null, message: `${label}: ${message.replace(/^\$\[0\]\.?/, "")}` }));
  return { record, errors: dedupeErrors(errors) };
}

function dedupeErrors(errors) {
  const seen = new Set();
  return errors.filter((error) => {
    const key = `${error.line}|${error.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function rootCauseText(record) {
  return record.root_cause || record.claimed_root_cause || "";
}

function stripLines(entries) {
  return JSON.stringify((entries || []).map((entry) => {
    const copy = { ...entry };
    delete copy.line;
    return copy;
  }));
}

/** Lists the material differences that require a fresh Phase 5 verifier. */
function materialChanges(before, after) {
  const changes = [];
  if (VERDICT_RANK[after.verdict] > VERDICT_RANK[before.verdict]) changes.push(`verdict promoted from ${before.verdict} to ${after.verdict}`);
  if (rootCauseText(before) !== rootCauseText(after)) changes.push("root cause changed");
  if (stripLines(before.trace) !== stripLines(after.trace)) changes.push("trace changed (beyond line numbers)");
  const executionBefore = before.execution || {};
  const executionAfter = after.execution || {};
  if (JSON.stringify(executionBefore.payloads || null) !== JSON.stringify(executionAfter.payloads || null) ||
      JSON.stringify(executionBefore.instructions || null) !== JSON.stringify(executionAfter.instructions || null)) {
    changes.push("execution input changed");
  }
  if ((executionBefore.observed_result || null) !== (executionAfter.observed_result || null)) changes.push("observed result changed");
  const severityBefore = before.severity || {};
  const severityAfter = after.severity || {};
  const score = (severity, key) => (severity[key] && severity[key].score) || null;
  if (score(severityBefore, "impact") !== score(severityAfter, "impact")) changes.push("demonstrated impact changed");
  if ((severityBefore.overall_severity || null) !== (severityAfter.overall_severity || null) || score(severityBefore, "likelihood") !== score(severityAfter, "likelihood")) {
    changes.push("severity changed");
  }
  return changes;
}

/** Converts a record to another verdict's shape for a verifier template. */
function reshapeRecord(record, verdict) {
  const branch = branchFor(verdict);
  if (!branch) return clone(record);
  const out = { verdict };
  const source = clone(record);
  if (verdict === "confirmed" && !source.root_cause && source.claimed_root_cause) source.root_cause = source.claimed_root_cause;
  if (verdict !== "confirmed" && !source.claimed_root_cause && source.root_cause) source.claimed_root_cause = source.root_cause;
  for (const key of Object.keys(branch.properties)) {
    if (key !== "verdict" && hasOwn(source, key)) out[key] = source[key];
  }
  return out;
}

// ---------------------------------------------------------------------------
// Ledger units
// ---------------------------------------------------------------------------

function defaultWave(ctx) {
  return ctx.state.wave === 0 ? 1 : ctx.state.wave + 1;
}

function emptyEvidence(unit) {
  unit.agent_id = null;
  unit.reviewed_paths = [];
  unit.local_checks = [];
  unit.result_fingerprints = [];
}

function unionPaths(checks) {
  return uniq(checks.flatMap((check) => (Array.isArray(check.reviewed_paths) ? check.reviewed_paths : [])));
}

function checkArtifact(ctx, check) {
  if (check.method !== "local" || typeof check.artifact !== "string") return null;
  if (!ledgerValidator.isSafeRelativePath(check.artifact)) return "artifact must be a safe output-relative path";
  const prefix = `agents/${check.agent_id}/artifacts/`;
  if (!check.artifact.startsWith(prefix) || check.artifact.length === prefix.length) {
    return `artifact must be below ${prefix} (the check owner's parent-promoted artifacts)`;
  }
  let current = ctx.run;
  const parts = check.artifact.split("/");
  for (let index = 0; index < parts.length; index++) {
    current = path.join(current, parts[index]);
    let stat;
    try {
      stat = fs.lstatSync(current);
    } catch {
      return `artifact ${check.artifact} does not exist; only files the parent promoted into artifacts/ count as evidence`;
    }
    if (stat.isSymbolicLink()) return `artifact path ${check.artifact} contains a symlink`;
    if (index < parts.length - 1 && !stat.isDirectory()) return `artifact path ${check.artifact} has a non-directory component`;
    if (index === parts.length - 1 && (!stat.isFile() || stat.nlink > 1)) return `artifact ${check.artifact} must be a regular file with a single link`;
  }
  return null;
}

function normalizeChecks(ctx, checks, defaultAgent, lineInfo, errors, label) {
  return (checks || []).map((check) => {
    const info = lineInfo && lineInfo.get(check);
    const line = info ? info.line : null;
    const out = {
      agent_id: check.agent_id || defaultAgent,
      reviewed_paths: check.reviewed_paths || [],
      invariant: check.invariant,
      method: check.method,
      result: check.result,
      artifact: check.artifact === undefined ? null : check.artifact,
    };
    for (const key of ["invariant", "method", "result"]) {
      if (out[key] === undefined) errors.push({ line, message: `${label} [check]: ${key} is required` });
    }
    if (out.reviewed_paths.length === 0) errors.push({ line, message: `${label} [check]: reviewed_paths needs at least one repository-relative path` });
    for (const reviewed of out.reviewed_paths) {
      if (!ledgerValidator.isSafeRelativePath(reviewed)) errors.push({ line, message: `${label} [check]: ${JSON.stringify(reviewed)} is not a safe repository-relative path (no leading /, no .., no backslashes or colons)` });
    }
    if (!ledgerValidator.isSafeAgentId(out.agent_id)) errors.push({ line, message: `${label} [check]: agent_id ${JSON.stringify(out.agent_id)} is not a canonical lowercase agent ID` });
    if (out.method === "source" && out.artifact !== null) errors.push({ line, message: `${label} [check]: a source check has no artifact; leave artifact empty` });
    if (out.method === "local") {
      if (out.artifact === null) errors.push({ line, message: `${label} [check]: a local check needs artifact: agents/${out.agent_id}/artifacts/<file>` });
      else {
        const problem = checkArtifact(ctx, out);
        if (problem) errors.push({ line, message: `${label} [check]: ${problem}` });
      }
    }
    if (info && lineInfo) lineInfo.set(out, info);
    return out;
  });
}

/** Validates the ledger after `mutate(clone)`; returns mapped errors. */
function simulateLedger(ctx, mutate, unitLines) {
  const simulated = clone(ensureLedger(ctx));
  mutate(simulated);
  sortLedger(simulated);
  return ledgerValidator.validateDocument(simulated).map((message) => ({ line: null, message: describeLedgerError(message, simulated, unitLines) }));
}

// ---------------------------------------------------------------------------
// Result compilation (shared by check and ingest)
// ---------------------------------------------------------------------------

function parseWith(specs, rootName, text) {
  const parsed = RT.parseRecordText(text, specs, rootName);
  RT.splitFileLines(parsed.value, specs, rootName);
  return parsed;
}

function compileResult(ctx, agent, text, options = {}) {
  switch (agent.role) {
    case "hunter": return compileHunter(ctx, agent, text);
    case "critic":
    case "final-critic": return compileCritic(ctx, agent, text);
    case "verifier": return compileVerifier(ctx, agent, text, options);
    case "record-verifier": return compileRecordVerifier(ctx, agent, text, options);
    case "triager": return compileTriager(ctx, agent, text);
    default: throw new UserError(`agent ${agent.id} has role ${agent.role}, which returns no result file; use "agent finish"`);
  }
}

/** A triager adds or revises the validation priority of decided needs_validation records. */
function compileTriager(ctx, agent, text) {
  const { value, errors, lineInfo } = parseWith(TRIAGER_SPECS, "result", text);
  const assigned = new Set(agent.fingerprints);
  const seen = new Map();
  const leads = [];
  for (const raw of value.leads || []) {
    const line = (lineInfo.get(raw) || {}).line || null;
    if (!raw.fingerprint) {
      errors.push({ line, message: "[lead]: fingerprint is required" });
      continue;
    }
    if (!assigned.has(raw.fingerprint)) {
      errors.push({ line, message: `[lead] ${raw.fingerprint}: not assigned to ${agent.id} (assigned: ${agent.fingerprints.join(", ")})` });
      continue;
    }
    if (seen.has(raw.fingerprint)) {
      errors.push({ line, message: `[lead] ${raw.fingerprint}: appears twice (first on line ${seen.get(raw.fingerprint)})` });
      continue;
    }
    seen.set(raw.fingerprint, line);
    const candidate = findCandidate(ctx, raw.fingerprint);
    const base = clone(candidate.record);
    delete base.verdict;
    base.triage = raw.triage || {};
    if (lineInfo.has(raw)) lineInfo.set(base, lineInfo.get(raw));
    const finalized = finalizeRecord(base, "needs_validation", lineInfo, `[lead] ${raw.fingerprint}`);
    errors.push(...finalized.errors);
    leads.push({ fingerprint: raw.fingerprint, triage: finalized.record.triage, record: finalized.record });
  }
  for (const fingerprint of agent.fingerprints) {
    if (!seen.has(fingerprint)) errors.push({ line: null, message: `assigned lead ${fingerprint} has no [lead] section (add "[lead]" with "fingerprint: ${fingerprint}")` });
  }
  const counts = countBy(leads.map((lead) => lead.triage || {}), "priority");
  const compiled = { leads: leads.map(({ fingerprint, triage }) => ({ fingerprint, triage })) };
  Object.defineProperty(compiled, "records", { value: leads, enumerable: false });
  return { compiled, errors: dedupeErrors(errors), summary: `${leads.length} lead(s) triaged (${formatCounts(counts)})` };
}

function applyTriager(ctx, agent, compiled) {
  const lines = [];
  for (const lead of compiled.records) {
    const candidate = requireCandidate(ctx, lead.fingerprint);
    const before = candidate.record.triage ? candidate.record.triage.priority : null;
    candidate.record = lead.record;
    candidate.triager = null;
    candidate.final.push({ agent_id: agent.id, decision: "triaged", priority: lead.triage.priority, at: now() });
    candidate.updated_at = now();
    recordDecision(ctx, candidate.fingerprint, { phase: 5, agent_id: agent.id, decision: "triaged" });
    lines.push(`  ${candidate.fingerprint}: ${before ? `${before} → ` : ""}${lead.triage.priority}`);
  }
  syncFindingsIfWritten(ctx);
  return lines;
}

function compileHunter(ctx, agent, text) {
  const { value, errors, lineInfo } = parseWith(HUNTER_SPECS, "result", text);
  const lineOf = (object) => (lineInfo.get(object) || {}).line || null;
  const assigned = agent.units.map((id) => findUnit(ctx, id)).filter(Boolean);
  const assignedIds = new Set(assigned.map((unit) => unit.coverage_id));
  const units = [];
  const seen = new Map();
  const unitLines = new Map();

  for (const raw of value.units || []) {
    const line = lineOf(raw);
    if (!raw.coverage_id) {
      errors.push({ line, message: "[unit]: coverage_id is required (for example coverage_id: U3)" });
      continue;
    }
    const unit = findUnit(ctx, raw.coverage_id);
    if (!unit) {
      errors.push({ line, message: `[unit]: unknown coverage unit ${JSON.stringify(raw.coverage_id)}` });
      continue;
    }
    const label = `[unit] ${alias(unit)}`;
    if (!assignedIds.has(unit.coverage_id)) {
      errors.push({ line, message: `${label}: not assigned to ${agent.id} (assigned: ${assigned.map(alias).join(", ")})` });
      continue;
    }
    if (seen.has(unit.coverage_id)) {
      errors.push({ line, message: `${label}: appears twice (first on line ${seen.get(unit.coverage_id)})` });
      continue;
    }
    seen.set(unit.coverage_id, line);
    unitLines.set(unit.coverage_id, line);
    if (!raw.disposition) errors.push({ line, message: `${label}: disposition is required (covered | candidate | blocked)` });
    const checks = normalizeChecks(ctx, raw.checks, agent.id, lineInfo, errors, label);
    if (checks.length === 0) errors.push({ line, message: `${label}: add at least one [check] below it` });
    const reviewed = unionPaths(checks);
    for (const extra of raw.reviewed_paths || []) {
      if (!reviewed.includes(extra)) errors.push({ line, message: `${label}: reviewed path ${JSON.stringify(extra)} belongs to no check; add it to the reviewed_paths of the check that reviewed it` });
    }
    const fingerprints = uniq(raw.candidate_fingerprints || []);
    if (raw.disposition && raw.disposition !== "candidate" && fingerprints.length > 0) {
      errors.push({ line, message: `${label}: candidate_fingerprints are only allowed with disposition candidate` });
    }
    if (raw.disposition === "candidate" && fingerprints.length === 0) errors.push({ line, message: `${label}: disposition candidate needs candidate_fingerprints` });
    if (raw.disposition === "blocked" && (raw.unresolved || []).length === 0) errors.push({ line, message: `${label}: disposition blocked needs at least one unresolved fact` });
    if (raw.disposition === "covered" && (raw.unresolved || []).length > 0) errors.push({ line, message: `${label}: a covered unit has no unresolved facts; use blocked instead` });
    units.push({ coverage_id: unit.coverage_id, disposition: raw.disposition, reviewed_paths: reviewed, checks, candidate_fingerprints: fingerprints, unresolved: raw.unresolved || [] });
  }
  for (const unit of assigned) {
    if (!seen.has(unit.coverage_id)) errors.push({ line: null, message: `assigned unit ${alias(unit)} has no [unit] section (add "[unit]" with "coverage_id: ${alias(unit)}")` });
  }

  const candidates = [];
  const candidateLines = new Map();
  for (const raw of value.candidates || []) {
    const line = lineOf(raw);
    const fingerprint = raw.fingerprint || "(no fingerprint)";
    if (!raw.proposed_verdict) {
      errors.push({ line, message: `[candidate] ${fingerprint}: proposed_verdict is required (confirmed | needs_validation)` });
      continue;
    }
    if (candidateLines.has(raw.fingerprint)) {
      errors.push({ line, message: `[candidate] ${fingerprint}: the same fingerprint appears twice (line ${candidateLines.get(raw.fingerprint)}); consolidate one root cause into one candidate` });
      continue;
    }
    candidateLines.set(raw.fingerprint, line);
    const { record, errors: recordErrors } = finalizeRecord(raw, raw.proposed_verdict, lineInfo, `[candidate] ${fingerprint}`);
    errors.push(...recordErrors);
    const proposal = { proposed_verdict: record.verdict, ...record };
    delete proposal.verdict;
    candidates.push(proposal);
  }

  const linked = new Set(units.flatMap((unit) => unit.candidate_fingerprints));
  for (const unit of units) {
    for (const fingerprint of unit.candidate_fingerprints) {
      if (!FINGERPRINT.test(fingerprint)) errors.push({ line: unitLines.get(unit.coverage_id), message: `[unit] ${alias(findUnit(ctx, unit.coverage_id))}: ${JSON.stringify(fingerprint)} is not a valid fingerprint` });
      else if (!candidateLines.has(fingerprint) && !findCandidate(ctx, fingerprint)) {
        errors.push({ line: unitLines.get(unit.coverage_id), message: `[unit] ${alias(findUnit(ctx, unit.coverage_id))}: fingerprint ${fingerprint} has no [candidate] section in this result and no earlier candidate` });
      }
    }
  }
  for (const [fingerprint, line] of candidateLines) {
    if (!linked.has(fingerprint)) errors.push({ line, message: `[candidate] ${fingerprint}: list this fingerprint in the candidate_fingerprints of the [unit] that found it` });
  }

  const uncovered = [];
  for (const raw of value.uncovered || []) {
    const line = lineOf(raw);
    for (const key of [...REF_FIELDS, "reason"]) if (!raw[key]) errors.push({ line, message: `[uncovered]: ${key} is required` });
    if (!(raw.starting_paths || []).length) errors.push({ line, message: "[uncovered]: starting_paths needs at least one path" });
    for (const start of raw.starting_paths || []) if (!ledgerValidator.isSafeRelativePath(start)) errors.push({ line, message: `[uncovered]: ${JSON.stringify(start)} is not a safe repository-relative path` });
    uncovered.push({ surface: raw.surface, boundary: raw.boundary, subsystem: raw.subsystem, attack_class: raw.attack_class, starting_paths: raw.starting_paths || [], reason: raw.reason });
  }

  const compiled = { units, candidates, hardening: value.hardening || [], uncovered };
  if (errors.length === 0) {
    errors.push(...simulateLedger(ctx, (ledger) => applyHunterUnits(ledger, compiled, agent), unitLines));
  }
  return { compiled, errors: dedupeErrors(errors), summary: summarizeHunter(compiled) };
}

function applyHunterUnits(ledger, compiled, agent) {
  for (const result of compiled.units) {
    const unit = ledger.find((entry) => entry.coverage_id === result.coverage_id);
    unit.status = result.disposition;
    unit.agent_id = agent.id;
    unit.reviewed_paths = result.reviewed_paths;
    unit.local_checks = result.checks;
    unit.result_fingerprints = result.disposition === "candidate" ? result.candidate_fingerprints : [];
    unit.unresolved = result.unresolved;
    if (compiled.hardening.length > 0) {
      const book = bookkeeping(unit);
      book.hardening = (book.hardening || []).concat(compiled.hardening.map((note) => ({ agent_id: agent.id, note })));
    }
  }
}

function summarizeHunter(compiled) {
  const counts = {};
  for (const unit of compiled.units) counts[unit.disposition] = (counts[unit.disposition] || 0) + 1;
  const parts = Object.entries(counts).map(([key, count]) => `${count} ${key}`);
  return `${compiled.units.length} unit(s)${parts.length ? ` (${parts.join(", ")})` : ""}, ${compiled.candidates.length} candidate(s), ${compiled.uncovered.length} uncovered, ${compiled.hardening.length} hardening note(s)`;
}

function compileCritic(ctx, agent, text) {
  const { value, errors, lineInfo } = parseWith(CRITIC_SPECS, "result", text);
  const lineOf = (object) => (lineInfo.get(object) || {}).line || null;
  const rootFields = (lineInfo.get(value) || { fields: new Map() }).fields;
  if (value.stop === undefined) errors.push({ line: null, message: "stop is required: write \"stop: true\" or \"stop: false\"" });
  const reassign = [];
  for (const ref of uniq(value.reassign_ids || [])) {
    const unit = findUnit(ctx, ref);
    if (!unit) errors.push({ line: rootFields.get("reassign_ids") || null, message: `reassign_ids: unknown coverage unit ${JSON.stringify(ref)}` });
    else reassign.push(unit.coverage_id);
  }
  const leads = uniq(value.resolved_prior_leads || []);
  for (const lead of leads) if (!FINGERPRINT.test(lead)) errors.push({ line: rootFields.get("resolved_prior_leads") || null, message: `resolved_prior_leads: ${JSON.stringify(lead)} is not a valid fingerprint` });
  const missing = [];
  for (const raw of value.missing_units || []) {
    const line = lineOf(raw);
    for (const key of [...REF_FIELDS, "reason"]) if (!raw[key]) errors.push({ line, message: `[missing_unit]: ${key} is required` });
    if (!(raw.starting_paths || []).length) errors.push({ line, message: "[missing_unit]: starting_paths needs at least one path" });
    for (const start of raw.starting_paths || []) if (!ledgerValidator.isSafeRelativePath(start)) errors.push({ line, message: `[missing_unit]: ${JSON.stringify(start)} is not a safe repository-relative path` });
    const excluded = (raw.excluded_blocks || []).map((entry) => {
      if (!entry.block || !entry.reason) errors.push({ line: lineOf(entry), message: "[excluded_block]: block and reason are both required" });
      return { block: entry.block, reason: entry.reason };
    });
    missing.push({ surface: raw.surface, boundary: raw.boundary, subsystem: raw.subsystem, attack_class: raw.attack_class, starting_paths: raw.starting_paths || [], selected_companion_blocks: raw.selected_companion_blocks || [], excluded_blocks: excluded, reason: raw.reason });
  }
  if (value.stop === true && (missing.length > 0 || reassign.length > 0)) {
    errors.push({ line: rootFields.get("stop") || null, message: "stop: true is only allowed with no missing units and no reassign_ids" });
  }
  const compiled = { missing_units: missing, reassign_ids: reassign, resolved_prior_leads: leads, stop: value.stop === true };
  return { compiled, errors: dedupeErrors(errors), summary: `${missing.length} missing unit(s), ${reassign.length} reassignment(s), ${leads.length} resolved prior lead(s), stop ${compiled.stop}` };
}

function compileVerifier(ctx, agent, text, options) {
  const { value, errors, lineInfo } = parseWith(VERIFIER_SPECS, "result", text);
  const assigned = agent.fingerprints[0];
  const candidate = findCandidate(ctx, assigned);
  if (!value.decision) errors.push({ line: null, message: "decision is required: confirmed | needs_validation | rejected" });
  let record = null;
  if (!value.record) {
    errors.push({ line: null, message: "add a [record] section with the final record for your decision" });
  } else {
    const recordLine = (lineInfo.get(value.record) || {}).line || null;
    const verdict = value.record.verdict || value.decision;
    if (value.decision && value.record.verdict && value.record.verdict !== value.decision) {
      errors.push({ line: recordLine, message: `[record]: verdict ${value.record.verdict} differs from decision ${value.decision}` });
    }
    if (verdict) {
      const finalized = finalizeRecord(value.record, verdict, lineInfo, "[record]");
      record = finalized.record;
      errors.push(...finalized.errors);
      if (record.fingerprint && record.fingerprint !== assigned && !options.newRootCause) {
        errors.push({ line: recordLine, message: `[record]: fingerprint ${record.fingerprint} differs from the assigned candidate ${assigned}; keep the fingerprint for the same root cause (the parent passes --new-root-cause only for a genuinely different root cause)` });
      }
      if (record.fingerprint && record.fingerprint !== assigned && options.newRootCause && findCandidate(ctx, record.fingerprint)) {
        errors.push({ line: recordLine, message: `[record]: fingerprint ${record.fingerprint} already belongs to another candidate` });
      }
    }
  }

  const linked = candidate ? linkedUnits(ctx, assigned) : [];
  const owned = linked.filter((unit) => unit.status === "in_progress" && unit.agent_id === agent.id);
  const checks = [];
  for (const raw of value.checks || []) {
    const info = lineInfo.get(raw);
    const line = info ? info.line : null;
    let unit = null;
    if (raw.coverage_id) {
      unit = findUnit(ctx, raw.coverage_id);
      if (!unit || !linked.includes(unit)) {
        errors.push({ line, message: `[check]: ${JSON.stringify(raw.coverage_id)} is not a unit linked to ${assigned} (linked: ${linked.map(alias).join(", ") || "none"})` });
        continue;
      }
    } else if (linked.length === 1) {
      unit = linked[0];
    } else {
      errors.push({ line, message: `[check]: coverage_id is required because ${assigned} links several units (${linked.map(alias).join(", ")})` });
      continue;
    }
    const [check] = normalizeChecks(ctx, [raw], agent.id, lineInfo, errors, `unit ${alias(unit)}`);
    checks.push({ coverage_id: unit.coverage_id, ...check });
  }
  for (const unit of owned) {
    if (!checks.some((check) => check.coverage_id === unit.coverage_id)) {
      errors.push({ line: null, message: `unit ${alias(unit)} carries a prior record and is yours: add a [check] (coverage_id: ${alias(unit)}) with your source re-check` });
    }
  }
  const compiled = { decision: value.decision, record, checks };
  if (errors.length === 0) errors.push(...simulateLedger(ctx, (ledger) => applyVerifierChecks(ledger, compiled, agent, assigned)));
  return { compiled, errors: dedupeErrors(errors), summary: `decision ${value.decision || "?"} for ${assigned}${checks.length ? `, ${checks.length} check(s)` : ""}` };
}

function applyVerifierChecks(ledger, compiled, agent, fingerprint) {
  const finalFingerprint = compiled.record ? compiled.record.fingerprint : fingerprint;
  for (const check of compiled.checks) {
    const unit = ledger.find((entry) => entry.coverage_id === check.coverage_id);
    const { coverage_id: ignored, ...entry } = check;
    if (unit.status === "in_progress" && unit.agent_id === agent.id) {
      unit.status = "candidate";
      unit.local_checks = [entry];
      unit.result_fingerprints = [finalFingerprint];
      unit.unresolved = [];
    } else {
      unit.local_checks = (unit.local_checks || []).concat([entry]);
    }
    unit.reviewed_paths = unionPaths(unit.local_checks);
  }
  if (finalFingerprint !== fingerprint) {
    for (const unit of ledger) {
      unit.result_fingerprints = (unit.result_fingerprints || []).map((value) => (value === fingerprint ? finalFingerprint : value));
    }
  }
}

function compileRecordVerifier(ctx, agent, text, options) {
  const { value, errors, lineInfo } = parseWith(RECORD_VERIFIER_SPECS, "result", text);
  const assigned = agent.fingerprints[0];
  let compiled = null;
  if (!value.decision) errors.push({ line: null, message: "decision is required: verified | replace" });
  if (value.decision === "verified") {
    if (value.fingerprint !== assigned) errors.push({ line: null, message: `fingerprint must be the record you verified: ${assigned}` });
    if (value.record) errors.push({ line: (lineInfo.get(value.record) || {}).line || null, message: "remove the [record] section: a verified decision carries only the fingerprint" });
    compiled = { decision: "verified", fingerprint: assigned };
  } else if (value.decision === "replace") {
    if (!value.reason) errors.push({ line: null, message: "reason is required for replace" });
    let record = null;
    if (!value.record) {
      errors.push({ line: null, message: "add a [record] section with the complete replacement record" });
    } else if (!value.record.verdict) {
      errors.push({ line: (lineInfo.get(value.record) || {}).line || null, message: "[record]: verdict is required (confirmed | needs_validation | rejected)" });
    } else {
      const finalized = finalizeRecord(value.record, value.record.verdict, lineInfo, "[record]");
      record = finalized.record;
      errors.push(...finalized.errors);
      if (record.fingerprint && record.fingerprint !== assigned && !options.newRootCause) {
        errors.push({ line: (lineInfo.get(value.record) || {}).line || null, message: `[record]: fingerprint ${record.fingerprint} differs from ${assigned}; a separate root cause needs its own fingerprint and independent candidate validation (the parent passes --new-root-cause to register it)` });
      }
    }
    compiled = { decision: "replace", reason: value.reason, record };
  }
  return { compiled, errors: dedupeErrors(errors), summary: `decision ${value.decision || "?"} for ${assigned}` };
}

// ---------------------------------------------------------------------------
// Candidates and findings
// ---------------------------------------------------------------------------

function upsertCandidate(ctx, fingerprint, title) {
  let candidate = findCandidate(ctx, fingerprint);
  if (!candidate) {
    candidate = {
      fingerprint,
      title,
      status: "proposed",
      verdict: null,
      carried: null,
      proposals: [],
      validation: [],
      final: [],
      record: null,
      pending: null,
      reviewer: null,
      previous_status: null,
      duplicate_of: null,
      removed_reason: null,
      created_at: now(),
      updated_at: now(),
    };
    ctx.state.candidates.push(candidate);
    ctx.state.candidates.sort((left, right) => (left.fingerprint < right.fingerprint ? -1 : 1));
  }
  return candidate;
}

function findingsRecords(ctx) {
  return ctx.state.candidates
    .filter((candidate) => candidate.record && ["validated", "final_review", "replacement_pending", "verified"].includes(candidate.status))
    .map((candidate) => candidate.record)
    .sort((left, right) => (left.fingerprint < right.fingerprint ? -1 : left.fingerprint > right.fingerprint ? 1 : 0));
}

function untriagedLeads(ctx) {
  return ctx.state.candidates.filter((candidate) => candidate.status !== "removed" && candidate.status !== "duplicate" && needsTriage(candidate.record));
}

function rebuildFindings(ctx) {
  const records = findingsRecords(ctx);
  const untriaged = untriagedLeads(ctx);
  if (untriaged.length > 0) {
    throw new UserError(`${untriaged.length} needs_validation record(s) have no validation priority yet (they predate triage); add it with a triager agent first`, [
      `${TOOL} agent start --run ${shellPath(ctx.run)} --agent <id> --role triager --untriaged 5`,
      ...untriaged.map((candidate) => candidate.fingerprint),
    ]);
  }
  const errors = findingsValidator.validateDocument(records, SCHEMA);
  if (errors.length > 0) throw new UserError("findings.json would be invalid; nothing was written", errors);
  if (Buffer.byteLength(JSON.stringify(records, null, 2)) > MAX_INPUT_BYTES) throw new UserError("findings.json would exceed the 5 MiB validator limit");
  ctx.findings = records;
  ctx.changed.add("findings");
}

/**
 * Keeps findings.json in step with the decided records once Phase 4 wrote it.
 * A run that predates triage keeps its last findings.json until every lead has
 * a validation priority, because the current schema requires one.
 */
function syncFindingsIfWritten(ctx) {
  if (!ctx.state.findings_written_at) return;
  const untriaged = untriagedLeads(ctx);
  if (untriaged.length > 0) {
    ctx.notes = (ctx.notes || []).concat([`findings.json is rewritten once every needs_validation record has a validation priority; ${untriaged.length} still need one (start a triager)`]);
    return;
  }
  rebuildFindings(ctx);
}

function recordDecision(ctx, fingerprint, entry) {
  for (const unit of linkedUnits(ctx, fingerprint)) {
    const book = bookkeeping(unit);
    book.decisions = (book.decisions || []).concat([{ ...entry, fingerprint, at: now() }]);
  }
  ctx.changed.add("ledger");
}

// ---------------------------------------------------------------------------
// Commit
// ---------------------------------------------------------------------------

function commit(ctx) {
  if (ctx.changed.has("ledger")) {
    sortLedger(ctx.ledger);
    const errors = ledgerValidator.validateDocument(ctx.ledger);
    if (errors.length > 0) throw new UserError("the coverage ledger would become invalid; nothing was written", errors.map((message) => describeLedgerError(message, ctx.ledger)));
    if (Buffer.byteLength(JSON.stringify(ctx.ledger, null, 2)) > MAX_INPUT_BYTES) throw new UserError("coverage-ledger.json would exceed the 5 MiB validator limit");
    ctx.state.validation.ledger = { ok: true, units: ctx.ledger.length, at: now() };
  }
  if (ctx.changed.has("findings")) {
    ctx.state.validation.findings = { ok: true, records: ctx.findings.length, at: now() };
  }
  ctx.state.updated_at = now();
  if (ctx.changed.has("metadata")) writeJson(ctx.P.metadata, ctx.metadata);
  if (ctx.changed.has("ledger")) writeJson(ctx.P.ledger, ctx.ledger);
  if (ctx.changed.has("findings")) writeJson(ctx.P.findings, ctx.findings);
  writeJson(ctx.P.state, ctx.state);
  if (ctx.events.length > 0) {
    fs.mkdirSync(ctx.P.stateDir, { recursive: true });
    fs.appendFileSync(ctx.P.events, ctx.events.map((entry) => JSON.stringify(entry)).join("\n") + "\n");
  }
  writeReport(ctx);
}

function loadEvents(P, limit = 400) {
  if (!fs.existsSync(P.events)) return [];
  const text = readTextLimited(P.events, MAX_STATE_BYTES, "events.jsonl");
  const lines = text.split("\n").filter(Boolean);
  return lines.slice(-limit).map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null;
    }
  }).filter(Boolean);
}

function writeReport(ctx) {
  const architecture = fs.existsSync(ctx.P.architecture) ? readTextLimited(ctx.P.architecture, MAX_INPUT_BYTES, "architecture.md") : null;
  const files = {};
  for (const name of ["run-metadata.json", "architecture.md", "coverage-ledger.json", "findings.json", "REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md"]) {
    files[name] = fs.existsSync(path.join(ctx.run, name));
  }
  const html = renderProgressHtml({
    metadata: ctx.metadata,
    ledger: ctx.ledger,
    findings: ctx.findings,
    state: ctx.state,
    events: loadEvents(ctx.P),
    architecture,
    files,
    generatedAt: now(),
    nextSteps: nextSteps(ctx),
  });
  writeAtomic(ctx.P.html, html);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

function cmdInit(options) {
  const run = path.resolve(requireOption(options, "run", "<new output directory>"));
  const P = runPaths(run);
  const { text, label } = readInputText(options);
  const parsed = RT.parseRecordText(text, METADATA_SPECS, "root");
  const errors = formatErrors(parsed.errors, label);
  const meta = parsed.value;
  for (const key of ["run_id", "repo", "target", "profile"]) if (!meta[key]) errors.push(`${label}: ${key} is required`);
  if (!meta.source_ref || !meta.source_ref.commit) errors.push(`${label}: source_ref.commit is required`);
  if (errors.length > 0) throw new UserError("run metadata is incomplete; nothing was written", errors);
  // Git Bash and MSYS write /c/Users/...; Node on Windows would resolve that to C:\c\Users\...
  const nativeTarget = process.platform === "win32" ? meta.target.replace(/^\/([A-Za-z])(?=\/|$)/, "$1:") : meta.target;
  const target = path.resolve(nativeTarget);
  const relative = path.relative(target, run);
  if (!options["allow-inside-target"] && (relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative)))) {
    throw new UserError(`the output directory ${run} is inside the target ${target}; choose an external directory (or pass --allow-inside-target after verifying version control ignores it)`);
  }
  if (fs.existsSync(P.metadata)) throw new UserError(`${P.metadata} already exists; use "metadata" to update it`);
  fs.mkdirSync(run, { recursive: true });
  const metadata = {
    run_id: meta.run_id,
    repo: meta.repo,
    target,
    source_ref: { commit: meta.source_ref.commit, dirty: meta.source_ref.dirty === true },
    profile: meta.profile,
    scope_paths: meta.scope_paths || [],
    budget: meta.budget === undefined ? null : meta.budget,
    execution_policy: "sandboxed-source-and-local-only",
    selected_companions: meta.selected_companions || [],
    prior_runs: meta.prior_runs || [],
    shared_file_owners: Object.fromEntries(SHARED_FILES.map((name) => [name, "parent"])),
    run_status: "in_progress",
  };
  for (const [key, value] of Object.entries(meta)) if (!hasOwn(metadata, key) && key !== "run_status") metadata[key] = value;
  return withLock(P, () => {
    const ctx = { run, P, options, metadata, ledger: null, findings: null, state: newState(), changed: new Set(["metadata"]), events: [], output: [] };
    event(ctx, "init", `run ${metadata.run_id} initialized (${metadata.profile} profile)`);
    commit(ctx);
    return [`Initialized ${run}`, `Progress report: ${P.html}`];
  });
}

function cmdMetadata(options) {
  const ctx = openRun(options);
  return withLock(ctx.P, () => {
    const fresh = openRun(options);
    let updates = {};
    if (options.file) {
      const { text, label } = readInputText(options);
      const parsed = RT.parseRecordText(text, METADATA_SPECS, "root");
      if (parsed.errors.length) throw new UserError("metadata file has errors; nothing was written", formatErrors(parsed.errors, label));
      updates = parsed.value;
    }
    for (const assignment of options.set || []) {
      const equals = assignment.indexOf("=");
      if (equals === -1) throw new UserError(`--set expects key=value, got ${JSON.stringify(assignment)}`);
      const parsed = RT.parseRecordText(`${assignment.slice(0, equals).trim()}: ${assignment.slice(equals + 1)}`, METADATA_SPECS, "root");
      if (parsed.errors.length) throw new UserError("invalid --set", formatErrors(parsed.errors, "--set"));
      updates = mergeDeep(updates, parsed.value);
    }
    if (Object.keys(updates).length === 0) throw new UserError("nothing to update: pass --file <record text> or --set key=value");
    if (updates.run_status === "complete") throw new UserError("use \"finish --status complete\" so the tool can check that the run really is complete");
    for (const key of ["execution_policy", "shared_file_owners"]) if (hasOwn(updates, key)) throw new UserError(`${key} is fixed by the tool`);
    fresh.metadata = mergeDeep(fresh.metadata, updates);
    fresh.changed.add("metadata");
    event(fresh, "metadata", `metadata updated: ${Object.keys(updates).join(", ")}`);
    commit(fresh);
    return [`Updated run-metadata.json: ${Object.keys(updates).join(", ")}`];
  });
}

function mergeDeep(base, updates) {
  const out = { ...(base || {}) };
  for (const [key, value] of Object.entries(updates)) {
    out[key] = value && typeof value === "object" && !Array.isArray(value) && out[key] && typeof out[key] === "object" && !Array.isArray(out[key])
      ? mergeDeep(out[key], value)
      : value;
  }
  return out;
}

function mutate(options, fn) {
  const probe = openRun(options);
  return withLock(probe.P, () => {
    const ctx = openRun(options);
    const output = fn(ctx);
    commit(ctx);
    return output.concat(ctx.notes || []);
  });
}

function cmdUnitsAdd(options) {
  return mutate(options, (ctx) => {
    const { text, label } = readInputText(options);
    const parsed = RT.parseRecordText(text, UNIT_SPECS, "root");
    const errors = formatErrors(parsed.errors, label);
    const ledger = ensureLedger(ctx);
    const added = [];
    const unitLines = new Map();
    const existingIds = new Map(ledger.map((unit) => [unit.coverage_id, unit]));
    const hasPriorRuns = Array.isArray(ctx.metadata.prior_runs) && ctx.metadata.prior_runs.length > 0;
    const waveOverride = options.wave !== undefined ? Number(options.wave) : null;
    if (waveOverride !== null && (!Number.isInteger(waveOverride) || waveOverride < 1)) throw new UserError("--wave must be a positive whole number");
    for (const seed of parsed.value.units || []) {
      const line = (parsed.lineInfo.get(seed) || {}).line;
      const where = `${label}:${line}`;
      const refs = seed.canonical_refs || {};
      const missing = REF_FIELDS.filter((key) => !refs[key]).concat(REF_FIELDS.filter((key) => !seed[key]).map((key) => `${key} (label)`));
      if (missing.length > 0) {
        errors.push(`${where}: [unit] is missing ${missing.map((key) => (key.endsWith("(label)") ? key : `canonical_refs.${key}`)).join(", ")}`);
        continue;
      }
      if (Boolean(seed.lifecycle) !== Boolean(refs.lifecycle)) {
        errors.push(`${where}: lifecycle and canonical_refs.lifecycle must be given together`);
        continue;
      }
      const canonicalRefs = { surface: refs.surface, boundary: refs.boundary, subsystem: refs.subsystem, attack_class: refs.attack_class };
      if (refs.lifecycle) canonicalRefs.lifecycle = refs.lifecycle;
      let coverageId;
      try {
        coverageId = ledgerValidator.canonicalCoverageId(canonicalRefs);
      } catch {
        errors.push(`${where}: a canonical reference is invalid (it must be NFC text with visible content, no control or invisible characters, and no surrounding spaces)`);
        continue;
      }
      if (existingIds.has(coverageId)) {
        errors.push(`${where}: this unit already exists as ${alias(existingIds.get(coverageId))}`);
        continue;
      }
      const status = seed.status || "planned";
      const unit = {
        coverage_id: coverageId,
        canonical_refs: canonicalRefs,
        surface: seed.surface,
        boundary: seed.boundary,
        subsystem: seed.subsystem,
        attack_class: seed.attack_class,
      };
      if (seed.lifecycle) unit.lifecycle = seed.lifecycle;
      Object.assign(unit, {
        starting_paths: seed.starting_paths || [],
        ordinary_attack_class_block: seed.ordinary_attack_class_block === undefined ? null : seed.ordinary_attack_class_block,
        selected_companion_blocks: seed.selected_companion_blocks || [],
        excluded_blocks: (seed.excluded_blocks || []).map((entry) => ({ block: entry.block, reason: entry.reason })),
        prior_status: seed.prior_status || (hasPriorRuns ? "new" : "none"),
        attempts: [],
        wave: seed.wave || waveOverride || defaultWave(ctx),
        status,
        agent_id: null,
        reviewed_paths: [],
        local_checks: [],
        result_fingerprints: [],
        unresolved: status === "planned" ? [] : (seed.unresolved || []),
        bookkeeping: { alias: `U${ctx.state.next_alias++}`, added_at: now() },
      });
      if (status === "planned" && (seed.unresolved || []).length > 0) errors.push(`${where}: a planned unit has no unresolved reason; set status deferred, out_of_scope, or not_applicable`);
      if (seed.priority_rationale) unit.bookkeeping.priority_rationale = seed.priority_rationale;
      if (seed.from_proposal) {
        const proposal = ctx.state.proposals.find((entry) => entry.id.toLowerCase() === seed.from_proposal.toLowerCase());
        if (!proposal) errors.push(`${where}: unknown proposal ${seed.from_proposal}`);
        else if (proposal.status !== "open") errors.push(`${where}: proposal ${proposal.id} is already ${proposal.status}`);
        else {
          proposal.status = "accepted";
          proposal.resolution = `added as ${unit.bookkeeping.alias}`;
          proposal.coverage_id = coverageId;
          proposal.resolved_at = now();
          unit.bookkeeping.from_proposal = proposal.id;
        }
      }
      existingIds.set(coverageId, unit);
      unitLines.set(coverageId, line);
      ledger.push(unit);
      added.push(unit);
    }
    if (errors.length > 0) throw new UserError("units file has errors; nothing was written", errors);
    if (added.length === 0) throw new UserError(`${label} contains no [unit] sections`);
    sortLedger(ledger);
    const ledgerErrors = ledgerValidator.validateDocument(ledger);
    if (ledgerErrors.length > 0) throw new UserError("the coverage ledger would become invalid; nothing was written", ledgerErrors.map((message) => describeLedgerError(message, ledger, unitLines)));
    ctx.changed.add("ledger");
    event(ctx, "units add", `added ${added.length} unit(s): ${added.map(alias).join(", ")}`);
    return [`Added ${added.length} unit(s):`, ...added.map((unit) => `  ${alias(unit).padEnd(5)} wave ${unit.wave}  ${unit.status.padEnd(9)} ${unit.surface} × ${unit.boundary} × ${unit.attack_class}`)];
  });
}

function cmdUnitsStatus(options) {
  return mutate(options, (ctx) => {
    const target = requireOption(options, "to", "planned|deferred|out_of_scope|not_applicable");
    if (!SEED_STATUSES.includes(target)) throw new UserError(`--to must be one of ${SEED_STATUSES.join(", ")}`);
    const reason = target === "planned" ? null : readReason(options);
    const units = splitList(requireOption(options, "units", "U1,U2")).map((ref) => requireUnit(ctx, ref));
    for (const unit of units) {
      if (!SEED_STATUSES.includes(unit.status)) {
        throw new UserError(`unit ${alias(unit)} is ${unit.status}; only planned, deferred, out_of_scope, and not_applicable units change status here${unit.status === "in_progress" ? " (use \"agent fail\" to release an assignment)" : " (use \"units reassign\" to archive evidence)"}`);
      }
      unit.status = target;
      emptyEvidence(unit);
      unit.unresolved = reason ? [reason] : [];
      if (target === "planned" && options.wave !== undefined) unit.wave = Number(options.wave);
    }
    ctx.changed.add("ledger");
    event(ctx, "units status", `${units.map(alias).join(", ")} → ${target}${reason ? ` (${reason})` : ""}`);
    return [`${units.map(alias).join(", ")} → ${target}`];
  });
}

function cmdUnitsReassign(options) {
  return mutate(options, (ctx) => {
    const unit = requireUnit(ctx, requireOption(options, "unit", "U3"));
    const reason = readReason(options);
    const deferReason = typeof options.defer === "string" ? options.defer : null;
    if (!["blocked", "covered", "candidate"].includes(unit.status)) {
      throw new UserError(`unit ${alias(unit)} is ${unit.status}; only blocked, covered, or candidate units carry evidence to archive`);
    }
    unit.attempts = (unit.attempts || []).concat([{
      wave: unit.wave,
      status: unit.status,
      agent_id: unit.agent_id,
      reviewed_paths: unit.reviewed_paths,
      local_checks: unit.local_checks,
      result_fingerprints: unit.result_fingerprints,
      unresolved: unit.unresolved,
      reassignment_reason: reason,
    }]);
    unit.wave = Math.max(unit.wave + 1, ctx.state.wave + 1);
    emptyEvidence(unit);
    unit.status = deferReason ? "deferred" : "planned";
    unit.unresolved = deferReason ? [deferReason] : [];
    for (const proposal of ctx.state.proposals) {
      if (proposal.status === "open" && proposal.type === "reassign" && proposal.coverage_id === unit.coverage_id) {
        proposal.status = "accepted";
        proposal.resolution = deferReason ? `archived and deferred (${deferReason})` : `archived; wave ${unit.wave}`;
        proposal.resolved_at = now();
      }
    }
    ctx.changed.add("ledger");
    event(ctx, "units reassign", `${alias(unit)} archived attempt ${unit.attempts.length}; now ${unit.status} in wave ${unit.wave}`);
    return [`${alias(unit)}: archived the ${unit.attempts[unit.attempts.length - 1].status} attempt; live state ${unit.status}, wave ${unit.wave}`];
  });
}

function cmdUnitsNote(options) {
  return mutate(options, (ctx) => {
    const unit = requireUnit(ctx, requireOption(options, "unit", "U3"));
    const text = readReason(options, "text");
    const book = bookkeeping(unit);
    book.notes = (book.notes || []).concat([{ at: now(), note: text }]);
    ctx.changed.add("ledger");
    event(ctx, "units note", `${alias(unit)}: ${text}`);
    return [`Noted on ${alias(unit)}`];
  });
}

function ensureBudget(ctx, options) {
  const budget = ctx.metadata.budget;
  const spent = ctx.state.agents.length;
  if (Number.isInteger(budget) && spent + 1 > budget && !options["allow-over-budget"]) {
    throw new UserError(`the strict budget of ${budget} agent invocations is spent (${spent} used); never exceed it silently — set the run incomplete, or pass --allow-over-budget only if the user raised the budget`);
  }
}

function cmdAgentStart(options) {
  return mutate(options, (ctx) => {
    const id = requireOption(options, "agent", "<canonical lowercase id>");
    const role = requireOption(options, "role", ROLES.join("|"));
    if (!ROLES.includes(role)) throw new UserError(`--role must be one of ${ROLES.join(", ")}`);
    if (!ledgerValidator.isSafeAgentId(id)) throw new UserError(`agent ID ${JSON.stringify(id)} must match ^[a-z0-9][a-z0-9_-]{0,63}$ and not be a Windows device name`);
    if (findAgent(ctx, id)) throw new UserError(`agent ID ${id} was already used in this run; every invocation needs a fresh ID`);
    if (RESULT_ROLES.has(role) && fs.existsSync(ctx.P.agentDir(id))) throw new UserError(`${ctx.P.agentDir(id)} already exists`);
    ensureBudget(ctx, options);

    const agent = { id, role, phase: ROLE_PHASE[role], wave: null, status: "running", units: [], fingerprints: [], note: typeof options.note === "string" ? options.note : null, started_at: now(), ended_at: null, summary: null, last_errors: [] };
    if (options.allowlist || options["max-file-bytes"] || options["max-total-bytes"]) {
      agent.promotion = { allowlist: splitList(options.allowlist), max_file_bytes: options["max-file-bytes"] ? Number(options["max-file-bytes"]) : null, max_total_bytes: options["max-total-bytes"] ? Number(options["max-total-bytes"]) : null };
    }

    if (role === "hunter") {
      const units = splitList(requireOption(options, "units", "U1,U2")).map((ref) => requireUnit(ctx, ref));
      if (units.length === 0) throw new UserError("--units needs at least one unit");
      for (const unit of units) {
        if (unit.status !== "planned") throw new UserError(`unit ${alias(unit)} is ${unit.status}; only planned units can be assigned (reassign or set it planned first)`);
        if ((unit.attempts || []).some((attempt) => attempt.agent_id === id)) throw new UserError(`agent ${id} owned an archived attempt of ${alias(unit)}; use a fresh agent`);
      }
      for (const unit of units) {
        unit.status = "in_progress";
        unit.agent_id = id;
      }
      agent.units = units.map((unit) => unit.coverage_id);
      agent.wave = Math.max(...units.map((unit) => unit.wave));
      ctx.state.wave = Math.max(ctx.state.wave, agent.wave);
      ctx.changed.add("ledger");
    } else if (role === "verifier" || role === "record-verifier") {
      const fingerprints = splitList(requireOption(options, "fingerprint", "<candidate fingerprint>"));
      if (fingerprints.length !== 1) throw new UserError("give each verifier exactly one candidate (--fingerprint <fp>)");
      const candidate = requireCandidate(ctx, fingerprints[0]);
      const involved = new Set([
        ...candidate.proposals.map((proposal) => proposal.agent_id),
        ...candidate.validation.map((entry) => entry.agent_id),
        ...candidate.final.map((entry) => entry.agent_id),
      ]);
      if (involved.has(id)) throw new UserError(`${id} already worked on ${candidate.fingerprint}; verifiers must be independent`);
      if (role === "verifier") {
        if (candidate.status !== "proposed") throw new UserError(`candidate ${candidate.fingerprint} is ${candidate.status}; only proposed candidates go to a Phase 3 verifier`);
        candidate.previous_status = candidate.status;
        candidate.status = "validating";
        for (const unit of linkedUnits(ctx, candidate.fingerprint)) {
          if (unit.status === "planned" && ((unit.bookkeeping && unit.bookkeeping.carried_fingerprints) || []).includes(candidate.fingerprint)) {
            unit.status = "in_progress";
            unit.agent_id = id;
            agent.units.push(unit.coverage_id);
            ctx.changed.add("ledger");
          }
        }
      } else {
        if (profile(ctx) === "quick") throw new UserError("the quick profile merges Phase 5 into Phase 3; its verifier result is already final");
        if (!["validated", "replacement_pending"].includes(candidate.status)) throw new UserError(`candidate ${candidate.fingerprint} is ${candidate.status}; record verification needs a validated record or a pending replacement`);
        if (candidate.verdict === "rejected" && candidate.status === "validated") throw new UserError(`candidate ${candidate.fingerprint} was rejected; Phase 5 reviews confirmed and needs_validation records`);
        candidate.previous_status = candidate.status;
        candidate.status = "final_review";
      }
      candidate.reviewer = id;
      candidate.updated_at = now();
      agent.fingerprints = [candidate.fingerprint];
    } else if (role === "triager") {
      const triageable = (candidate) => candidate.record && candidate.record.verdict === "needs_validation" && ["validated", "verified"].includes(candidate.status);
      const busy = (candidate) => candidate.triager && ctx.state.agents.some((other) => other.id === candidate.triager && other.status === "running");
      let candidates;
      if (options.untriaged !== undefined) {
        const count = Number(options.untriaged);
        if (!Number.isInteger(count) || count < 1) throw new UserError("--untriaged needs a positive number of leads");
        candidates = untriagedLeads(ctx).filter((candidate) => triageable(candidate) && !busy(candidate)).slice(0, count);
        if (candidates.length === 0) throw new UserError("no untriaged needs_validation record is waiting for a triager");
      } else {
        candidates = splitList(requireOption(options, "fingerprint", "<fp>[,<fp>...] or --untriaged <n>")).map((fingerprint) => requireCandidate(ctx, fingerprint));
      }
      for (const candidate of candidates) {
        if (!triageable(candidate)) throw new UserError(`${candidate.fingerprint} is not a decided needs_validation record (status ${candidate.status}, verdict ${candidate.verdict || "none"}); triage applies to validated or verified leads`);
        if (busy(candidate)) throw new UserError(`${candidate.fingerprint} is already being triaged by ${candidate.triager}`);
      }
      for (const candidate of candidates) candidate.triager = id;
      agent.fingerprints = candidates.map((candidate) => candidate.fingerprint);
    }

    if (RESULT_ROLES.has(role)) {
      fs.mkdirSync(path.join(ctx.run, "agents"), { recursive: true });
      fs.mkdirSync(ctx.P.agentDir(id));
      if (EXECUTING_ROLES.has(role)) {
        fs.mkdirSync(path.join(ctx.P.agentDir(id), "scratch"));
        fs.mkdirSync(path.join(ctx.P.agentDir(id), "artifacts"));
      }
      ctx.state.agents.push(agent);
      fs.writeFileSync(ctx.P.result(id), buildTemplate(ctx, agent, {}), { flag: "wx" });
      agent.result_path = relativeResultPath(id);
    } else {
      ctx.state.agents.push(agent);
    }
    raisePhase(ctx, ROLE_PHASE[role]);
    event(ctx, "agent start", `${id} (${role}) started${agent.units.length ? ` on ${agent.units.map((unitId) => alias(findUnit(ctx, unitId))).join(", ")}` : ""}${agent.fingerprints.length ? ` for ${agent.fingerprints[0]}` : ""}`, { agent: id });
    const lines = [`Started ${id} (${role}). Agents used: ${ctx.state.agents.length}${Number.isInteger(ctx.metadata.budget) ? ` of ${ctx.metadata.budget}` : ""}.`];
    if (RESULT_ROLES.has(role)) lines.push(`Result file with template: ${ctx.P.result(id)}`, `Prompt material: ${TOOL} brief --run ${shellPath(ctx.run)} --agent ${id}`);
    return lines;
  });
}

function cmdAgentFinish(options) {
  return mutate(options, (ctx) => {
    const agent = requireAgent(ctx, requireOption(options, "agent"));
    if (RESULT_ROLES.has(agent.role)) throw new UserError(`${agent.id} is a ${agent.role}; record its result with "ingest --agent ${agent.id}" (or "agent fail")`);
    if (agent.status !== "running") throw new UserError(`${agent.id} is already ${agent.status}`);
    agent.status = "done";
    agent.ended_at = now();
    agent.summary = typeof options.note === "string" ? options.note : agent.summary;
    event(ctx, "agent finish", `${agent.id} finished`, { agent: agent.id });
    return [`${agent.id} marked done`];
  });
}

function releaseAgent(ctx, agent) {
  for (const unit of ensureLedger(ctx)) {
    if (unit.status === "in_progress" && unit.agent_id === agent.id) {
      unit.status = "planned";
      unit.agent_id = null;
      ctx.changed.add("ledger");
    }
  }
  for (const fingerprint of agent.fingerprints) {
    const candidate = findCandidate(ctx, fingerprint);
    if (candidate && candidate.reviewer === agent.id && ["validating", "final_review"].includes(candidate.status)) {
      candidate.status = candidate.previous_status || "proposed";
      candidate.reviewer = null;
    }
    if (candidate && candidate.triager === agent.id) candidate.triager = null;
  }
}

function cmdAgentFail(options) {
  return mutate(options, (ctx) => {
    const agent = requireAgent(ctx, requireOption(options, "agent"));
    if (agent.status !== "running") throw new UserError(`${agent.id} is already ${agent.status}`);
    const reason = readReason(options);
    releaseAgent(ctx, agent);
    agent.status = "failed";
    agent.ended_at = now();
    agent.summary = reason;
    event(ctx, "agent fail", `${agent.id} failed: ${reason}`, { agent: agent.id });
    return [`${agent.id} marked failed; its units and candidates were released for a fresh agent`];
  });
}

function loadResultText(ctx, agent, options) {
  const file = options.file ? path.resolve(options.file) : ctx.P.result(agent.id);
  return { text: readTextLimited(file, MAX_INPUT_BYTES, file), label: options.file || relativeResultPath(agent.id) };
}

function cmdCheck(options) {
  const ctx = openRun(options);
  const agent = requireAgent(ctx, requireOption(options, "agent"));
  const { text, label } = loadResultText(ctx, agent, options);
  const { compiled, errors, summary } = compileResult(ctx, agent, text, { newRootCause: Boolean(options["new-root-cause"]) });
  if (errors.length > 0) throw new UserError(`${errors.length} problem(s) in ${label}; fix each line and run check again`, formatErrors(errors, label));
  const lines = [`OK: ${label} is valid — ${summary}`];
  if (options.json) lines.push(JSON.stringify(compiled, null, 2));
  else lines.push(`Reply with: RESULT ${relativeResultPath(agent.id)}`);
  return lines;
}

function cmdIngest(options) {
  const probe = openRun(options);
  return withLock(probe.P, () => {
    const ctx = openRun(options);
    const agent = requireAgent(ctx, requireOption(options, "agent"));
    if (agent.status !== "running") throw new UserError(`${agent.id} is ${agent.status}; only a running agent's result can be ingested`);
    const { text, label } = loadResultText(ctx, agent, options);
    const newRootCause = Boolean(options["new-root-cause"]);
    const { compiled, errors, summary } = compileResult(ctx, agent, text, { newRootCause });
    if (errors.length > 0) {
      agent.last_errors = formatErrors(errors, label).slice(0, 50);
      agent.last_error_at = now();
      event(ctx, "ingest", `${agent.id}: result rejected with ${errors.length} problem(s)`, { agent: agent.id, level: "error" });
      commit(ctx);
      throw new UserError(`${agent.id}'s result was not ingested (${errors.length} problem(s)). Never edit an agent's result yourself: send these lines back to the same agent to fix its own file, or run "agent fail" and use a fresh agent.`, agent.last_errors);
    }
    const lines = applyResult(ctx, agent, compiled, { newRootCause });
    agent.status = "done";
    agent.ended_at = now();
    agent.summary = summary;
    agent.last_errors = [];
    agent.compiled_result = `state/results/${agent.id}.json`;
    event(ctx, "ingest", `${agent.id}: ${summary}`, { agent: agent.id });
    commit(ctx);
    // The compiled contract object, kept as the audit trail of exactly what was ingested.
    writeJson(path.join(ctx.P.results, `${agent.id}.json`), compiled);
    return [`Ingested ${agent.id}: ${summary}`, ...lines, ...(ctx.notes || [])];
  });
}

function applyResult(ctx, agent, compiled, options) {
  switch (agent.role) {
    case "hunter": return applyHunter(ctx, agent, compiled);
    case "critic":
    case "final-critic": return applyCritic(ctx, agent, compiled);
    case "verifier": return applyVerifier(ctx, agent, compiled, options);
    case "record-verifier": return applyRecordVerifier(ctx, agent, compiled, options);
    case "triager": return applyTriager(ctx, agent, compiled);
    default: return [];
  }
}

function applyHunter(ctx, agent, compiled) {
  applyHunterUnits(ensureLedger(ctx), compiled, agent);
  ctx.changed.add("ledger");
  const lines = [];
  for (const proposal of compiled.candidates) {
    const { proposed_verdict: verdict, ...record } = proposal;
    const candidate = upsertCandidate(ctx, record.fingerprint, record.title);
    candidate.proposals.push({ agent_id: agent.id, source: "hunter", proposed_verdict: verdict, record: { verdict, ...record }, at: now() });
    candidate.updated_at = now();
    lines.push(`  candidate ${record.fingerprint} (${verdict})${candidate.proposals.length > 1 ? ` — duplicate proposal #${candidate.proposals.length}, consolidated by fingerprint` : ""}`);
  }
  for (const entry of compiled.uncovered) {
    const id = `P${ctx.state.next_proposal++}`;
    ctx.state.proposals.push({ id, type: "uncovered", from_agent: agent.id, data: entry, status: "open", at: now() });
    lines.push(`  proposal ${id}: uncovered ${entry.surface} × ${entry.boundary} × ${entry.attack_class}`);
  }
  return lines;
}

function applyCritic(ctx, agent, compiled) {
  const lines = [];
  for (const entry of compiled.missing_units) {
    const id = `P${ctx.state.next_proposal++}`;
    ctx.state.proposals.push({ id, type: "missing_unit", from_agent: agent.id, data: entry, status: "open", at: now() });
    lines.push(`  proposal ${id}: missing unit ${entry.surface} × ${entry.boundary} × ${entry.attack_class}`);
  }
  for (const coverageId of compiled.reassign_ids) {
    const unit = findUnit(ctx, coverageId);
    const id = `P${ctx.state.next_proposal++}`;
    const legitimate = ["blocked", "covered", "candidate"].includes(unit.status);
    ctx.state.proposals.push({ id, type: "reassign", from_agent: agent.id, coverage_id: coverageId, data: { unit: alias(unit), status: unit.status }, status: "open", at: now() });
    lines.push(`  proposal ${id}: reassign ${alias(unit)} (${unit.status}${legitimate ? "" : " — carries no evidence to archive"})`);
  }
  for (const fingerprint of compiled.resolved_prior_leads) {
    const units = linkedUnits(ctx, fingerprint);
    for (const unit of units) {
      const book = bookkeeping(unit);
      book.resolved_prior_leads = (book.resolved_prior_leads || []).concat([{ fingerprint, agent_id: agent.id, at: now() }]);
      ctx.changed.add("ledger");
    }
    lines.push(`  resolved prior lead ${fingerprint}${units.length ? ` on ${units.map(alias).join(", ")}` : " (no linked unit; record the reason with units note)"}`);
  }
  agent.critic = { stop: compiled.stop, missing_units: compiled.missing_units.length, reassign_ids: compiled.reassign_ids.length };
  lines.push(`  critic stop: ${compiled.stop}`);
  return lines;
}

function applyVerifier(ctx, agent, compiled, options) {
  const assigned = agent.fingerprints[0];
  const candidate = requireCandidate(ctx, assigned);
  applyVerifierChecks(ensureLedger(ctx), compiled, agent, assigned);
  ctx.changed.add("ledger");
  const lines = [];
  if (compiled.record.fingerprint !== assigned && options.newRootCause) {
    lines.push(`  fingerprint renamed ${assigned} → ${compiled.record.fingerprint} (different root cause)`);
    candidate.renamed_from = assigned;
    candidate.fingerprint = compiled.record.fingerprint;
    agent.fingerprints = [candidate.fingerprint];
    ctx.state.candidates.sort((left, right) => (left.fingerprint < right.fingerprint ? -1 : 1));
  }
  candidate.validation.push({ agent_id: agent.id, decision: compiled.decision, record: compiled.record, at: now() });
  candidate.record = compiled.record;
  candidate.verdict = compiled.decision;
  candidate.title = compiled.record.title;
  candidate.status = profile(ctx) === "quick" ? "verified" : "validated";
  candidate.reviewer = null;
  candidate.updated_at = now();
  recordDecision(ctx, candidate.fingerprint, { phase: 3, agent_id: agent.id, decision: compiled.decision });
  syncFindingsIfWritten(ctx);
  lines.push(`  ${candidate.fingerprint}: ${compiled.decision}${profile(ctx) === "quick" ? " (quick profile: final)" : ""}`);
  return lines;
}

function applyRecordVerifier(ctx, agent, compiled, options) {
  const assigned = agent.fingerprints[0];
  const candidate = requireCandidate(ctx, assigned);
  const underReview = candidate.pending ? candidate.pending.record : candidate.record;
  const lines = [];
  const entry = { agent_id: agent.id, decision: compiled.decision, at: now(), reviewed: candidate.pending ? "pending replacement" : "current record" };
  candidate.reviewer = null;
  if (compiled.decision === "verified") {
    if (candidate.pending) {
      candidate.record = candidate.pending.record;
      candidate.verdict = candidate.record.verdict;
      candidate.title = candidate.record.title;
      lines.push(`  ${assigned}: replacement from ${candidate.pending.agent_id} verified and applied`);
      candidate.pending = null;
    } else {
      lines.push(`  ${assigned}: verified`);
    }
    candidate.status = "verified";
  } else if (compiled.record.fingerprint !== assigned && options.newRootCause) {
    const fresh = upsertCandidate(ctx, compiled.record.fingerprint, compiled.record.title);
    const { verdict, ...record } = compiled.record;
    fresh.proposals.push({ agent_id: agent.id, source: "record-verifier", proposed_verdict: verdict, record: { verdict, ...record }, at: now() });
    for (const unit of linkedUnits(ctx, assigned)) {
      if (unit.status === "candidate" && !unit.result_fingerprints.includes(fresh.fingerprint)) unit.result_fingerprints.push(fresh.fingerprint);
    }
    candidate.status = candidate.previous_status || "validated";
    entry.decision = "separate_root_cause";
    entry.new_fingerprint = fresh.fingerprint;
    lines.push(`  ${fresh.fingerprint}: registered as a new candidate; it needs independent Phase 3 validation`, `  ${assigned}: still needs its own final verification`);
  } else {
    entry.reason = compiled.reason;
    const material = materialChanges(underReview, compiled.record);
    entry.material = material;
    if (material.length > 0) {
      candidate.pending = { agent_id: agent.id, reason: compiled.reason, record: compiled.record, material, at: now() };
      candidate.status = "replacement_pending";
      lines.push(`  ${assigned}: material replacement (${material.join("; ")}) — give it to a fresh record-verifier before it applies`);
    } else {
      candidate.record = compiled.record;
      candidate.verdict = compiled.record.verdict;
      candidate.title = compiled.record.title;
      candidate.pending = null;
      candidate.status = "verified";
      lines.push(`  ${assigned}: non-material replacement applied`);
    }
  }
  candidate.final.push(entry);
  candidate.updated_at = now();
  recordDecision(ctx, assigned, { phase: 5, agent_id: agent.id, decision: entry.decision });
  syncFindingsIfWritten(ctx);
  return lines;
}

function cmdCarry(options) {
  return mutate(options, (ctx) => {
    const priorPath = path.resolve(requireOption(options, "prior", "<prior run>/findings.json"));
    const fingerprint = requireOption(options, "fingerprint");
    const unit = requireUnit(ctx, requireOption(options, "unit", "U5"));
    const prior = JSON.parse(readTextLimited(priorPath));
    if (!Array.isArray(prior)) throw new UserError(`${priorPath} is not a findings array`);
    const record = prior.find((entry) => entry && entry.fingerprint === fingerprint);
    if (!record) throw new UserError(`${priorPath} has no record with fingerprint ${fingerprint}`);
    if (!["confirmed", "needs_validation"].includes(record.verdict)) throw new UserError(`only confirmed and needs_validation records are carried; ${fingerprint} is ${record.verdict}`);
    const expected = record.verdict === "confirmed" ? "prior_confirmed_same_source" : "prior_needs_validation";
    if (unit.status !== "planned" || unit.prior_status !== expected) throw new UserError(`carry into a planned unit with prior_status ${expected}; ${alias(unit)} is ${unit.status} with prior_status ${unit.prior_status}`);
    let errors = findingsValidator.validateDocument([record], SCHEMA);
    // A lead from a run that predates triage still carries; its Phase 3 verifier adds the validation priority.
    const predatesTriage = record.verdict === "needs_validation" && !hasOwn(record, "triage");
    if (predatesTriage) errors = errors.filter((message) => !message.includes("missing required field \"triage\"") && !message.includes("must match exactly one schema in oneOf"));
    if (errors.length > 0) throw new UserError(`the prior record no longer meets the current contract; create a revalidation unit instead`, errors);
    const candidate = upsertCandidate(ctx, fingerprint, record.title);
    if (candidate.proposals.some((proposal) => proposal.source === "prior")) throw new UserError(`${fingerprint} is already carried`);
    candidate.carried = { prior_status: expected, prior_path: priorPath, unit: unit.coverage_id };
    const { verdict, ...rest } = record;
    candidate.proposals.push({ agent_id: "prior-run", source: "prior", proposed_verdict: verdict, record: { verdict, ...rest }, at: now() });
    const book = bookkeeping(unit);
    book.carried_fingerprints = uniq((book.carried_fingerprints || []).concat([fingerprint]));
    ctx.changed.add("ledger");
    event(ctx, "carry", `carried ${verdict} ${fingerprint} from ${priorPath} into ${alias(unit)}`);
    return [`Carried ${fingerprint} (${verdict}) into ${alias(unit)}; it goes through Phase 3 like any candidate`];
  });
}

function cmdCandidateDuplicate(options) {
  return mutate(options, (ctx) => {
    const duplicate = requireCandidate(ctx, requireOption(options, "fingerprint"));
    const original = requireCandidate(ctx, requireOption(options, "of"));
    if (duplicate === original) throw new UserError("a candidate cannot duplicate itself");
    if (duplicate.status !== "proposed") throw new UserError(`${duplicate.fingerprint} is ${duplicate.status}; only proposed candidates can be consolidated`);
    duplicate.status = "duplicate";
    duplicate.duplicate_of = original.fingerprint;
    duplicate.duplicate_reason = readReason(options, "reason", false);
    duplicate.updated_at = now();
    event(ctx, "candidate duplicate", `${duplicate.fingerprint} consolidated into ${original.fingerprint}`);
    return [`${duplicate.fingerprint} → duplicate of ${original.fingerprint}; it will not be validated separately`];
  });
}

function cmdProposalReject(options) {
  return mutate(options, (ctx) => {
    const id = requireOption(options, "proposal", "P3");
    const proposal = ctx.state.proposals.find((entry) => entry.id.toLowerCase() === String(id).toLowerCase());
    if (!proposal) throw new UserError(`unknown proposal ${id}`);
    if (proposal.status !== "open") throw new UserError(`proposal ${proposal.id} is already ${proposal.status}`);
    proposal.status = "rejected";
    proposal.resolution = readReason(options);
    proposal.resolved_at = now();
    event(ctx, "proposal reject", `${proposal.id} rejected: ${proposal.resolution}`);
    return [`${proposal.id} rejected`];
  });
}

function cmdRecordApply(options) {
  return mutate(options, (ctx) => {
    const candidate = requireCandidate(ctx, requireOption(options, "fingerprint"));
    if (candidate.status !== "replacement_pending" || !candidate.pending) throw new UserError(`${candidate.fingerprint} has no pending replacement`);
    if (!options["non-material"]) throw new UserError("pass --non-material to confirm the flagged changes are only wording or line corrections that change no meaning or evidence; otherwise start a fresh record-verifier");
    const reason = readReason(options);
    candidate.record = candidate.pending.record;
    candidate.verdict = candidate.record.verdict;
    candidate.title = candidate.record.title;
    candidate.final.push({ agent_id: "parent", decision: "applied_non_material", reason, material: candidate.pending.material, at: now() });
    candidate.pending = null;
    candidate.status = "verified";
    candidate.updated_at = now();
    syncFindingsIfWritten(ctx);
    recordDecision(ctx, candidate.fingerprint, { phase: 5, agent_id: "parent", decision: "applied_non_material" });
    event(ctx, "record apply", `${candidate.fingerprint}: pending replacement applied as non-material (${reason})`);
    return [`${candidate.fingerprint}: replacement applied`];
  });
}

function cmdRecordRemove(options) {
  return mutate(options, (ctx) => {
    const candidate = requireCandidate(ctx, requireOption(options, "fingerprint"));
    const reason = readReason(options);
    candidate.status = "removed";
    candidate.removed_reason = reason;
    candidate.updated_at = now();
    syncFindingsIfWritten(ctx);
    event(ctx, "record remove", `${candidate.fingerprint} removed from findings: ${reason}`, { level: "warn" });
    return [`${candidate.fingerprint} removed from findings.json; its ledger unit stays an unresolved candidate.`, `The run must end incomplete: finish --status incomplete --reason "<exact reason>"`];
  });
}

function cmdFindingsWrite(options) {
  return mutate(options, (ctx) => {
    rebuildFindings(ctx);
    ctx.state.findings_written_at = now();
    raisePhase(ctx, 4);
    const counts = {};
    for (const record of ctx.findings) counts[record.verdict] = (counts[record.verdict] || 0) + 1;
    const pending = ctx.state.candidates.filter((candidate) => ["proposed", "validating"].includes(candidate.status));
    event(ctx, "findings write", `findings.json written with ${ctx.findings.length} record(s)`);
    const lines = [`Wrote findings.json: ${ctx.findings.length} record(s) ${JSON.stringify(counts)} — validated against report-schema.json`];
    if (pending.length > 0) lines.push(`Not included (no independent decision yet): ${pending.map((candidate) => candidate.fingerprint).join(", ")}`);
    return lines;
  });
}

function cmdPhase(options) {
  return mutate(options, (ctx) => {
    const phase = Number(requireOption(options, "set", "1-6"));
    if (!Number.isInteger(phase) || phase < 1 || phase > 6) throw new UserError("--set must be 1 to 6");
    ctx.state.phase = phase;
    event(ctx, "phase", `phase set to ${phase}`);
    return [`Phase ${phase}`];
  });
}

function completionBlockers(ctx) {
  const blockers = [];
  for (const unit of ensureLedger(ctx)) {
    if (["planned", "in_progress"].includes(unit.status)) blockers.push(`unit ${alias(unit)} is ${unit.status}`);
  }
  for (const agent of ctx.state.agents) if (agent.status === "running") blockers.push(`agent ${agent.id} is still running`);
  for (const candidate of ctx.state.candidates) {
    if (["duplicate"].includes(candidate.status)) continue;
    if (candidate.status === "removed") blockers.push(`${candidate.fingerprint} was removed (${candidate.removed_reason}); the run is incomplete`);
    else if (["proposed", "validating"].includes(candidate.status)) blockers.push(`${candidate.fingerprint} has no independent Phase 3 decision`);
    else if (candidate.status === "replacement_pending") blockers.push(`${candidate.fingerprint} has a material replacement awaiting fresh verification`);
    else if (candidate.status === "final_review") blockers.push(`${candidate.fingerprint} is in Phase 5 review`);
    else if (candidate.status === "validated" && candidate.verdict !== "rejected" && profile(ctx) !== "quick") blockers.push(`${candidate.fingerprint} has not passed Phase 5 record verification`);
    if (!["removed", "proposed", "validating"].includes(candidate.status) && needsTriage(candidate.record)) blockers.push(`${candidate.fingerprint} has no validation priority (start a triager)`);
  }
  if (!ctx.state.findings_written_at) blockers.push("findings.json has not been written (findings write)");
  for (const proposal of ctx.state.proposals) if (proposal.status === "open") blockers.push(`proposal ${proposal.id} (${proposal.type}) is still open`);
  return blockers;
}

function cmdFinish(options) {
  return mutate(options, (ctx) => {
    const status = requireOption(options, "status", "complete|incomplete");
    if (status === "complete") {
      const blockers = completionBlockers(ctx);
      if (blockers.length > 0) throw new UserError("the run is not complete", blockers);
      ctx.metadata.run_status = "complete";
      delete ctx.metadata.incomplete_reason;
    } else if (status === "incomplete") {
      ctx.metadata.run_status = "incomplete";
      ctx.metadata.incomplete_reason = readReason(options);
    } else {
      throw new UserError("--status must be complete or incomplete");
    }
    raisePhase(ctx, 6);
    ctx.changed.add("metadata");
    event(ctx, "finish", `run_status ${status}${ctx.metadata.incomplete_reason ? ` (${ctx.metadata.incomplete_reason})` : ""}`);
    return [`run_status: ${status}`];
  });
}

function cmdReport(options) {
  const ctx = openRun(options);
  return withLock(ctx.P, () => {
    const fresh = openRun(options);
    writeReport(fresh);
    return [`Wrote ${fresh.P.html}`];
  });
}

// ---------------------------------------------------------------------------
// Status, show, brief, template
// ---------------------------------------------------------------------------

function countBy(items, key) {
  const counts = {};
  for (const item of items) counts[item[key]] = (counts[item[key]] || 0) + 1;
  return counts;
}

function formatCounts(counts) {
  const entries = Object.entries(counts);
  return entries.length ? entries.map(([key, count]) => `${key} ${count}`).join(", ") : "none";
}

function nextSteps(ctx) {
  const steps = [];
  const ledger = ctx.ledger || [];
  const running = ctx.state.agents.filter((agent) => agent.status === "running");
  const withErrors = running.filter((agent) => (agent.last_errors || []).length > 0);
  if (withErrors.length) steps.push(`Results rejected for ${withErrors.map((agent) => agent.id).join(", ")}: send the errors back to the same agent, or agent fail`);
  const waiting = running.filter((agent) => RESULT_ROLES.has(agent.role) && !(agent.last_errors || []).length);
  if (waiting.length) steps.push(`When ${waiting.map((agent) => agent.id).join(", ")} return: ingest --agent <id>`);
  const recon = running.filter((agent) => agent.role === "recon");
  if (recon.length) steps.push(`When reconnaissance agents ${recon.map((agent) => agent.id).join(", ")} return: agent finish --agent <id>`);
  if (!ctx.ledger && ctx.state.phase <= 1) steps.push("Seed the coverage ledger: units add --file <units record text>");
  const planned = ledger.filter((unit) => unit.status === "planned");
  if (planned.length) steps.push(`Assign or defer ${planned.length} planned unit(s): ${planned.slice(0, 12).map(alias).join(", ")}${planned.length > 12 ? ", ..." : ""}`);
  const open = ctx.state.proposals.filter((proposal) => proposal.status === "open");
  if (open.length) steps.push(`Decide ${open.length} open proposal(s): ${open.map((proposal) => proposal.id).join(", ")} (units add with from_proposal, units reassign, or proposal reject)`);
  const proposed = ctx.state.candidates.filter((candidate) => candidate.status === "proposed");
  const inProgress = ledger.filter((unit) => unit.status === "in_progress");
  if (proposed.length && !planned.length && !inProgress.length) steps.push(`Start a fresh verifier per proposed candidate: ${proposed.map((candidate) => candidate.fingerprint).join(", ")}`);
  const decided = ctx.state.candidates.filter((candidate) => ["validated", "verified", "replacement_pending", "final_review"].includes(candidate.status));
  if (decided.length && !ctx.state.findings_written_at && !proposed.length) steps.push("Write findings.json: findings write");
  if (ctx.state.findings_written_at && profile(ctx) !== "quick") {
    const awaiting = ctx.state.candidates.filter((candidate) => candidate.status === "validated" && candidate.verdict !== "rejected");
    if (awaiting.length) steps.push(`Start a fresh record-verifier per record: ${awaiting.map((candidate) => candidate.fingerprint).join(", ")}`);
  }
  const pendingReplacements = ctx.state.candidates.filter((candidate) => candidate.status === "replacement_pending");
  if (pendingReplacements.length) steps.push(`Material replacements need a fresh record-verifier (or record remove): ${pendingReplacements.map((candidate) => candidate.fingerprint).join(", ")}`);
  const untriaged = untriagedLeads(ctx).filter((candidate) => ["validated", "verified"].includes(candidate.status) && !candidate.triager);
  if (untriaged.length) steps.push(`${untriaged.length} needs_validation record(s) predate validation priorities: agent start --role triager --untriaged <n> (a few leads per triager)`);
  if (steps.length === 0 && ctx.metadata && ctx.metadata.run_status === "in_progress" && ctx.state.findings_written_at) steps.push("Write the Phase 6 reports, then: finish --status complete");
  return steps;
}

function cmdStatus(options) {
  const ctx = openRun(options);
  const meta = ctx.metadata || {};
  const ledger = ctx.ledger || [];
  const lines = [];
  lines.push(`Run ${meta.run_id} (${meta.repo}) — phase ${ctx.state.phase} — ${meta.run_status}${meta.incomplete_reason ? ` (${meta.incomplete_reason})` : ""} — profile ${meta.profile}`);
  const running = ctx.state.agents.filter((agent) => agent.status === "running");
  lines.push(`Agents: ${ctx.state.agents.length} started${Number.isInteger(meta.budget) ? ` of budget ${meta.budget}` : ""}; running: ${running.map((agent) => agent.id).join(", ") || "none"}`);
  lines.push(`Coverage (${ledger.length} unit(s)): ${formatCounts(countBy(ledger, "status"))}`);
  lines.push(`Candidates (${ctx.state.candidates.length}): ${formatCounts(countBy(ctx.state.candidates, "status"))}`);
  lines.push(`Findings: ${ctx.findings ? formatCounts(countBy(ctx.findings, "verdict")) : "not written yet"}`);
  const leads = ctx.state.candidates.filter((candidate) => candidate.record && candidate.record.verdict === "needs_validation" && !["removed", "duplicate"].includes(candidate.status));
  if (leads.length) {
    const priorities = countBy(leads.map((candidate) => ({ priority: (candidate.record.triage && candidate.record.triage.priority) || "untriaged" })), "priority");
    lines.push(`Validation priorities of ${leads.length} needs_validation lead(s): ${["P1", "P2", "P3", "P4", "untriaged"].filter((key) => priorities[key]).map((key) => `${key} ${priorities[key]}`).join(", ")}`);
  }
  const open = ctx.state.proposals.filter((proposal) => proposal.status === "open");
  lines.push(`Open proposals: ${open.length ? open.map((proposal) => `${proposal.id} ${proposal.type} from ${proposal.from_agent}`).join("; ") : "none"}`);
  if (ctx.ledger) {
    const errors = ledgerValidator.validateDocument(ctx.ledger);
    lines.push(`Ledger validator: ${errors.length ? `FAIL (${errors.length})` : "PASS"}`);
  }
  if (ctx.findings) {
    const errors = findingsValidator.validateDocument(ctx.findings, SCHEMA);
    lines.push(`Findings validator: ${errors.length ? `FAIL (${errors.length})` : "PASS"}`);
  }
  const steps = nextSteps(ctx);
  if (steps.length) lines.push("Next:", ...steps.map((step) => `  - ${step}`));
  lines.push(`Progress report: ${ctx.P.html}`);
  return lines;
}

function unitDisplay(unit) {
  const shown = clone(unit);
  return [`# ${alias(unit)} — ${unit.status}, wave ${unit.wave}`, ...RT.displayText(shown)];
}

/** A comment line naming a lead's derived validation priority, which templates hide. */
function priorityNote(record) {
  const triage = record && record.triage;
  if (!triage || !triage.priority) return [];
  return [`# validation priority ${triage.priority} (impact if confirmed: ${triage.potential_impact.score}; plausibility: ${triage.plausibility.score}) — not a severity`];
}

function cmdShow(options, positionals) {
  const ctx = openRun(options);
  const [kind, ref] = positionals;
  const asJson = Boolean(options.json);
  const emit = (value, display) => (asJson ? [JSON.stringify(value, null, 2)] : display());
  switch (kind) {
    case "unit": {
      const unit = requireUnit(ctx, ref);
      return emit(unit, () => unitDisplay(unit));
    }
    case "units": {
      const ledger = ensureLedger(ctx);
      return emit(ledger, () => ledger.map((unit) => `${alias(unit).padEnd(5)} ${unit.status.padEnd(14)} w${unit.wave} ${(unit.agent_id || "-").padEnd(14)} ${unit.surface} × ${unit.boundary} × ${unit.attack_class}${unit.lifecycle ? ` × ${unit.lifecycle}` : ""}`));
    }
    case "candidate": {
      const candidate = requireCandidate(ctx, ref);
      return emit(candidate, () => {
        const record = candidate.pending ? candidate.pending.record : candidate.record || (candidate.proposals[0] && candidate.proposals[0].record);
        return [`# ${candidate.fingerprint} — ${candidate.status}${candidate.verdict ? ` (${candidate.verdict})` : ""}; proposed by ${candidate.proposals.map((proposal) => proposal.agent_id).join(", ")}; linked units ${linkedUnits(ctx, candidate.fingerprint).map(alias).join(", ") || "none"}`, ...priorityNote(record), RT.serializeRecordText(record, RECORD_SPECS, "record").trimEnd()];
      });
    }
    case "finding": {
      const record = (ctx.findings || []).find((entry) => entry.fingerprint === ref);
      if (!record) throw new UserError(`findings.json has no record ${JSON.stringify(ref)}`);
      return emit(record, () => [...priorityNote(record), RT.serializeRecordText(record, RECORD_SPECS, "record").trimEnd()]);
    }
    case "agent": {
      const agent = requireAgent(ctx, ref);
      return emit(agent, () => RT.displayText(agent));
    }
    case "proposals": {
      return emit(ctx.state.proposals, () => ctx.state.proposals.map((proposal) => `${proposal.id.padEnd(4)} ${proposal.status.padEnd(9)} ${proposal.type.padEnd(12)} from ${proposal.from_agent}: ${proposal.type === "reassign" ? proposal.data.unit : `${proposal.data.surface} × ${proposal.data.boundary} × ${proposal.data.attack_class} — ${proposal.data.reason}`}${proposal.resolution ? ` [${proposal.resolution}]` : ""}`));
    }
    default:
      throw new UserError("show what? unit <U#> | units | candidate <fp> | finding <fp> | agent <id> | proposals");
  }
}

const RESULT_INSTRUCTIONS = (ctx, agent) => [
  "## Result file — write record text, never JSON",
  `Your result file is: ${ctx.P.result(agent.id)}`,
  "It already holds a template for your role. Fill it in; keep its sections.",
  "Record text rules:",
  "- `key: value` — the value runs to the end of the line. Never quote or escape it.",
  "- `key: <<<`, then the lines, then a line containing only `>>>` — text over several lines (code, payloads).",
  "- Repeat a key, or put `- item` lines under an empty `key:`, for list fields.",
  "- `[section]` starts a new item. Write an item's own fields before its sub-sections.",
  "- Lines starting with `#` are comments. Leave `key:` empty when a field does not apply; untouched template sections are ignored.",
  "- `key = null` or `key = \"\"` only when an exact empty or null value is required.",
  `When done, run: ${TOOL} check --run ${shellPath(ctx.run)} --agent ${agent.id}`,
  "Fix every reported line and run check again until it prints OK.",
  `Then reply with exactly one line: RESULT ${relativeResultPath(agent.id)}`,
  `Write nothing outside ${EXECUTING_ROLES.has(agent.role) ? "your scratch/ directory and " : ""}this result file. If you have no file-writing tool, reply with the record text only.`,
];

function cmdBrief(options) {
  const ctx = openRun(options);
  const agent = requireAgent(ctx, requireOption(options, "agent"));
  const lines = [];
  const ledger = ensureLedger(ctx);
  if (agent.role === "hunter") {
    lines.push(`## Assigned coverage units (${agent.id}, wave ${agent.wave})`);
    for (const coverageId of agent.units) {
      const unit = findUnit(ctx, coverageId);
      const view = { alias: alias(unit), coverage_id: unit.coverage_id, surface: unit.surface, boundary: unit.boundary, subsystem: unit.subsystem, attack_class: unit.attack_class };
      if (unit.lifecycle) view.lifecycle = unit.lifecycle;
      Object.assign(view, { starting_paths: unit.starting_paths, ordinary_attack_class_block: unit.ordinary_attack_class_block, selected_companion_blocks: unit.selected_companion_blocks, excluded_blocks: unit.excluded_blocks, prior_status: unit.prior_status });
      lines.push("", `[unit ${alias(unit)}]`, ...RT.displayText(view));
    }
    const exclusions = ctx.state.candidates.filter((candidate) => candidate.carried && candidate.carried.prior_status === "prior_confirmed_same_source");
    lines.push("", "## Carried same-source prior confirmed exclusions");
    if (exclusions.length === 0) lines.push("(none)");
    for (const candidate of exclusions) {
      const record = candidate.proposals.find((proposal) => proposal.source === "prior").record;
      lines.push(`- ${candidate.fingerprint} — ${record.title} — root cause: ${record.root_cause || record.claimed_root_cause}`);
    }
    const peers = ledger.filter((unit) => unit.agent_id && unit.agent_id !== agent.id && ["in_progress", "covered", "candidate", "blocked"].includes(unit.status));
    lines.push("", "## Peer-owned coverage IDs — do not duplicate");
    if (peers.length === 0) lines.push("(none)");
    for (const unit of peers) lines.push(`- ${alias(unit)} (${unit.agent_id}, ${unit.status}): ${unit.coverage_id}`);
  } else if (agent.role === "verifier" || agent.role === "record-verifier") {
    const candidate = requireCandidate(ctx, agent.fingerprints[0]);
    if (agent.role === "verifier") {
      const proposal = candidate.proposals[candidate.proposals.length - 1];
      lines.push(`## Candidate ${candidate.fingerprint} (proposed ${proposal.proposed_verdict} by ${candidate.proposals.map((entry) => entry.agent_id).join(", ")})`, RT.serializeRecordText(proposal.record, RECORD_SPECS, "record").trimEnd());
      if (candidate.carried) lines.push("", `## Prior record with the same fingerprint`, `Carried from ${candidate.carried.prior_path} (${candidate.carried.prior_status}); your source re-check is the first check of its unit.`);
      lines.push("", "## Linked coverage-unit checks and artifacts");
      for (const unit of linkedUnits(ctx, candidate.fingerprint)) {
        lines.push(`[unit ${alias(unit)}] ${unit.surface} × ${unit.boundary} × ${unit.attack_class} (${unit.status})`);
        for (const check of unit.local_checks) lines.push(`- ${check.agent_id} ${check.method}: ${check.invariant} → ${check.result}${check.artifact ? ` [artifact ${check.artifact}]` : ""}`);
      }
    } else {
      const record = candidate.pending ? candidate.pending.record : candidate.record;
      lines.push(`## Record to verify: ${candidate.fingerprint} (${record.verdict}${candidate.pending ? `, pending replacement proposed by ${candidate.pending.agent_id}` : ""})`, ...priorityNote(record), RT.serializeRecordText(record, RECORD_SPECS, "record").trimEnd());
    }
  } else if (agent.role === "triager") {
    lines.push("## Task", ...TRIAGE_GUIDE, "", `## Leads to triage (${agent.fingerprints.length})`);
    for (const fingerprint of agent.fingerprints) {
      const record = requireCandidate(ctx, fingerprint).record;
      lines.push("", `[lead ${fingerprint}]`, ...priorityNote(record), RT.serializeRecordText(record, RECORD_SPECS, "record").trimEnd());
    }
  } else if (agent.role === "critic" || agent.role === "final-critic") {
    lines.push(`## Coverage ledger (${ledger.length} units) with assignment block maps`);
    for (const unit of ledger) {
      lines.push("", `[unit ${alias(unit)}] ${unit.status}, wave ${unit.wave}, owner ${unit.agent_id || "-"}`);
      const view = { coverage_id: unit.coverage_id, surface: unit.surface, boundary: unit.boundary, subsystem: unit.subsystem, attack_class: unit.attack_class };
      if (unit.lifecycle) view.lifecycle = unit.lifecycle;
      Object.assign(view, { starting_paths: unit.starting_paths, ordinary_attack_class_block: unit.ordinary_attack_class_block, selected_companion_blocks: unit.selected_companion_blocks, excluded_blocks: unit.excluded_blocks, prior_status: unit.prior_status, reviewed_paths: unit.reviewed_paths, checks: unit.local_checks.map((check) => `${check.agent_id} ${check.method}: ${check.invariant}`), result_fingerprints: unit.result_fingerprints, unresolved: unit.unresolved, archived_attempts: (unit.attempts || []).length });
      lines.push(...RT.displayText(view));
    }
    lines.push("", "## Candidate fingerprints and states");
    if (ctx.state.candidates.length === 0) lines.push("(none)");
    for (const candidate of ctx.state.candidates) lines.push(`- ${candidate.fingerprint}: ${candidate.status}${candidate.verdict ? ` (${candidate.verdict})` : ""}`);
    const priorGaps = ledger.filter((unit) => !["none", "new"].includes(unit.prior_status));
    lines.push("", "## Prior-ledger gap summary");
    if (priorGaps.length === 0) lines.push("(no prior-run units)");
    for (const unit of priorGaps) lines.push(`- ${alias(unit)}: ${unit.prior_status} (${unit.status})`);
  } else {
    throw new UserError(`${agent.role} agents return prose to the parent; there is no brief`);
  }
  lines.push("", "## Paths", `Agent ID: ${agent.id}`);
  if (EXECUTING_ROLES.has(agent.role)) {
    lines.push(`Scratch (the only place you and sandboxed target code may write): ${path.join(ctx.P.agentDir(agent.id), "scratch")}${path.sep}`);
    lines.push(`Retained artifacts (parent-owned; cite as agents/${agent.id}/artifacts/<file>): ${path.join(ctx.P.agentDir(agent.id), "artifacts")}${path.sep}`);
    if (agent.promotion) lines.push(`Promotion allowlist: ${agent.promotion.allowlist.join(", ") || "(none)"}; per-file limit ${agent.promotion.max_file_bytes || "?"} bytes; cumulative limit ${agent.promotion.max_total_bytes || "?"} bytes`);
  }
  lines.push("", ...RESULT_INSTRUCTIONS(ctx, agent));
  return lines;
}

function hunterTemplate(ctx, agent) {
  const header = [
    `Hunter result for ${agent.id}. Record text — not JSON. Rules:`,
    "  key: value       the value runs to the end of the line; never quote or escape it",
    "  key: <<<         then lines, then a line with only >>>  (multi-line text)",
    "  repeat a list key, or write `- item` lines under an empty key:",
    "  [section]        starts a new item; untouched template sections are ignored",
    `Check: ${TOOL} check --run ${shellPath(ctx.run)} --agent ${agent.id}`,
    "",
  ];
  const out = [RT.serializeRecordText({}, { result: { fields: HUNTER_SPECS.result.fields, sections: {} } }, "result", { skeleton: true, header }).trimEnd()];
  for (const coverageId of agent.units) {
    const unit = findUnit(ctx, coverageId);
    out.push("", `# ---- ${alias(unit)}: ${unit.surface} × ${unit.boundary} × ${unit.attack_class}${unit.lifecycle ? ` × ${unit.lifecycle}` : ""}`);
    out.push(RT.serializeRecordText({ coverage_id: alias(unit) }, HUNTER_SPECS, "unit", { skeleton: true, onlyFields: null }).trimEnd().replace(/^/, "[unit]\n"));
  }
  out.push("", "# ---- Candidates: copy the whole [candidate] block (with its sub-sections) once per candidate.");
  out.push("# Fill only the fields for your proposed_verdict; leave the others empty.");
  out.push(`[candidate]\n${RT.serializeRecordText({}, HUNTER_SPECS, "candidate", { skeleton: true }).trimEnd()}`);
  out.push("", `[uncovered]\n${RT.serializeRecordText({}, HUNTER_SPECS, "uncovered", { skeleton: true }).trimEnd()}`);
  return `${out.join("\n")}\n`;
}

function verifierTemplate(ctx, agent, decision) {
  const candidate = findCandidate(ctx, agent.fingerprints[0]);
  const proposal = candidate.proposals[candidate.proposals.length - 1];
  const source = proposal ? proposal.record : {};
  const shaped = decision ? reshapeRecord(source, decision) : { ...source };
  if (!decision) delete shaped.verdict;
  const header = [
    `Candidate-verifier result for ${agent.id} (candidate ${candidate.fingerprint}). Record text — not JSON.`,
    "The [record] below starts as the candidate under review. Try to refute it; correct it into the final record.",
    "Fields allowed in a record depend on its verdict (see the comments). To reshape the record for another decision run:",
    `  ${TOOL} template --run ${shellPath(ctx.run)} --agent ${agent.id} --decision rejected --write --force`,
    `Check: ${TOOL} check --run ${shellPath(ctx.run)} --agent ${agent.id}`,
    "",
  ];
  const owned = linkedUnits(ctx, candidate.fingerprint).filter((unit) => unit.status === "in_progress" && unit.agent_id === agent.id);
  const value = { decision, record: shaped, checks: owned.map((unit) => ({ coverage_id: alias(unit) })) };
  return RT.serializeRecordText(value, VERIFIER_SPECS, "result", { skeleton: true, header, onlyFields: { record: recordFieldsFor(decision || source.verdict) } });
}

/** The record keys and [sections] that a verdict's schema branch allows. */
function recordFieldsFor(verdict) {
  const fields = RECORD_SPECS.record.fields;
  const allowed = new Set(Object.keys(fields).filter((key) => key === "verdict" || fields[key].verdicts.has(verdict)));
  for (const [name, childName] of Object.entries(RECORD_SPECS.record.sections)) {
    if (RECORD_SPECS[childName].verdicts.has(verdict)) allowed.add(`[${name}]`);
  }
  return allowed;
}

function recordVerifierTemplate(ctx, agent, decision) {
  const candidate = findCandidate(ctx, agent.fingerprints[0]);
  const underReview = candidate.pending ? candidate.pending.record : candidate.record;
  const header = [
    `Record-verifier result for ${agent.id} (record ${candidate.fingerprint}). Record text — not JSON.`,
    "decision verified: keep fingerprint, leave reason empty, no [record] section.",
    "decision replace: give reason and the complete replacement [record]. To get the record pre-filled run:",
    `  ${TOOL} template --run ${shellPath(ctx.run)} --agent ${agent.id} --decision replace --write --force`,
    `Check: ${TOOL} check --run ${shellPath(ctx.run)} --agent ${agent.id}`,
    "",
  ];
  if (decision === "replace") {
    return RT.serializeRecordText({ decision: "replace", record: clone(underReview) }, RECORD_VERIFIER_SPECS, "result", { skeleton: true, header, onlyFields: { result: new Set(["decision", "reason", "[record]"]), record: recordFieldsFor(underReview.verdict) } });
  }
  return RT.serializeRecordText({ fingerprint: candidate.fingerprint }, RECORD_VERIFIER_SPECS, "result", { skeleton: true, header, onlyFields: { result: new Set(["decision", "fingerprint", "reason"]) } });
}

function criticTemplate(ctx, agent) {
  const header = [
    `Coverage-critic result for ${agent.id}. Record text — not JSON. Propose coverage, not findings.`,
    `Check: ${TOOL} check --run ${shellPath(ctx.run)} --agent ${agent.id}`,
    "",
  ];
  return RT.serializeRecordText({}, CRITIC_SPECS, "result", { skeleton: true, header });
}

const TRIAGE_GUIDE = [
  "Give each needs_validation lead a validation priority. Do not change its verdict, trace, blockers, or plans, and never present the result as a severity.",
  "Read the cited source; do not run target code or contact any service. Score potential impact as if the claimed root cause holds, with the SKILL.md severity anchors, and name the affected principal or resource.",
  "Score plausibility by how strongly the visible source supports the vulnerable outcome, and name exactly what the blocker hides:",
  "  high: only the blocked fact stands between the visible source and the result",
  "  medium: the source points that way, but a plausible control may sit behind the blocker",
  "  low: the visible source leans against the result",
  "The tool derives the priority from the two scores:",
  "  impact critical: P1 (plausibility high or medium), P2 (low)",
  "  impact high:     P1 (high), P2 (medium), P3 (low)",
  "  impact medium:   P2 (high), P3 (medium or low)",
  "  impact low:      P3 (high), P4 (medium or low); informational: P4",
];

function triagerTemplate(ctx, agent) {
  const header = [
    `Triage result for ${agent.id}. Record text — not JSON. One [lead] per assigned record; fill in the four triage fields.`,
    ...TRIAGE_GUIDE,
    `Check: ${TOOL} check --run ${shellPath(ctx.run)} --agent ${agent.id}`,
    "",
  ];
  const leads = agent.fingerprints.map((fingerprint) => {
    const triage = (requireCandidate(ctx, fingerprint).record || {}).triage;
    return { fingerprint, ...(triage ? { triage: { potential_impact: triage.potential_impact, plausibility: triage.plausibility } } : {}) };
  });
  return RT.serializeRecordText({ leads }, TRIAGER_SPECS, "result", { skeleton: true, header });
}

function buildTemplate(ctx, agent, { decision } = {}) {
  switch (agent.role) {
    case "triager": return triagerTemplate(ctx, agent);
    case "hunter": return hunterTemplate(ctx, agent);
    case "verifier": return verifierTemplate(ctx, agent, decision);
    case "record-verifier": return recordVerifierTemplate(ctx, agent, decision);
    case "critic":
    case "final-critic": return criticTemplate(ctx, agent);
    default: throw new UserError(`${agent.role} agents have no result template`);
  }
}

function genericTemplate(kind) {
  switch (kind) {
    case "metadata": return RT.serializeRecordText({}, METADATA_SPECS, "root", { skeleton: true, onlyFields: { root: new Set(Object.keys(METADATA_SPECS.root.fields).filter((key) => !["run_status", "incomplete_reason"].includes(key))) }, header: ["run-metadata record text for: audit-state.cjs init --run <dir> --file <this file>", ""] });
    case "units": return RT.serializeRecordText({}, UNIT_SPECS, "root", { skeleton: true, header: ["Coverage units for: audit-state.cjs units add --run <dir> --file <this file>", "Copy the [unit] block (with its [excluded_block] sections) once per unit.", ""] });
    case "hunter": return `[unit]\n${RT.serializeRecordText({}, HUNTER_SPECS, "unit", { skeleton: true })}\n[candidate]\n${RT.serializeRecordText({}, HUNTER_SPECS, "candidate", { skeleton: true })}`;
    case "critic": return RT.serializeRecordText({}, CRITIC_SPECS, "result", { skeleton: true });
    case "verifier": return RT.serializeRecordText({}, VERIFIER_SPECS, "result", { skeleton: true });
    case "record-verifier": return RT.serializeRecordText({}, RECORD_VERIFIER_SPECS, "result", { skeleton: true });
    case "triager": return RT.serializeRecordText({}, TRIAGER_SPECS, "result", { skeleton: true, header: TRIAGE_GUIDE.concat([""]) });
    default: throw new UserError("template kinds: metadata | units | hunter | critic | verifier | record-verifier | triager (or --run <dir> --agent <id> for a pre-filled one)");
  }
}

function cmdTemplate(options, positionals) {
  if (!options.agent) return [genericTemplate(positionals[0]).trimEnd()];
  const ctx = openRun(options);
  const agent = requireAgent(ctx, options.agent);
  const decision = typeof options.decision === "string" ? options.decision : undefined;
  if (decision) {
    const allowed = agent.role === "verifier" ? ["confirmed", "needs_validation", "rejected"] : agent.role === "record-verifier" ? ["verified", "replace"] : [];
    if (!allowed.includes(decision)) throw new UserError(`--decision for a ${agent.role}: ${allowed.join(" | ") || "not supported"}`);
  }
  const text = buildTemplate(ctx, agent, { decision });
  if (!options.write) return [text.trimEnd()];
  const file = ctx.P.result(agent.id);
  if (fs.existsSync(file) && !options.force) throw new UserError(`${file} exists; pass --force to replace it with a fresh template`);
  const stat = fs.existsSync(file) ? fs.lstatSync(file) : null;
  if (stat && (stat.isSymbolicLink() || !stat.isFile())) throw new UserError(`refusing to overwrite ${file}: not a regular file`);
  writeAtomic(file, text);
  return [`Wrote a fresh template to ${file}`];
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const HELP = `audit-state.cjs — builds every JSON file of a full-audit run from record text

Parent (the only writer of shared run files):
  init           --run <dir> --file <metadata.txt>         create run-metadata.json
  metadata       --run <dir> --file <f> | --set key=value  update metadata facts
  units add      --run <dir> --file <units.txt> [--wave N] seed or add ledger units (IDs derived)
  units status   --run <dir> --units U1,U2 --to <status> --reason <text>
  units reassign --run <dir> --unit U3 --reason <text> [--defer <reason>]
  units note     --run <dir> --unit U3 --text <text>
  agent start    --run <dir> --agent <id> --role <role> [--units U1,U2 | --fingerprint <fp>] [--note <text>]
                 triager: --fingerprint <fp>,<fp>... | --untriaged <n>   adds validation priorities to needs_validation leads
                 roles: ${ROLES.join(", ")}
  agent finish   --run <dir> --agent <id>                  recon agents (prose results)
  agent fail     --run <dir> --agent <id> --reason <text>  release its units/candidates
  ingest         --run <dir> --agent <id> [--file <f>] [--new-root-cause]
  carry          --run <dir> --prior <findings.json> --fingerprint <fp> --unit U5
  candidate duplicate --run <dir> --fingerprint <fp> --of <fp> [--reason <text>]
  proposal reject     --run <dir> --proposal P3 --reason <text>
  record apply   --run <dir> --fingerprint <fp> --non-material --reason <text>
  record remove  --run <dir> --fingerprint <fp> --reason <text>
  findings write --run <dir>                               build and validate findings.json
  phase          --run <dir> --set <1-6>
  finish         --run <dir> --status complete|incomplete [--reason <text>]
  report         --run <dir>                               regenerate progress.html

Anyone (read-only):
  status         --run <dir>
  show           unit <U#> | units | candidate <fp> | finding <fp> | agent <id> | proposals  --run <dir> [--json]
  brief          --run <dir> --agent <id>                  prompt material for a delegated agent
  template       <kind> | --run <dir> --agent <id> [--decision <d>] [--write [--force]]

Delegated agents:
  check          --run <dir> --agent <id>                  validate your result file; prints OK or line errors

Text options also accept --reason-file / --text-file for text containing quotes.
`;

function dispatch(argv) {
  const { positionals, options } = parseArgs(argv);
  const [command, sub, ...rest] = positionals;
  if (!command || command === "help" || options.help) return [HELP.trimEnd()];
  switch (command) {
    case "init": return cmdInit(options);
    case "metadata": return cmdMetadata(options);
    case "units":
      if (sub === "add") return cmdUnitsAdd(options);
      if (sub === "status") return cmdUnitsStatus(options);
      if (sub === "reassign") return cmdUnitsReassign(options);
      if (sub === "note") return cmdUnitsNote(options);
      throw new UserError("units add | status | reassign | note");
    case "agent":
      if (sub === "start") return cmdAgentStart(options);
      if (sub === "finish") return cmdAgentFinish(options);
      if (sub === "fail") return cmdAgentFail(options);
      throw new UserError("agent start | finish | fail");
    case "ingest": return cmdIngest(options);
    case "check": return cmdCheck(options);
    case "carry": return cmdCarry(options);
    case "candidate":
      if (sub === "duplicate") return cmdCandidateDuplicate(options);
      throw new UserError("candidate duplicate");
    case "proposal":
      if (sub === "reject") return cmdProposalReject(options);
      throw new UserError("proposal reject");
    case "record":
      if (sub === "apply") return cmdRecordApply(options);
      if (sub === "remove") return cmdRecordRemove(options);
      throw new UserError("record apply | remove");
    case "findings":
      if (sub === "write") return cmdFindingsWrite(options);
      throw new UserError("findings write");
    case "phase": return cmdPhase(options);
    case "finish": return cmdFinish(options);
    case "report": return cmdReport(options);
    case "status": return cmdStatus(options);
    case "show": return cmdShow(options, [sub, ...rest]);
    case "brief": return cmdBrief(options);
    case "template": return cmdTemplate(options, [sub, ...rest]);
    default: throw new UserError(`unknown command ${JSON.stringify(command)}; run "help"`);
  }
}

function main(argv) {
  try {
    const lines = dispatch(argv);
    if (lines && lines.length) process.stdout.write(`${lines.join("\n")}\n`);
    return 0;
  } catch (error) {
    if (error instanceof UserError) {
      process.stderr.write(`ERROR: ${error.message}\n`);
      for (const detail of error.details.slice(0, 100)) process.stderr.write(`  ${detail}\n`);
      return 1;
    }
    process.stderr.write(`ERROR: unexpected failure: ${error && error.stack ? error.stack : error}\n`);
    return 2;
  }
}

module.exports = {
  HUNTER_SPECS,
  CRITIC_SPECS,
  VERIFIER_SPECS,
  RECORD_VERIFIER_SPECS,
  RECORD_SPECS,
  UNIT_SPECS,
  METADATA_SPECS,
  dispatch,
  main,
  materialChanges,
  reshapeRecord,
  UserError,
};

if (require.main === module) process.exit(main(process.argv.slice(2)));
