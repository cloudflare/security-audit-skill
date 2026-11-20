const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const RT = require("./record-text.cjs");
const state = require("./audit-state.cjs");
const ledgerValidator = require("./validate-coverage-ledger.cjs");
const findingsValidator = require("./validate-findings.cjs");
const schema = require("./report-schema.json");

const TOOL = path.join(__dirname, "audit-state.cjs");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sandbox() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "audit-state-"));
  const target = path.join(root, "target");
  fs.mkdirSync(target);
  return { root, target, run: path.join(root, "run"), file: (name, text) => {
    const file = path.join(root, name);
    fs.writeFileSync(file, text);
    return file;
  } };
}

function ok(args) {
  return state.dispatch(args).join("\n");
}

function fails(args, pattern) {
  let error = null;
  try {
    state.dispatch(args);
  } catch (caught) {
    error = caught;
  }
  assert.ok(error, `expected ${args.slice(0, 2).join(" ")} to fail`);
  assert.ok(error instanceof state.UserError, `unexpected error: ${error && error.stack}`);
  const text = [error.message, ...error.details].join("\n");
  if (pattern) assert.match(text, pattern);
  return text;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeResult(box, agent, text) {
  fs.writeFileSync(path.join(box.run, "agents", agent, "result.txt"), text);
}

function metadataText(box, extra = "") {
  return `run_id: run-1\nrepo: demo\ntarget: ${box.target}\nsource_ref.commit: abc123\nprofile: standard\nbudget: 30\n${extra}`;
}

const UNITS = `
[unit]
surface: Update-user route
boundary: Object ownership
subsystem: API
attack_class: Access control
canonical_refs.surface: src/router.ts#POST /users/:id
canonical_refs.boundary: src/authz.ts#requireOwner
canonical_refs.subsystem: packages/api
canonical_refs.attack_class: ATTACK-CLASSES.md#Access control
starting_paths: src/router.ts
ordinary_attack_class_block: ATTACK-CLASSES.md#Access control
[excluded_block]
block: WEB-PROTOCOL-AND-AUTH.md#Cache behavior
reason: The route is not cached.

[unit]
surface: Avatar upload
boundary: Upload confinement
subsystem: API
attack_class: Resource and file handling
ref.surface: src/upload.ts#POST /avatar
ref.boundary: src/upload.ts#safeJoin
ref.subsystem: packages/api
ref.attack_class: ATTACK-CLASSES.md#Resource and file handling
starting_paths:
  - src/upload.ts
`;

const CONFIRMED_CANDIDATE = `
[candidate]
proposed_verdict: confirmed
fingerprint: src-users-missing-owner-check
title: Any user can modify another user's profile
description: The update route never checks ownership.
root_cause: updateUser omits requireOwner.
intended_behavior: Only the owner can update a record.
execution.attacker_perspective: A normal authenticated user.
execution.payloads: <<<
PATCH /users/2
{"name": "a \\"quoted\\" value"}
>>>
execution.instructions: Log in as user 1.
execution.instructions: Send the payload for user 2.
execution.observed_result: User 2's record changed.
remediation.strategy: Call requireOwner before the write.
severity.likelihood.score: high
severity.likelihood.reason: Any account reaches the route.
severity.impact.score: medium
severity.impact.reason: One protected record changes.
severity.overall_severity: medium
confidence.score: high
confidence.reason: Reproduced locally.
[trace]
file: src/router.ts:42
scope: router.patch
description: Accepts the request.
[trace]
file: src/users.ts:88
scope: updateUser
description: Writes without the check.
[evidence]
file: src/users.ts:88
description: No ownership check.
[code_change]
file_name: src/users.ts
fixed_code: <<<
function updateUser(req) {
\trequireOwner(req);
}
>>>
`;

function hunterResult({ u1 = "candidate", candidate = CONFIRMED_CANDIDATE } = {}) {
  return `hardening: Cookie lacks SameSite=Strict; CSRF tokens cover state changes.
[unit]
coverage_id: U1
disposition: ${u1}
${u1 === "candidate" ? "candidate_fingerprints: src-users-missing-owner-check" : ""}
[check]
invariant: Only the owner can update a user.
method: source
reviewed_paths: src/router.ts
reviewed_paths: src/users.ts
result: updateUser never calls requireOwner.

[unit]
coverage_id: U2
disposition: covered
[check]
invariant: Upload paths stay inside the upload root.
method: source
reviewed_paths: src/upload.ts
result: safeJoin rejects traversal after normalization.
${u1 === "candidate" ? candidate : ""}`;
}

const LEAD_FINGERPRINT = "src-reset-token-unbound";

const LEAD_CANDIDATE = `
[candidate]
proposed_verdict: needs_validation
fingerprint: ${LEAD_FINGERPRINT}
title: Reset token may reset another user's password
description: The reset endpoint takes the user id from the request body.
claimed_root_cause: verifyToken does not compare the token subject with the submitted user id.
blockers: The token store is generated at deploy time and absent from the checkout.
validation_plan.local: Generate the token store fixture and submit user 1's token with user id 2.
triage.potential_impact.score: high
triage.potential_impact.reason: Any account could reset another user's password and take over that account.
triage.plausibility.score: medium
triage.plausibility.reason: verifyToken visibly checks only expiry; the generated store might still compare subjects.
[trace]
file: src/reset.ts:12
scope: POST /reset
description: Accepts the token and user id from the body.
[trace]
file: src/reset.ts:20
scope: setPassword
description: Writes the password for the body user id.
[evidence]
file: src/tokens.ts:30
description: No subject comparison.
`;

function leadHunterResult(candidate = LEAD_CANDIDATE) {
  return `[unit]
coverage_id: U1
disposition: candidate
candidate_fingerprints: ${LEAD_FINGERPRINT}
[check]
invariant: A reset token is bound to the user it was issued for.
method: source
reviewed_paths: src/reset.ts
result: verifyToken checks expiry only.

[unit]
coverage_id: U2
disposition: covered
[check]
invariant: Upload paths stay inside the upload root.
method: source
reviewed_paths: src/upload.ts
result: safeJoin rejects traversal after normalization.
${candidate}`;
}

/** Runs a needs_validation lead through hunting and Phase 3 and writes findings.json. */
function decidedLeadRun() {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1,U2"]);
  writeResult(box, "hunter-1", leadHunterResult());
  ok(["ingest", "--run", box.run, "--agent", "hunter-1"]);
  ok(["agent", "start", "--run", box.run, "--agent", "verifier-1", "--role", "verifier", "--fingerprint", LEAD_FINGERPRINT]);
  const file = path.join(box.run, "agents", "verifier-1", "result.txt");
  fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace(/^decision:$/m, "decision: needs_validation"));
  ok(["ingest", "--run", box.run, "--agent", "verifier-1"]);
  ok(["findings", "write", "--run", box.run]);
  return box;
}

function seededRun(extraMetadata = "") {
  const box = sandbox();
  ok(["init", "--run", box.run, "--file", box.file("meta.txt", metadataText(box, extraMetadata))]);
  ok(["units", "add", "--run", box.run, "--file", box.file("units.txt", UNITS)]);
  return box;
}

function validateRun(box) {
  const ledger = readJson(path.join(box.run, "coverage-ledger.json"));
  assert.deepEqual(ledgerValidator.validateDocument(ledger), []);
  const findingsPath = path.join(box.run, "findings.json");
  if (fs.existsSync(findingsPath)) assert.deepEqual(findingsValidator.validateDocument(readJson(findingsPath), schema), []);
  return ledger;
}

// ---------------------------------------------------------------------------
// Record text
// ---------------------------------------------------------------------------

const RECORD_SPECS = state.RECORD_SPECS;

test("record text reads blocks, lists, JSON values, fences, and comments", () => {
  const text = [
    "```text",
    "# a comment",
    "fingerprint: fp-1",
    "title: A title with \"quotes\", a # hash and a: colon",
    "description: <<<END",
    "line one",
    ">>>",
    "END",
    "execution.payloads = \"\\u0000nul\"",
    "execution.payloads = \"\"",
    "execution.instructions:",
    "- step one",
    "- step two",
    "blockers:",
    "[trace]",
    "file: src/a.c:7",
    "scope: f",
    "description: d",
    "```",
  ].join("\r\n");
  const parsed = RT.parseRecordText(text, RECORD_SPECS, "result" in RECORD_SPECS ? "result" : "record");
  assert.deepEqual(parsed.errors, []);
});

test("record text builds exact values for every verdict field", () => {
  const specs = { ...RECORD_SPECS, root: { fields: {}, sections: { record: "record" } } };
  const text = [
    "[record]",
    "fingerprint: fp-1",
    "title: Title \"quoted\" \\ backslash",
    "description: <<<",
    "first",
    "  indented",
    ">>>",
    "execution.payloads: <<<",
    "  leading spaces kept",
    "\ttab kept",
    ">>>",
    "execution.payloads = \"\\u0000\"",
    "execution.instructions:",
    "- one",
    "- two",
    "blockers:",
    "[trace]",
    "file: src/a.c:7",
    "scope: f",
    "description: d",
  ].join("\n");
  const parsed = RT.parseRecordText(text, specs, "root");
  assert.deepEqual(parsed.errors, []);
  RT.splitFileLines(parsed.value, specs, "root");
  const record = parsed.value.record;
  assert.equal(record.title, "Title \"quoted\" \\ backslash");
  assert.equal(record.description, "first\n  indented");
  assert.deepEqual(record.execution.payloads, ["  leading spaces kept\n\ttab kept", "\u0000"]);
  assert.deepEqual(record.execution.instructions, ["one", "two"]);
  assert.equal(record.blockers, undefined);
  assert.deepEqual(record.trace, [{ file: "src/a.c", line: 7, scope: "f", description: "d" }]);
});

test("record text reports unknown fields, duplicates, bad enums, and unclosed blocks by line", () => {
  const specs = { ...RECORD_SPECS, root: { fields: {}, sections: { record: "record" } } };
  const text = [
    "[record]",
    "titel: typo",
    "title: one",
    "title: two",
    "severity.impact.score: huge",
    "[nonsense]",
    "description: <<<",
    "never closed",
  ].join("\n");
  const { errors } = RT.parseRecordText(text, specs, "root");
  const byLine = Object.fromEntries(errors.map((error) => [error.line, error.message]));
  assert.match(byLine[2], /unknown field "titel".*did you mean "title"/);
  assert.match(byLine[4], /given twice/);
  assert.match(byLine[5], /expected one of informational \| low \| medium \| high \| critical/);
  assert.match(byLine[6], /unknown section \[nonsense\]/);
  assert.match(byLine[7], /never closed/);
});

test("record text rejects stray prose lines with guidance", () => {
  const specs = { ...RECORD_SPECS, root: { fields: {}, sections: { record: "record" } } };
  const { errors } = RT.parseRecordText("[record]\ntitle: x\nthis line continues the title\n", specs, "root");
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 3);
  assert.match(errors[0].message, /key: <<</);
});

test("serialized records parse back to identical JSON", () => {
  const specs = { ...RECORD_SPECS, root: { fields: {}, sections: { record: "record" } } };
  const tricky = [
    "",
    " leading space",
    "trailing space ",
    "multi\nline\n>>>\nwith terminator",
    "ends with newline\n",
    "\u202ebidi\u200b",
    "quotes \"and\" 'single'",
    "\ttab\tinside",
    "<<< looks like a block",
  ];
  const record = {
    verdict: "confirmed",
    fingerprint: "fp-1",
    title: "T",
    description: "multi\nline description",
    execution: { attacker_perspective: "A", payloads: tricky, instructions: ["x"], observed_result: "o" },
    remediation: { strategy: "s", code_changes: [{ file_name: "src/a.c", fixed_code: "a\n>>>\nb\n" }] },
    trace: [{ kind: "sink", file: "src/a.c", line: 3, scope: "f", description: "d" }],
  };
  const text = RT.serializeRecordText({ record }, specs, "root");
  const parsed = RT.parseRecordText(text, specs, "root");
  assert.deepEqual(parsed.errors, []);
  assert.deepEqual(parsed.value.record, record);
});

test("untouched template skeletons are ignored and every generic template parses", () => {
  for (const kind of ["metadata", "units", "critic", "verifier", "record-verifier"]) {
    const text = state.dispatch(["template", kind]).join("\n");
    const specs = { metadata: state.METADATA_SPECS, units: state.UNIT_SPECS, critic: state.CRITIC_SPECS, verifier: state.VERIFIER_SPECS, "record-verifier": state.RECORD_VERIFIER_SPECS }[kind];
    const root = kind === "metadata" || kind === "units" ? "root" : "result";
    const parsed = RT.parseRecordText(text, specs, root);
    assert.deepEqual(parsed.errors, [], kind);
    assert.deepEqual(parsed.value, {}, kind);
  }
});

// ---------------------------------------------------------------------------
// Run setup and ledger
// ---------------------------------------------------------------------------

test("init writes metadata with fixed policy fields and refuses an output directory inside the target", () => {
  const box = sandbox();
  ok(["init", "--run", box.run, "--file", box.file("meta.txt", metadataText(box))]);
  const metadata = readJson(path.join(box.run, "run-metadata.json"));
  assert.equal(metadata.execution_policy, "sandboxed-source-and-local-only");
  assert.equal(metadata.run_status, "in_progress");
  assert.equal(metadata.budget, 30);
  assert.deepEqual(metadata.source_ref, { commit: "abc123", dirty: false });
  assert.equal(metadata.shared_file_owners["findings.json"], "parent");
  assert.ok(fs.existsSync(path.join(box.run, "progress.html")));
  fails(["init", "--run", box.run, "--file", path.join(box.root, "meta.txt")], /already exists/);
  const inside = path.join(box.target, "audit");
  fails(["init", "--run", inside, "--file", path.join(box.root, "meta.txt")], /inside the target/);
});

test("units add derives canonical IDs, aliases, and defaults, and rejects duplicates", () => {
  const box = seededRun();
  const ledger = validateRun(box);
  assert.equal(ledger.length, 2);
  for (const unit of ledger) assert.equal(unit.coverage_id, ledgerValidator.canonicalCoverageId(unit.canonical_refs));
  const aliases = ledger.map((unit) => unit.bookkeeping.alias).sort();
  assert.deepEqual(aliases, ["U1", "U2"]);
  const first = ledger.find((unit) => unit.bookkeeping.alias === "U1");
  assert.equal(first.status, "planned");
  assert.equal(first.prior_status, "none");
  assert.equal(first.wave, 1);
  assert.deepEqual(first.excluded_blocks, [{ block: "WEB-PROTOCOL-AND-AUTH.md#Cache behavior", reason: "The route is not cached." }]);
  fails(["units", "add", "--run", box.run, "--file", path.join(box.root, "units.txt")], /already exists as U1/);
});

test("units add reports missing references by source line and writes nothing", () => {
  const box = seededRun();
  const before = fs.readFileSync(path.join(box.run, "coverage-ledger.json"), "utf8");
  const text = fails(["units", "add", "--run", box.run, "--file", box.file("bad.txt", "\n[unit]\nsurface: S\nboundary: B\nsubsystem: X\nattack_class: A\n")], /bad\.txt:2: \[unit\] is missing canonical_refs\.surface/);
  assert.match(text, /nothing was written/);
  assert.equal(fs.readFileSync(path.join(box.run, "coverage-ledger.json"), "utf8"), before);
});

// ---------------------------------------------------------------------------
// Agents and results
// ---------------------------------------------------------------------------

test("hunter results compile to the documented contract and update the ledger", () => {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1,U2"]);
  assert.ok(fs.existsSync(path.join(box.run, "agents", "hunter-1", "scratch")));
  assert.ok(fs.existsSync(path.join(box.run, "agents", "hunter-1", "artifacts")));
  const template = fs.readFileSync(path.join(box.run, "agents", "hunter-1", "result.txt"), "utf8");
  assert.match(template, /coverage_id: U1/);
  assert.match(template, /coverage_id: U2/);
  writeResult(box, "hunter-1", hunterResult());
  assert.match(ok(["check", "--run", box.run, "--agent", "hunter-1"]), /^OK/);
  ok(["ingest", "--run", box.run, "--agent", "hunter-1"]);
  const ledger = validateRun(box);
  const unit = ledger.find((entry) => entry.bookkeeping.alias === "U1");
  assert.equal(unit.status, "candidate");
  assert.equal(unit.agent_id, "hunter-1");
  assert.deepEqual(unit.reviewed_paths, ["src/router.ts", "src/users.ts"]);
  assert.deepEqual(unit.result_fingerprints, ["src-users-missing-owner-check"]);
  assert.equal(unit.local_checks[0].artifact, null);
  assert.equal(unit.bookkeeping.hardening[0].agent_id, "hunter-1");
  const compiled = readJson(path.join(box.run, "state", "results", "hunter-1.json"));
  assert.deepEqual(Object.keys(compiled), ["units", "candidates", "hardening", "uncovered"]);
  const candidate = compiled.candidates[0];
  assert.equal(candidate.proposed_verdict, "confirmed");
  assert.deepEqual(candidate.trace.map((step) => step.kind), ["entrypoint", "sink"]);
  assert.deepEqual(candidate.conditions, []);
  assert.equal(candidate.execution.payloads[0], "PATCH /users/2\n{\"name\": \"a \\\"quoted\\\" value\"}");
  assert.equal(candidate.remediation.code_changes[0].fixed_code, "function updateUser(req) {\n\trequireOwner(req);\n}");
});

test("check maps schema and contract errors to result-file lines without changing state", () => {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1,U2"]);
  const broken = hunterResult({ candidate: CONFIRMED_CANDIDATE.replace("severity.overall_severity: medium", "severity.overall_severity: high") })
    .replace("coverage_id: U2\ndisposition: covered", "coverage_id: U2");
  writeResult(box, "hunter-1", broken);
  const lines = broken.split("\n");
  const severityLine = lines.findIndex((line) => line.startsWith("severity.overall_severity")) + 1;
  const unitLine = lines.findIndex((line) => line === "coverage_id: U2") ;
  const text = fails(["check", "--run", box.run, "--agent", "hunter-1"], /problem\(s\)/);
  assert.match(text, new RegExp(`result\\.txt:${severityLine}: \\[candidate\\] src-users-missing-owner-check severity\\.overall_severity: cannot exceed demonstrated impact`));
  assert.match(text, new RegExp(`result\\.txt:${unitLine}: \\[unit\\] U2: disposition is required`));
  const before = fs.readFileSync(path.join(box.run, "coverage-ledger.json"), "utf8");
  fails(["ingest", "--run", box.run, "--agent", "hunter-1"], /Never edit an agent's result yourself/);
  assert.equal(fs.readFileSync(path.join(box.run, "coverage-ledger.json"), "utf8"), before);
  const saved = readJson(path.join(box.run, "state", "audit-state.json"));
  assert.ok(saved.agents[0].last_errors.length >= 2);
  assert.equal(saved.agents[0].status, "running");
});

test("hunter results must cover exactly the assigned units and link every candidate", () => {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1"]);
  writeResult(box, "hunter-1", hunterResult());
  fails(["check", "--run", box.run, "--agent", "hunter-1"], /U2: not assigned to hunter-1/);
  writeResult(box, "hunter-1", `[unit]\ncoverage_id: U1\ndisposition: covered\n[check]\ninvariant: i\nmethod: source\nreviewed_paths: src/router.ts\nresult: r\n${CONFIRMED_CANDIDATE}`);
  fails(["check", "--run", box.run, "--agent", "hunter-1"], /list this fingerprint in the candidate_fingerprints/);
});

test("local checks need a regular artifact under the check owner's artifacts directory", () => {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1"]);
  const result = (artifact) => `[unit]\ncoverage_id: U1\ndisposition: blocked\nunresolved: Deployment mount options are not in source.\n[check]\ninvariant: i\nmethod: local\nreviewed_paths: src/router.ts\nresult: r\nartifact: ${artifact}\n`;
  writeResult(box, "hunter-1", result("agents/hunter-1/artifacts/out.txt"));
  fails(["check", "--run", box.run, "--agent", "hunter-1"], /does not exist/);
  writeResult(box, "hunter-1", result("agents/hunter-1/scratch/out.txt"));
  fails(["check", "--run", box.run, "--agent", "hunter-1"], /must be below agents\/hunter-1\/artifacts\//);
  fs.writeFileSync(path.join(box.run, "agents", "hunter-1", "artifacts", "out.txt"), "observed\n");
  writeResult(box, "hunter-1", result("agents/hunter-1/artifacts/out.txt"));
  ok(["ingest", "--run", box.run, "--agent", "hunter-1"]);
  const unit = validateRun(box).find((entry) => entry.bookkeeping.alias === "U1");
  assert.equal(unit.status, "blocked");
  assert.equal(unit.local_checks[0].artifact, "agents/hunter-1/artifacts/out.txt");
});

test("agent IDs are canonical and unique, and a strict budget is enforced", () => {
  const box = seededRun();
  fails(["agent", "start", "--run", box.run, "--agent", "Hunter", "--role", "recon"], /must match/);
  fails(["agent", "start", "--run", box.run, "--agent", "con", "--role", "recon"], /Windows device name/);
  ok(["metadata", "--run", box.run, "--set", "budget=2"]);
  ok(["agent", "start", "--run", box.run, "--agent", "recon-1", "--role", "recon"]);
  fails(["agent", "start", "--run", box.run, "--agent", "recon-1", "--role", "recon"], /already used/);
  ok(["agent", "start", "--run", box.run, "--agent", "recon-2", "--role", "recon"]);
  fails(["agent", "start", "--run", box.run, "--agent", "recon-3", "--role", "recon"], /strict budget of 2/);
});

test("agent fail releases assignments for a fresh agent", () => {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1"]);
  ok(["agent", "fail", "--run", box.run, "--agent", "hunter-1", "--reason", "malformed result"]);
  const unit = validateRun(box).find((entry) => entry.bookkeeping.alias === "U1");
  assert.equal(unit.status, "planned");
  assert.equal(unit.agent_id, null);
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-2", "--role", "hunter", "--units", "U1"]);
});

test("critic proposals become units or reassignments with archived attempts", () => {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1,U2"]);
  writeResult(box, "hunter-1", hunterResult());
  ok(["ingest", "--run", box.run, "--agent", "hunter-1"]);
  ok(["agent", "start", "--run", box.run, "--agent", "critic-1", "--role", "critic"]);
  writeResult(box, "critic-1", "stop: true\nreassign_ids: U2\n");
  fails(["check", "--run", box.run, "--agent", "critic-1"], /stop: true is only allowed/);
  writeResult(box, "critic-1", "stop: false\nreassign_ids: U2\n[missing_unit]\nsurface: Reset\nboundary: Token binding\nsubsystem: API\nattack_class: Access control\nstarting_paths: src/reset.ts\nreason: No unit covers src/reset.ts.\n");
  ok(["ingest", "--run", box.run, "--agent", "critic-1"]);
  ok(["units", "add", "--run", box.run, "--file", box.file("more.txt", "[unit]\nfrom_proposal: P1\nsurface: Reset\nboundary: Token binding\nsubsystem: API\nattack_class: Access control\nref.surface: src/reset.ts#POST /reset\nref.boundary: src/reset.ts#verify\nref.subsystem: packages/api\nref.attack_class: ATTACK-CLASSES.md#Access control\nstarting_paths: src/reset.ts\n")]);
  ok(["units", "reassign", "--run", box.run, "--unit", "U2", "--reason", "The symlink-following open was not checked."]);
  const ledger = validateRun(box);
  const reassigned = ledger.find((entry) => entry.bookkeeping.alias === "U2");
  assert.equal(reassigned.status, "planned");
  assert.equal(reassigned.wave, 2);
  assert.equal(reassigned.attempts[0].agent_id, "hunter-1");
  assert.equal(reassigned.attempts[0].status, "covered");
  assert.equal(ledger.find((entry) => entry.bookkeeping.alias === "U3").wave, 2);
  const saved = readJson(path.join(box.run, "state", "audit-state.json"));
  assert.deepEqual(saved.proposals.map((proposal) => proposal.status), ["accepted", "accepted"]);
  fails(["agent", "start", "--run", box.run, "--agent", "hunter-1b", "--role", "hunter", "--units", "U1"], /only planned units/);
});

test("the complete workflow produces validator-clean files and blocks premature completion", () => {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1,U2"]);
  writeResult(box, "hunter-1", hunterResult());
  ok(["ingest", "--run", box.run, "--agent", "hunter-1"]);
  for (const id of ["critic-1", "critic-final"]) {
    ok(["agent", "start", "--run", box.run, "--agent", id, "--role", id === "critic-1" ? "critic" : "final-critic"]);
    writeResult(box, id, "stop: true\n");
    ok(["ingest", "--run", box.run, "--agent", id]);
  }
  fails(["finish", "--run", box.run, "--status", "complete"], /no independent Phase 3 decision/);
  ok(["agent", "start", "--run", box.run, "--agent", "verifier-1", "--role", "verifier", "--fingerprint", "src-users-missing-owner-check"]);
  fails(["agent", "start", "--run", box.run, "--agent", "hunter-1x", "--role", "verifier", "--fingerprint", "src-users-missing-owner-check"], /only proposed candidates/);
  const verifierFile = path.join(box.run, "agents", "verifier-1", "result.txt");
  fs.writeFileSync(verifierFile, fs.readFileSync(verifierFile, "utf8").replace(/^decision:$/m, "decision: confirmed"));
  ok(["ingest", "--run", box.run, "--agent", "verifier-1"]);
  ok(["findings", "write", "--run", box.run]);
  let findings = readJson(path.join(box.run, "findings.json"));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].verdict, "confirmed");
  assert.deepEqual(Object.keys(findings[0]), Object.keys(schema.items.oneOf[0].properties).filter((key) => key in findings[0]));
  fails(["finish", "--run", box.run, "--status", "complete"], /has not passed Phase 5/);

  ok(["agent", "start", "--run", box.run, "--agent", "rv-1", "--role", "record-verifier", "--fingerprint", "src-users-missing-owner-check"]);
  ok(["template", "--run", box.run, "--agent", "rv-1", "--decision", "replace", "--write", "--force"]);
  const rvFile = path.join(box.run, "agents", "rv-1", "result.txt");
  fs.writeFileSync(rvFile, fs.readFileSync(rvFile, "utf8")
    .replace(/^reason:$/m, "reason: The route also changes the role field.")
    .replace("severity.impact.score: medium", "severity.impact.score: high")
    .replace("severity.overall_severity: medium", "severity.overall_severity: high"));
  const ingest = ok(["ingest", "--run", box.run, "--agent", "rv-1"]);
  assert.match(ingest, /material replacement \(demonstrated impact changed; severity changed\)/);
  findings = readJson(path.join(box.run, "findings.json"));
  assert.equal(findings[0].severity.overall_severity, "medium", "a material replacement is not applied before fresh verification");
  fails(["agent", "start", "--run", box.run, "--agent", "rv-1b", "--role", "record-verifier", "--fingerprint", "nope"], /unknown candidate/);
  ok(["agent", "start", "--run", box.run, "--agent", "rv-2", "--role", "record-verifier", "--fingerprint", "src-users-missing-owner-check"]);
  assert.match(ok(["brief", "--run", box.run, "--agent", "rv-2"]), /pending replacement proposed by rv-1/);
  writeResult(box, "rv-2", "decision: verified\nfingerprint: src-users-missing-owner-check\n");
  ok(["ingest", "--run", box.run, "--agent", "rv-2"]);
  findings = readJson(path.join(box.run, "findings.json"));
  assert.equal(findings[0].severity.overall_severity, "high");
  ok(["finish", "--run", box.run, "--status", "complete"]);
  assert.equal(readJson(path.join(box.run, "run-metadata.json")).run_status, "complete");
  const ledger = validateRun(box);
  const decisions = ledger.find((entry) => entry.bookkeeping.alias === "U1").bookkeeping.decisions;
  assert.deepEqual(decisions.map((entry) => `${entry.phase}:${entry.decision}`), ["3:confirmed", "5:replace", "5:verified"]);
});

test("verifiers can reshape a record for another decision with a fresh template", () => {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1,U2"]);
  writeResult(box, "hunter-1", hunterResult());
  ok(["ingest", "--run", box.run, "--agent", "hunter-1"]);
  ok(["agent", "start", "--run", box.run, "--agent", "verifier-1", "--role", "verifier", "--fingerprint", "src-users-missing-owner-check"]);
  const file = path.join(box.run, "agents", "verifier-1", "result.txt");
  fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace(/^decision:$/m, "decision: rejected"));
  fails(["check", "--run", box.run, "--agent", "verifier-1"], /rejected finding must not contain "severity"/);
  ok(["template", "--run", box.run, "--agent", "verifier-1", "--decision", "rejected", "--write", "--force"]);
  const reshaped = fs.readFileSync(file, "utf8");
  assert.match(reshaped, /^claimed_root_cause: updateUser omits requireOwner\.$/m);
  assert.doesNotMatch(reshaped, /^severity/m);
  fs.writeFileSync(file, reshaped.replace(/^decision:$/m, "decision: rejected").replace(/^reason:$/m, "reason: The router applies requireOwner globally."));
  ok(["ingest", "--run", box.run, "--agent", "verifier-1"]);
  ok(["findings", "write", "--run", box.run]);
  const [record] = readJson(path.join(box.run, "findings.json"));
  assert.equal(record.verdict, "rejected");
  assert.equal(record.reason, "The router applies requireOwner globally.");
});

test("carried prior records go through a verifier who owns the seeded unit", () => {
  const prior = seededRun();
  ok(["agent", "start", "--run", prior.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1,U2"]);
  writeResult(prior, "hunter-1", hunterResult());
  ok(["ingest", "--run", prior.run, "--agent", "hunter-1"]);
  ok(["agent", "start", "--run", prior.run, "--agent", "verifier-1", "--role", "verifier", "--fingerprint", "src-users-missing-owner-check"]);
  const file = path.join(prior.run, "agents", "verifier-1", "result.txt");
  fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace(/^decision:$/m, "decision: confirmed"));
  ok(["ingest", "--run", prior.run, "--agent", "verifier-1"]);
  ok(["findings", "write", "--run", prior.run]);

  const box = sandbox();
  ok(["init", "--run", box.run, "--file", box.file("meta.txt", metadataText(box, `prior_runs: ${prior.run}\n`))]);
  ok(["units", "add", "--run", box.run, "--file", box.file("units.txt", UNITS.replace("starting_paths: src/router.ts", "starting_paths: src/router.ts\nprior_status: prior_confirmed_same_source"))]);
  const priorFindings = path.join(prior.run, "findings.json");
  fails(["carry", "--run", box.run, "--prior", priorFindings, "--fingerprint", "src-users-missing-owner-check", "--unit", "U2"], /prior_status prior_confirmed_same_source/);
  ok(["carry", "--run", box.run, "--prior", priorFindings, "--fingerprint", "src-users-missing-owner-check", "--unit", "U1"]);
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-2", "--role", "hunter", "--units", "U2"]);
  assert.match(ok(["brief", "--run", box.run, "--agent", "hunter-2"]), /src-users-missing-owner-check — Any user can modify/);
  ok(["agent", "start", "--run", box.run, "--agent", "verifier-2", "--role", "verifier", "--fingerprint", "src-users-missing-owner-check"]);
  let unit = readJson(path.join(box.run, "coverage-ledger.json")).find((entry) => entry.bookkeeping.alias === "U1");
  assert.equal(unit.status, "in_progress");
  assert.equal(unit.agent_id, "verifier-2");
  const verifierFile = path.join(box.run, "agents", "verifier-2", "result.txt");
  const template = fs.readFileSync(verifierFile, "utf8").replace(/^decision:$/m, "decision: confirmed");
  fs.writeFileSync(verifierFile, template);
  fails(["check", "--run", box.run, "--agent", "verifier-2"], /unit U1 \[check\]: invariant is required/);
  fs.writeFileSync(verifierFile, template.replace(/^coverage_id: U1$/m, "coverage_id:"));
  fails(["check", "--run", box.run, "--agent", "verifier-2"], /carries a prior record and is yours: add a \[check\]/);
  fs.writeFileSync(verifierFile, template
    .replace(/^invariant:$/m, "invariant: Only the owner can update a user.")
    .replace(/^method:$/m, "method: source")
    .replace(/^reviewed_paths:$/m, "reviewed_paths: src/users.ts")
    .replace(/^result:$/m, "result: Current source still omits requireOwner."));
  ok(["ingest", "--run", box.run, "--agent", "verifier-2"]);
  unit = validateRun(box).find((entry) => entry.bookkeeping.alias === "U1");
  assert.equal(unit.status, "candidate");
  assert.equal(unit.agent_id, "verifier-2");
  assert.deepEqual(unit.result_fingerprints, ["src-users-missing-owner-check"]);
  assert.equal(unit.local_checks[0].agent_id, "verifier-2");
});

test("the quick profile treats the candidate verifier's decision as final", () => {
  const box = sandbox();
  ok(["init", "--run", box.run, "--file", box.file("meta.txt", metadataText(box).replace("profile: standard", "profile: quick"))]);
  ok(["units", "add", "--run", box.run, "--file", box.file("units.txt", UNITS)]);
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1,U2"]);
  writeResult(box, "hunter-1", hunterResult());
  ok(["ingest", "--run", box.run, "--agent", "hunter-1"]);
  ok(["agent", "start", "--run", box.run, "--agent", "critic-1", "--role", "critic"]);
  writeResult(box, "critic-1", "stop: true\n");
  ok(["ingest", "--run", box.run, "--agent", "critic-1"]);
  ok(["agent", "start", "--run", box.run, "--agent", "verifier-1", "--role", "verifier", "--fingerprint", "src-users-missing-owner-check"]);
  const file = path.join(box.run, "agents", "verifier-1", "result.txt");
  fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace(/^decision:$/m, "decision: confirmed"));
  ok(["ingest", "--run", box.run, "--agent", "verifier-1"]);
  fails(["agent", "start", "--run", box.run, "--agent", "rv-1", "--role", "record-verifier", "--fingerprint", "src-users-missing-owner-check"], /quick profile merges Phase 5/);
  ok(["findings", "write", "--run", box.run]);
  ok(["finish", "--run", box.run, "--status", "complete"]);
});

// ---------------------------------------------------------------------------
// Validation priority (triage) for needs_validation leads
// ---------------------------------------------------------------------------

test("the tool derives a lead's validation priority and replaces any authored value", () => {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1,U2"]);
  const template = fs.readFileSync(path.join(box.run, "agents", "hunter-1", "result.txt"), "utf8");
  assert.match(template, /^triage\.potential_impact\.score:$/m);
  assert.doesNotMatch(template, /^triage\.priority/m, "the derived priority is never offered for authoring");
  writeResult(box, "hunter-1", leadHunterResult(LEAD_CANDIDATE.replace("[trace]", "triage.priority: P4\n[trace]")));
  ok(["ingest", "--run", box.run, "--agent", "hunter-1"]);
  const [proposal] = readJson(path.join(box.run, "state", "results", "hunter-1.json")).candidates;
  assert.equal(proposal.triage.priority, "P2");
  assert.deepEqual(Object.keys(proposal.triage), ["potential_impact", "plausibility", "priority"]);
});

test("a missing triage score is reported on its own line without a derived-priority error", () => {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1,U2"]);
  const text = leadHunterResult(LEAD_CANDIDATE.replace("triage.plausibility.score: medium\n", ""));
  writeResult(box, "hunter-1", text);
  const output = fails(["check", "--run", box.run, "--agent", "hunter-1"]);
  const reasonLine = text.split("\n").findIndex((line) => line.startsWith("triage.plausibility.reason")) + 1;
  assert.match(output, new RegExp(`result\\.txt:${reasonLine}: \\[candidate\\] ${LEAD_FINGERPRINT} triage\\.plausibility: missing required field "score"`));
  assert.doesNotMatch(output, /"priority"/);
});

test("decided leads keep their priority in findings.json, status, and progress.html", () => {
  const box = decidedLeadRun();
  const [record] = validateRunFindings(box);
  assert.equal(record.verdict, "needs_validation");
  assert.equal(record.triage.priority, "P2");
  assert.match(ok(["status", "--run", box.run]), /Validation priorities of 1 needs_validation lead\(s\): P2 1/);
  assert.match(ok(["show", "finding", LEAD_FINGERPRINT, "--run", box.run]), /# validation priority P2 \(impact if confirmed: high; plausibility: medium\) — not a severity/);
  const html = fs.readFileSync(path.join(box.run, "progress.html"), "utf8");
  assert.match(html, /data-status="needs_validation P2"/);
  assert.match(html, /class="pill pri-P2"/);
  assert.match(html, /if confirmed: high/);
  assert.match(html, /data-value="P2">P2 1</);
});

function validateRunFindings(box) {
  validateRun(box);
  return readJson(path.join(box.run, "findings.json"));
}

/** Rewrites a run's files as a run from before triage existed would have left them. */
function stripTriage(box) {
  const statePath = path.join(box.run, "state", "audit-state.json");
  const saved = readJson(statePath);
  for (const candidate of saved.candidates) if (candidate.record) delete candidate.record.triage;
  fs.writeFileSync(statePath, JSON.stringify(saved, null, 2));
  const findingsPath = path.join(box.run, "findings.json");
  const findings = readJson(findingsPath);
  for (const record of findings) delete record.triage;
  fs.writeFileSync(findingsPath, JSON.stringify(findings, null, 2));
}

test("a triager backfills validation priorities for a run that predates them", () => {
  const box = decidedLeadRun();
  stripTriage(box);
  fails(["findings", "write", "--run", box.run], /have no validation priority yet/);
  assert.match(ok(["status", "--run", box.run]), /untriaged 1/);
  fails(["agent", "start", "--run", box.run, "--agent", "triager-0", "--role", "triager", "--fingerprint", "src-users-missing-owner-check"], /unknown candidate/);
  ok(["agent", "start", "--run", box.run, "--agent", "triager-1", "--role", "triager", "--untriaged", "5"]);
  fails(["agent", "start", "--run", box.run, "--agent", "triager-2", "--role", "triager", "--untriaged", "5"], /no untriaged needs_validation record is waiting/);
  assert.match(ok(["brief", "--run", box.run, "--agent", "triager-1"]), new RegExp(`\\[lead ${LEAD_FINGERPRINT}\\][\\s\\S]*claimed_root_cause: verifyToken`));
  const file = path.join(box.run, "agents", "triager-1", "result.txt");
  const template = fs.readFileSync(file, "utf8");
  assert.match(template, new RegExp(`^fingerprint: ${LEAD_FINGERPRINT}$`, "m"));
  fs.writeFileSync(file, template
    .replace(/^triage\.potential_impact\.score:$/m, "triage.potential_impact.score: critical")
    .replace(/^triage\.potential_impact\.reason:$/m, "triage.potential_impact.reason: Unauthenticated takeover of any account through the public reset route.")
    .replace(/^triage\.plausibility\.score:$/m, "triage.plausibility.score: high")
    .replace(/^triage\.plausibility\.reason:$/m, "triage.plausibility.reason: Only the generated store's comparison is unseen; every visible step uses the body user id."));
  const output = ok(["ingest", "--run", box.run, "--agent", "triager-1"]);
  assert.match(output, new RegExp(`${LEAD_FINGERPRINT}: P1`));
  const [record] = validateRunFindings(box);
  assert.equal(record.triage.priority, "P1");
  assert.equal(record.claimed_root_cause, "verifyToken does not compare the token subject with the submitted user id.", "triage never changes the lead itself");
});

test("an untriaged lead from an older run still carries, and its verifier adds the priority", () => {
  const prior = decidedLeadRun();
  stripTriage(prior);
  const box = sandbox();
  ok(["init", "--run", box.run, "--file", box.file("meta.txt", metadataText(box, `prior_runs: ${prior.run}\n`))]);
  ok(["units", "add", "--run", box.run, "--file", box.file("units.txt", UNITS.replace("starting_paths: src/router.ts", "starting_paths: src/router.ts\nprior_status: prior_needs_validation"))]);
  ok(["carry", "--run", box.run, "--prior", path.join(prior.run, "findings.json"), "--fingerprint", LEAD_FINGERPRINT, "--unit", "U1"]);
  ok(["agent", "start", "--run", box.run, "--agent", "verifier-2", "--role", "verifier", "--fingerprint", LEAD_FINGERPRINT]);
  const file = path.join(box.run, "agents", "verifier-2", "result.txt");
  const filled = fs.readFileSync(file, "utf8")
    .replace(/^decision:$/m, "decision: needs_validation")
    .replace(/^invariant:$/m, "invariant: A reset token is bound to its user.")
    .replace(/^method:$/m, "method: source")
    .replace(/^reviewed_paths:$/m, "reviewed_paths: src/reset.ts")
    .replace(/^result:$/m, "result: Current source still checks expiry only.");
  fs.writeFileSync(file, filled);
  fails(["check", "--run", box.run, "--agent", "verifier-2"], /\[record\]: missing required field "triage"/);
  fs.writeFileSync(file, filled
    .replace(/^triage\.potential_impact\.score:$/m, "triage.potential_impact.score: high")
    .replace(/^triage\.potential_impact\.reason:$/m, "triage.potential_impact.reason: Another user's password could be reset.")
    .replace(/^triage\.plausibility\.score:$/m, "triage.plausibility.score: low")
    .replace(/^triage\.plausibility\.reason:$/m, "triage.plausibility.reason: tokens.ts appears to sign the subject into the token."));
  ok(["ingest", "--run", box.run, "--agent", "verifier-2"]);
  ok(["findings", "write", "--run", box.run]);
  assert.equal(validateRunFindings(box)[0].triage.priority, "P3");
});

// ---------------------------------------------------------------------------
// Progress report
// ---------------------------------------------------------------------------

test("progress.html escapes agent-supplied text and pins its only script and style by hash", () => {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1,U2"]);
  const hostile = CONFIRMED_CANDIDATE.replace("title: Any user can modify another user's profile", "title: <script>alert(1)</script><img src=x onerror=alert(2)> \u202eevil");
  writeResult(box, "hunter-1", hunterResult({ candidate: hostile }));
  ok(["ingest", "--run", box.run, "--agent", "hunter-1"]);
  fs.writeFileSync(path.join(box.run, "architecture.md"), "# Arch\n\n<script>alert(3)</script> and [x](javascript:alert(4))\n");
  ok(["report", "--run", box.run]);
  const html = fs.readFileSync(path.join(box.run, "progress.html"), "utf8");
  assert.equal((html.match(/<script>/g) || []).length, 1, "only the page's own script");
  assert.doesNotMatch(html, /<img src=x/);
  assert.doesNotMatch(html, /href="javascript:/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /U\+202E/);
  assert.doesNotMatch(html, /\u202e/);
  const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)[1];
  assert.match(csp, /default-src 'none'; style-src 'sha256-[^']+'; script-src 'sha256-[^']+'/);
  const crypto = require("node:crypto");
  const script = /<script>([\s\S]*?)<\/script>/.exec(html)[1];
  const style = /<style>([\s\S]*?)<\/style>/.exec(html)[1];
  assert.ok(csp.includes(`'sha256-${crypto.createHash("sha256").update(script).digest("base64")}'`));
  assert.ok(csp.includes(`'sha256-${crypto.createHash("sha256").update(style).digest("base64")}'`));
  for (const id of ["overview", "knowledge", "coverage", "candidates", "findings", "agents", "gaps", "activity"]) assert.match(html, new RegExp(`<section id="${id}"`));
});

test("progress.html renders runs that predate the tool from their JSON files alone", () => {
  const { renderProgressHtml } = require("./progress-report.cjs");
  const html = renderProgressHtml({ metadata: { run_id: "old", repo: "r", run_status: "complete" }, ledger: [], findings: [], state: null, events: [], architecture: null, files: {}, generatedAt: new Date().toISOString() });
  assert.match(html, /<section id="findings"/);
  assert.doesNotMatch(html, /<section id="agents"/);
});

test("the CLI prints line errors on stderr and exits non-zero", () => {
  const box = seededRun();
  ok(["agent", "start", "--run", box.run, "--agent", "hunter-1", "--role", "hunter", "--units", "U1"]);
  writeResult(box, "hunter-1", "[unit]\ncoverage_id: U1\ndisposition: maybe\n");
  const result = spawnSync(process.execPath, [TOOL, "check", "--run", box.run, "--agent", "hunter-1"], { encoding: "utf8", timeout: 10000 });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /result\.txt:3: disposition: expected one of covered \| candidate \| blocked/);
  const help = spawnSync(process.execPath, [TOOL, "help"], { encoding: "utf8", timeout: 10000 });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /units add/);
});
