const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const {
  INCOMPLETE_REASONS,
  LIMITS,
  hasVisibleProse,
  isSafeRelativePath,
  preflightJsonText,
  validateDocument,
} = require("./validate-run-metadata.cjs");
const { canonicalCoverageId } = require("./validate-coverage-ledger.cjs");

const validatorPath = path.join(__dirname, "validate-run-metadata.cjs");
const CLI_TIMEOUT_MS = 5000;
const HAS_SAFE_INPUT_OPEN = Number.isInteger(fs.constants.O_NOFOLLOW) &&
  fs.constants.O_NOFOLLOW !== 0 &&
  Number.isInteger(fs.constants.O_NONBLOCK) &&
  fs.constants.O_NONBLOCK !== 0;
const TERMINAL_CONTROL_PAYLOAD = "\u001b\u0007\u0085\u202e";
const TERMINAL_CONTROL_BYTES = [
  Buffer.from([0x1b]),
  Buffer.from([0x07]),
  Buffer.from("\u0085"),
  Buffer.from("\u202e"),
];

function metadata(overrides = {}) {
  return {
    run_id: "run-1",
    repo: "example",
    target: "/tmp/example",
    source_ref: "HEAD",
    profile: "standard",
    scope_paths: [],
    budget: null,
    execution_policy: "sandboxed-source-and-local-only",
    run_status: "in_progress",
    ...overrides,
  };
}

function candidateUnit(fingerprint = "src-router-missing-owner-check") {
  const canonicalRefs = {
    surface: "src/router.ts#POST /users/:id",
    boundary: "src/authz.ts#requireOwner",
    subsystem: "packages/api",
    attack_class: "ATTACK-CLASSES.md#Access control",
  };
  return {
    coverage_id: canonicalCoverageId(canonicalRefs),
    canonical_refs: canonicalRefs,
    surface: "Update-user route",
    boundary: "Object ownership",
    subsystem: "API",
    attack_class: "Access control",
    starting_paths: ["src/router.ts", "src/authz.ts"],
    ordinary_attack_class_block: "ATTACK-CLASSES.md#Access control",
    selected_companion_blocks: [],
    excluded_blocks: [{ block: "WEB-PROTOCOL-AND-AUTH.md#Cache behavior", reason: "The route is not cached." }],
    prior_status: "new",
    attempts: [],
    wave: 1,
    status: "candidate",
    agent_id: "hunter-1",
    reviewed_paths: ["src/router.ts"],
    local_checks: [{
      agent_id: "hunter-1",
      reviewed_paths: ["src/router.ts"],
      invariant: "The route checks object ownership.",
      method: "source",
      result: "The owner check is missing.",
      artifact: null,
    }],
    result_fingerprints: [fingerprint],
    unresolved: ["validation_budget_exhausted"],
  };
}

function errorsFor(value, options) {
  return validateDocument(value, options);
}

function runCli(files, options = {}) {
  const { timeout = CLI_TIMEOUT_MS } = options;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "validate-run-metadata-"));
  try {
    for (const [name, contents] of Object.entries(files)) {
      fs.writeFileSync(path.join(directory, name), contents);
    }
    return spawnSync(process.execPath, [validatorPath, path.join(directory, "run-metadata.json")], {
      encoding: "utf8",
      timeout,
    });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

function cliOutput(result) {
  return `${result.stdout}${result.stderr}`;
}

function assertNoInjectedControlBytes(output) {
  const bytes = Buffer.isBuffer(output) ? output : Buffer.from(output, "utf8");
  for (const marker of TERMINAL_CONTROL_BYTES) {
    assert.equal(bytes.indexOf(marker), -1, `found raw control bytes ${marker.toString("hex")}`);
  }
}

test("accepts in_progress, complete, and documented incomplete reasons", () => {
  assert.deepEqual(errorsFor(metadata()), []);
  assert.deepEqual(errorsFor(metadata({ run_status: "complete" })), []);
  assert.deepEqual(errorsFor(metadata({
    profile: "quick",
    run_status: "complete",
    scope_paths: ["src/router.ts"],
  })), []);
  for (const reason of INCOMPLETE_REASONS) {
    assert.deepEqual(errorsFor(metadata({
      run_status: "incomplete",
      incomplete_reason: reason,
    })), [], reason);
  }
});

test("rejects missing required fields and invalid enums", () => {
  const missing = metadata();
  delete missing.run_id;
  assert(errorsFor(missing).some((error) => error.includes('missing required field "run_id"')));

  assert(errorsFor(metadata({ profile: "Quick" })).some((error) => error.includes("$.profile")));
  assert(errorsFor(metadata({ run_status: "InProgress" })).some((error) => error.includes("$.run_status")));
  assert(errorsFor(metadata({ execution_policy: "source-only" })).some((error) => error.includes("$.execution_policy")));
  assert(errorsFor(metadata({ budget: 0 })).some((error) => error.includes("$.budget")));
  assert(errorsFor(metadata({ budget: 1.5 })).some((error) => error.includes("$.budget")));
  assert(errorsFor(metadata({ scope_paths: ["/etc/passwd"] })).some((error) => error.includes("repository-relative path")));
  assert.deepEqual(errorsFor([]), ["$: expected a top-level object"]);
});

test("requires an exact incomplete_reason only for incomplete runs", () => {
  assert(errorsFor(metadata({ run_status: "incomplete" }))
    .some((error) => error.includes("required when run_status is \"incomplete\"")));
  assert(errorsFor(metadata({
    run_status: "incomplete",
    incomplete_reason: "validation budget exhausted ",
  })).some((error) => error.includes("incomplete_reason")));
  assert(errorsFor(metadata({
    run_status: "complete",
    incomplete_reason: "validation_budget_exhausted",
  })).some((error) => error.includes("allowed only when run_status is \"incomplete\"")));
  assert(errorsFor(metadata({
    run_status: "in_progress",
    incomplete_reason: "critic_budget_exhausted",
  })).some((error) => error.includes("allowed only when run_status is \"incomplete\"")));
});

test("complete cross-check rejects candidate fingerprints missing from findings", () => {
  const fingerprint = "src-router-missing-owner-check";
  const ledger = [candidateUnit(fingerprint)];
  const complete = metadata({ run_status: "complete" });

  const missing = errorsFor(complete, { ledger, findings: [] });
  assert(missing.some((error) => error.includes("absent from findings.json")));
  assert(missing.some((error) => error.includes(fingerprint)));

  assert.deepEqual(errorsFor(complete, {
    ledger,
    findings: [{ fingerprint }],
  }), []);

  assert(errorsFor(complete, { completeRequiresLedger: true })
    .some((error) => error.includes("requires sibling coverage-ledger.json")));
});

test("in_progress metadata does not require sibling ledger cross-check", () => {
  const ledger = [candidateUnit()];
  assert.deepEqual(errorsFor(metadata(), { ledger, findings: [], completeRequiresLedger: true }), []);
});

test("accepts a complete run with matching findings through the CLI", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  const fingerprint = "src-router-missing-owner-check";
  const result = runCli({
    "run-metadata.json": JSON.stringify(metadata({ run_status: "complete" })),
    "coverage-ledger.json": JSON.stringify([candidateUnit(fingerprint)]),
    "findings.json": JSON.stringify([{ fingerprint }]),
  });
  assert.equal(result.status, 0, cliOutput(result));
  assert.match(result.stdout, /PASS: run metadata valid/);
});

test("CLI rejects the complete-with-unvalidated-candidate case", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  const result = runCli({
    "run-metadata.json": JSON.stringify(metadata({ run_status: "complete" })),
    "coverage-ledger.json": JSON.stringify([candidateUnit()]),
  });
  const output = cliOutput(result);
  assert.equal(result.status, 1, output);
  assert.match(output, /absent from findings.json/);
  assert.match(output, /FAIL: 1 validation error/);
});

test("CLI rejects complete metadata when the coverage ledger sibling is missing", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  const result = runCli({
    "run-metadata.json": JSON.stringify(metadata({ run_status: "complete" })),
  });
  const output = cliOutput(result);
  assert.equal(result.status, 1, output);
  assert.match(output, /requires sibling coverage-ledger.json/);
});

test("CLI accepts in_progress metadata without siblings", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  const result = runCli({
    "run-metadata.json": JSON.stringify(metadata()),
  });
  assert.equal(result.status, 0, cliOutput(result));
  assert.match(result.stdout, /PASS: run metadata valid/);
});

test("quotes input-derived controls in validation errors", () => {
  const output = errorsFor(metadata({
    run_status: `invalid-${TERMINAL_CONTROL_PAYLOAD}`,
  })).join("\n");
  assert.match(output, /\$\.run_status/);
  assert.match(output, /\\u001b/);
  assert.match(output, /\\u0007/);
  assert.match(output, /\\u0085/);
  assert.match(output, /\\u202e/);
  assertNoInjectedControlBytes(output);
});

test("quotes input-derived controls in CLI validation errors", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  const result = runCli({
    "run-metadata.json": JSON.stringify(metadata({
      run_status: `invalid-${TERMINAL_CONTROL_PAYLOAD}`,
    })),
  });
  assert.equal(result.status, 1, cliOutput(result));
  assert.match(result.stderr, /\$\.run_status/);
  assert.match(result.stderr, /\\u001b/);
  assertNoInjectedControlBytes(result.stderr);
});

test("does not reflect controls from a failed CLI input path", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "validate-run-metadata-path-"));
  const missingPath = path.join(directory, `missing-${TERMINAL_CONTROL_PAYLOAD}.json`);
  try {
    const result = spawnSync(process.execPath, [validatorPath, missingPath], {
      encoding: "utf8",
      timeout: CLI_TIMEOUT_MS,
    });
    assert.equal(result.status, 1, cliOutput(result));
    assert.match(result.stderr, /Failed to read run metadata:/);
    assertNoInjectedControlBytes(result.stderr);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("CLI rejects invalid UTF-8 without an exception trace", { skip: !HAS_SAFE_INPUT_OPEN }, () => {
  const encoded = Buffer.from(JSON.stringify(metadata()));
  const marker = Buffer.from("example");
  const markerOffset = encoded.indexOf(marker);
  assert.notEqual(markerOffset, -1);
  const malformed = Buffer.concat([
    encoded.subarray(0, markerOffset),
    Buffer.from([0x80]),
    encoded.subarray(markerOffset + marker.length),
  ]);
  const result = runCli({ "run-metadata.json": malformed });
  const output = cliOutput(result);
  assert.equal(result.status, 1, output);
  assert.match(output, /input is not valid UTF-8/);
  assert.doesNotMatch(output, /TypeError|stack|at validate-run-metadata/i);
});

test("CLI rejects a FIFO without blocking", { skip: process.platform === "win32" || !HAS_SAFE_INPUT_OPEN }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "validate-run-metadata-fifo-"));
  const fifoPath = path.join(directory, "run-metadata.json");
  try {
    const created = spawnSync("mkfifo", [fifoPath], { encoding: "utf8", timeout: CLI_TIMEOUT_MS });
    assert.equal(created.status, 0, cliOutput(created));
    const result = spawnSync(process.execPath, [validatorPath, fifoPath], {
      encoding: "utf8",
      timeout: CLI_TIMEOUT_MS,
    });
    const output = cliOutput(result);
    assert.notEqual(result.error && result.error.code, "ETIMEDOUT", output);
    assert.equal(result.status, 1, output);
    assert.match(output, /input must be a regular file/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("CLI rejects a symlink without following it", { skip: process.platform === "win32" || !HAS_SAFE_INPUT_OPEN }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "validate-run-metadata-symlink-"));
  const targetPath = path.join(directory, "target.json");
  const symlinkPath = path.join(directory, "run-metadata.json");
  try {
    fs.writeFileSync(targetPath, JSON.stringify(metadata()));
    fs.symlinkSync(targetPath, symlinkPath);
    const result = spawnSync(process.execPath, [validatorPath, symlinkPath], {
      encoding: "utf8",
      timeout: CLI_TIMEOUT_MS,
    });
    const output = cliOutput(result);
    assert.notEqual(result.error && result.error.code, "ETIMEDOUT", output);
    assert.equal(result.status, 1, output);
    assert.match(output, /input must not be a symlink/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("text preflight enforces nesting depth", () => {
  const depthLimit = LIMITS.nestingDepth;
  assert.doesNotThrow(() => preflightJsonText(`${"[".repeat(depthLimit)}0${"]".repeat(depthLimit)}`));
  assert.throws(
    () => preflightJsonText(`${"[".repeat(depthLimit + 1)}0${"]".repeat(depthLimit + 1)}`),
    /exceeds nesting depth limit 64/,
  );
});

test("keeps shared helpers aligned with the other validators", () => {
  const findingsModule = require("./validate-findings.cjs");
  const ledgerModule = require("./validate-coverage-ledger.cjs");
  const metadataModule = require("./validate-run-metadata.cjs");

  for (const name of [
    "VISIBLE_CONTENT",
    "PATH_FORBIDDEN_CHARACTER",
    "WINDOWS_RESERVED_COMPONENT",
    "UNSAFE_DIAGNOSTIC_CHARACTER",
  ]) {
    assert.equal(metadataModule[name].source, ledgerModule[name].source, `${name} source vs ledger`);
    assert.equal(metadataModule[name].source, findingsModule[name].source, `${name} source vs findings`);
  }
  for (const key of ["inputBytes", "nestingDepth", "validationErrors"]) {
    assert.equal(metadataModule.LIMITS[key], ledgerModule.LIMITS[key], `LIMITS.${key}`);
  }
  assert.equal(isSafeRelativePath("src/handler.js"), ledgerModule.isSafeRelativePath("src/handler.js"));
  assert.equal(hasVisibleProse("Valid prose."), findingsModule.hasVisibleProse("Valid prose."));
});
