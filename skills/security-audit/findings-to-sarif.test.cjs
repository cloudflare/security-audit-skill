const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { FINGERPRINT_KEY, SECURITY_SEVERITY, toSarif } = require("./findings-to-sarif.cjs");

const converterPath = path.join(__dirname, "findings-to-sarif.cjs");
const idPath = path.join(__dirname, "coverage-id.cjs");

function step(kind, file = "src/handler.c", line = 10) {
  return { kind, file, line, scope: "handle", description: "Attacker data reaches the operation." };
}

function confirmed(overrides = {}) {
  return {
    verdict: "confirmed",
    fingerprint: "src-handler-missing-check",
    title: "Missing ownership check",
    description: "An attacker can reach an operation without the intended ownership check.",
    root_cause: "handle omits the ownership check before changing the object.",
    intended_behavior: "Only the object's owner can change it.",
    trace: [step("entrypoint"), step("propagation", "src/model dir/m.c", 20), step("sink", "src/store.c", 30)],
    evidence: [{ file: "src/handler.c", line: 10, description: "No ownership check precedes the change." }],
    conditions: [],
    execution: {
      attacker_perspective: "An unprivileged remote user with their own account.",
      payloads: ["An object identifier owned by another user."],
      instructions: ["Submit the identifier through the public operation."],
      observed_result: "The other user's object changes.",
    },
    remediation: { strategy: "Check ownership before the state change." },
    severity: {
      likelihood: { score: "medium", reason: "The operation is directly reachable." },
      impact: { score: "medium", reason: "The attacker changes one protected object." },
      overall_severity: "medium",
    },
    confidence: { score: "high", reason: "The source path and result were reproduced." },
    ...overrides,
  };
}

function needsValidation() {
  return {
    verdict: "needs_validation",
    fingerprint: "src-parser-size-hypothesis",
    title: "Unchecked parsed size",
    description: "A parsed size may reach an allocation without a limit.",
    claimed_root_cause: "parse_size may pass an unbounded value to allocate.",
    trace: [step("entrypoint")],
    evidence: [{ file: "src/handler.c", line: 10, description: "Size flows to allocate." }],
    blockers: ["The generated parser source is absent from this checkout."],
    validation_plan: { local: "Generate the parser and submit the smallest input that exceeds the documented limit." },
  };
}

function rejected() {
  return {
    verdict: "rejected",
    fingerprint: "src-router-auth-bypass",
    title: "Authorization bypass in router",
    description: "The candidate claimed a route bypassed authorization.",
    claimed_root_cause: "dispatch was claimed to skip the authorization wrapper.",
    trace: [step("sink")],
    evidence: [{ file: "src/handler.c", line: 10, description: "Wrapper is applied." }],
    reason: "All routes pass through the authorization wrapper before dispatch.",
  };
}

function withFile(contents, fn) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "sarif-test-"));
  try {
    const file = path.join(directory, "findings.json");
    fs.writeFileSync(file, typeof contents === "string" ? contents : JSON.stringify(contents));
    return fn(file, directory);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test("exports confirmed records only by default", () => {
  const sarif = toSarif([confirmed(), needsValidation(), rejected()]);
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0];
  assert.deepEqual(run.results.map((r) => r.ruleId), ["src-handler-missing-check"]);
  assert.equal(run.tool.driver.rules.length, 1);
});

test("maps severity to level and GitHub security-severity", () => {
  for (const [severity, level] of [["critical", "error"], ["high", "error"], ["medium", "warning"], ["low", "note"], ["informational", "note"]]) {
    const record = confirmed({ severity: { ...confirmed().severity, overall_severity: severity } });
    const result = toSarif([record]).runs[0].results[0];
    assert.equal(result.level, level);
    assert.equal(result.properties["security-severity"], SECURITY_SEVERITY[severity]);
  }
});

test("primary location is the sink and the trace becomes a code flow in order", () => {
  const result = toSarif([confirmed()]).runs[0].results[0];
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "src/store.c");
  assert.equal(result.locations[0].physicalLocation.region.startLine, 30);
  const flow = result.codeFlows[0].threadFlows[0].locations;
  assert.deepEqual(flow.map((item) => item.location.message.text.split(":")[0]), ["entrypoint", "propagation", "sink"]);
});

test("paths are percent-encoded as URI references and carry the fingerprint", () => {
  const result = toSarif([confirmed()]).runs[0].results[0];
  const uris = result.codeFlows[0].threadFlows[0].locations.map((item) => item.location.physicalLocation.artifactLocation.uri);
  assert.ok(uris.includes("src/model%20dir/m.c"));
  assert.equal(result.partialFingerprints[FINGERPRINT_KEY], "src-handler-missing-check");
});

test("needs_validation is opt-in, level note, and never carries severity", () => {
  const run = toSarif([confirmed(), needsValidation()], { includeNeedsValidation: true }).runs[0];
  const lead = run.results.find((r) => r.ruleId === "src-parser-size-hypothesis");
  assert.equal(lead.level, "note");
  assert.equal(lead.properties.verdict, "needs_validation");
  assert.equal("security-severity" in lead.properties, false);
  assert.equal("security-severity" in run.tool.driver.rules.find((r) => r.id === lead.ruleId).properties, false);
  assert.match(lead.message.text, /not a confirmed vulnerability/);
});

test("output is deterministic regardless of input order", () => {
  const a = confirmed({ fingerprint: "a-first" });
  const b = confirmed({ fingerprint: "b-second" });
  assert.deepEqual(toSarif([b, a]), toSarif([a, b]));
});

test("CLI refuses findings that fail validation", () => {
  withFile([{ verdict: "confirmed" }], (file) => {
    const result = spawnSync(process.execPath, [converterPath, file], { encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Refusing to export/);
    assert.equal(result.stdout, "");
  });
});

test("CLI writes valid SARIF to stdout and refuses to overwrite --output", () => {
  withFile([confirmed(), needsValidation(), rejected()], (file, directory) => {
    const stdout = spawnSync(process.execPath, [converterPath, file], { encoding: "utf8" });
    assert.equal(stdout.status, 0);
    assert.equal(JSON.parse(stdout.stdout).runs[0].results.length, 1);

    const out = path.join(directory, "out.sarif");
    const first = spawnSync(process.execPath, [converterPath, file, "--output", out, "--include-needs-validation"], { encoding: "utf8" });
    assert.equal(first.status, 0);
    assert.equal(JSON.parse(fs.readFileSync(out, "utf8")).runs[0].results.length, 2);

    const second = spawnSync(process.execPath, [converterPath, file, "--output", out], { encoding: "utf8" });
    assert.equal(second.status, 1);
    assert.match(second.stderr, /already exists/);
  });
});

test("CLI does not follow a symlinked output path", { skip: process.platform === "win32" }, () => {
  withFile([confirmed()], (file, directory) => {
    const target = path.join(directory, "victim.txt");
    fs.writeFileSync(target, "keep");
    const link = path.join(directory, "link.sarif");
    fs.symlinkSync(target, link);
    const result = spawnSync(process.execPath, [converterPath, file, "--output", link], { encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.equal(fs.readFileSync(target, "utf8"), "keep");
  });
});

test("CLI rejects unknown options and missing input", () => {
  assert.equal(spawnSync(process.execPath, [converterPath], { encoding: "utf8" }).status, 1);
  assert.equal(spawnSync(process.execPath, [converterPath, "x.json", "--bogus"], { encoding: "utf8" }).status, 1);
});

const REFS = {
  surface: "src/router.ts#POST /users/:id",
  boundary: "src/authz.ts#requireOwner",
  subsystem: "packages/api",
  attack_class: "ATTACK-CLASSES.md#Access control",
};

test("coverage-id derives the percent-encoded ID and supports lifecycle", () => {
  const out = spawnSync(process.execPath, [idPath, JSON.stringify(REFS)], { encoding: "utf8" });
  assert.equal(out.status, 0);
  assert.equal(
    out.stdout.trim(),
    "src%2Frouter.ts%23POST%20%2Fusers%2F%3Aid::src%2Fauthz.ts%23requireOwner::packages%2Fapi::ATTACK-CLASSES.md%23Access%20control",
  );
  const withLifecycle = spawnSync(process.execPath, [idPath, JSON.stringify({ ...REFS, lifecycle: "restore" })], { encoding: "utf8" });
  assert.ok(withLifecycle.stdout.trim().endsWith("::restore"));
});

test("coverage-id rejects missing fields, unexpected fields, and unsafe references", () => {
  for (const bad of [{ surface: "a" }, { ...REFS, extra: "x" }, { ...REFS, surface: " padded" }, { ...REFS, surface: "a\u0007b" }, { ...REFS, surface: "e\u0301" }]) {
    const out = spawnSync(process.execPath, [idPath, JSON.stringify(bad)], { encoding: "utf8" });
    assert.equal(out.status, 1, JSON.stringify(bad));
  }
  assert.equal(spawnSync(process.execPath, [idPath, "not json"], { encoding: "utf8" }).status, 1);
});

test("coverage-id agrees with the ledger validator for the same references", () => {
  const { canonicalCoverageId } = require("./validate-coverage-ledger.cjs");
  const out = spawnSync(process.execPath, [idPath, "-"], { encoding: "utf8", input: JSON.stringify(REFS) });
  assert.equal(out.stdout.trim(), canonicalCoverageId(REFS));
});
