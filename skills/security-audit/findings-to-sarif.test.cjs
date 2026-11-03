const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { validateDocument } = require("./validate-findings.cjs");
const schema = require("./report-schema.json");
const { toSarif } = require("./findings-to-sarif.cjs");

const converterPath = path.join(__dirname, "findings-to-sarif.cjs");

function step(kind, file, line) {
  return { kind, file, line, scope: "handle", description: "Attacker data reaches the operation." };
}

function confirmed({ fingerprint = "src-handler-missing-check", title = "Missing ownership check", overall = "medium" } = {}) {
  return {
    verdict: "confirmed",
    fingerprint,
    title,
    description: "An attacker can reach an operation without the intended ownership check.",
    root_cause: "handle omits the ownership check before changing the object.",
    intended_behavior: "Only the object's owner can change it.",
    trace: [step("entrypoint", "src/handler.c", 10), step("propagation", "src/model.c", 20), step("sink", "src/store.c", 30)],
    evidence: [{ file: "src/handler.c", line: 10, description: "The source performs the operation without the required check." }],
    conditions: [],
    execution: {
      attacker_perspective: "An unprivileged remote user with their own account.",
      payloads: ["An object identifier owned by another user."],
      instructions: ["Submit the identifier through the public operation."],
      observed_result: "The other user's object changes.",
    },
    remediation: { strategy: "Check ownership before the state change." },
    severity: {
      likelihood: { score: overall, reason: "The operation is directly reachable." },
      impact: { score: overall, reason: "The attacker changes one protected object." },
      overall_severity: overall,
    },
    confidence: { score: "high", reason: "The source path and result were reproduced." },
  };
}

function needsValidation() {
  return {
    verdict: "needs_validation",
    fingerprint: "src-parser-size-hypothesis",
    title: "Unchecked parsed size",
    description: "A parsed size may reach an allocation without a limit.",
    claimed_root_cause: "parse_size may pass an unbounded value to allocate.",
    trace: [step("entrypoint", "src/parser.c", 5)],
    evidence: [{ file: "src/parser.c", line: 5, description: "The size is read from the request." }],
    blockers: ["The generated parser source is absent from this checkout."],
    validation_plan: {
      local: "Generate the parser and submit the smallest input that exceeds the documented limit.",
      deployment: "In an approved test deployment, confirm the request reaches the generated parser.",
    },
  };
}

function rejected() {
  return {
    verdict: "rejected",
    fingerprint: "src-auth-bypass-candidate",
    title: "Session check bypass",
    description: "A candidate claimed the session check could be skipped.",
    claimed_root_cause: "login skips the session check for some routes.",
    trace: [step("entrypoint", "src/auth.c", 7)],
    evidence: [{ file: "src/auth.c", line: 7, description: "Every route passes through the session check." }],
    reason: "The session check runs before the router for every route.",
  };
}

function ruleOf(run, result) {
  assert.equal(run.tool.driver.rules[result.ruleIndex].id, result.ruleId);
  return run.tool.driver.rules[result.ruleIndex];
}

test("the fixtures are schema-valid findings", () => {
  const findings = [
    confirmed({ fingerprint: "a", overall: "high" }),
    confirmed({ fingerprint: "b", overall: "low" }),
    needsValidation(),
    rejected(),
  ].sort((x, y) => (x.fingerprint < y.fingerprint ? -1 : 1));
  assert.deepEqual(validateDocument(findings, schema), []);
});

test("findings with the same title and different severities get their own rules, in either order", () => {
  const high = confirmed({ fingerprint: "src-a", overall: "high" });
  const low = confirmed({ fingerprint: "src-b", overall: "low" });

  for (const findings of [[high, low], [low, high]]) {
    const run = toSarif(findings).sarif.runs[0];
    assert.equal(run.tool.driver.rules.length, 2);
    const byFingerprint = new Map(run.results.map((r) => [r.partialFingerprints["findingFingerprint/v1"], r]));

    const highResult = byFingerprint.get("src-a");
    assert.equal(highResult.level, "error");
    assert.equal(ruleOf(run, highResult).properties["security-severity"], "7.5");

    const lowResult = byFingerprint.get("src-b");
    assert.equal(lowResult.level, "note");
    assert.equal(ruleOf(run, lowResult).properties["security-severity"], "2.5");

    assert.notEqual(highResult.ruleId, lowResult.ruleId);
  }
});

test("titles that slugify to the same ID do not share a rule", () => {
  const first = confirmed({ fingerprint: "src-a", title: "SQL injection!" });
  const second = confirmed({ fingerprint: "src-b", title: "SQL Injection?" });
  const run = toSarif([first, second]).sarif.runs[0];

  assert.equal(run.tool.driver.rules.length, 2);
  assert.notEqual(run.results[0].ruleId, run.results[1].ruleId);
  assert.equal(ruleOf(run, run.results[0]).shortDescription.text, "SQL injection!");
  assert.equal(ruleOf(run, run.results[1]).shortDescription.text, "SQL Injection?");
});

test("findings with the same title and severity share one rule", () => {
  const run = toSarif([confirmed({ fingerprint: "src-a" }), confirmed({ fingerprint: "src-b" })]).sarif.runs[0];

  assert.equal(run.tool.driver.rules.length, 1);
  assert.equal(run.results.length, 2);
  assert.equal(run.results[0].ruleIndex, 0);
  assert.equal(run.results[1].ruleIndex, 0);
});

test("only confirmed findings become results; the other verdicts are counted", () => {
  const { sarif, skipped } = toSarif([confirmed(), needsValidation(), rejected(), { verdict: "unknown" }]);
  const run = sarif.runs[0];

  assert.equal(run.results.length, 1);
  assert.deepEqual(run.properties, { confirmedFindings: 1, needsValidationFindings: 1, rejectedFindings: 1 });
  assert.equal(skipped, 1);
});

test("the trace becomes a codeFlow, the sink is the location, and the fingerprint comes from the finding", () => {
  const finding = confirmed({ fingerprint: "src-store-write" });
  const result = toSarif([finding]).sarif.runs[0].results[0];

  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "src/store.c");
  assert.equal(result.locations[0].physicalLocation.region.startLine, 30);
  assert.deepEqual(
    result.codeFlows[0].threadFlows[0].locations.map((l) => l.location.physicalLocation.artifactLocation.uri),
    ["src/handler.c", "src/model.c", "src/store.c"],
  );
  assert.equal(result.partialFingerprints["findingFingerprint/v1"], "src-store-write");

  // Rescoring a finding does not change its fingerprint.
  const rescored = toSarif([confirmed({ fingerprint: "src-store-write", overall: "critical" })]).sarif.runs[0].results[0];
  assert.deepEqual(rescored.partialFingerprints, result.partialFingerprints);
});

test("the CLI writes SARIF to the output path and fails on invalid JSON", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "findings-to-sarif-"));
  try {
    const input = path.join(dir, "findings.json");
    const output = path.join(dir, "findings.sarif");
    fs.writeFileSync(input, JSON.stringify([confirmed(), rejected()]));

    const ok = spawnSync(process.execPath, [converterPath, input, output], { encoding: "utf8", timeout: 5000 });
    assert.equal(ok.status, 0, ok.stderr);
    const sarif = JSON.parse(fs.readFileSync(output, "utf8"));
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0].automationDetails.id, "security-audit/findings.json");
    assert.equal(sarif.runs[0].results.length, 1);

    fs.writeFileSync(input, "{not json");
    const bad = spawnSync(process.execPath, [converterPath, input, output], { encoding: "utf8", timeout: 5000 });
    assert.equal(bad.status, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
