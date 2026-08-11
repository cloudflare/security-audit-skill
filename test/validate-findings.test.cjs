const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { mkdtempSync, rmSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");
const { describe, test } = require("node:test");

const validator = path.join(__dirname, "..", "skills", "security-audit", "validate-findings.cjs");

function confirmedFinding(line) {
  const traceStep = (kind, scope) => ({
    kind,
    file: "src/app.js",
    line,
    scope,
    description: `${kind} description`,
  });

  return {
    verdict: "confirmed",
    title: "Example finding",
    description: "Example description",
    root_cause: "handler in src/app.js does not validate input, allowing unauthorized access",
    intended_behavior: "The handler rejects unauthorized access.",
    trace: [traceStep("entrypoint", "handler"), traceStep("sink", "readSecret")],
    conditions: [],
    execution: {
      attacker_perspective: "An unauthenticated remote user.",
      payloads: ["GET /secret"],
      instructions: ["Send the request."],
      expected_result: "The response contains the secret.",
    },
    remediation: { strategy: "Validate authorization before reading the secret." },
    severity: {
      likelihood: { score: "high", reason: "The endpoint is public." },
      impact: { score: "high", reason: "The response exposes a secret." },
      overall_severity: "high",
    },
    confidence: { score: "high", reason: "The trace was reproduced." },
  };
}

function validateLine(line) {
  const directory = mkdtempSync(path.join(tmpdir(), "security-audit-validator-"));
  const findingsPath = path.join(directory, "findings.json");
  writeFileSync(findingsPath, JSON.stringify([confirmedFinding(line)]));

  try {
    return spawnSync(process.execPath, [validator, findingsPath], { encoding: "utf8" });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe("trace line validation", () => {
  test("accepts positive source lines", () => {
    const result = validateLine(1);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /PASS: 1 findings valid/);
  });

  test("rejects line zero", () => {
    const result = validateLine(0);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /line: must be >= 1, got 0/);
  });

  test("rejects negative source lines", () => {
    const result = validateLine(-1);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /line: must be >= 1, got -1/);
  });
});
