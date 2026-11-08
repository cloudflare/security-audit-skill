#!/usr/bin/env node

/**
 * Converts a validated findings.json into SARIF 2.1.0 so results can be loaded
 * into GitHub code scanning, VS Code SARIF viewers, and other SARIF consumers.
 *
 * Usage:
 *   node findings-to-sarif.cjs <findings.json> [--output <file.sarif>]
 *                              [--include-needs-validation]
 *
 * Contract:
 * - The input must pass validate-findings.cjs. Invalid input is refused.
 * - `confirmed` records become results with severity-derived levels.
 * - `needs_validation` records are omitted unless --include-needs-validation is
 *   given. When included they are always level "note", carry no severity, and
 *   are tagged so they cannot be mistaken for confirmed vulnerabilities.
 * - `rejected` records are never exported.
 * - Output is written with exclusive creation and never follows or overwrites
 *   an existing path. Without --output the SARIF goes to stdout.
 * - Zero dependencies; the parent agent runs this after Phase 5 passes.
 */

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION = "2.1.0";
const TOOL_NAME = "security-audit-skill";
const TOOL_URI = "https://github.com/cloudflare/security-audit-skill";
const FINGERPRINT_KEY = "securityAuditFingerprint/v1";

// GitHub maps `security-severity` (CVSS-like 0.0-10.0) onto its severity bands:
// >=9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
const SECURITY_SEVERITY = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  informational: "0.5",
};

const LEVEL = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  informational: "note",
};

function artifactLocation(file) {
  // Schema-validated repository-relative path; SARIF wants a URI reference.
  const uri = file.split("/").map(encodeURIComponent).join("/");
  return { uri, uriBaseId: "%SRCROOT%" };
}

function physicalLocation(file, line) {
  return { artifactLocation: artifactLocation(file), region: { startLine: line } };
}

function traceLocations(trace) {
  return trace.map((step) => ({
    location: {
      physicalLocation: physicalLocation(step.file, step.line),
      message: { text: `${step.kind}: ${step.description}` },
    },
  }));
}

function primaryLocation(record) {
  const sink = record.trace.find((step) => step.kind === "sink") || record.trace[record.trace.length - 1];
  return { physicalLocation: physicalLocation(sink.file, sink.line) };
}

function confirmedRule(record) {
  const severity = record.severity.overall_severity;
  return {
    id: record.fingerprint,
    name: record.fingerprint,
    shortDescription: { text: record.title },
    fullDescription: { text: record.root_cause },
    help: {
      text: `Intended behavior: ${record.intended_behavior}\nFix: ${record.remediation.strategy}`,
    },
    defaultConfiguration: { level: LEVEL[severity] },
    properties: {
      tags: ["security", "confirmed"],
      precision: record.confidence.score === "high" ? "high" : record.confidence.score === "medium" ? "medium" : "low",
      "security-severity": SECURITY_SEVERITY[severity],
    },
  };
}

function needsValidationRule(record) {
  return {
    id: record.fingerprint,
    name: record.fingerprint,
    shortDescription: { text: `[needs validation] ${record.title}` },
    fullDescription: { text: record.claimed_root_cause },
    help: { text: `Blockers: ${record.blockers.join("; ")}` },
    defaultConfiguration: { level: "note" },
    // No security-severity on purpose: needs_validation records carry no severity.
    properties: { tags: ["security", "needs-validation"], precision: "low" },
  };
}

function confirmedResult(record) {
  const severity = record.severity.overall_severity;
  return {
    ruleId: record.fingerprint,
    level: LEVEL[severity],
    message: { text: `${record.title}. ${record.description}` },
    locations: [primaryLocation(record)],
    codeFlows: [{ threadFlows: [{ locations: traceLocations(record.trace) }] }],
    relatedLocations: record.evidence.map((item, index) => ({
      id: index,
      physicalLocation: physicalLocation(item.file, item.line),
      message: { text: item.description },
    })),
    partialFingerprints: { [FINGERPRINT_KEY]: record.fingerprint },
    properties: {
      verdict: "confirmed",
      "security-severity": SECURITY_SEVERITY[severity],
      overallSeverity: severity,
      confidence: record.confidence.score,
      remediation: record.remediation.strategy,
    },
  };
}

function needsValidationResult(record) {
  return {
    ruleId: record.fingerprint,
    level: "note",
    message: { text: `[Needs validation, not a confirmed vulnerability] ${record.title}. ${record.description}` },
    locations: [primaryLocation(record)],
    codeFlows: [{ threadFlows: [{ locations: traceLocations(record.trace) }] }],
    relatedLocations: record.evidence.map((item, index) => ({
      id: index,
      physicalLocation: physicalLocation(item.file, item.line),
      message: { text: item.description },
    })),
    partialFingerprints: { [FINGERPRINT_KEY]: record.fingerprint },
    properties: { verdict: "needs_validation", blockers: record.blockers },
  };
}

/**
 * Pure conversion. Callers must validate `findings` first (the CLI does).
 * Records are emitted in fingerprint order so output is deterministic.
 */
function toSarif(findings, options = {}) {
  const includeNeedsValidation = options.includeNeedsValidation === true;
  const selected = findings
    .filter((record) => record.verdict === "confirmed" || (includeNeedsValidation && record.verdict === "needs_validation"))
    .slice()
    .sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0));

  const rules = [];
  const results = [];
  for (const record of selected) {
    if (record.verdict === "confirmed") {
      rules.push(confirmedRule(record));
      results.push(confirmedResult(record));
    } else {
      rules.push(needsValidationRule(record));
      results.push(needsValidationResult(record));
    }
  }

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: { driver: { name: TOOL_NAME, informationUri: TOOL_URI, rules } },
        originalUriBaseIds: { "%SRCROOT%": { description: { text: "Root of the audited repository at the reviewed source ref." } } },
        results,
      },
    ],
  };
}

function parseArgs(argv) {
  const args = { input: null, output: null, includeNeedsValidation: false };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === "--output") {
      args.output = argv[++index];
      if (!args.output) throw new Error("--output requires a path");
    } else if (arg === "--include-needs-validation") {
      args.includeNeedsValidation = true;
    } else if (arg.startsWith("--")) {
      throw new Error(`unknown option ${arg}`);
    } else if (args.input === null) {
      args.input = arg;
    } else {
      throw new Error("only one input file is accepted");
    }
  }
  if (!args.input) throw new Error("missing findings.json path");
  return args;
}

function run(argv) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (error) {
    console.error(`Usage: node findings-to-sarif.cjs <findings.json> [--output <file.sarif>] [--include-needs-validation]\n${error.message}`);
    return 1;
  }

  // Delegate input safety and schema/semantic validation to the canonical validator.
  const validation = spawnSync(process.execPath, [path.join(__dirname, "validate-findings.cjs"), args.input], {
    encoding: "utf8",
    timeout: 60000,
  });
  if (validation.status !== 0) {
    console.error("Refusing to export: findings.json failed validate-findings.cjs.");
    if (validation.stderr) console.error(validation.stderr.trimEnd());
    return 1;
  }

  let findings;
  try {
    findings = JSON.parse(fs.readFileSync(args.input, "utf8"));
  } catch {
    console.error("Failed to read validated findings.json.");
    return 1;
  }

  const text = `${JSON.stringify(toSarif(findings, { includeNeedsValidation: args.includeNeedsValidation }), null, 2)}\n`;
  if (!args.output) {
    process.stdout.write(text);
    return 0;
  }

  try {
    // wx: fail if the path exists (including as a symlink) instead of following or overwriting it.
    fs.writeFileSync(args.output, text, { flag: "wx", mode: 0o600 });
  } catch (error) {
    console.error(`Failed to write SARIF: ${error.code === "EEXIST" ? "output path already exists" : "output could not be created"}`);
    return 1;
  }
  console.error(`Wrote SARIF with ${JSON.parse(text).runs[0].results.length} result(s) to ${args.output}`);
  return 0;
}

module.exports = { FINGERPRINT_KEY, LEVEL, SECURITY_SEVERITY, toSarif };

if (require.main === module) process.exit(run(process.argv.slice(2)));
