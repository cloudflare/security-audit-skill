#!/usr/bin/env node

/**
 * Converts findings.json to SARIF 2.1.0 so audit results plug into GitHub code
 * scanning, VS Code SARIF viewers, DefectDojo, and other SARIF consumers.
 * Usage: node findings-to-sarif.cjs <path-to-findings.json> [output.sarif]
 *        (writes to stdout when no output path is given)
 *
 * Mapping:
 * - Only confirmed findings become results. needs_validation and rejected
 *   records are counted in run.properties, not reported as results.
 * - The trace maps to a codeFlow. The sink step is the primary location.
 * - overall_severity maps to the result level and to the rule's
 *   security-severity. Code scanning reads security-severity from the rule, so
 *   a rule is one title at one severity: findings with the same title and
 *   different severities get different rules, and titles that slugify to the
 *   same ID get a title hash in theirs.
 * - The finding's fingerprint field is the result's partialFingerprint, so an
 *   alert keeps its identity across runs.
 *
 * Run validate-findings.cjs first; this converter assumes schema-valid input.
 * Zero dependencies. Exits 0 on success, 1 on failure.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const LEVEL_BY_SEVERITY = new Map([
  ["critical", "error"],
  ["high", "error"],
  ["medium", "warning"],
  ["low", "note"],
  ["informational", "note"],
]);

// Code scanning buckets: critical >= 9.0, high >= 7.0, medium >= 4.0, low > 0.0.
const SECURITY_SEVERITY_SCORE = new Map([
  ["critical", "9.5"],
  ["high", "7.5"],
  ["medium", "5.0"],
  ["low", "2.5"],
  ["informational", "0.0"],
]);

function slugify(title) {
  const slug = String(title || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return slug || "finding";
}

function shortHash(text) {
  return crypto.createHash("sha256").update(Buffer.from(String(text), "utf8")).digest("hex").slice(0, 8);
}

function toLocation(step) {
  return {
    physicalLocation: {
      artifactLocation: { uri: step.file, uriBaseId: "SRCROOT" },
      region: { startLine: step.line },
    },
    logicalLocations: [{ name: step.scope, kind: "function" }],
    message: { text: `${step.kind}: ${step.description}` },
  };
}

function sinkOf(trace) {
  for (let i = trace.length - 1; i >= 0; i--) {
    if (trace[i] && trace[i].kind === "sink") return trace[i];
  }
  return trace.length > 0 ? trace[trace.length - 1] : null;
}

function toSarif(findings, { automationId = "security-audit/findings.json" } = {}) {
  const rules = [];
  const ruleIndexByKey = new Map();
  const ruleIds = new Set();
  const results = [];
  const counts = { needsValidation: 0, rejected: 0, skipped: 0 };

  // One rule per (title, severity): the rule carries security-severity, so
  // findings that differ in either must not share it.
  function ruleIndexFor(f, overall) {
    const key = `${f.title}\u0000${overall}`;
    if (ruleIndexByKey.has(key)) return ruleIndexByKey.get(key);
    const slug = slugify(f.title);
    let id = `${slug}/${overall}`;
    if (ruleIds.has(id)) id = `${slug}-${shortHash(f.title)}/${overall}`;
    ruleIds.add(id);
    ruleIndexByKey.set(key, rules.length);
    rules.push({
      id,
      name: slug,
      shortDescription: { text: f.title || slug },
      fullDescription: { text: f.intended_behavior || f.title || slug },
      help: { text: (f.remediation && f.remediation.strategy) || "See finding description." },
      properties: { "security-severity": SECURITY_SEVERITY_SCORE.get(overall) },
    });
    return rules.length - 1;
  }

  for (const f of findings) {
    const verdict = f && typeof f === "object" ? f.verdict : undefined;
    if (verdict === "needs_validation") {
      counts.needsValidation++;
      continue;
    }
    if (verdict === "rejected") {
      counts.rejected++;
      continue;
    }
    if (verdict !== "confirmed") {
      counts.skipped++;
      continue;
    }

    const stated = f.severity && f.severity.overall_severity;
    const overall = SECURITY_SEVERITY_SCORE.has(stated) ? stated : "medium";
    const ruleIndex = ruleIndexFor(f, overall);
    const trace = Array.isArray(f.trace) ? f.trace : [];
    const sink = sinkOf(trace);

    const result = {
      ruleId: rules[ruleIndex].id,
      ruleIndex,
      level: LEVEL_BY_SEVERITY.get(overall),
      message: { text: `${f.description}\n\nRoot cause: ${f.root_cause}` },
      partialFingerprints: { "findingFingerprint/v1": String(f.fingerprint) },
      properties: {
        verdict: f.verdict,
        fingerprint: f.fingerprint,
        root_cause: f.root_cause,
        intended_behavior: f.intended_behavior,
        evidence: f.evidence,
        conditions: f.conditions,
        execution: f.execution,
        remediation: f.remediation,
        severity: f.severity,
        confidence: f.confidence,
      },
    };
    if (sink) result.locations = [toLocation(sink)];
    if (trace.length >= 2) {
      result.codeFlows = [{ threadFlows: [{ locations: trace.map((step) => ({ location: toLocation(step) })) }] }];
    }
    results.push(result);
  }

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "security-audit-skill",
            informationUri: "https://github.com/cloudflare/security-audit-skill",
            rules,
          },
        },
        automationDetails: { id: automationId },
        originalUriBaseIds: {
          SRCROOT: { description: { text: "Root of the audited repository." } },
        },
        columnKind: "utf16CodeUnits",
        results,
        properties: {
          confirmedFindings: results.length,
          needsValidationFindings: counts.needsValidation,
          rejectedFindings: counts.rejected,
        },
      },
    ],
  };
  return { sarif, skipped: counts.skipped };
}

function run(inputPath, outputPath) {
  if (!inputPath) {
    console.error("Usage: node findings-to-sarif.cjs <path-to-findings.json> [output.sarif]");
    return 1;
  }
  let findings;
  try {
    findings = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  } catch (e) {
    console.error("Failed to parse JSON:", e.message);
    return 1;
  }
  if (!Array.isArray(findings)) {
    console.error("findings.json must be an array");
    return 1;
  }

  const { sarif, skipped } = toSarif(findings, { automationId: `security-audit/${path.basename(inputPath)}` });
  const json = JSON.stringify(sarif, null, 2) + "\n";
  const { confirmedFindings, needsValidationFindings, rejectedFindings } = sarif.runs[0].properties;
  if (outputPath) {
    fs.writeFileSync(outputPath, json);
    console.log(
      `Wrote ${confirmedFindings} result(s) to ${outputPath} ` +
        `(${needsValidationFindings} needs_validation and ${rejectedFindings} rejected record(s) not reported as results)`,
    );
  } else {
    process.stdout.write(json);
  }
  if (skipped > 0) {
    console.error(`WARNING: ${skipped} entr(y/ies) had no recognized verdict and were skipped`);
  }
  return 0;
}

module.exports = { slugify, toSarif };

if (require.main === module) process.exit(run(process.argv[2], process.argv[3]));
