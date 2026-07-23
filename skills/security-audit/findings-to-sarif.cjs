#!/usr/bin/env node

/**
 * Converts findings.json to SARIF 2.1.0 so audit results plug into the
 * existing security toolchain: GitHub code scanning, VS Code SARIF viewers,
 * DefectDojo, and any other SARIF consumer.
 * Usage: node findings-to-sarif.cjs <path-to-findings.json> [output.sarif]
 *        (writes to stdout when no output path is given)
 *
 * Mapping notes:
 * - Only "confirmed" findings become SARIF results. "rejected" findings are
 *   excluded from results but counted in run.properties.rejectedFindings so
 *   the audit trail stays visible.
 * - The finding's trace (entrypoint → propagation → sink) maps to a SARIF
 *   codeFlow, which GitHub code scanning renders as a step-through path.
 *   The sink is used as the result's primary location — that is where the
 *   defect manifests and where a fix lands.
 * - overall_severity maps to SARIF level (critical/high → error,
 *   medium → warning, low/informational → note) and to the GitHub
 *   "security-severity" rule property for code scanning's severity buckets.
 * - partialFingerprints hashes the raw UTF-8 octets of stable finding
 *   identity fields (never a re-encoded/pretty-printed form), so the same
 *   finding keeps the same fingerprint across runs and platforms.
 *
 * Run validate-findings.cjs first; this converter assumes schema-valid input.
 * Zero dependencies. Exits 0 on success, 1 on failure.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const inputPath = process.argv[2];
const outputPath = process.argv[3];
if (!inputPath) {
	console.error("Usage: node findings-to-sarif.cjs <path-to-findings.json> [output.sarif]");
	process.exit(1);
}

let findings;
try {
	findings = JSON.parse(fs.readFileSync(inputPath, "utf8"));
} catch (e) {
	console.error("Failed to parse JSON:", e.message);
	process.exit(1);
}
if (!Array.isArray(findings)) {
	console.error("findings.json must be an array");
	process.exit(1);
}

// --- Mapping helpers ------------------------------------------------------------

const LEVEL_BY_SEVERITY = {
	critical: "error",
	high: "error",
	medium: "warning",
	low: "note",
	informational: "note",
};

// GitHub code scanning buckets: critical >= 9.0, high >= 7.0, medium >= 4.0.
const SECURITY_SEVERITY_SCORE = {
	critical: "9.5",
	high: "7.5",
	medium: "5.0",
	low: "2.5",
	informational: "0.0",
};

function slugify(title, index) {
	const slug = String(title || "")
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "")
		.slice(0, 80);
	return slug || `finding-${index}`;
}

// Fingerprint over the raw UTF-8 octets of the identity fields, joined with an
// unambiguous separator. Hashing raw octets (not a pretty-printed or otherwise
// re-encoded form) keeps fingerprints stable across tools and platforms.
function fingerprint(ruleId, sink, rootCause) {
	const identity = [ruleId, sink ? sink.file : "", sink ? String(sink.line) : "", rootCause || ""].join("\u0000");
	return crypto.createHash("sha256").update(Buffer.from(identity, "utf8")).digest("hex");
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

// --- Convert --------------------------------------------------------------------

const rules = [];
const ruleIndexById = new Map();
const results = [];
let rejected = 0;
let skipped = 0;

findings.forEach((f, i) => {
	if (!f || typeof f !== "object" || f.verdict === "rejected") {
		rejected += f && f.verdict === "rejected" ? 1 : 0;
		skipped += f && f.verdict === "rejected" ? 0 : 1;
		return;
	}
	if (f.verdict !== "confirmed") {
		skipped++;
		return;
	}

	const overall = (f.severity && f.severity.overall_severity) || "medium";
	const ruleId = slugify(f.title, i);

	if (!ruleIndexById.has(ruleId)) {
		ruleIndexById.set(ruleId, rules.length);
		rules.push({
			id: ruleId,
			name: ruleId,
			shortDescription: { text: f.title || ruleId },
			fullDescription: { text: f.intended_behavior || f.title || ruleId },
			help: { text: (f.remediation && f.remediation.strategy) || "See finding description." },
			properties: {
				"security-severity": SECURITY_SEVERITY_SCORE[overall] || "5.0",
			},
		});
	}

	const trace = Array.isArray(f.trace) ? f.trace : [];
	const sink = trace.length > 0 ? trace[trace.length - 1] : null;

	const result = {
		ruleId,
		ruleIndex: ruleIndexById.get(ruleId),
		level: LEVEL_BY_SEVERITY[overall] || "warning",
		message: { text: `${f.description}\n\nRoot cause: ${f.root_cause}` },
		partialFingerprints: {
			"findingHash/v1": fingerprint(ruleId, sink, f.root_cause),
		},
		properties: {
			verdict: f.verdict,
			root_cause: f.root_cause,
			intended_behavior: f.intended_behavior,
			conditions: f.conditions,
			execution: f.execution,
			remediation: f.remediation,
			severity: f.severity,
			confidence: f.confidence,
		},
	};

	if (sink) {
		result.locations = [toLocation(sink)];
	}
	if (trace.length >= 2) {
		result.codeFlows = [
			{
				threadFlows: [
					{
						locations: trace.map((step) => ({ location: toLocation(step) })),
					},
				],
			},
		];
	}

	results.push(result);
});

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
			automationDetails: { id: `security-audit/${path.basename(inputPath)}` },
			originalUriBaseIds: {
				SRCROOT: { description: { text: "Root of the audited repository." } },
			},
			columnKind: "utf16CodeUnits",
			results,
			properties: {
				confirmedFindings: results.length,
				rejectedFindings: rejected,
			},
		},
	],
};

const json = JSON.stringify(sarif, null, 2) + "\n";
if (outputPath) {
	fs.writeFileSync(outputPath, json);
	console.log(`Wrote ${results.length} result(s) to ${outputPath} (${rejected} rejected finding(s) excluded)`);
} else {
	process.stdout.write(json);
}
if (skipped > 0) {
	console.error(`WARNING: ${skipped} entr(y/ies) had no recognized verdict and were skipped`);
}
