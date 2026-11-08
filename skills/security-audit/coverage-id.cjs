#!/usr/bin/env node

/**
 * Derives the canonical coverage_id for a ledger unit so the parent never has to
 * hand-compute the NFC + RFC 3986 percent-encoding rules in RECONNAISSANCE.md.
 *
 * Usage:
 *   node coverage-id.cjs '<canonical_refs JSON>'
 *   node coverage-id.cjs --file <canonical-refs.json>
 *   echo '<canonical_refs JSON>' | node coverage-id.cjs -
 *
 * The input is the unit's `canonical_refs` object: surface, boundary, subsystem,
 * attack_class, and optionally lifecycle. Output is the coverage_id. Invalid
 * references (non-NFC, control characters, surrounding whitespace, missing or
 * extra fields) are rejected with a nonzero exit status.
 */

const fs = require("node:fs");
const { canonicalCoverageId } = require("./validate-coverage-ledger.cjs");

const MAX_BYTES = 64 * 1024;

function readInput(argv) {
  if (argv.length === 2 && argv[0] === "--file") return fs.readFileSync(argv[1], "utf8");
  if (argv.length === 1 && argv[0] === "-") return fs.readFileSync(0, "utf8");
  if (argv.length === 1) return argv[0];
  throw new Error("expected a JSON argument, --file <path>, or -");
}

function run(argv) {
  let refs;
  try {
    const text = readInput(argv);
    if (Buffer.byteLength(text, "utf8") > MAX_BYTES) throw new Error(`input exceeds ${MAX_BYTES} bytes`);
    refs = JSON.parse(text);
  } catch (error) {
    console.error(`Usage: node coverage-id.cjs '<canonical_refs JSON>' | --file <path> | -\n${error.message}`);
    return 1;
  }
  try {
    process.stdout.write(`${canonicalCoverageId(refs)}\n`);
    return 0;
  } catch (error) {
    console.error(`Invalid canonical_refs: ${error.message}`);
    return 1;
  }
}

if (require.main === module) process.exit(run(process.argv.slice(2)));

module.exports = { run };
