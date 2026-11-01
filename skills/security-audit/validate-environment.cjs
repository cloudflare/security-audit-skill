#!/usr/bin/env node

/**
 * Fail-closed environment isolation gate for a security audit run.
 *
 * Usage:
 *   node validate-environment.cjs --scratch <dir> [--json]
 *   node validate-environment.cjs --scratch <dir> --home <dir> --tmp <dir> --cache <dir> [...]
 *
 * Exit codes:
 *   0  PASS  every isolation check holds; target-controlled processes may run
 *   1  FAIL  isolation is absent or unproven; do not execute target code
 *   2  usage error (no checks were performed)
 *
 * Why this exists: "use an empty environment with scratch-local HOME, temporary
 * directories, and caches" describes a desired state but does not verify it. An
 * agent that cannot create that state can still believe it did, and "creating" a
 * clean environment by emptying the current one destroys the host. This gate
 * turns the description into a check that fails closed.
 *
 * The gate proves only what it can observe. It never mutates anything; it reads
 * paths, resolves them, and compares. When it cannot prove isolation it fails.
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

const WINDOWS = process.platform === "win32";

/** Normalize a path for comparison. Windows paths are case-insensitive. */
function normalizePath(value) {
  const resolved = path.resolve(value);
  return WINDOWS ? resolved.toLowerCase() : resolved;
}

/** True when `child` is `parent` or lives underneath it. */
function isInside(child, parent) {
  const c = normalizePath(child);
  const p = normalizePath(parent);
  if (c === p) return true;
  const withSeparator = p.endsWith(path.sep) ? p : p + path.sep;
  return c.startsWith(withSeparator);
}

/** True for `/`, `C:\`, and UNC share roots. */
function isFilesystemRoot(value) {
  const resolved = path.resolve(value);
  return path.dirname(resolved) === resolved;
}

function readEnv(env, names) {
  for (const name of names) {
    const value = env[name];
    if (typeof value === "string" && value.trim() !== "") return value;
  }
  return undefined;
}

/**
 * Run every isolation check.
 *
 * @param {object} options
 * @param {string} options.scratch absolute scratch root for this agent
 * @param {string} [options.home] expected isolated HOME (defaults to the environment)
 * @param {string} [options.tmp] expected isolated temp directory
 * @param {string[]} [options.caches] expected isolated cache directories
 * @param {object} [env] environment to inspect (defaults to process.env)
 * @returns {{ok: boolean, checks: Array<{id: string, ok: boolean, detail: string}>}}
 */
function validateEnvironment(options, env = process.env) {
  const checks = [];
  const record = (id, ok, detail) => checks.push({ id, ok: Boolean(ok), detail });

  const scratch = options && typeof options.scratch === "string" ? options.scratch.trim() : "";
  if (!scratch) {
    record("scratch-provided", false, "no --scratch directory was given");
    return { ok: false, checks };
  }
  if (!path.isAbsolute(scratch)) {
    record("scratch-absolute", false, `scratch is not absolute: ${scratch}`);
    return { ok: false, checks };
  }
  record("scratch-absolute", true, scratch);

  if (isFilesystemRoot(scratch)) {
    record("scratch-not-root", false, `scratch is a filesystem root: ${scratch}`);
    return { ok: false, checks };
  }
  record("scratch-not-root", true, scratch);

  let scratchStat;
  try {
    scratchStat = fs.statSync(scratch);
  } catch (error) {
    record("scratch-exists", false, `scratch does not exist: ${scratch}`);
    return { ok: false, checks };
  }
  if (!scratchStat.isDirectory()) {
    record("scratch-exists", false, `scratch is not a directory: ${scratch}`);
    return { ok: false, checks };
  }
  record("scratch-exists", true, scratch);

  // The scratch root must not be the host home directory itself. Writing "inside
  // the scratch dir" is fine; making the host home the scratch dir is not.
  const realHome = os.homedir();
  if (normalizePath(scratch) === normalizePath(realHome)) {
    record("scratch-not-host-home", false, `scratch is the host home directory: ${scratch}`);
  } else {
    record("scratch-not-host-home", true, `host home is ${realHome}`);
  }

  const home = options.home || readEnv(env, ["HOME", "USERPROFILE"]);
  if (!home) {
    record("home-isolated", false, "HOME/USERPROFILE is unset; isolation is unproven");
  } else if (!isInside(home, scratch)) {
    record("home-isolated", false, `HOME is outside scratch: ${home}`);
  } else {
    record("home-isolated", true, home);
  }

  const tmp = options.tmp || readEnv(env, ["TMPDIR", "TEMP", "TMP"]);
  if (!tmp) {
    record("tmp-isolated", false, "TMPDIR/TEMP/TMP is unset; isolation is unproven");
  } else if (!isInside(tmp, scratch)) {
    record("tmp-isolated", false, `temporary directory is outside scratch: ${tmp}`);
  } else {
    record("tmp-isolated", true, tmp);
  }

  const caches = options.caches && options.caches.length > 0
    ? options.caches
    : [
        readEnv(env, ["XDG_CACHE_HOME"]),
        readEnv(env, ["LOCALAPPDATA"]) && path.join(readEnv(env, ["LOCALAPPDATA"]), "cache"),
      ].filter(Boolean);

  if (caches.length === 0) {
    record("caches-isolated", false, "no cache directory is configured; isolation is unproven");
  } else {
    const outside = caches.filter((cache) => !isInside(cache, scratch));
    if (outside.length > 0) {
      record("caches-isolated", false, `cache directory outside scratch: ${outside.join(", ")}`);
    } else {
      record("caches-isolated", true, caches.join(", "));
    }
  }

  // A gate that cannot tell the difference between "isolated" and "the real
  // profile" must not report success.
  const realTemp = os.tmpdir();
  if (normalizePath(home || "") === normalizePath(realHome) && normalizePath(scratch) !== normalizePath(realHome)) {
    record("real-home-unused", false, `HOME still resolves to the host home: ${realHome}`);
  } else {
    record("real-home-unused", true, `host home ${realHome} is not the run's HOME`);
  }

  return { ok: checks.every((check) => check.ok), checks };
}

function parseArgs(argv) {
  const options = { scratch: "", home: "", tmp: "", caches: [], json: false };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const next = () => {
      index += 1;
      if (index >= argv.length) throw new Error(`missing value for ${flag}`);
      return argv[index];
    };
    switch (flag) {
      case "--scratch": options.scratch = next(); break;
      case "--home": options.home = next(); break;
      case "--tmp": options.tmp = next(); break;
      case "--cache": options.caches.push(next()); break;
      case "--json": options.json = true; break;
      case "-h":
      case "--help": options.help = true; break;
      default: throw new Error(`unknown argument: ${flag}`);
    }
  }
  return options;
}

function formatHuman(result) {
  const lines = result.checks.map((check) => `${check.ok ? "PASS" : "FAIL"}  ${check.id}: ${check.detail}`);
  lines.push(result.ok ? "RESULT: PASS" : "RESULT: FAIL");
  if (!result.ok) {
    lines.push("Do not execute target-controlled code. Report the missing isolation as a needs-validation blocker.");
  }
  return lines.join("\n");
}

function main(argv) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.stderr.write("usage: node validate-environment.cjs --scratch <dir> [--home <dir>] [--tmp <dir>] [--cache <dir>...] [--json]\n");
    return 2;
  }
  if (options.help) {
    process.stdout.write("usage: node validate-environment.cjs --scratch <dir> [--home <dir>] [--tmp <dir>] [--cache <dir>...] [--json]\n");
    return 0;
  }
  const result = validateEnvironment(options);
  process.stdout.write(options.json ? JSON.stringify({ ok: result.ok, checks: result.checks }, null, 2) + "\n" : formatHuman(result) + "\n");
  return result.ok ? 0 : 1;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { isInside, isFilesystemRoot, validateEnvironment };
