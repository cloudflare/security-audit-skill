#!/usr/bin/env node

/**
 * Fail-closed environment isolation gate for a security audit run.
 *
 * Usage:
 *   node validate-environment.cjs --scratch <dir> [--json]
 *   node validate-environment.cjs --scratch <dir> --home <dir> --tmp <dir> --cache <dir> [...]
 * Run with the environment intended for target code. The optional path flags
 * are assertions about that environment.
 *
 * Exit codes:
 *   0  PASS  the environment passes the path checks
 *   1  FAIL  isolation is absent or unproven; do not execute target code
 *   2  usage error (no checks were performed)
 *
 * Why this exists: "use an empty environment with scratch-local HOME, temporary
 * directories, and caches" describes a desired state but does not verify it. An
 * agent that cannot create that state can still believe it did, and "creating" a
 * clean environment by emptying the current one destroys the host. This gate
 * turns the description into a check that fails closed.
 *
 * The gate compares normalized path values. Filesystem isolation is enforced
 * by the sandbox. This check performs no writes.
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");

const WINDOWS = process.platform === "win32";
const HOME_VARIABLE = WINDOWS ? "USERPROFILE" : "HOME";
const TEMP_VARIABLES = WINDOWS ? ["TEMP", "TMP"] : ["TMPDIR", "TMP", "TEMP"];

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

function isAbsolutePath(value) {
  return typeof value === "string" && path.isAbsolute(value) &&
    (!WINDOWS || path.parse(value).root.length > 1);
}

function readEnvPaths(env, names) {
  return Object.entries(env).flatMap(([key, value]) => {
    const name = WINDOWS ? key.toUpperCase() : key;
    if (!names.includes(name) || typeof value !== "string" || value === "") return [];
    return [{ name, value }];
  });
}

/**
 * Run every isolation check.
 *
 * @param {object} options
 * @param {string} options.scratch absolute scratch root for this agent
 * @param {string} [options.home] expected value of the platform's home variable
 * @param {string} [options.tmp] expected value of the effective temp variable
 * @param {string[]} [options.caches] expected paths among the configured caches
 * @param {object} [env] environment that will run target code (defaults to process.env)
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
  if (!isAbsolutePath(scratch)) {
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

  // os.homedir() reads the same environment that we are validating.
  let realHome;
  try {
    realHome = os.userInfo().homedir;
  } catch {
    record("scratch-not-host-home", false, "could not determine the OS account's home directory");
    return { ok: false, checks };
  }
  if (!isAbsolutePath(realHome)) {
    record("scratch-not-host-home", false, "the OS account has no absolute home directory");
    return { ok: false, checks };
  }
  const scratchIsHostHome = normalizePath(scratch) === normalizePath(realHome);
  record("scratch-not-host-home", !scratchIsHostHome,
    scratchIsHostHome ? `scratch is the host home directory: ${scratch}` : `host home is ${realHome}`);

  function checkPaths(id, configured, actual, expected, missing) {
    const invalid = configured.find(({ value }) => !isAbsolutePath(value) || !isInside(value, scratch));
    if (invalid) {
      record(id, false, `${invalid.name} must be absolute and inside scratch: ${invalid.value}`);
    } else if (actual.length === 0) {
      record(id, false, missing);
    } else if (expected.some((value) => !isAbsolutePath(value) ||
      !actual.some((observed) => normalizePath(observed) === normalizePath(value)))) {
      record(id, false, `expected ${expected.join(", ")} but the environment configured ${actual.join(", ")}`);
    } else {
      record(id, true, actual.join(", "));
    }
  }

  const homes = readEnvPaths(env, ["HOME", "USERPROFILE"]);
  const actualHome = homes.find(({ name }) => name === HOME_VARIABLE);
  checkPaths("home-isolated", homes, actualHome ? [actualHome.value] : [],
    options.home === undefined ? [] : [options.home], `${HOME_VARIABLE} is unset; isolation is unproven`);

  const temps = readEnvPaths(env, ["TMPDIR", "TEMP", "TMP"]);
  const tempName = TEMP_VARIABLES.find((name) => temps.some((entry) => entry.name === name));
  const actualTemp = temps.find(({ name }) => name === tempName);
  checkPaths("tmp-isolated", temps, actualTemp ? [actualTemp.value] : [],
    options.tmp === undefined ? [] : [options.tmp], `${TEMP_VARIABLES.join("/")} is unset; isolation is unproven`);

  const caches = readEnvPaths(env, ["XDG_CACHE_HOME", "LOCALAPPDATA"]);
  const actualCaches = caches.map(({ name, value }) => name === "LOCALAPPDATA" ? path.join(value, "cache") : value);
  checkPaths("caches-isolated", caches, actualCaches, options.caches ?? [],
    "XDG_CACHE_HOME/LOCALAPPDATA is unset; cache isolation is unproven");

  const hostHomeUsed = homes.some(({ value }) =>
    isAbsolutePath(value) && normalizePath(value) === normalizePath(realHome));
  record("real-home-unused", !hostHomeUsed,
    hostHomeUsed ? `a home variable still points to the host home: ${realHome}` : "home variables avoid the host home");

  return { ok: checks.every((check) => check.ok), checks };
}

function parseArgs(argv) {
  const options = { scratch: "", caches: [], json: false };
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
