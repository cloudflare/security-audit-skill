#!/usr/bin/env node

/**
 * Exclusive host lock for steps that mutate the machine.
 *
 * Usage:
 *   node host-lock.cjs acquire --lock <path> --owner <id> [--purpose <text>] [--ttl <seconds>] [--force]
 *   node host-lock.cjs release --lock <path> --owner <id>
 *   node host-lock.cjs status  --lock <path> [--json]
 *
 * Exit codes: 0 ok, 1 lock held (or not held by this owner), 2 usage error.
 *
 * Why this exists: installing, upgrading, cleaning, resetting, deleting, or
 * moving anything outside the run directory are host mutations. Two agents doing
 * them at once corrupt each other (observed: package installers aborting with
 * exit -1 and exit 1 while a second installer ran). The lock makes that
 * serialization explicit, and makes an unattended mutation impossible.
 *
 * The lock is advisory but fail-closed: if the file cannot be created
 * exclusively, the caller must assume another holder exists.
 */

"use strict";

const fs = require("fs");
const path = require("path");

const DEFAULT_TTL_SECONDS = 900;
const MAX_PURPOSE_LENGTH = 200;

class LockError extends Error {}

function nowMs() {
  return Date.now();
}

function readLock(lockPath) {
  try {
    const raw = fs.readFileSync(lockPath, "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") return parsed;
    return null;
  } catch (error) {
    return null;
  }
}

/**
 * Inspect a lock without taking it.
 * @returns {{held: boolean, stale: boolean, info: object|null}}
 */
function inspectLock(lockPath, ttlSeconds = DEFAULT_TTL_SECONDS) {
  if (!fs.existsSync(lockPath)) return { held: false, stale: false, info: null };
  const info = readLock(lockPath);
  let ageSeconds = null;
  try {
    ageSeconds = (nowMs() - fs.statSync(lockPath).mtimeMs) / 1000;
  } catch (error) {
    ageSeconds = null;
  }
  const ttl = info && Number.isFinite(info.ttlSeconds) ? info.ttlSeconds : ttlSeconds;
  const stale = ageSeconds !== null && ageSeconds > ttl;
  return { held: true, stale, info, ageSeconds };
}

/**
 * Take the lock or fail.
 *
 * @param {object} options
 * @param {string} options.lockPath absolute path of the lock file
 * @param {string} options.owner stable identifier of the agent taking the lock
 * @param {string} [options.purpose] short description of the mutation
 * @param {number} [options.ttlSeconds] stale-after window
 * @param {boolean} [options.force] reclaim a stale lock
 */
function acquireLock(options) {
  const { lockPath, owner, purpose = "", ttlSeconds = DEFAULT_TTL_SECONDS, force = false } = options || {};
  if (!lockPath || !path.isAbsolute(lockPath)) throw new LockError("lockPath must be absolute");
  if (!owner || typeof owner !== "string") throw new LockError("owner is required");
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) throw new LockError("ttlSeconds must be positive");
  if (purpose.length > MAX_PURPOSE_LENGTH) throw new LockError("purpose is too long");

  fs.mkdirSync(path.dirname(lockPath), { recursive: true });

  const payload = JSON.stringify(
    { owner, purpose, pid: process.pid, createdAt: new Date().toISOString(), ttlSeconds },
    null,
    2,
  );

  const attempt = () => fs.writeFileSync(lockPath, payload, { encoding: "utf8", flag: "wx" });

  try {
    attempt();
    return { acquired: true, info: readLock(lockPath) };
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }

  const current = inspectLock(lockPath, ttlSeconds);
  if (current.stale && force) {
    // Reclaim: remove and retry the exclusive create. A racing holder loses the
    // same way it would have lost the first attempt.
    try {
      fs.unlinkSync(lockPath);
    } catch (error) {
      // Someone else removed it first; the exclusive create below decides.
    }
    try {
      attempt();
      return { acquired: true, reclaimed: true, info: readLock(lockPath) };
    } catch (error) {
      throw new LockError(`lock is held and reclaim failed: ${error.code}`);
    }
  }

  const holder = current.info && current.info.owner ? current.info.owner : "unknown";
  const why = current.stale ? " (stale; pass --force to reclaim)" : "";
  throw new LockError(`lock is held by ${holder}${why}`);
}

/** Release only when this owner holds it. */
function releaseLock(options) {
  const { lockPath, owner } = options || {};
  if (!lockPath || !path.isAbsolute(lockPath)) throw new LockError("lockPath must be absolute");
  if (!fs.existsSync(lockPath)) return { released: false, reason: "not-held" };
  const info = readLock(lockPath);
  if (!info || info.owner !== owner) {
    return { released: false, reason: "not-owner", holder: info && info.owner };
  }
  fs.unlinkSync(lockPath);
  return { released: true };
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = { command, lockPath: "", owner: "", purpose: "", ttlSeconds: DEFAULT_TTL_SECONDS, force: false, json: false };
  for (let index = 0; index < rest.length; index += 1) {
    const flag = rest[index];
    const next = () => {
      index += 1;
      if (index >= rest.length) throw new LockError(`missing value for ${flag}`);
      return rest[index];
    };
    switch (flag) {
      case "--lock": options.lockPath = next(); break;
      case "--owner": options.owner = next(); break;
      case "--purpose": options.purpose = next(); break;
      case "--ttl": options.ttlSeconds = Number(next()); break;
      case "--force": options.force = true; break;
      case "--json": options.json = true; break;
      default: throw new LockError(`unknown argument: ${flag}`);
    }
  }
  return options;
}

function main(argv) {
  let options;
  try {
    options = parseArgs(argv);
    switch (options.command) {
      case "acquire": {
        try {
          const result = acquireLock(options);
          process.stdout.write(JSON.stringify(result) + "\n");
          return 0;
        } catch (error) {
          if (error instanceof LockError && /^lock is held/.test(error.message)) {
            process.stderr.write(`${error.message}\n`);
            return 1;
          }
          throw error;
        }
      }
      case "release": {
        const result = releaseLock(options);
        process.stdout.write(JSON.stringify(result) + "\n");
        return result.released ? 0 : 1;
      }
      case "status": {
        const result = inspectLock(options.lockPath, options.ttlSeconds);
        process.stdout.write(
          options.json ? JSON.stringify(result, null, 2) + "\n" : `${result.held ? "HELD" : "FREE"}${result.stale ? " (stale)" : ""}\n`,
        );
        return result.held ? 1 : 0;
      }
      default:
        throw new LockError("command must be acquire, release, or status");
    }
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.stderr.write("usage: node host-lock.cjs <acquire|release|status> --lock <path> [--owner <id>] [--purpose <text>] [--ttl <seconds>] [--force] [--json]\n");
    return 2;
  }
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { DEFAULT_TTL_SECONDS, LockError, acquireLock, inspectLock, releaseLock };
