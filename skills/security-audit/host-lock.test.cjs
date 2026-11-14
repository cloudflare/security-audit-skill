const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { LockError, acquireLock, inspectLock, releaseLock } = require("./host-lock.cjs");

const lockCliPath = path.join(__dirname, "host-lock.cjs");

function tempLock() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-lock-"));
  return { dir, lockPath: path.join(dir, "host.lock") };
}

function clean(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

function runCli(args) {
  return spawnSync(process.execPath, [lockCliPath, ...args], { encoding: "utf8", timeout: 10000 });
}

test("acquire creates the lock and a second owner is refused", () => {
  const { dir, lockPath } = tempLock();
  try {
    const first = acquireLock({ lockPath, owner: "hunter-a", purpose: "install fixture deps" });
    assert.equal(first.acquired, true);
    assert.equal(fs.existsSync(lockPath), true);

    assert.throws(
      () => acquireLock({ lockPath, owner: "hunter-b" }),
      (error) => error instanceof LockError && /held by hunter-a/.test(error.message),
    );
  } finally {
    clean(dir);
  }
});

test("release only succeeds for the owner", () => {
  const { dir, lockPath } = tempLock();
  try {
    acquireLock({ lockPath, owner: "hunter-a" });
    const wrong = releaseLock({ lockPath, owner: "hunter-b" });
    assert.equal(wrong.released, false);
    assert.equal(wrong.reason, "not-owner");
    assert.equal(fs.existsSync(lockPath), true);

    const right = releaseLock({ lockPath, owner: "hunter-a" });
    assert.equal(right.released, true);
    assert.equal(fs.existsSync(lockPath), false);
  } finally {
    clean(dir);
  }
});

test("releasing a missing lock is reported, not thrown", () => {
  const { dir, lockPath } = tempLock();
  try {
    const result = releaseLock({ lockPath, owner: "hunter-a" });
    assert.deepEqual(result, { released: false, reason: "not-held" });
  } finally {
    clean(dir);
  }
});

test("a fresh lock is not stale", () => {
  const { dir, lockPath } = tempLock();
  try {
    acquireLock({ lockPath, owner: "hunter-a", ttlSeconds: 600 });
    const state = inspectLock(lockPath);
    assert.equal(state.held, true);
    assert.equal(state.stale, false);
    assert.equal(state.info.owner, "hunter-a");
  } finally {
    clean(dir);
  }
});

test("a stale lock blocks unless reclaimed with force", () => {
  const { dir, lockPath } = tempLock();
  try {
    acquireLock({ lockPath, owner: "dead-agent", ttlSeconds: 1 });
    const past = new Date(Date.now() - 60_000);
    fs.utimesSync(lockPath, past, past);

    assert.equal(inspectLock(lockPath, 1).stale, true);
    assert.throws(() => acquireLock({ lockPath, owner: "hunter-b", ttlSeconds: 1 }), /stale/);

    const reclaimed = acquireLock({ lockPath, owner: "hunter-b", ttlSeconds: 1, force: true });
    assert.equal(reclaimed.acquired, true);
    assert.equal(reclaimed.reclaimed, true);
    assert.equal(inspectLock(lockPath).info.owner, "hunter-b");
  } finally {
    clean(dir);
  }
});

test("only one of two overlapping forced acquires gets the stale lock", (t) => {
  const { dir, lockPath } = tempLock();
  t.after(() => clean(dir));
  acquireLock({ lockPath, owner: "dead-agent" });
  const past = new Date(Date.now() - 3_600_000);
  fs.utimesSync(lockPath, past, past);

  let contender;
  const statSync = fs.statSync;
  t.mock.method(fs, "statSync", (file, ...args) => {
    const stat = statSync(file, ...args);
    if (file === lockPath && !contender) {
      // Run a second process after reading the old mtime and before using it.
      contender = runCli(["acquire", "--lock", lockPath, "--owner", "hunter-b", "--force"]);
    }
    return stat;
  });

  let acquired = false;
  try {
    acquired = acquireLock({ lockPath, owner: "hunter-a", force: true }).acquired;
  } catch (error) {
    assert.ok(error instanceof LockError);
    assert.match(error.message, /^lock is held/);
  }
  assert.ok(contender, "the second process must run during the first acquire");
  assert.ifError(contender.error);
  assert.ok([0, 1].includes(contender.status), contender.stderr);
  assert.equal(Number(acquired) + Number(contender.status === 0), 1);
  const owner = acquired ? "hunter-a" : "hunter-b";
  assert.equal(inspectLock(lockPath).info.owner, owner);
  assert.deepEqual(releaseLock({ lockPath, owner }), { released: true });
  assert.equal(inspectLock(lockPath).held, false);
});

test("an interrupted update keeps a missing lock unavailable", (t) => {
  const { dir, lockPath } = tempLock();
  t.after(() => clean(dir));
  fs.mkdirSync(`${lockPath}.guard`);

  assert.equal(inspectLock(lockPath).held, true);
  assert.throws(() => acquireLock({ lockPath, owner: "hunter-a", force: true }), /lock is held/);
  assert.equal(runCli(["release", "--lock", lockPath, "--owner", "hunter-a"]).status, 1);
});

test("rejects a relative lock path and a missing owner", () => {
  assert.throws(() => acquireLock({ lockPath: "relative.lock", owner: "a" }), LockError);
  const { dir, lockPath } = tempLock();
  try {
    assert.throws(() => acquireLock({ lockPath }), /owner is required/);
  } finally {
    clean(dir);
  }
});

test("creates missing parent directories for the lock file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-lock-"));
  try {
    const lockPath = path.join(dir, "run-1", "agents", "hunter-a", "host.lock");
    acquireLock({ lockPath, owner: "hunter-a" });
    assert.equal(fs.existsSync(lockPath), true);
  } finally {
    clean(dir);
  }
});

test("CLI acquire then status then release round-trips", () => {
  const { dir, lockPath } = tempLock();
  try {
    const acquired = runCli(["acquire", "--lock", lockPath, "--owner", "hunter-a", "--purpose", "fixture setup"]);
    assert.equal(acquired.status, 0, acquired.stderr);

    const busy = runCli(["status", "--lock", lockPath]);
    assert.equal(busy.status, 1);
    assert.match(busy.stdout, /HELD/);

    const released = runCli(["release", "--lock", lockPath, "--owner", "hunter-a"]);
    assert.equal(released.status, 0, released.stderr);

    const free = runCli(["status", "--lock", lockPath]);
    assert.equal(free.status, 0);
    assert.match(free.stdout, /FREE/);
  } finally {
    clean(dir);
  }
});

test("CLI refuses a second acquire and exits 2 on a bad command", () => {
  const { dir, lockPath } = tempLock();
  try {
    assert.equal(runCli(["acquire", "--lock", lockPath, "--owner", "a"]).status, 0);
    const second = runCli(["acquire", "--lock", lockPath, "--owner", "b"]);
    assert.equal(second.status, 1);
    assert.match(second.stderr, /held by a/);

    const bad = runCli(["frobnicate", "--lock", lockPath]);
    assert.equal(bad.status, 2);
  } finally {
    clean(dir);
  }
});

test("CLI status --json is machine readable", () => {
  const { dir, lockPath } = tempLock();
  try {
    acquireLock({ lockPath, owner: "hunter-a" });
    const result = runCli(["status", "--lock", lockPath, "--json"]);
    assert.equal(result.status, 1);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.held, true);
    assert.equal(parsed.info.owner, "hunter-a");
  } finally {
    clean(dir);
  }
});
