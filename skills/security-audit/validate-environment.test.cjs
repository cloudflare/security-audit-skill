const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { isFilesystemRoot, isInside, validateEnvironment } = require("./validate-environment.cjs");

const validatorPath = path.join(__dirname, "validate-environment.cjs");

function makeScratch() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "audit-scratch-"));
}

function cleanDir(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
}

function isolatedEnv(scratch) {
  const home = path.join(scratch, "home");
  const tmp = path.join(scratch, "tmp");
  return { HOME: home, USERPROFILE: home, TMPDIR: tmp, TEMP: tmp, TMP: tmp, XDG_CACHE_HOME: path.join(scratch, "cache") };
}

function runCli(args, env = {}) {
  return spawnSync(process.execPath, [validatorPath, ...args], {
    env: { SystemRoot: process.env.SystemRoot, ...env },
    encoding: "utf8",
    timeout: 10000,
  });
}

test("isInside treats the directory itself and children as inside", () => {
  const root = path.resolve(os.tmpdir(), "run-root");
  assert.equal(isInside(root, root), true);
  assert.equal(isInside(path.join(root, "scratch", "home"), root), true);
  assert.equal(isInside(path.resolve(os.tmpdir(), "run-root-sibling"), root), false);
});

test("isFilesystemRoot recognises roots only", () => {
  assert.equal(isFilesystemRoot(path.parse(process.cwd()).root), true);
  assert.equal(isFilesystemRoot(path.join(os.tmpdir(), "run-root")), false);
});

test("passes when HOME, temp and caches all resolve inside scratch", () => {
  const scratch = makeScratch();
  try {
    const result = validateEnvironment({
      scratch,
      home: path.join(scratch, "home"),
      tmp: path.join(scratch, "tmp"),
      caches: [path.join(scratch, "cache")],
    }, isolatedEnv(scratch));
    assert.equal(result.ok, true, JSON.stringify(result.checks));
    assert.equal(result.checks.every((check) => check.ok), true);
  } finally {
    cleanDir(scratch);
  }
});

test("fails when HOME is the real user profile", () => {
  const scratch = makeScratch();
  try {
    const result = validateEnvironment({
      scratch,
      home: os.homedir(),
      tmp: path.join(scratch, "tmp"),
      caches: [path.join(scratch, "cache")],
    }, { ...isolatedEnv(scratch), HOME: os.userInfo().homedir, USERPROFILE: os.userInfo().homedir });
    assert.equal(result.ok, false);
    const home = result.checks.find((check) => check.id === "home-isolated");
    assert.equal(home.ok, false);
  } finally {
    cleanDir(scratch);
  }
});

test("fails when the temporary directory is outside scratch", () => {
  const scratch = makeScratch();
  try {
    const result = validateEnvironment({
      scratch,
      home: path.join(scratch, "home"),
      tmp: os.tmpdir(),
      caches: [path.join(scratch, "cache")],
    }, { ...isolatedEnv(scratch), TMPDIR: os.tmpdir(), TEMP: os.tmpdir(), TMP: os.tmpdir() });
    assert.equal(result.ok, false);
    assert.equal(result.checks.find((check) => check.id === "tmp-isolated").ok, false);
  } finally {
    cleanDir(scratch);
  }
});

test("fails when a cache directory is outside scratch", () => {
  const scratch = makeScratch();
  try {
    const result = validateEnvironment({
      scratch,
      home: path.join(scratch, "home"),
      tmp: path.join(scratch, "tmp"),
      caches: [path.join(scratch, "cache"), path.resolve(os.tmpdir(), "elsewhere")],
    }, { ...isolatedEnv(scratch), LOCALAPPDATA: os.tmpdir() });
    assert.equal(result.ok, false);
    assert.equal(result.checks.find((check) => check.id === "caches-isolated").ok, false);
  } finally {
    cleanDir(scratch);
  }
});

test("fails closed when no scratch directory is given", () => {
  const result = validateEnvironment({});
  assert.equal(result.ok, false);
  assert.equal(result.checks[0].id, "scratch-provided");
});

test("fails when scratch is relative", () => {
  const result = validateEnvironment({ scratch: "relative/scratch" });
  assert.equal(result.ok, false);
  assert.equal(result.checks[0].id, "scratch-absolute");
});

test("fails when scratch is a filesystem root", () => {
  const root = path.parse(process.cwd()).root;
  const result = validateEnvironment({ scratch: root });
  assert.equal(result.ok, false);
  assert.equal(result.checks.at(-1).id, "scratch-not-root");
});

test("fails when the scratch directory does not exist", () => {
  const missing = path.join(os.tmpdir(), `audit-missing-${Date.now()}`);
  const result = validateEnvironment({ scratch: missing });
  assert.equal(result.ok, false);
  assert.equal(result.checks.at(-1).id, "scratch-exists");
});

test("reads home, temp and cache paths from the environment without flags", () => {
  const scratch = makeScratch();
  try {
    const env = isolatedEnv(scratch);
    const result = validateEnvironment({ scratch }, env);
    assert.equal(result.ok, true, JSON.stringify(result.checks));
    assert.equal(result.checks.find((check) => check.id === "home-isolated").detail, env.HOME);
  } finally {
    cleanDir(scratch);
  }
});

test("fails when the environment still points at the host home", () => {
  const scratch = makeScratch();
  try {
    const realHome = os.userInfo().homedir;
    const env = { ...isolatedEnv(scratch), HOME: realHome, USERPROFILE: realHome };
    const result = validateEnvironment({ scratch }, env);
    assert.equal(result.ok, false);
    assert.equal(result.checks.find((check) => check.id === "real-home-unused").ok, false);
  } finally {
    cleanDir(scratch);
  }
});

test("fails when flags are supplied but the actual environment is unset", (t) => {
  const scratch = makeScratch();
  t.after(() => cleanDir(scratch));
  const expected = isolatedEnv(scratch);
  const result = validateEnvironment({
    scratch, home: expected.HOME, tmp: expected.TEMP, caches: [expected.XDG_CACHE_HOME],
  }, {});
  assert.equal(result.ok, false);
  for (const id of ["home-isolated", "tmp-isolated", "caches-isolated"]) {
    assert.equal(result.checks.find((check) => check.id === id).ok, false);
  }
});

test("fails when expected paths differ from the actual scratch-local paths", (t) => {
  const scratch = makeScratch();
  t.after(() => cleanDir(scratch));
  const result = validateEnvironment({
    scratch,
    home: path.join(scratch, "other-home"),
    tmp: path.join(scratch, "other-tmp"),
    caches: [path.join(scratch, "other-cache")],
  }, isolatedEnv(scratch));
  assert.equal(result.ok, false);
  for (const id of ["home-isolated", "tmp-isolated", "caches-isolated"]) {
    assert.equal(result.checks.find((check) => check.id === id).ok, false);
  }
});

test("fails when secondary home, temp, or cache variables escape scratch", (t) => {
  const scratch = makeScratch();
  t.after(() => cleanDir(scratch));
  const outside = os.tmpdir();
  const env = {
    ...isolatedEnv(scratch),
    [process.platform === "win32" ? "HOME" : "USERPROFILE"]: outside,
    TMP: outside,
    LOCALAPPDATA: outside,
  };
  const result = validateEnvironment({ scratch }, env);
  assert.equal(result.ok, false);
  for (const id of ["home-isolated", "tmp-isolated", "caches-isolated"]) {
    assert.equal(result.checks.find((check) => check.id === id).ok, false);
  }
});

test("requires the platform's home and temp variables", (t) => {
  const scratch = makeScratch();
  t.after(() => cleanDir(scratch));
  const paths = isolatedEnv(scratch);
  const env = process.platform === "win32"
    ? { HOME: paths.HOME, TMPDIR: paths.TMPDIR }
    : { USERPROFILE: paths.USERPROFILE };
  const result = validateEnvironment({ scratch }, { ...env, XDG_CACHE_HOME: paths.XDG_CACHE_HOME });
  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === "home-isolated").ok, false);
  assert.equal(result.checks.find((check) => check.id === "tmp-isolated").ok, false);
});

test("accepts a LOCALAPPDATA cache path alongside XDG_CACHE_HOME", (t) => {
  const scratch = makeScratch();
  t.after(() => cleanDir(scratch));
  const env = { ...isolatedEnv(scratch), LOCALAPPDATA: path.join(scratch, "localappdata") };
  const result = validateEnvironment({
    scratch,
    caches: [env.XDG_CACHE_HOME, path.join(env.LOCALAPPDATA, "cache")],
  }, env);
  assert.equal(result.ok, true, JSON.stringify(result.checks));
});

test("CLI rejects the account home as scratch even when home variables are changed", () => {
  const scratch = os.userInfo().homedir;
  const result = runCli(["--scratch", scratch, "--json"], isolatedEnv(scratch));
  assert.equal(result.status, 1, result.stderr);
  const { checks } = JSON.parse(result.stdout);
  assert.equal(checks.find((check) => check.id === "scratch-not-host-home").ok, false);
});

test("CLI exits 0 and prints PASS for an isolated environment", () => {
  const scratch = makeScratch();
  try {
    const result = runCli([
      "--scratch", scratch,
      "--home", path.join(scratch, "home"),
      "--tmp", path.join(scratch, "tmp"),
      "--cache", path.join(scratch, "cache"),
    ], isolatedEnv(scratch));
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /RESULT: PASS/);
  } finally {
    cleanDir(scratch);
  }
});

test("CLI exits 1 when scratch-local flags would mask host environment paths", () => {
  const scratch = makeScratch();
  try {
    const realHome = os.userInfo().homedir;
    const env = { ...isolatedEnv(scratch), HOME: realHome, USERPROFILE: realHome, TEMP: os.tmpdir(), XDG_CACHE_HOME: path.join(realHome, ".cache") };
    const result = runCli([
      "--scratch", scratch,
      "--home", path.join(scratch, "home"),
      "--tmp", path.join(scratch, "tmp"),
      "--cache", path.join(scratch, "cache"),
    ], env);
    assert.equal(result.status, 1);
    assert.match(result.stdout, /RESULT: FAIL/);
    assert.match(result.stdout, /Do not execute target-controlled code/);
  } finally {
    cleanDir(scratch);
  }
});

test("CLI exits 2 on an unknown argument", () => {
  const result = runCli(["--nope"]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unknown argument/);
});

test("CLI --json emits a machine-readable result", () => {
  const scratch = makeScratch();
  try {
    const result = runCli(["--scratch", scratch, "--home", path.join(scratch, "home"), "--tmp", path.join(scratch, "tmp"), "--cache", path.join(scratch, "cache"), "--json"], isolatedEnv(scratch));
    assert.equal(result.status, 0);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.ok, true);
    assert.equal(Array.isArray(parsed.checks), true);
  } finally {
    cleanDir(scratch);
  }
});
