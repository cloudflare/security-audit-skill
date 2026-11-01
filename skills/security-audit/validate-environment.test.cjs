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

function runCli(args) {
  return spawnSync(process.execPath, [validatorPath, ...args], { encoding: "utf8", timeout: 10000 });
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
    });
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
    });
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
    });
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
    });
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

test("reads HOME and temp from the environment when not overridden", () => {
  const scratch = makeScratch();
  try {
    const env = { HOME: path.join(scratch, "home"), TMPDIR: path.join(scratch, "tmp"), XDG_CACHE_HOME: path.join(scratch, "cache") };
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
    const env = { HOME: os.homedir(), TMPDIR: os.tmpdir(), XDG_CACHE_HOME: path.join(os.homedir(), ".cache") };
    const result = validateEnvironment({ scratch }, env);
    assert.equal(result.ok, false);
    assert.equal(result.checks.find((check) => check.id === "real-home-unused").ok, false);
  } finally {
    cleanDir(scratch);
  }
});

test("CLI exits 0 and prints PASS for an isolated environment", () => {
  const scratch = makeScratch();
  try {
    const result = runCli([
      "--scratch", scratch,
      "--home", path.join(scratch, "home"),
      "--tmp", path.join(scratch, "tmp"),
      "--cache", path.join(scratch, "cache"),
    ]);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /RESULT: PASS/);
  } finally {
    cleanDir(scratch);
  }
});

test("CLI exits 1 and prints FAIL when HOME escapes scratch", () => {
  const scratch = makeScratch();
  try {
    const result = runCli(["--scratch", scratch, "--home", os.homedir(), "--tmp", path.join(scratch, "tmp"), "--cache", path.join(scratch, "cache")]);
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
    const result = runCli(["--scratch", scratch, "--home", path.join(scratch, "home"), "--tmp", path.join(scratch, "tmp"), "--cache", path.join(scratch, "cache"), "--json"]);
    assert.equal(result.status, 0);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.ok, true);
    assert.equal(Array.isArray(parsed.checks), true);
  } finally {
    cleanDir(scratch);
  }
});
