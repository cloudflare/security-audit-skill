const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const {
  LIMITS,
  PATH_FORBIDDEN_CHARACTER,
  UNSAFE_DIAGNOSTIC_CHARACTER,
  VISIBLE_CONTENT,
  WINDOWS_RESERVED_COMPONENT,
  checkPosixProcFdSupport,
  checkPromotionSupport,
  escapeUnsafeDiagnosticCharacters,
  isSafeRelativePath,
  openTrustedRoots,
  preflightJsonText,
  promoteArtifacts,
  promoteFromDescriptors,
  run,
  validateAllowlist,
} = require("./promote-artifacts.cjs");

const scriptPath = path.join(__dirname, "promote-artifacts.cjs");
const CLI_TIMEOUT_MS = 5000;
const HAS_PROMOTION_SUPPORT = checkPosixProcFdSupport().supported;

function makeError(code, message = code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function createVirtualFs() {
  let nextIno = 100n;
  let nextFd = 10;
  const openFds = new Map();
  const rootDirs = new Map();

  function makeDirNode() {
    return {
      kind: "dir",
      dev: 1n,
      ino: nextIno++,
      mode: 0o40700,
      nlink: 2n,
      entries: new Map(),
    };
  }

  function makeFileNode(content, overrides = {}) {
    const buffer = Buffer.isBuffer(content) ? Buffer.from(content) : Buffer.from(content, "utf8");
    return {
      kind: "file",
      dev: 1n,
      ino: nextIno++,
      mode: 0o100600,
      nlink: 1n,
      mtimeNs: 1000000n,
      data: buffer,
      readChunks: null,
      onRead: null,
      onAfterRead: null,
      ...overrides,
    };
  }

  function makeSpecialNode(kind, extra = {}) {
    return {
      kind,
      dev: 1n,
      ino: nextIno++,
      mode: kind === "fifo" ? 0o10600 : 0o140600,
      nlink: 1n,
      mtimeNs: 1000000n,
      data: Buffer.alloc(0),
      ...extra,
    };
  }

  function makeSymlinkNode(target) {
    return { kind: "symlink", target };
  }

  function statForNode(node) {
    return {
      dev: node.dev,
      ino: node.ino,
      mode: node.mode,
      nlink: node.nlink,
      size: node.kind === "file" ? BigInt(node.data.length) : 0n,
      mtimeNs: node.mtimeNs ?? 0n,
      isFile: () => node.kind === "file",
      isDirectory: () => node.kind === "dir",
    };
  }

  const scratchRoot = makeDirNode();
  const artifactsRoot = makeDirNode();
  rootDirs.set("/virtual/scratch", scratchRoot);
  rootDirs.set("/virtual/artifacts", artifactsRoot);

  const hooks = {
    supported: true,
    unsupportedReason: null,
    onMkdirExclusive: null,
    onWrite: null,
    maxWriteChunk: Infinity,
  };

  function getFdRecord(fd) {
    const record = openFds.get(fd);
    if (!record) throw makeError("EBADF", `bad fd ${fd}`);
    return record;
  }

  const ops = {
    checkSupport() {
      return hooks.supported
        ? { supported: true, reason: null }
        : { supported: false, reason: hooks.unsupportedReason || "OS promotion primitives unavailable" };
    },
    openRootDir(dirPath) {
      const node = rootDirs.get(dirPath);
      if (!node) throw makeError("ENOENT");
      if (node.kind === "symlink") throw makeError("ELOOP");
      if (node.kind !== "dir") throw makeError("ENOTDIR");
      const fd = nextFd++;
      openFds.set(fd, { node, offset: 0, writable: false });
      return fd;
    },
    openDirNoFollow(dirFd, component) {
      const dir = getFdRecord(dirFd).node;
      if (dir.kind !== "dir") throw makeError("ENOTDIR");
      if (!dir.entries.has(component)) throw makeError("ENOENT");
      const child = dir.entries.get(component);
      if (child.kind === "symlink") throw makeError("ELOOP");
      if (child.kind !== "dir") throw makeError("ENOTDIR");
      const fd = nextFd++;
      openFds.set(fd, { node: child, offset: 0, writable: false });
      return fd;
    },
    mkdirExclusive(dirFd, component) {
      const dir = getFdRecord(dirFd).node;
      if (dir.kind !== "dir") throw makeError("ENOTDIR");
      if (hooks.onMkdirExclusive) hooks.onMkdirExclusive(dir, component);
      if (dir.entries.has(component)) throw makeError("EEXIST");
      dir.entries.set(component, makeDirNode());
    },
    openLeafReadNoFollowNonBlock(dirFd, component) {
      const dir = getFdRecord(dirFd).node;
      if (dir.kind !== "dir") throw makeError("ENOTDIR");
      if (!dir.entries.has(component)) throw makeError("ENOENT");
      const child = dir.entries.get(component);
      if (child.kind === "symlink") throw makeError("ELOOP");
      if (child.openErrorCode) throw makeError(child.openErrorCode);
      const fd = nextFd++;
      openFds.set(fd, { node: child, offset: 0, writable: false, readCalls: 0 });
      return fd;
    },
    openLeafWriteExclusiveNoFollow(dirFd, component) {
      const dir = getFdRecord(dirFd).node;
      if (dir.kind !== "dir") throw makeError("ENOTDIR");
      if (dir.entries.has(component)) {
        const existing = dir.entries.get(component);
        if (existing.kind === "symlink") throw makeError("EEXIST");
        throw makeError("EEXIST");
      }
      const file = makeFileNode(Buffer.alloc(0));
      dir.entries.set(component, file);
      const fd = nextFd++;
      openFds.set(fd, { node: file, offset: 0, writable: true });
      return fd;
    },
    unlinkRelative(dirFd, component) {
      const dir = getFdRecord(dirFd).node;
      if (!dir.entries.has(component)) throw makeError("ENOENT");
      dir.entries.delete(component);
    },
    fstat(fd) {
      const record = getFdRecord(fd);
      return statForNode(record.node);
    },
    read(fd, buffer, offset, length) {
      const record = getFdRecord(fd);
      const node = record.node;
      if (node.onRead) node.onRead(node, record);
      if (node.readChunks) {
        const chunk = node.readChunks[record.readCalls++] || null;
        if (!chunk) {
          if (node.onAfterRead) node.onAfterRead(node, record);
          return 0;
        }
        const toCopy = Math.min(chunk.length, length);
        chunk.copy(buffer, offset, 0, toCopy);
        return toCopy;
      }
      const remaining = node.data.length - record.offset;
      if (remaining <= 0) {
        if (node.onAfterRead) node.onAfterRead(node, record);
        return 0;
      }
      const count = Math.min(remaining, length);
      node.data.copy(buffer, offset, record.offset, record.offset + count);
      record.offset += count;
      return count;
    },
    write(fd, buffer, offset, length) {
      const record = getFdRecord(fd);
      if (!record.writable) throw makeError("EBADF");
      const toWrite = Math.min(length, hooks.maxWriteChunk);
      const slice = Buffer.from(buffer.subarray(offset, offset + toWrite));
      record.node.data = Buffer.concat([record.node.data, slice]);
      if (hooks.onWrite) hooks.onWrite(record.node, slice);
      return toWrite;
    },
    close(fd) {
      if (!openFds.has(fd)) throw makeError("EBADF");
      openFds.delete(fd);
    },
  };

  return {
    ops,
    hooks,
    rootDirs,
    scratchRoot,
    artifactsRoot,
    openFds,
    makeDirNode,
    makeFileNode,
    makeSpecialNode,
    makeSymlinkNode,
  };
}

function cliOutput(result) {
  return `${result.stdout}${result.stderr}`;
}

test("keeps shared helpers aligned with both validators", () => {
  const findingsModule = require("./validate-findings.cjs");
  const ledgerModule = require("./validate-coverage-ledger.cjs");
  const promoteModule = require("./promote-artifacts.cjs");

  for (const name of [
    "VISIBLE_CONTENT",
    "PATH_FORBIDDEN_CHARACTER",
    "WINDOWS_RESERVED_COMPONENT",
    "UNSAFE_DIAGNOSTIC_CHARACTER",
  ]) {
    assert.equal(promoteModule[name].source, findingsModule[name].source, `${name} source`);
    assert.equal(promoteModule[name].flags, findingsModule[name].flags, `${name} flags`);
    assert.equal(promoteModule[name].source, ledgerModule[name].source, `${name} ledger source`);
    assert.equal(promoteModule[name].flags, ledgerModule[name].flags, `${name} ledger flags`);
  }

  for (const key of ["inputBytes", "nestingDepth", "validationErrors"]) {
    assert.equal(promoteModule.LIMITS[key], findingsModule.LIMITS[key], `LIMITS.${key} vs findings`);
    assert.equal(promoteModule.LIMITS[key], ledgerModule.LIMITS[key], `LIMITS.${key} vs ledger`);
  }

  const pathCorpus = [
    "evidence/test.log",
    "nested/caf\u00e9/out.json",
    "src/con.txt",
    "CON",
    "src/COM\u00b9.log",
    "/etc/passwd",
    "../secret.txt",
    "a/../b.txt",
    "a/./b.txt",
    "a//b.txt",
    "a\\b.txt",
    "a:b.txt",
    "~home/out.log",
    "C:/out.log",
    "out.log ",
    "out.log.",
    "out\u202e.log",
    "out\u200b.log",
    "out\ud800.log",
    "",
  ];
  for (const candidate of pathCorpus) {
    assert.equal(
      isSafeRelativePath(candidate),
      ledgerModule.isSafeRelativePath(candidate),
      `isSafeRelativePath(${JSON.stringify(candidate)})`,
    );
  }
});

test("validateAllowlist accepts valid manifests and rejects malformed, unsafe, or duplicate entries", () => {
  assert.deepEqual(
    validateAllowlist({
      max_total_bytes: 1024,
      files: [
        { path: "unit-test.log", max_bytes: 512 },
        { path: "nested/result.json", max_bytes: 512 },
      ],
    }),
    [],
  );

  assert.deepEqual(validateAllowlist({ max_total_bytes: 0, files: [] }), []);

  assert(validateAllowlist(null).length > 0);
  assert(validateAllowlist([]).length > 0);
  assert(validateAllowlist({ max_total_bytes: 10, files: [], extra: true }).some((e) => /unexpected property/.test(e)));
  assert(validateAllowlist({ max_total_bytes: -1, files: [] }).some((e) => /max_total_bytes/.test(e)));
  assert(validateAllowlist({ max_total_bytes: 10, files: [{ path: "a.log", max_bytes: 11 }] }).some((e) => /exceeds max_total_bytes/.test(e)));
  assert(
    validateAllowlist({
      max_total_bytes: 100,
      files: [
        { path: "a.log", max_bytes: 50 },
        { path: "a.log", max_bytes: 50 },
      ],
    }).some((e) => /duplicate allowlist path/.test(e)),
  );

  for (const badPath of ["", "/abs.log", ".", "..", "a/../b.log", "a/./b.log", "a//b.log", "a\\b.log", "C:/a.log", "CON.txt", "a\u202eb.log"]) {
    const errors = validateAllowlist({
      max_total_bytes: 100,
      files: [{ path: badPath, max_bytes: 10 }],
    });
    assert(errors.length > 0, `expected error for bad path ${JSON.stringify(badPath)}`);
  }

  const tooMany = Array.from({ length: LIMITS.collectionItems + 1 }, (_, i) => ({
    path: `file-${i}.log`,
    max_bytes: 1,
  }));
  assert(validateAllowlist({ max_total_bytes: 10000, files: tooMany }).some((e) => /exceeds 1000 entries/.test(e)));

  const manyBad = Array.from({ length: 150 }, () => ({ path: "/bad\u001b", max_bytes: -1 }));
  const capped = validateAllowlist({ max_total_bytes: 100, files: manyBad });
  assert.equal(capped.length, LIMITS.validationErrors);
  assert.doesNotMatch(capped.join("\n"), /\u001b/);
});

test("preflightJsonText enforces nesting depth and structure bounds", () => {
  assert.doesNotThrow(() => preflightJsonText('{"max_total_bytes":10,"files":[]}'));
  assert.throws(() => preflightJsonText("[".repeat(LIMITS.nestingDepth + 1) + "]".repeat(LIMITS.nestingDepth + 1)), /nesting depth limit/);
  assert.throws(() => preflightJsonText('{"files":['), /truncated JSON structure/);
});

test("promotes valid flat and nested files from retained descriptors with zero fd leaks", () => {
  const vfs = createVirtualFs();
  const sub = vfs.makeDirNode();
  sub.entries.set("trace.txt", vfs.makeFileNode("hello-nested-artifact"));
  vfs.scratchRoot.entries.set("sub", sub);
  vfs.scratchRoot.entries.set("top.log", vfs.makeFileNode("top-content"));

  // Simulate partial writes to verify the write loop handles short writes.
  vfs.hooks.maxWriteChunk = 5;

  const roots = openTrustedRoots("/virtual/scratch", "/virtual/artifacts", vfs.ops);
  try {
    const result = promoteFromDescriptors(
      roots.scratchFd,
      roots.artifactsFd,
      {
        max_total_bytes: 100,
        files: [
          { path: "top.log", max_bytes: 50 },
          { path: "sub/trace.txt", max_bytes: 50 },
        ],
      },
      vfs.ops,
    );

    assert.equal(result.ok, true, result.errors.join("\n"));
    assert.equal(result.promoted.length, 2);
    assert.equal(result.totalBytes, "top-content".length + "hello-nested-artifact".length);
    assert.equal(vfs.artifactsRoot.entries.get("top.log").data.toString("utf8"), "top-content");
    assert.equal(vfs.artifactsRoot.entries.get("sub").entries.get("trace.txt").data.toString("utf8"), "hello-nested-artifact");

    // Only the two retained root descriptors remain open.
    assert.equal(vfs.openFds.size, 2);
  } finally {
    roots.close();
  }
  assert.equal(vfs.openFds.size, 0);
});

test("rejects symlinks in scratch leaf, scratch parent, and artifacts parent", () => {
  const vfs = createVirtualFs();
  vfs.scratchRoot.entries.set("link.log", vfs.makeSymlinkNode("/etc/passwd"));

  const linkedParent = vfs.makeSymlinkNode("/etc");
  vfs.scratchRoot.entries.set("escape", linkedParent);

  const validDir = vfs.makeDirNode();
  validDir.entries.set("ok.log", vfs.makeFileNode("safe"));
  vfs.scratchRoot.entries.set("destlink", validDir);
  vfs.artifactsRoot.entries.set("destlink", vfs.makeSymlinkNode("/tmp/evil"));

  const result = promoteArtifacts(
    "/virtual/scratch",
    "/virtual/artifacts",
    {
      max_total_bytes: 1000,
      files: [
        { path: "link.log", max_bytes: 100 },
        { path: "escape/passwd", max_bytes: 100 },
        { path: "destlink/ok.log", max_bytes: 100 },
      ],
    },
    vfs.ops,
  );

  assert.equal(result.ok, false);
  assert.equal(result.promoted.length, 0);
  assert.deepEqual(
    result.rejected.map((r) => r.code),
    ["SYMLINK_REJECTED", "SYMLINK_REJECTED", "SYMLINK_REJECTED"],
  );
  assert.equal(vfs.openFds.size, 0);
});

test("rejects hard links, FIFOs, sockets, devices, and directories", () => {
  const vfs = createVirtualFs();
  vfs.scratchRoot.entries.set("hardlink.log", vfs.makeFileNode("data", { nlink: 2n }));
  vfs.scratchRoot.entries.set("pipe.fifo", vfs.makeSpecialNode("fifo"));
  vfs.scratchRoot.entries.set("pipe-enxio.fifo", vfs.makeSpecialNode("fifo", { openErrorCode: "ENXIO" }));
  vfs.scratchRoot.entries.set("ipc.sock", vfs.makeSpecialNode("socket"));
  vfs.scratchRoot.entries.set("subdir", vfs.makeDirNode());

  const result = promoteArtifacts(
    "/virtual/scratch",
    "/virtual/artifacts",
    {
      max_total_bytes: 1000,
      files: [
        { path: "hardlink.log", max_bytes: 100 },
        { path: "pipe.fifo", max_bytes: 100 },
        { path: "pipe-enxio.fifo", max_bytes: 100 },
        { path: "ipc.sock", max_bytes: 100 },
        { path: "subdir", max_bytes: 100 },
      ],
    },
    vfs.ops,
  );

  assert.equal(result.ok, false);
  assert.equal(result.promoted.length, 0);
  assert.deepEqual(
    result.rejected.map((r) => r.code),
    ["HARD_LINK_REJECTED", "NON_REGULAR_FILE", "NON_REGULAR_FILE", "NON_REGULAR_FILE", "NON_REGULAR_FILE"],
  );
  assert.equal(vfs.artifactsRoot.entries.size, 0);
  assert.equal(vfs.openFds.size, 0);
});

test("enforces per-file and cumulative byte limits", () => {
  const vfs = createVirtualFs();
  vfs.scratchRoot.entries.set("too-big.log", vfs.makeFileNode("12345678901"));
  vfs.scratchRoot.entries.set("first.log", vfs.makeFileNode("123456"));
  vfs.scratchRoot.entries.set("second.log", vfs.makeFileNode("123456"));

  const result = promoteArtifacts(
    "/virtual/scratch",
    "/virtual/artifacts",
    {
      max_total_bytes: 10,
      files: [
        { path: "too-big.log", max_bytes: 10 },
        { path: "first.log", max_bytes: 10 },
        { path: "second.log", max_bytes: 10 },
      ],
    },
    vfs.ops,
  );

  assert.equal(result.ok, false);
  assert.deepEqual(result.promoted, [{ path: "first.log", bytes: 6 }]);
  assert.deepEqual(
    result.rejected.map((r) => ({ path: r.path, code: r.code })),
    [
      { path: "too-big.log", code: "FILE_TOO_LARGE" },
      { path: "second.log", code: "CUMULATIVE_LIMIT_EXCEEDED" },
    ],
  );
  assert.equal(vfs.artifactsRoot.entries.has("first.log"), true);
  assert.equal(vfs.artifactsRoot.entries.has("too-big.log"), false);
  assert.equal(vfs.artifactsRoot.entries.has("second.log"), false);
  assert.equal(vfs.openFds.size, 0);
});

test("rejects files that grow, shrink, or change identity/nlink/mtime during copy and unlinks partial destination", () => {
  const vfs = createVirtualFs();

  // Case 1: file grows during streaming read
  vfs.scratchRoot.entries.set(
    "grows.log",
    vfs.makeFileNode("1234", {
      readChunks: [Buffer.from("1234"), Buffer.from("56")],
    }),
  );

  // Case 2: file shrinks during streaming read
  vfs.scratchRoot.entries.set(
    "shrinks.log",
    vfs.makeFileNode("123456", {
      readChunks: [Buffer.from("12")],
    }),
  );

  // Case 3: file nlink changes before post-copy fstat
  vfs.scratchRoot.entries.set(
    "relinked.log",
    vfs.makeFileNode("abcd", {
      onAfterRead(node) {
        node.nlink = 2n;
      },
    }),
  );

  // Case 4: file mtime changes in place (same size) during copy
  vfs.scratchRoot.entries.set(
    "overwritten.log",
    vfs.makeFileNode("abcd", {
      onAfterRead(node) {
        node.mtimeNs = 2000000n;
      },
    }),
  );

  const result = promoteArtifacts(
    "/virtual/scratch",
    "/virtual/artifacts",
    {
      max_total_bytes: 1000,
      files: [
        { path: "grows.log", max_bytes: 100 },
        { path: "shrinks.log", max_bytes: 100 },
        { path: "relinked.log", max_bytes: 100 },
        { path: "overwritten.log", max_bytes: 100 },
      ],
    },
    vfs.ops,
  );

  assert.equal(result.ok, false);
  assert.equal(result.promoted.length, 0);
  assert.deepEqual(
    result.rejected.map((r) => r.code),
    ["SOURCE_CHANGED", "SOURCE_CHANGED", "SOURCE_CHANGED", "SOURCE_CHANGED"],
  );
  // Every partial destination file must have been unlinked on failure!
  assert.equal(vfs.artifactsRoot.entries.size, 0);
  assert.equal(vfs.openFds.size, 0);
});

test("rejects existing destination leaf, destination mkdir race, and identical root directories", () => {
  const vfs = createVirtualFs();
  vfs.scratchRoot.entries.set("dup.log", vfs.makeFileNode("new"));
  vfs.artifactsRoot.entries.set("dup.log", vfs.makeFileNode("existing"));

  const raceDir = vfs.makeDirNode();
  raceDir.entries.set("r.log", vfs.makeFileNode("data"));
  vfs.scratchRoot.entries.set("race", raceDir);
  vfs.hooks.onMkdirExclusive = (dir, component) => {
    if (component === "race") {
      dir.entries.set("race", vfs.makeSymlinkNode("/tmp/evil"));
    }
  };

  const result = promoteArtifacts(
    "/virtual/scratch",
    "/virtual/artifacts",
    {
      max_total_bytes: 100,
      files: [
        { path: "dup.log", max_bytes: 50 },
        { path: "race/r.log", max_bytes: 50 },
      ],
    },
    vfs.ops,
  );

  assert.equal(result.ok, false);
  assert.deepEqual(
    result.rejected.map((r) => r.code),
    ["DEST_EXISTS", "DEST_DIR_RACE"],
  );
  // Existing destination must not be overwritten.
  assert.equal(vfs.artifactsRoot.entries.get("dup.log").data.toString("utf8"), "existing");

  // Identical scratch and artifacts roots must be rejected.
  const sameRootResult = promoteArtifacts(
    "/virtual/scratch",
    "/virtual/scratch",
    { max_total_bytes: 100, files: [] },
    vfs.ops,
  );
  assert.equal(sameRootResult.ok, false);
  assert.match(sameRootResult.errors[0], /distinct directories/);
  assert.equal(vfs.openFds.size, 0);
});

test("fails closed when OS promotion primitives are unavailable", () => {
  const vfs = createVirtualFs();
  vfs.hooks.supported = false;
  vfs.hooks.unsupportedReason = "OS descriptor-anchored no-follow primitives unavailable";

  const support = checkPromotionSupport(vfs.ops);
  assert.equal(support.supported, false);

  const result = promoteArtifacts(
    "/virtual/scratch",
    "/virtual/artifacts",
    { max_total_bytes: 100, files: [] },
    vfs.ops,
  );
  assert.equal(result.ok, false);
  assert.match(result.errors[0], /unavailable/);

  assert.equal(run(["--check"], vfs.ops), 1);
});

test("CLI --check and invocation fail closed cleanly on platforms without POSIX /proc/self/fd support", { skip: HAS_PROMOTION_SUPPORT }, () => {
  const checkResult = spawnSync(process.execPath, [scriptPath, "--check"], {
    encoding: "utf8",
    timeout: CLI_TIMEOUT_MS,
  });
  assert.equal(checkResult.status, 1, cliOutput(checkResult));
  assert.match(cliOutput(checkResult), /FAIL:.*unavailable/);
  assert.doesNotMatch(cliOutput(checkResult), /Error:|at promote-artifacts/);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "promote-artifacts-win-"));
  try {
    const scratch = path.join(tmp, "scratch");
    const artifacts = path.join(tmp, "artifacts");
    const allowlist = path.join(tmp, "allowlist.json");
    fs.mkdirSync(scratch);
    fs.mkdirSync(artifacts);
    fs.writeFileSync(path.join(scratch, "out.log"), "hello");
    fs.writeFileSync(allowlist, JSON.stringify({ max_total_bytes: 100, files: [{ path: "out.log", max_bytes: 100 }] }));

    const runResult = spawnSync(process.execPath, [scriptPath, scratch, artifacts, allowlist], {
      encoding: "utf8",
      timeout: CLI_TIMEOUT_MS,
    });
    assert.equal(runResult.status, 1, cliOutput(runResult));
    assert.match(cliOutput(runResult), /Failed to promote artifacts:.*unavailable/);
    assert.equal(fs.existsSync(path.join(artifacts, "out.log")), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("POSIX live filesystem promotion covers real symlinks, hard links, FIFOs, size limits, and CLI", { skip: !HAS_PROMOTION_SUPPORT }, () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "promote-artifacts-posix-"));
  try {
    const scratch = path.join(tmp, "scratch");
    const artifacts = path.join(tmp, "artifacts");
    fs.mkdirSync(scratch);
    fs.mkdirSync(artifacts);
    fs.mkdirSync(path.join(scratch, "nested"));

    fs.writeFileSync(path.join(scratch, "nested", "good.log"), "verified-output");
    fs.symlinkSync(path.join(scratch, "nested", "good.log"), path.join(scratch, "sym.log"));
    fs.writeFileSync(path.join(scratch, "hl-base.log"), "hardlinked");
    fs.linkSync(path.join(scratch, "hl-base.log"), path.join(scratch, "hl-copy.log"));
    fs.writeFileSync(path.join(scratch, "oversized.log"), "0123456789abcdef");

    const fifoPath = path.join(scratch, "events.fifo");
    const mkfifo = spawnSync("mkfifo", [fifoPath], { encoding: "utf8" });
    const hasFifo = mkfifo.status === 0;

    const allowlistFiles = [
      { path: "nested/good.log", max_bytes: 64 },
      { path: "sym.log", max_bytes: 64 },
      { path: "hl-copy.log", max_bytes: 64 },
      { path: "oversized.log", max_bytes: 8 },
    ];
    if (hasFifo) allowlistFiles.push({ path: "events.fifo", max_bytes: 64 });

    const result = promoteArtifacts(scratch, artifacts, {
      max_total_bytes: 256,
      files: allowlistFiles,
    });

    assert.equal(result.ok, false);
    assert.deepEqual(result.promoted, [{ path: "nested/good.log", bytes: "verified-output".length }]);
    assert.equal(fs.readFileSync(path.join(artifacts, "nested", "good.log"), "utf8"), "verified-output");
    assert.equal(fs.existsSync(path.join(artifacts, "sym.log")), false);
    assert.equal(fs.existsSync(path.join(artifacts, "hl-copy.log")), false);
    assert.equal(fs.existsSync(path.join(artifacts, "oversized.log")), false);
    if (hasFifo) assert.equal(fs.existsSync(path.join(artifacts, "events.fifo")), false);

    // CLI --check and happy path
    const checkResult = spawnSync(process.execPath, [scriptPath, "--check"], {
      encoding: "utf8",
      timeout: CLI_TIMEOUT_MS,
    });
    assert.equal(checkResult.status, 0, cliOutput(checkResult));
    assert.match(cliOutput(checkResult), /PASS: artifact promotion primitives available/);

    const artifacts2 = path.join(tmp, "artifacts2");
    fs.mkdirSync(artifacts2);
    const allowlistPath = path.join(tmp, "allowlist.json");
    fs.writeFileSync(
      allowlistPath,
      JSON.stringify({
        max_total_bytes: 64,
        files: [{ path: "nested/good.log", max_bytes: 64 }],
      }),
    );
    const cliRes = spawnSync(process.execPath, [scriptPath, scratch, artifacts2, allowlistPath], {
      encoding: "utf8",
      timeout: CLI_TIMEOUT_MS,
    });
    assert.equal(cliRes.status, 0, cliOutput(cliRes));
    assert.match(cliOutput(cliRes), /PASS: promoted 1 artifact\(s\)/);
    assert.equal(fs.readFileSync(path.join(artifacts2, "nested", "good.log"), "utf8"), "verified-output");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("HUNTING.md and VALIDATION-AND-REPORTING.md keep identical promotion procedure blocks", () => {
  const hunting = fs.readFileSync(path.join(__dirname, "HUNTING.md"), "utf8").replace(/\r\n/g, "\n");
  const validation = fs.readFileSync(path.join(__dirname, "VALIDATION-AND-REPORTING.md"), "utf8").replace(/\r\n/g, "\n");
  const blockPattern = /```text\nArtifact promotion procedure \(trusted parent-side code only\):[\s\S]*?\n```/;
  const huntingMatch = hunting.match(blockPattern);
  const validationMatch = validation.match(blockPattern);
  assert(huntingMatch, "HUNTING.md promotion block not found");
  assert(validationMatch, "VALIDATION-AND-REPORTING.md promotion block not found");
  assert.equal(huntingMatch[0], validationMatch[0]);
});
