#!/usr/bin/env node

/**
 * Promotes predeclared scratch-relative artifact files into parent-owned artifacts/
 * using descriptor-anchored no-follow, nonblocking, and exclusive-create operations.
 *
 * Usage:
 *   node promote-artifacts.cjs --check
 *   node promote-artifacts.cjs <scratch-dir> <artifacts-dir> <allowlist.json>
 */

const fs = require("node:fs");
const path = require("node:path");
const { TextDecoder } = require("node:util");

const LIMITS = Object.freeze({
  inputBytes: 5 * 1024 * 1024,
  collectionItems: 1000,
  objectFields: 1000,
  nestingDepth: 64,
  preflightValues: 500000,
  validationErrors: 100,
});
const COPY_CHUNK_BYTES = 64 * 1024;
const VISIBLE_CONTENT = /[^\p{White_Space}\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}]/u;
const PATH_FORBIDDEN_CHARACTER = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/u;
const WINDOWS_RESERVED_COMPONENT = /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9\u00b9\u00b2\u00b3]|lpt[1-9\u00b9\u00b2\u00b3])(?:\.|$)/iu;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const UNSAFE_DIAGNOSTIC_CHARACTER = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu;
const MAX_DIAGNOSTIC_STRING_LENGTH = 256;

const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

class JsonStructureError extends Error {}
class SafeInputError extends Error {}
class PromotionError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function escapeUnsafeDiagnosticCharacters(value) {
  return String(value).replace(UNSAFE_DIAGNOSTIC_CHARACTER, (character) => {
    const codePoint = character.codePointAt(0);
    return codePoint <= 0xffff
      ? `\\u${codePoint.toString(16).padStart(4, "0")}`
      : `\\u{${codePoint.toString(16)}}`;
  });
}

function safeQuote(value) {
  let serialized;
  if (typeof value === "string") {
    const clipped = value.length > MAX_DIAGNOSTIC_STRING_LENGTH
      ? `${value.slice(0, MAX_DIAGNOSTIC_STRING_LENGTH)}...`
      : value;
    serialized = JSON.stringify(clipped);
  } else if (value === null || typeof value === "boolean") {
    serialized = String(value);
  } else if (typeof value === "number" && Number.isFinite(value)) {
    serialized = String(value);
  } else {
    serialized = `"<${Array.isArray(value) ? "array" : typeof value}>"`;
  }
  return escapeUnsafeDiagnosticCharacters(serialized);
}

function createErrorList() {
  const errors = [];
  Object.defineProperty(errors, "push", {
    value(...messages) {
      const remaining = LIMITS.validationErrors - this.length;
      if (remaining > 0) {
        Array.prototype.push.apply(this, messages.slice(0, remaining).map(escapeUnsafeDiagnosticCharacters));
      }
      return this.length;
    },
  });
  return errors;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasValidUnicodeScalarValues(value) {
  let index = 0;
  while (index < value.length) {
    const first = value.charCodeAt(index++);
    if (first >= 0xd800 && first <= 0xdbff) {
      if (index >= value.length) return false;
      const second = value.charCodeAt(index++);
      if (second < 0xdc00 || second > 0xdfff) return false;
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function isSafeRelativePath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !hasValidUnicodeScalarValues(value) ||
    value.trim() !== value ||
    PATH_FORBIDDEN_CHARACTER.test(value) ||
    value.includes("\\") ||
    value.includes(":")
  ) {
    return false;
  }
  if (path.posix.isAbsolute(value) || path.win32.isAbsolute(value) || /^[A-Za-z]:/.test(value) || value.startsWith("~")) {
    return false;
  }
  return value.split("/").every((segment) =>
    segment !== "" &&
    segment !== "." &&
    segment !== ".." &&
    !/[ .]$/u.test(segment) &&
    !WINDOWS_RESERVED_COMPONENT.test(segment));
}

function preflightJsonText(contents) {
  const containers = [];
  let rootState = "value";
  let inString = false;
  let escaped = false;
  let totalValues = 0;

  function fail(message) {
    throw new JsonStructureError(`input ${message}`);
  }

  function currentContainer() {
    return containers[containers.length - 1];
  }

  function countValue() {
    totalValues++;
    if (totalValues > LIMITS.preflightValues) {
      fail(`exceeds ${LIMITS.preflightValues} total value limit`);
    }
  }

  function beginValue() {
    const container = currentContainer();
    if (!container) {
      if (rootState !== "value") fail("has trailing JSON tokens");
      rootState = "end";
      countValue();
      return;
    }
    if (container.type === "array") {
      if (container.state !== "firstOrEnd" && container.state !== "value") {
        fail("has malformed JSON array structure");
      }
      container.items++;
      if (container.items > LIMITS.collectionItems) {
        fail(`exceeds ${LIMITS.collectionItems} item array limit`);
      }
      container.state = "commaOrEnd";
      countValue();
      return;
    }
    if (container.state !== "value") fail("has malformed JSON object structure");
    container.state = "commaOrEnd";
    countValue();
  }

  function beginString() {
    const container = currentContainer();
    if (container && container.type === "object" && (container.state === "firstOrEnd" || container.state === "key")) {
      container.fields++;
      if (container.fields > LIMITS.objectFields) {
        fail(`exceeds ${LIMITS.objectFields} field object limit`);
      }
      container.state = "colon";
      inString = true;
      return;
    }
    beginValue();
    inString = true;
  }

  function beginContainer(type) {
    beginValue();
    if (containers.length >= LIMITS.nestingDepth) {
      fail(`exceeds ${LIMITS.nestingDepth} level nesting depth limit`);
    }
    containers.push({ type, state: "firstOrEnd", items: 0, fields: 0 });
  }

  function closeContainer(type) {
    const container = currentContainer();
    if (!container || container.type !== type || (container.state !== "firstOrEnd" && container.state !== "commaOrEnd")) {
      fail(`has malformed JSON ${type} closing delimiter`);
    }
    containers.pop();
  }

  function isWhitespace(character) {
    return character === " " || character === "\t" || character === "\n" || character === "\r";
  }

  function isTokenDelimiter(character) {
    return isWhitespace(character) || character === "," || character === "]" || character === "}" || character === ":";
  }

  for (let index = 0; index < contents.length; index++) {
    const character = contents[index];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === "\"") {
        inString = false;
      }
      continue;
    }
    if (isWhitespace(character)) continue;

    if (character === "\"") {
      beginString();
    } else if (character === "[") {
      beginContainer("array");
    } else if (character === "{") {
      beginContainer("object");
    } else if (character === "]") {
      closeContainer("array");
    } else if (character === "}") {
      closeContainer("object");
    } else if (character === ":") {
      const container = currentContainer();
      if (!container || container.type !== "object" || container.state !== "colon") {
        fail("has malformed JSON object structure");
      }
      container.state = "value";
    } else if (character === ",") {
      const container = currentContainer();
      if (!container || container.state !== "commaOrEnd") fail("has malformed JSON collection structure");
      container.state = container.type === "array" ? "value" : "key";
    } else {
      beginValue();
      while (index + 1 < contents.length && !isTokenDelimiter(contents[index + 1])) index++;
    }
  }

  if (inString) fail("has an unterminated JSON string");
  if (containers.length > 0) fail("has truncated JSON structure");
  if (rootState !== "end") fail("has no JSON value");
}

function readFileWithinLimit(file) {
  const noFollow = fs.constants.O_NOFOLLOW;
  const nonBlock = fs.constants.O_NONBLOCK;
  if (!Number.isInteger(noFollow) || noFollow === 0 || !Number.isInteger(nonBlock) || nonBlock === 0) {
    throw new SafeInputError("OS no-follow and nonblocking input protection is unavailable");
  }

  const cloexec = Number.isInteger(fs.constants.O_CLOEXEC) ? fs.constants.O_CLOEXEC : 0;
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | noFollow | nonBlock | cloexec);
  } catch (error) {
    if (error && (error.code === "ELOOP" || error.code === "EMLINK")) {
      throw new SafeInputError("input must not be a symlink");
    }
    throw error;
  }
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) {
      throw new SafeInputError("input must be a regular file");
    }
    if (stat.size > LIMITS.inputBytes) {
      throw new SafeInputError(`input exceeds ${LIMITS.inputBytes} byte limit`);
    }

    const chunks = [];
    const buffer = Buffer.allocUnsafe(COPY_CHUNK_BYTES);
    let bytesRead = 0;
    while (true) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      bytesRead += count;
      if (bytesRead > LIMITS.inputBytes) {
        throw new SafeInputError(`input exceeds ${LIMITS.inputBytes} byte limit`);
      }
      chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    try {
      return UTF8_DECODER.decode(Buffer.concat(chunks, bytesRead));
    } catch {
      throw new SafeInputError("input is not valid UTF-8");
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function validateAllowlist(allowlist) {
  const errors = createErrorList();
  if (!isObject(allowlist)) {
    errors.push("$: expected a top-level object with max_total_bytes and files");
    return errors;
  }

  const keys = Object.keys(allowlist);
  for (const key of keys) {
    if (key !== "max_total_bytes" && key !== "files") {
      errors.push(`$: unexpected property ${safeQuote(key)}`);
    }
  }

  if (!hasOwn(allowlist, "max_total_bytes") || !Number.isSafeInteger(allowlist.max_total_bytes) || allowlist.max_total_bytes < 0) {
    errors.push("$.max_total_bytes: expected a non-negative safe integer");
  }

  if (!hasOwn(allowlist, "files") || !Array.isArray(allowlist.files)) {
    errors.push("$.files: expected an array");
    return errors;
  }

  if (allowlist.files.length > LIMITS.collectionItems) {
    errors.push(`$.files: exceeds ${LIMITS.collectionItems} entries`);
    return errors;
  }

  const seenPaths = new Set();
  const hasValidTotal = Number.isSafeInteger(allowlist.max_total_bytes) && allowlist.max_total_bytes >= 0;

  for (let index = 0; index < allowlist.files.length && errors.length < LIMITS.validationErrors; index++) {
    const entry = allowlist.files[index];
    const location = `$.files[${index}]`;
    if (!isObject(entry)) {
      errors.push(`${location}: expected an object with path and max_bytes`);
      continue;
    }

    for (const key of Object.keys(entry)) {
      if (key !== "path" && key !== "max_bytes") {
        errors.push(`${location}: unexpected property ${safeQuote(key)}`);
      }
    }

    if (!hasOwn(entry, "path") || !isSafeRelativePath(entry.path)) {
      errors.push(`${location}.path: must be a safe relative path without absolute, empty, '.', '..', or forbidden components`);
    } else if (seenPaths.has(entry.path)) {
      errors.push(`${location}.path: duplicate allowlist path ${safeQuote(entry.path)}`);
    } else {
      seenPaths.add(entry.path);
    }

    if (!hasOwn(entry, "max_bytes") || !Number.isSafeInteger(entry.max_bytes) || entry.max_bytes < 0) {
      errors.push(`${location}.max_bytes: expected a non-negative safe integer`);
    } else if (hasValidTotal && entry.max_bytes > allowlist.max_total_bytes) {
      errors.push(`${location}.max_bytes: exceeds max_total_bytes (${allowlist.max_total_bytes})`);
    }
  }

  return errors;
}

function checkPosixProcFdSupport() {
  const {
    O_RDONLY,
    O_WRONLY,
    O_CREAT,
    O_EXCL,
    O_NOFOLLOW,
    O_NONBLOCK,
    O_DIRECTORY,
    O_CLOEXEC,
  } = fs.constants;

  const hasRequiredFlags =
    Number.isInteger(O_RDONLY) &&
    Number.isInteger(O_WRONLY) &&
    Number.isInteger(O_CREAT) && O_CREAT !== 0 &&
    Number.isInteger(O_EXCL) && O_EXCL !== 0 &&
    Number.isInteger(O_NOFOLLOW) && O_NOFOLLOW !== 0 &&
    Number.isInteger(O_NONBLOCK) && O_NONBLOCK !== 0 &&
    Number.isInteger(O_DIRECTORY) && O_DIRECTORY !== 0 &&
    Number.isInteger(O_CLOEXEC) && O_CLOEXEC !== 0;

  if (!hasRequiredFlags) {
    return {
      supported: false,
      reason: "OS descriptor-anchored no-follow, nonblocking, directory, cloexec, and exclusive-create flags are unavailable",
    };
  }

  let probeFd;
  try {
    probeFd = fs.openSync(".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    const fdStat = fs.fstatSync(probeFd, { bigint: true });
    const procStat = fs.statSync(`/proc/self/fd/${probeFd}`, { bigint: true });
    if (!fdStat.isDirectory() || !procStat.isDirectory() || fdStat.dev !== procStat.dev || fdStat.ino !== procStat.ino) {
      return {
        supported: false,
        reason: "OS descriptor-anchored directory operations via /proc/self/fd are unavailable",
      };
    }
    return { supported: true, reason: null };
  } catch {
    return {
      supported: false,
      reason: "OS descriptor-anchored directory operations via /proc/self/fd are unavailable",
    };
  } finally {
    if (probeFd !== undefined) {
      try {
        fs.closeSync(probeFd);
      } catch {
        // Ignore close errors during capability probe.
      }
    }
  }
}

function createPosixProcFdOps() {
  return {
    checkSupport: checkPosixProcFdSupport,
    openRootDir(dirPath) {
      const { O_RDONLY, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, O_CLOEXEC } = fs.constants;
      return fs.openSync(dirPath, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    },
    openDirNoFollow(dirFd, component) {
      const { O_RDONLY, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, O_CLOEXEC } = fs.constants;
      return fs.openSync(`/proc/self/fd/${dirFd}/${component}`, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    },
    mkdirExclusive(dirFd, component) {
      fs.mkdirSync(`/proc/self/fd/${dirFd}/${component}`, { mode: 0o700 });
    },
    openLeafReadNoFollowNonBlock(dirFd, component) {
      const { O_RDONLY, O_NOFOLLOW, O_NONBLOCK, O_CLOEXEC } = fs.constants;
      return fs.openSync(`/proc/self/fd/${dirFd}/${component}`, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    },
    openLeafWriteExclusiveNoFollow(dirFd, component) {
      const { O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW, O_NONBLOCK, O_CLOEXEC } = fs.constants;
      return fs.openSync(
        `/proc/self/fd/${dirFd}/${component}`,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
        0o600,
      );
    },
    unlinkRelative(dirFd, component) {
      fs.unlinkSync(`/proc/self/fd/${dirFd}/${component}`);
    },
    fstat(fd) {
      return fs.fstatSync(fd, { bigint: true });
    },
    read(fd, buffer, offset, length) {
      return fs.readSync(fd, buffer, offset, length, null);
    },
    write(fd, buffer, offset, length) {
      return fs.writeSync(fd, buffer, offset, length, null);
    },
    close(fd) {
      fs.closeSync(fd);
    },
  };
}

function toBigInt(value) {
  return typeof value === "bigint" ? value : BigInt(value);
}

function isSymlinkError(error) {
  return Boolean(error && (error.code === "ELOOP" || error.code === "EMLINK"));
}

function checkPromotionSupport(ops = createPosixProcFdOps()) {
  return ops.checkSupport();
}

function openTrustedRoots(scratchDir, artifactsDir, ops = createPosixProcFdOps()) {
  const support = ops.checkSupport();
  if (!support.supported) {
    throw new PromotionError("OS_PRIMITIVES_UNAVAILABLE", support.reason);
  }

  let scratchFd;
  let artifactsFd;
  try {
    try {
      scratchFd = ops.openRootDir(scratchDir);
    } catch (error) {
      if (isSymlinkError(error)) {
        throw new PromotionError("SYMLINK_REJECTED", "scratch root must not be a symlink");
      }
      throw new PromotionError("ROOT_OPEN_FAILED", "scratch root could not be opened as a trusted directory");
    }

    const scratchStat = ops.fstat(scratchFd);
    if (!scratchStat.isDirectory()) {
      throw new PromotionError("ROOT_NOT_DIRECTORY", "scratch root must be a directory");
    }

    try {
      artifactsFd = ops.openRootDir(artifactsDir);
    } catch (error) {
      if (isSymlinkError(error)) {
        throw new PromotionError("SYMLINK_REJECTED", "artifacts root must not be a symlink");
      }
      throw new PromotionError("ROOT_OPEN_FAILED", "artifacts root could not be opened as a trusted directory");
    }

    const artifactsStat = ops.fstat(artifactsFd);
    if (!artifactsStat.isDirectory()) {
      throw new PromotionError("ROOT_NOT_DIRECTORY", "artifacts root must be a directory");
    }

    if (toBigInt(scratchStat.dev) === toBigInt(artifactsStat.dev) && toBigInt(scratchStat.ino) === toBigInt(artifactsStat.ino)) {
      throw new PromotionError("SAME_ROOT_DIRECTORY", "scratch root and artifacts root must be distinct directories");
    }

    let closed = false;
    return {
      scratchFd,
      artifactsFd,
      close() {
        if (closed) return;
        closed = true;
        try {
          ops.close(scratchFd);
        } finally {
          ops.close(artifactsFd);
        }
      },
    };
  } catch (error) {
    if (artifactsFd !== undefined) {
      try { ops.close(artifactsFd); } catch {}
    }
    if (scratchFd !== undefined) {
      try { ops.close(scratchFd); } catch {}
    }
    throw error;
  }
}

function walkScratchParents(scratchFd, parentSegments, ops) {
  let currentFd = scratchFd;
  try {
    for (const segment of parentSegments) {
      let nextFd;
      try {
        nextFd = ops.openDirNoFollow(currentFd, segment);
      } catch (error) {
        if (isSymlinkError(error)) {
          throw new PromotionError("SYMLINK_REJECTED", "scratch parent component must not be a symlink");
        }
        if (error && error.code === "ENOTDIR") {
          throw new PromotionError("NOT_A_DIRECTORY", "scratch parent component is not a directory");
        }
        if (error && error.code === "ENOENT") {
          throw new PromotionError("NOT_FOUND", "scratch parent directory does not exist");
        }
        throw new PromotionError("OPEN_FAILED", "scratch parent directory could not be opened safely");
      }

      const stat = ops.fstat(nextFd);
      if (!stat.isDirectory()) {
        try { ops.close(nextFd); } catch {}
        throw new PromotionError("NOT_A_DIRECTORY", "scratch parent component is not a directory");
      }

      if (currentFd !== scratchFd) {
        ops.close(currentFd);
      }
      currentFd = nextFd;
    }
    return currentFd;
  } catch (error) {
    if (currentFd !== scratchFd) {
      try { ops.close(currentFd); } catch {}
    }
    throw error;
  }
}

function walkOrCreateArtifactsParents(artifactsFd, parentSegments, ops) {
  let currentFd = artifactsFd;
  try {
    for (const segment of parentSegments) {
      let nextFd;
      try {
        nextFd = ops.openDirNoFollow(currentFd, segment);
      } catch (error) {
        if (error && error.code === "ENOENT") {
          try {
            ops.mkdirExclusive(currentFd, segment);
          } catch (mkdirError) {
            if (mkdirError && mkdirError.code === "EEXIST") {
              throw new PromotionError("DEST_DIR_RACE", "destination parent directory appeared concurrently during creation");
            }
            throw new PromotionError("DEST_MKDIR_FAILED", "destination parent directory could not be created exclusively");
          }
          try {
            nextFd = ops.openDirNoFollow(currentFd, segment);
          } catch (reopenError) {
            if (isSymlinkError(reopenError)) {
              throw new PromotionError("SYMLINK_REJECTED", "destination parent component must not be a symlink");
            }
            throw new PromotionError("DEST_OPEN_FAILED", "destination parent directory could not be reopened no-follow");
          }
        } else if (isSymlinkError(error)) {
          throw new PromotionError("SYMLINK_REJECTED", "destination parent component must not be a symlink");
        } else if (error && error.code === "ENOTDIR") {
          throw new PromotionError("DEST_NOT_DIRECTORY", "destination parent component is not a directory");
        } else {
          throw new PromotionError("DEST_OPEN_FAILED", "destination parent directory could not be opened safely");
        }
      }

      const stat = ops.fstat(nextFd);
      if (!stat.isDirectory()) {
        try { ops.close(nextFd); } catch {}
        throw new PromotionError("DEST_NOT_DIRECTORY", "destination parent component is not a directory");
      }

      if (currentFd !== artifactsFd) {
        ops.close(currentFd);
      }
      currentFd = nextFd;
    }
    return currentFd;
  } catch (error) {
    if (currentFd !== artifactsFd) {
      try { ops.close(currentFd); } catch {}
    }
    throw error;
  }
}

function statsMatchSourceIdentity(initialStat, finalStat) {
  if (!finalStat.isFile()) return false;
  if (toBigInt(finalStat.dev) !== toBigInt(initialStat.dev)) return false;
  if (toBigInt(finalStat.ino) !== toBigInt(initialStat.ino)) return false;
  if (toBigInt(finalStat.mode) !== toBigInt(initialStat.mode)) return false;
  if (toBigInt(finalStat.nlink) !== 1n || toBigInt(finalStat.nlink) !== toBigInt(initialStat.nlink)) return false;
  if (toBigInt(finalStat.size) !== toBigInt(initialStat.size)) return false;
  if (initialStat.mtimeNs !== undefined && finalStat.mtimeNs !== undefined) {
    if (toBigInt(finalStat.mtimeNs) !== toBigInt(initialStat.mtimeNs)) return false;
  } else if (initialStat.mtimeMs !== undefined && finalStat.mtimeMs !== undefined) {
    if (finalStat.mtimeMs !== initialStat.mtimeMs) return false;
  }
  return true;
}

function promoteSingleFile(scratchFd, artifactsFd, entry, remainingTotalBytes, ops) {
  // Step 1: Validate declared relative path.
  if (!isSafeRelativePath(entry.path)) {
    throw new PromotionError("INVALID_PATH", "declared path is not a safe relative path");
  }
  const segments = entry.path.split("/");
  const parentSegments = segments.slice(0, -1);
  const leafName = segments[segments.length - 1];

  let srcParentFd = scratchFd;
  let srcFd;
  let destParentFd = artifactsFd;
  let destFd;
  let destCreated = false;
  let succeeded = false;

  try {
    // Step 2: Walk scratch parent components from retained scratch-root descriptor no-follow.
    srcParentFd = walkScratchParents(scratchFd, parentSegments, ops);

    // Step 3: Open leaf no-follow and nonblocking.
    try {
      srcFd = ops.openLeafReadNoFollowNonBlock(srcParentFd, leafName);
    } catch (error) {
      if (isSymlinkError(error)) {
        throw new PromotionError("SYMLINK_REJECTED", "scratch entry must not be a symlink");
      }
      if (error && error.code === "ENOENT") {
        throw new PromotionError("NOT_FOUND", "scratch entry does not exist");
      }
      if (error && error.code === "ENXIO") {
        throw new PromotionError("NON_REGULAR_FILE", "scratch entry is not a regular file");
      }
      throw new PromotionError("OPEN_FAILED", "scratch entry could not be opened safely");
    }

    // Step 4: Verify with fstat that source is a regular file, nlink === 1, and within limits.
    const initialStat = ops.fstat(srcFd);
    if (!initialStat.isFile()) {
      throw new PromotionError("NON_REGULAR_FILE", "scratch entry must be a regular file");
    }
    if (toBigInt(initialStat.nlink) !== 1n) {
      throw new PromotionError("HARD_LINK_REJECTED", "scratch entry must have link count exactly 1");
    }

    const initialSize = toBigInt(initialStat.size);
    const entryLimit = BigInt(entry.max_bytes);
    const totalRemaining = BigInt(remainingTotalBytes);
    if (initialSize < 0n) {
      throw new PromotionError("INVALID_SIZE", "scratch entry reported a negative size");
    }
    if (initialSize > entryLimit) {
      throw new PromotionError("FILE_TOO_LARGE", `scratch entry exceeds per-file limit of ${entry.max_bytes} bytes`);
    }
    if (initialSize > totalRemaining) {
      throw new PromotionError("CUMULATIVE_LIMIT_EXCEEDED", `scratch entry exceeds remaining cumulative limit of ${remainingTotalBytes} bytes`);
    }

    // Step 7: Walk destination parent components from retained artifacts-root descriptor no-follow,
    // creating missing directories exclusively and reopening them no-follow.
    destParentFd = walkOrCreateArtifactsParents(artifactsFd, parentSegments, ops);

    // Step 8 (part 1): Create destination leaf exclusively without following links and verify fstat.
    try {
      destFd = ops.openLeafWriteExclusiveNoFollow(destParentFd, leafName);
    } catch (error) {
      if (error && error.code === "EEXIST") {
        throw new PromotionError("DEST_EXISTS", "destination artifact already exists");
      }
      if (isSymlinkError(error)) {
        throw new PromotionError("SYMLINK_REJECTED", "destination artifact must not be a symlink");
      }
      throw new PromotionError("DEST_OPEN_FAILED", "destination artifact could not be created exclusively");
    }
    destCreated = true;

    const destInitialStat = ops.fstat(destFd);
    if (!destInitialStat.isFile()) {
      throw new PromotionError("DEST_NOT_REGULAR", "destination artifact is not a regular file");
    }
    if (toBigInt(destInitialStat.nlink) !== 1n) {
      throw new PromotionError("DEST_HARD_LINK", "destination artifact must have link count exactly 1");
    }

    // Steps 5, 6, and 8 (part 2): Enforce limits while reading from srcFd and copying to destFd.
    const buffer = Buffer.allocUnsafe(COPY_CHUNK_BYTES);
    let bytesCopied = 0n;
    while (true) {
      const count = ops.read(srcFd, buffer, 0, buffer.length);
      if (count === 0) break;
      bytesCopied += BigInt(count);

      if (bytesCopied > entryLimit) {
        throw new PromotionError("FILE_TOO_LARGE", `scratch entry exceeded per-file limit of ${entry.max_bytes} bytes while reading`);
      }
      if (bytesCopied > totalRemaining) {
        throw new PromotionError("CUMULATIVE_LIMIT_EXCEEDED", `scratch entry exceeded remaining cumulative limit of ${remainingTotalBytes} bytes while reading`);
      }
      if (bytesCopied > initialSize) {
        throw new PromotionError("SOURCE_CHANGED", "scratch entry grew during copy");
      }

      let offset = 0;
      while (offset < count) {
        const written = ops.write(destFd, buffer, offset, count - offset);
        if (written <= 0) {
          throw new PromotionError("DEST_WRITE_FAILED", "destination write made no progress");
        }
        offset += written;
      }
    }

    if (bytesCopied !== initialSize) {
      throw new PromotionError("SOURCE_CHANGED", "scratch entry size changed during copy");
    }

    // Step 6: Repeat fstat on source descriptor and reject changed identity, type, link count, size, or mtime.
    const finalStat = ops.fstat(srcFd);
    if (!statsMatchSourceIdentity(initialStat, finalStat)) {
      throw new PromotionError("SOURCE_CHANGED", "scratch entry changed identity, type, link count, size, or modification time during copy");
    }

    // Confirm destination descriptor still matches a single-link regular file with exact copied size.
    const destFinalStat = ops.fstat(destFd);
    if (
      !destFinalStat.isFile() ||
      toBigInt(destFinalStat.dev) !== toBigInt(destInitialStat.dev) ||
      toBigInt(destFinalStat.ino) !== toBigInt(destInitialStat.ino) ||
      toBigInt(destFinalStat.nlink) !== 1n ||
      toBigInt(destFinalStat.size) !== bytesCopied
    ) {
      throw new PromotionError("DEST_CHANGED", "destination artifact changed during copy");
    }

    succeeded = true;
    return { path: entry.path, bytes: Number(bytesCopied) };
  } finally {
    if (srcFd !== undefined) {
      try { ops.close(srcFd); } catch {}
    }
    if (srcParentFd !== scratchFd) {
      try { ops.close(srcParentFd); } catch {}
    }
    if (destFd !== undefined) {
      try { ops.close(destFd); } catch {}
    }
    if (destCreated && !succeeded) {
      try { ops.unlinkRelative(destParentFd, leafName); } catch {}
    }
    if (destParentFd !== artifactsFd) {
      try { ops.close(destParentFd); } catch {}
    }
  }
}

function promoteFromDescriptors(scratchFd, artifactsFd, allowlist, ops = createPosixProcFdOps()) {
  const errors = createErrorList();
  const support = ops.checkSupport();
  if (!support.supported) {
    errors.push(support.reason);
    return { ok: false, promoted: [], rejected: [], totalBytes: 0, errors };
  }

  const allowlistErrors = validateAllowlist(allowlist);
  if (allowlistErrors.length > 0) {
    errors.push(...allowlistErrors);
    return { ok: false, promoted: [], rejected: [], totalBytes: 0, errors };
  }

  let scratchStat;
  let artifactsStat;
  try {
    scratchStat = ops.fstat(scratchFd);
    artifactsStat = ops.fstat(artifactsFd);
  } catch {
    errors.push("retained root descriptors could not be verified with fstat");
    return { ok: false, promoted: [], rejected: [], totalBytes: 0, errors };
  }

  if (!scratchStat.isDirectory() || !artifactsStat.isDirectory()) {
    errors.push("retained scratch and artifacts descriptors must both be directories");
    return { ok: false, promoted: [], rejected: [], totalBytes: 0, errors };
  }

  if (toBigInt(scratchStat.dev) === toBigInt(artifactsStat.dev) && toBigInt(scratchStat.ino) === toBigInt(artifactsStat.ino)) {
    errors.push("scratch root and artifacts root must be distinct directories");
    return { ok: false, promoted: [], rejected: [], totalBytes: 0, errors };
  }

  const promoted = [];
  const rejected = [];
  let totalBytes = 0;

  for (const entry of allowlist.files) {
    const remainingTotalBytes = allowlist.max_total_bytes - totalBytes;
    try {
      const item = promoteSingleFile(scratchFd, artifactsFd, entry, remainingTotalBytes, ops);
      promoted.push(item);
      totalBytes += item.bytes;
    } catch (error) {
      const code = error instanceof PromotionError ? error.code : "PROMOTION_FAILED";
      const reason = error instanceof PromotionError ? error.message : "artifact could not be promoted safely";
      rejected.push({ path: entry.path, code, reason });
      errors.push(`${safeQuote(entry.path)}: ${reason}`);
    }
  }

  return {
    ok: rejected.length === 0 && errors.length === 0,
    promoted,
    rejected,
    totalBytes,
    errors,
  };
}

function promoteArtifacts(scratchDir, artifactsDir, allowlist, ops = createPosixProcFdOps()) {
  const errors = createErrorList();
  const support = ops.checkSupport();
  if (!support.supported) {
    errors.push(support.reason);
    return { ok: false, promoted: [], rejected: [], totalBytes: 0, errors };
  }

  const allowlistErrors = validateAllowlist(allowlist);
  if (allowlistErrors.length > 0) {
    errors.push(...allowlistErrors);
    return { ok: false, promoted: [], rejected: [], totalBytes: 0, errors };
  }

  let roots;
  try {
    roots = openTrustedRoots(scratchDir, artifactsDir, ops);
  } catch (error) {
    const reason = error instanceof PromotionError ? error.message : "trusted root directories could not be opened safely";
    errors.push(reason);
    return { ok: false, promoted: [], rejected: [], totalBytes: 0, errors };
  }

  try {
    return promoteFromDescriptors(roots.scratchFd, roots.artifactsFd, allowlist, ops);
  } finally {
    roots.close();
  }
}

function run(argv = process.argv.slice(2), ops = createPosixProcFdOps()) {
  if (argv.length === 1 && argv[0] === "--check") {
    const support = checkPromotionSupport(ops);
    if (!support.supported) {
      console.error(`FAIL: ${escapeUnsafeDiagnosticCharacters(support.reason)}`);
      return 1;
    }
    console.log("PASS: artifact promotion primitives available");
    return 0;
  }

  if (argv.length !== 3) {
    console.error("Usage: node promote-artifacts.cjs <scratch-dir> <artifacts-dir> <allowlist.json>");
    console.error("       node promote-artifacts.cjs --check");
    return 1;
  }

  const [scratchDir, artifactsDir, allowlistPath] = argv;

  const support = checkPromotionSupport(ops);
  if (!support.supported) {
    console.error(`Failed to promote artifacts: ${escapeUnsafeDiagnosticCharacters(support.reason)}`);
    return 1;
  }

  let contents;
  try {
    contents = readFileWithinLimit(allowlistPath);
  } catch (error) {
    const reason = error instanceof SafeInputError ? error.message : "input could not be opened or read safely";
    console.error(`Failed to read allowlist JSON: ${escapeUnsafeDiagnosticCharacters(reason)}`);
    return 1;
  }

  try {
    preflightJsonText(contents);
  } catch (error) {
    const reason = error instanceof JsonStructureError ? error.message : "invalid JSON structure";
    console.error(`Failed to parse allowlist JSON: ${escapeUnsafeDiagnosticCharacters(reason)}`);
    return 1;
  }

  let allowlist;
  try {
    allowlist = JSON.parse(contents);
  } catch {
    console.error("Failed to parse allowlist JSON: invalid JSON syntax");
    return 1;
  }

  const result = promoteArtifacts(scratchDir, artifactsDir, allowlist, ops);
  for (const message of result.errors) {
    console.error("ERROR:", escapeUnsafeDiagnosticCharacters(message));
  }
  if (!result.ok) {
    const cap = result.errors.length === LIMITS.validationErrors ? `; output capped at ${LIMITS.validationErrors}` : "";
    console.error(`FAIL: ${result.errors.length} promotion error(s)${cap}`);
    return 1;
  }

  console.log(`PASS: promoted ${result.promoted.length} artifact(s) (${result.totalBytes} bytes)`);
  return 0;
}

module.exports = {
  COPY_CHUNK_BYTES,
  LIMITS,
  PATH_FORBIDDEN_CHARACTER,
  PromotionError,
  SafeInputError,
  UNSAFE_DIAGNOSTIC_CHARACTER,
  VISIBLE_CONTENT,
  WINDOWS_RESERVED_COMPONENT,
  checkPosixProcFdSupport,
  checkPromotionSupport,
  createPosixProcFdOps,
  escapeUnsafeDiagnosticCharacters,
  isSafeRelativePath,
  openTrustedRoots,
  preflightJsonText,
  promoteArtifacts,
  promoteFromDescriptors,
  readFileWithinLimit,
  run,
  safeQuote,
  validateAllowlist,
};

if (require.main === module) process.exit(run(process.argv.slice(2)));
