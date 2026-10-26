import { createHash } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import { runWsl as defaultRunWsl } from '../wsl.js';
import * as z from 'zod/v4';
import { assertWorkspacePath, loadScope } from '../scope.js';
import { WORKSPACE_WORKER_SOURCE } from './workspace-command.js';

const DEFAULT_MAX_IMPORT_BYTES = 256 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_RESULT_BYTES = 4096;
const MAX_WORKSPACE_WRITE_BYTES = 256 * 1024 * 1024;
function canonicalHostPath(value) {
  return path.win32.normalize(realpathSync(value).replace(/^\\\\\?\\/, ''));
}

function isInside(root, candidate) {
  const relative = path.win32.relative(root, candidate);
  return relative === '' || (
    relative !== '..'
    && !relative.startsWith(`..${path.win32.sep}`)
    && !path.win32.isAbsolute(relative)
  );
}

function safeRelativePath(root, file) {
  const relative = path.win32.relative(root, file);
  if (!relative || relative === '..' || relative.startsWith(`..${path.win32.sep}`) || path.win32.isAbsolute(relative)) {
    throw new Error('Source path is outside an allowed source root.');
  }
  const segments = relative.split(/[\\/]+/);
  if (segments.some((segment) => !segment || segment === '.' || segment === '..')) {
    throw new Error('Source path contains an invalid component.');
  }
  return segments;
}

function sameFile(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function readVerifiedSource(sourcePath, sourceRealPath, expectedStat, maxImportBytes) {
  const descriptor = openSync(sourceRealPath, 'r');
  try {
    const openedStat = fstatSync(descriptor);
    if (!openedStat.isFile() || !sameFile(expectedStat, openedStat)) {
      throw new Error('Source file changed during validation.');
    }

    const buffer = Buffer.alloc(64 * 1024);
    const chunks = [];
    let total = 0;
    while (true) {
      const bytesRead = readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maxImportBytes) {
        throw new RangeError(`Source file exceeds the ${maxImportBytes}-byte import size limit.`);
      }
      chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }

    if (!sameFile(openedStat, fstatSync(descriptor)) || canonicalHostPath(sourcePath) !== sourceRealPath) {
      throw new Error('Source file changed during import.');
    }
    return Buffer.concat(chunks, total);
  } finally {
    closeSync(descriptor);
  }
}

async function writeWorkspaceBytesInternal({
  bytes,
  destinationPath,
  scope,
  runWsl = defaultRunWsl,
  maxBytes = DEFAULT_MAX_IMPORT_BYTES,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}, operation) {
  if (!Buffer.isBuffer(bytes)) throw new TypeError('bytes must be a Buffer');
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_WORKSPACE_WRITE_BYTES) {
    throw new RangeError(`maxBytes must be from 1 to ${MAX_WORKSPACE_WRITE_BYTES}`);
  }
  if (bytes.length > maxBytes) throw new RangeError(`workspace write exceeds the ${maxBytes}-byte limit`);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new RangeError('timeoutMs must be a positive integer');
  const destination = assertWorkspacePath(destinationPath, scope);
  if (destination !== destinationPath) throw new TypeError('destinationPath must be canonical');

  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const result = await runWsl([
    '--distribution', 'kali-linux', '--user', 'ctfagent', '--exec',
    'python3', '-c', WORKSPACE_WORKER_SOURCE, 'write', scope.wslWorkspace, destination, String(maxBytes),
  ], { input: bytes, timeoutMs, maxOutputBytes: MAX_RESULT_BYTES });
  if (result.exitCode !== 0 || result.timedOut || result.truncated) {
    throw new Error(`${operation} failed: ${result.stderr || 'WSL transfer did not complete.'}`);
  }

  let written;
  try {
    written = JSON.parse(result.stdout.trim());
  } catch {
    throw new Error(`${operation} returned an invalid verification response.`);
  }
  if (written.bytes !== bytes.length || written.sha256 !== sha256) {
    throw new Error(`${operation} digest mismatch.`);
  }
  return { destinationPath: destination, bytes: bytes.length, sha256 };
}

export function writeWorkspaceBytes(options = {}) {
  return writeWorkspaceBytesInternal(options, 'Workspace write');
}

export async function importWorkspaceFile({
  sourcePath,
  scope,
  runWsl = defaultRunWsl,
  maxImportBytes = DEFAULT_MAX_IMPORT_BYTES,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (typeof sourcePath !== 'string' || !path.win32.isAbsolute(sourcePath)) {
    throw new TypeError('sourcePath must be an absolute path');
  }
  if (!Number.isSafeInteger(maxImportBytes) || maxImportBytes < 1) {
    throw new RangeError('maxImportBytes must be a positive integer');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new RangeError('timeoutMs must be a positive integer');
  }
  if (!scope || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(scope.challengeId ?? '') || !Array.isArray(scope.sourceRoots)) {
    throw new TypeError('a valid active challenge scope is required');
  }

  const sourceLstat = lstatSync(sourcePath);
  if (sourceLstat.isSymbolicLink() || !sourceLstat.isFile()) {
    throw new TypeError('sourcePath must be a regular non-symlink file');
  }
  const sourceRealPath = canonicalHostPath(sourcePath);
  const sourceRoots = scope.sourceRoots.map((root) => canonicalHostPath(root));
  const matchedRoot = sourceRoots.find((root) => isInside(root, sourceRealPath));
  if (!matchedRoot) throw new Error('Source path is outside every allowed source root.');

  const sourceStat = statSync(sourceRealPath);
  if (sourceStat.size > maxImportBytes) {
    throw new RangeError(`Source file exceeds the ${maxImportBytes}-byte import size limit.`);
  }

  const relativeSegments = safeRelativePath(matchedRoot, sourceRealPath);
  const destinationRoot = `/home/ctfagent/ctf-workspaces/${scope.challengeId}`;
  const destinationPath = path.posix.resolve(destinationRoot, ...relativeSegments);
  const relativeDestination = path.posix.relative(destinationRoot, destinationPath);
  if (relativeDestination === '..' || relativeDestination.startsWith('../') || path.posix.isAbsolute(relativeDestination)) {
    throw new Error('Destination path escapes the scoped WSL workspace.');
  }

  const bytes = readVerifiedSource(sourcePath, sourceRealPath, sourceStat, maxImportBytes);
  const written = await writeWorkspaceBytesInternal({
    bytes,
    destinationPath,
    scope,
    runWsl,
    maxBytes: maxImportBytes,
    timeoutMs,
  }, 'Workspace import');

  return {
    challengeId: scope.challengeId,
    sourcePath: sourceRealPath,
    ...written,
  };
}

export function registerWorkspaceTool(server, { projectRoot, runWsl } = {}) {
  server.registerTool(
    'ctf_workspace_import',
    {
      description: 'Copy one regular challenge file from an allowed source root into the WSL workspace and verify its SHA-256.',
      inputSchema: z.object({ sourcePath: z.string().min(1).max(4096) }),
    },
    async ({ sourcePath }) => {
      try {
        const scope = loadScope(projectRoot);
        const result = await importWorkspaceFile({ sourcePath, scope, runWsl });
        return { content: [{ type: 'text', text: JSON.stringify(result) }] };
      } catch (error) {
        return {
          isError: true,
          content: [{
            type: 'text',
            text: JSON.stringify({
              code: error?.code ?? 'CTF_WORKSPACE_IMPORT_FAILED',
              message: error instanceof Error ? error.message : String(error),
            }),
          }],
        };
      }
    },
  );
}
