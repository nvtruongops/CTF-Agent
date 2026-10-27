import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { isIP } from 'node:net';
import { nativePath } from './paths.js';

function normalizeHost(host) {
  const normalized = String(host).replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (!normalized || normalized.includes('*')) {
    throw new TypeError('wildcard or empty hosts are not allowed');
  }

  if (isIP(normalized)) return normalized;

  const labels = normalized.split('.');
  const valid = labels.every((label) => (
    label.length >= 1
    && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  ));
  if (!valid || normalized.length > 253) {
    throw new TypeError('target host is invalid');
  }
  return normalized;
}

function parseTargetUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new TypeError('only HTTP and HTTPS URLs are supported');
    }
    if (url.username || url.password) throw new TypeError('URL credentials are not allowed');
    const host = normalizeHost(url.hostname);
    const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new TypeError('target port must be between 1 and 65535');
    }
    return { host, port };
  } catch (error) {
    if (error instanceof TypeError && error.message !== 'Invalid URL') throw error;
    throw new TypeError('target URL or port is invalid');
  }
}

export function parseTarget(value) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError('target must be a non-empty host:port string');
  }
  if (/^https?:\/\//i.test(value)) return parseTargetUrl(value);

  let url;
  try {
    url = new URL(`tcp://${value.trim()}`);
  } catch {
    throw new TypeError('target host or port is invalid');
  }
  if (url.username || url.password || (url.pathname !== '' && url.pathname !== '/') || url.search || url.hash) {
    throw new TypeError('target must contain only a host and port');
  }
  if (!url.port) throw new TypeError('target must include an explicit port');

  const host = normalizeHost(url.hostname);
  const port = Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TypeError('target port must be between 1 and 65535');
  }
  return { host, port };
}

function parseNetworkTarget(value) {
  return /^https?:\/\//i.test(String(value)) ? parseTargetUrl(value) : parseTarget(value);
}

export function isTargetAllowed(value, scope) {
  let target;
  try {
    target = parseNetworkTarget(value);
  } catch {
    return false;
  }
  return (scope?.targets ?? []).some((allowed) => (
    allowed.host === target.host && allowed.port === target.port
  ));
}

export function assertHostAllowed(value, scope) {
  const host = normalizeHost(value);
  if (!(scope?.targets ?? []).some((target) => target.host === host)) {
    const error = new Error(`Host ${host} is outside the active CTF scope.`);
    error.code = 'HOST_OUT_OF_SCOPE';
    throw error;
  }
  return host;
}

export function assertTargetAllowed(value, scope) {
  const target = parseNetworkTarget(value);
  if (!isTargetAllowed(value, scope)) {
    const error = new Error(`Target ${target.host}:${target.port} is outside the active CTF scope.`);
    error.code = 'TARGET_OUT_OF_SCOPE';
    throw error;
  }
  return target;
}

export function assertWorkspacePath(value, scope) {
  if (typeof value !== 'string' || !path.posix.isAbsolute(value) || value.includes('\\')) {
    throw new TypeError('workspace path must be an absolute canonical WSL path');
  }
  const segments = value.split('/');
  if (segments.some((segment) => segment === '.' || segment === '..')) {
    throw new TypeError('workspace path must be canonical and must not contain dot segments');
  }
  const root = path.posix.normalize(scope?.wslWorkspace ?? '');
  const candidate = path.posix.normalize(value);
  if (!root.startsWith('/home/ctfagent/ctf-workspaces/')) {
    throw new TypeError('active scope has an invalid WSL workspace root');
  }
  const relative = path.posix.relative(root, candidate);
  if (!relative || relative === '..' || relative.startsWith('../') || path.posix.isAbsolute(relative)) {
    throw new Error('path is outside the active WSL workspace');
  }
  return candidate;
}

function isInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (
    relative !== '..'
    && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative)
  );
}

function canonicalPath(value) {
  return path.normalize(realpathSync(nativePath(value)).replace(/^\\\\\?\\/, ''));
}

function validateChallengeId(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value) || value.includes('..')) {
    throw new TypeError('challenge ID must be 1-64 safe filename characters and cannot contain ..');
  }
  return value;
}

export function initScope({ projectRoot, challengeId, workspace, targets = [], sourceRoots = [] }) {
  projectRoot = nativePath(projectRoot);
  if (!path.isAbsolute(projectRoot)) {
    throw new TypeError('projectRoot must be an absolute path');
  }
  const id = validateChallengeId(challengeId);
  if (!Array.isArray(targets)) throw new TypeError('targets must be an array of host:port strings');
  const normalizedTargets = [...new Map(targets.map((target) => {
    const parsed = parseTarget(target);
    return [`${parsed.host}:${parsed.port}`, parsed];
  })).values()];
  const root = canonicalPath(projectRoot);
  const workspaceRoot = path.resolve(root, '.ctf-workspaces');
  const workspacePath = path.resolve(root, nativePath(workspace || path.join('.ctf-workspaces', id)));
  const expectedWorkspace = path.resolve(workspaceRoot, id);
  if (path.relative(expectedWorkspace, workspacePath) !== '') {
    throw new TypeError('workspace root must be inside .ctf-workspaces/<challenge-id>');
  }

  if (existsSync(workspaceRoot)) {
    if (lstatSync(workspaceRoot).isSymbolicLink()) {
      throw new TypeError('workspace root cannot be a symlink or junction');
    }
    const canonicalWorkspaceRoot = canonicalPath(workspaceRoot);
    if (!isInside(root, canonicalWorkspaceRoot)) {
      throw new TypeError('workspace root resolves outside the project');
    }
  }
  if (existsSync(workspacePath) && lstatSync(workspacePath).isSymbolicLink()) {
    throw new TypeError('workspace directory cannot be a symlink or junction');
  }

  const scopeDirectory = path.join(root, '.ctf-agent');
  const scopePath = path.join(scopeDirectory, 'scope.json');
  if (existsSync(scopeDirectory) && lstatSync(scopeDirectory).isSymbolicLink()) {
    throw new TypeError('scope directory cannot be a symlink or junction');
  }
  if (existsSync(scopePath)) throw new Error('scope already exists; clear it before initializing another challenge');

  mkdirSync(workspacePath, { recursive: true, mode: 0o700 });
  mkdirSync(scopeDirectory, { recursive: true, mode: 0o700 });
  const canonicalWorkspace = canonicalPath(workspacePath);
  if (!isInside(canonicalPath(workspaceRoot), canonicalWorkspace)) {
    throw new TypeError('workspace resolves outside .ctf-workspaces');
  }
  const roots = sourceRoots.length > 0 ? sourceRoots : [workspacePath];
  const canonicalRoots = [...new Set(roots.map((sourceRoot) => {
    const resolved = path.resolve(root, nativePath(sourceRoot));
    const sourceStat = statSync(resolved);
    if (!sourceStat.isDirectory()) throw new TypeError('each source root must be an existing directory');
    return canonicalPath(resolved);
  }))];

  const scope = {
    schemaVersion: 1,
    challengeId: id,
    workspace: path.relative(root, canonicalWorkspace).split(path.sep).join('/'),
    wslWorkspace: `/home/ctfagent/ctf-workspaces/${id}`,
    sourceRoots: canonicalRoots,
    targets: normalizedTargets,
    createdAt: new Date().toISOString(),
  };

  writeFileSync(scopePath, `${JSON.stringify(scope, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return scope;
}

export function loadScope(projectRoot) {
  projectRoot = nativePath(projectRoot);
  if (!path.isAbsolute(projectRoot)) {
    throw new TypeError('projectRoot must be an absolute path');
  }
  const root = canonicalPath(projectRoot);
  const scopeDirectory = path.join(root, '.ctf-agent');
  const scopePath = path.join(scopeDirectory, 'scope.json');
  if (existsSync(scopeDirectory) && lstatSync(scopeDirectory).isSymbolicLink()) {
    const error = new Error('scope directory cannot be a symlink or junction');
    error.code = 'INVALID_SCOPE';
    throw error;
  }
  if (!existsSync(scopePath)) {
    const error = new Error('no active CTF scope is configured');
    error.code = 'NO_ACTIVE_SCOPE';
    throw error;
  }
  if (lstatSync(scopePath).isSymbolicLink()) {
    const error = new Error('scope file cannot be a symlink');
    error.code = 'INVALID_SCOPE';
    throw error;
  }

  let scope;
  try {
    scope = JSON.parse(readFileSync(scopePath, 'utf8'));
  } catch (error) {
    const invalid = new Error(`scope file is unreadable or invalid JSON: ${error.message}`);
    invalid.code = 'INVALID_SCOPE';
    throw invalid;
  }

  try {
    const challengeId = validateChallengeId(scope.challengeId);
    const expectedWorkspace = path.resolve(root, '.ctf-workspaces', challengeId);
    const actualWorkspace = path.resolve(root, scope.workspace);
    if (path.relative(expectedWorkspace, actualWorkspace) !== '') {
      throw new Error('workspace path does not match the challenge ID');
    }
    if (scope.wslWorkspace !== `/home/ctfagent/ctf-workspaces/${challengeId}`) {
      throw new Error('WSL workspace path does not match the challenge ID');
    }
    if (!Array.isArray(scope.targets) || !Array.isArray(scope.sourceRoots)) {
      throw new Error('targets and sourceRoots must be arrays');
    }
    const targets = scope.targets.map((target) => {
      const parsed = parseTarget(`${target.host}:${target.port}`);
      if (parsed.host !== target.host || parsed.port !== target.port) {
        throw new Error('target entry is not normalized');
      }
      return parsed;
    });
    const sourceRoots = scope.sourceRoots.map((sourceRoot) => {
      if (typeof sourceRoot !== 'string' || !path.isAbsolute(nativePath(sourceRoot))) {
        throw new Error('source root must be an absolute path');
      }
      const canonical = canonicalPath(sourceRoot);
      if (!statSync(canonical).isDirectory()) throw new Error('source root is not a directory');
      return canonical;
    });
    return { ...scope, challengeId, targets, sourceRoots };
  } catch (error) {
    const invalid = new Error(`scope contents are invalid: ${error.message}`);
    invalid.code = 'INVALID_SCOPE';
    throw invalid;
  }
}
