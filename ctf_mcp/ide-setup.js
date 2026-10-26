import { copyFileSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyEdits, modify, parse as parseJsonc } from 'jsonc-parser';
import { parse as parseToml, stringify as stringifyToml } from 'smol-toml';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const serverName = 'ctf-agent';
const packageName = 'ctf-agent';
const clientIds = new Set(['opencode', 'claude-code', 'codex', 'antigravity']);

function parseJson(text, client) {
  const errors = [];
  const value = parseJsonc(text, errors, { allowTrailingComma: true });
  if (errors.length || !value || Array.isArray(value) || typeof value !== 'object') {
    throw new TypeError(`invalid ${client} configuration`);
  }
  return value;
}

function mergeJson(text, client, propertyPath, entry) {
  const config = parseJson(text, client);
  let existing = config;
  for (const segment of propertyPath) existing = existing?.[segment];
  if (existing !== undefined && !isCtfAgentServer(existing)) {
    throw new TypeError(`${client} MCP server name is already used by an unrelated server`);
  }
  const edits = modify(text, propertyPath, entry, {
    formattingOptions: { insertSpaces: true, tabSize: 2, eol: '\n' },
  });
  return applyEdits(text, edits);
}

function isCtfAgentServer(server) {
  if (!server || typeof server !== 'object') return false;
  const command = Array.isArray(server.command) ? server.command : [server.command, ...(server.args ?? [])];
  return command[0] === 'npx'
    && command.some((argument) => typeof argument === 'string' && /^(?:@nvtruongops\/)?ctf-agent(?:-mcp)?@/.test(argument))
    && command.at(-1) === 'mcp';
}

function replaceTomlServer(text, entry) {
  const parsed = parseToml(text, { unsafeKeyBehaviour: 'throw' });
  if (parsed.mcp_servers !== undefined && (!parsed.mcp_servers || typeof parsed.mcp_servers !== 'object' || Array.isArray(parsed.mcp_servers))) {
    throw new TypeError('invalid Codex mcp_servers table');
  }
  const exists = Object.hasOwn(parsed.mcp_servers ?? {}, 'ctf_agent');
  if (exists && !isCtfAgentServer(parsed.mcp_servers.ctf_agent)) {
    throw new TypeError('Codex MCP server name is already used by an unrelated server');
  }
  const header = /^[ \t]*\[mcp_servers\.ctf_agent\][ \t]*(?:#.*)?$/gm;
  const matches = [...text.matchAll(header)];
  if (exists && matches.length !== 1) throw new TypeError('cannot safely update existing Codex ctf_agent table');
  const serialized = stringifyToml({ mcp_servers: { ctf_agent: entry } }).trimEnd();
  if (!exists) return `${text.trimEnd()}${text.trim() ? '\n\n' : ''}${serialized}\n`;

  const start = matches[0].index;
  const afterStart = start + matches[0][0].length;
  const nextTable = /^[ \t]*\[(?!\[)([^\]\r\n]+)\][ \t]*(?:#.*)?$|^[ \t]*\[\[([^\]\r\n]+)\]\][ \t]*(?:#.*)?$/gm;
  let end = text.length;
  for (const match of text.slice(afterStart).matchAll(nextTable)) {
    const tableName = (match[1] ?? match[2]).replaceAll('"', '').replaceAll("'", '');
    if (!tableName.startsWith('mcp_servers.ctf_agent.')) {
      end = afterStart + match.index;
      break;
    }
  }
  return `${text.slice(0, start)}${serialized}\n${text.slice(end).replace(/^\s*\n/, '')}`;
}

function configFor(client, homeDir, packageVersion, existingText) {
  const command = {
    command: 'npx',
    args: ['-y', `${packageName}@${packageVersion}`, 'mcp'],
  };
  if (client === 'opencode') {
    const entry = {
      type: 'local',
      command: ['npx', '-y', `${packageName}@${packageVersion}`, 'mcp'],
      cwd: '.',
      environment: {
        CTF_MCP_CTFD_URL: '{env:CTF_MCP_CTFD_URL}',
        CTF_MCP_CTFD_TOKEN: '{env:CTF_MCP_CTFD_TOKEN}',
      },
    };
    return {
      path: path.join(homeDir, '.config', 'opencode', 'opencode.json'),
      content: mergeJson(existingText, client, ['mcp', 'servers', serverName], entry),
    };
  }
  if (client === 'claude-code') {
    return {
      path: path.join(homeDir, '.claude.json'),
      content: mergeJson(existingText, client, ['mcpServers', serverName], {
        ...command,
        type: 'stdio',
        env: {
          CTF_MCP_CTFD_URL: '${CTF_MCP_CTFD_URL:-}',
          CTF_MCP_CTFD_TOKEN: '${CTF_MCP_CTFD_TOKEN:-}',
        },
      }),
    };
  }
  if (client === 'antigravity') {
    return {
      path: path.join(homeDir, '.gemini', 'config', 'mcp_config.json'),
      content: mergeJson(existingText, client, ['mcpServers', serverName], {
        ...command,
        cwd: '.',
      }),
    };
  }

  const tomlEntry = {
    ...command,
    cwd: '.',
    env_vars: ['CTF_MCP_CTFD_URL', 'CTF_MCP_CTFD_TOKEN'],
  };
  return {
    path: path.join(homeDir, '.codex', 'config.toml'),
    content: replaceTomlServer(existingText, tomlEntry),
  };
}

function readExisting(filePath) {
  try {
    const stat = lstatSync(filePath);
    if (stat.isSymbolicLink() || !stat.isFile()) throw new TypeError(`configuration path is not a regular file: ${filePath}`);
    return readFileSync(filePath, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function openCodeConfigPath(homeDir) {
  const json = path.join(homeDir, '.config', 'opencode', 'opencode.json');
  const jsonc = path.join(homeDir, '.config', 'opencode', 'opencode.jsonc');
  const existing = [json, jsonc].filter((filePath) => readExisting(filePath) !== null);
  if (existing.length > 1) throw new TypeError('multiple OpenCode global config files found; keep only opencode.json or opencode.jsonc');
  return existing[0] ?? json;
}

function guidanceFiles(root) {
  const result = [];
  for (const group of ['skills', 'references', 'rules']) {
    const groupPath = path.join(root, '.agents', group);
    const visit = (directory) => {
      for (const item of readdirSync(directory, { withFileTypes: true })) {
        const absolute = path.join(directory, item.name);
        if (item.isSymbolicLink()) throw new TypeError(`symbolic link in bundled guidance: ${absolute}`);
        if (item.isDirectory()) visit(absolute);
        else if (item.isFile() && item.name.endsWith('.md')) result.push(absolute);
      }
    };
    visit(groupPath);
  }
  return result;
}

function clientRoots(client, homeDir) {
  if (client === 'claude-code') {
    return { skills: path.join(homeDir, '.claude', 'skills'), support: path.join(homeDir, '.claude') };
  }
  if (client === 'antigravity') {
    return { skills: path.join(homeDir, '.gemini', 'config', 'skills'), support: path.join(homeDir, '.gemini', 'config') };
  }
  return { skills: path.join(homeDir, '.agents', 'skills'), support: path.join(homeDir, '.agents') };
}

export function buildIdeSetupPlan({ clients, homeDir, packageVersion, installSkills = true }) {
  if (!Array.isArray(clients) || clients.length === 0 || clients.some((client) => !clientIds.has(client))) {
    throw new TypeError('select one or more supported clients: opencode, claude-code, codex, antigravity');
  }
  if (typeof homeDir !== 'string' || !path.isAbsolute(homeDir)) throw new TypeError('homeDir must be an absolute path');
  if (typeof packageVersion !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(packageVersion)) {
    throw new TypeError('packageVersion must be a semantic version');
  }

  const operations = new Map();
  for (const client of new Set(clients)) {
    const roots = clientRoots(client, homeDir);
    const configPath = client === 'opencode'
      ? openCodeConfigPath(homeDir)
      : client === 'claude-code'
        ? path.join(homeDir, '.claude.json')
        : client === 'codex'
          ? path.join(homeDir, '.codex', 'config.toml')
          : path.join(homeDir, '.gemini', 'config', 'mcp_config.json');
    const originalContent = readExisting(configPath);
    const emptyConfig = client === 'codex' ? '' : '{}\n';
    const configuration = configFor(client, homeDir, packageVersion, originalContent ?? emptyConfig);
    operations.set(configPath, {
      client,
      clients: [client],
      path: configPath,
      action: 'merge',
      content: configuration.content,
      originalContent,
    });

    if (!installSkills) continue;
    for (const source of guidanceFiles(packageRoot)) {
      const relative = path.relative(path.join(packageRoot, '.agents'), source);
      const destination = relative.startsWith(`skills${path.sep}`)
        ? path.join(roots.skills, path.relative(path.join(packageRoot, '.agents', 'skills'), source))
        : path.join(roots.support, relative);
      const current = readExisting(destination);
      const operation = operations.get(destination);
      if (operation) {
        operation.clients.push(client);
      } else {
        operations.set(destination, {
          client,
          clients: [client],
          path: destination,
          action: 'copy',
          content: readFileSync(source, 'utf8'),
          originalContent: current,
        });
      }
    }
  }
  return [...operations.values()];
}

function backupPath(fsImpl, filePath) {
  const first = `${filePath}.bak`;
  if (!fsImpl.existsSync(first)) return first;
  let suffix = 1;
  while (fsImpl.existsSync(`${first}.${suffix}`)) suffix += 1;
  return `${first}.${suffix}`;
}

export function applyIdeSetupPlan(plan, { confirm, fsImpl = { copyFileSync, existsSync: (filePath) => {
  try { lstatSync(filePath); return true; } catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}, lstatSync, mkdirSync, readFileSync, writeFileSync } } = {}) {
  if (!Array.isArray(plan) || typeof confirm !== 'boolean') throw new TypeError('plan and explicit confirmation are required');
  if (!confirm) return { applied: false, backups: [], written: [] };

  const pending = plan.filter((operation) => operation.originalContent !== operation.content);
  for (const operation of pending) {
    let current = null;
    try {
      const stat = fsImpl.lstatSync(operation.path);
      if (stat.isSymbolicLink() || !stat.isFile()) throw new TypeError(`destination is not a regular file: ${operation.path}`);
      current = fsImpl.readFileSync(operation.path, 'utf8');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (current !== operation.originalContent) throw new Error(`file changed after preview: ${operation.path}`);
  }

  const backups = [];
  for (const operation of pending) {
    if (operation.originalContent === null) continue;
    const backup = backupPath(fsImpl, operation.path);
    fsImpl.copyFileSync(operation.path, backup);
    backups.push(backup);
  }
  const written = [];
  for (const operation of pending) {
    fsImpl.mkdirSync(path.dirname(operation.path), { recursive: true, mode: 0o700 });
    fsImpl.writeFileSync(operation.path, operation.content, { mode: 0o600 });
    written.push(operation.path);
  }
  return { applied: true, backups, written };
}
