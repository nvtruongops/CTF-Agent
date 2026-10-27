#!/usr/bin/env node

import { assertMcpAccount, runCommand, runWsl } from './wsl.js';
import { doctor } from './doctor.js';
import { loadManifest } from './manifest.js';
import { applySetupPlan, buildSetupPlan, packagesForProfile, probeAptPackages, setupReadinessIssues } from './setup.js';
import { applyIdeSetupPlan, buildIdeSetupPlan } from './ide-setup.js';
import { startMcpServer } from './server.js';
import { initScope } from './scope.js';
import { runLearnCommand } from './learning.js';
import { homedir } from 'node:os';
import { existsSync, readFileSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import path from 'node:path';

const [command, ...args] = process.argv.slice(2);

function printHelp() {
  process.stdout.write(`ctf-agent - scoped CTF tools over MCP\n\nUsage:\n  npx ctf-agent setup [--client opencode|claude-code|codex|antigravity ...] [--dry-run] [--skills=false] [--yes]\n  npx ctf-agent setup --all-detected [--dry-run] [--skills=false] [--yes]\n  npm run ctf-agent -- setup --plan|--apply [--profile full]\n  npm run ctf-agent -- doctor [--json]\n  npm run ctf-agent -- scope init --challenge ID --workspace PATH [--target HOST:PORT ...]\n  npm run ctf-agent -- learn --propose --input <json-file> | --list [--topic TOPIC] | --show ID | --promote ID\n  npm run ctf-agent -- mcp\n`);
}

function parseOptions(args, allowed, repeatable = []) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index];
    if (!token.startsWith('--')) throw new TypeError(`unexpected argument: ${token}`);
    const name = token.slice(2);
    if (!allowed.has(name)) throw new TypeError(`unknown option: ${token}`);
    const value = args[index + 1];
    if (value === undefined || value.startsWith('--')) throw new TypeError(`missing value for ${token}`);
    index += 1;
    if (repeatable.includes(name)) {
      options[name] ??= [];
      options[name].push(value);
    } else {
      if (Object.hasOwn(options, name)) throw new TypeError(`duplicate option: ${token}`);
      options[name] = value;
    }
  }
  return options;
}

function runScopeCommand(args) {
  const [action, ...rest] = args;
  if (!action || action === '--help' || action === '-h') {
    process.stdout.write('Usage: npm run ctf-agent -- scope init --challenge ID --workspace PATH [--source-root PATH ...] [--target HOST:PORT ...]\n');
    return;
  }
  if (action !== 'init') throw new TypeError(`unknown scope command: ${action}`);
  if (rest.includes('--help') || rest.includes('-h')) {
    process.stdout.write('Usage: npm run ctf-agent -- scope init --challenge ID --workspace PATH [--source-root PATH ...] [--target HOST:PORT ...]\n');
    return;
  }

  const options = parseOptions(
    rest,
    new Set(['challenge', 'workspace', 'source-root', 'target']),
    ['source-root', 'target'],
  );
  if (!options.challenge || !options.workspace) {
    throw new TypeError('scope init requires --challenge and --workspace');
  }

  const scope = initScope({
    projectRoot: process.env.CTF_AGENT_PROJECT_ROOT ?? process.cwd(),
    challengeId: options.challenge,
    workspace: options.workspace,
    sourceRoots: options['source-root'] ?? [],
    targets: options.target ?? [],
  });
  process.stdout.write(`${JSON.stringify(scope, null, 2)}\n`);
}

async function runDoctorCommand(args) {
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write('Usage: npm run ctf-agent -- doctor [--json]\n');
    return;
  }
  const unknown = args.filter((arg) => arg !== '--json');
  if (unknown.length > 0) throw new TypeError(`unknown doctor option: ${unknown[0]}`);

  const report = await doctor({ manifest: loadManifest() });
  if (args.includes('--json')) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }

  process.stdout.write(`CTF-Agent readiness: ${report.healthy ? 'ready' : 'needs setup'}\n`);
  process.stdout.write(`Node.js: ${report.node.status} (${report.node.version})\n`);
  process.stdout.write(`WSL: ${report.wsl.status} (default version ${report.wsl.version ?? 'unknown'})\n`);
  process.stdout.write(`Kali: ${report.kali.status}\n`);
  process.stdout.write(`ctfagent account: ${report.account.status}\n`);
  for (const category of report.categories) {
    process.stdout.write(`${category.id}: ${category.status}\n`);
    for (const tool of category.tools) {
      process.stdout.write(`  ${tool.id}: ${tool.status}${tool.version ? ` (${tool.version})` : ''}\n`);
    }
  }
}

function parseSetupOptions(args) {
  let mode = null;
  let profile = 'full';
  let json = false;
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (option === '--help' || option === '-h') return { help: true };
    if (option === '--plan' || option === '--apply') {
      if (mode) throw new TypeError('choose exactly one of --plan or --apply');
      mode = option.slice(2);
    } else if (option === '--json') {
      json = true;
    } else if (option === '--profile') {
      profile = args[index + 1];
      if (!profile || profile.startsWith('--')) throw new TypeError('--profile requires a value');
      index += 1;
    } else {
      throw new TypeError(`unknown setup option: ${option}`);
    }
  }
  if (!mode) throw new TypeError('setup requires either --plan or --apply');
  return { mode, profile, json };
}

function displaySetupResult(result, json) {
  if (json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  process.stdout.write(`CTF-Agent setup: ${result.status}\n`);
  process.stdout.write(`Profile: ${result.profile}\n`);
  if (result.packages?.length) process.stdout.write(`APT packages: ${result.packages.join(', ')}\n`);
  if (result.pythonPackages?.length) process.stdout.write(`Python packages: ${result.pythonPackages.join(', ')}\n`);
  for (const action of result.actions ?? []) {
    process.stdout.write(`- ${action.id}: ${action.command.join(' ')}\n`);
  }
  if (result.nextAction) process.stdout.write(`Next action: ${result.nextAction.join(' ')}\n`);
  if (result.reason) process.stdout.write(`Reason: ${result.reason}\n`);
}

async function executeSetupAction(action) {
  const [executable, ...args] = action.command;
  const options = { timeoutMs: 30 * 60 * 1000, maxOutputBytes: 2 * 1024 * 1024 };
  if (executable !== 'wsl.exe') throw new TypeError(`unsupported setup executable: ${executable}`);
  if (args[0] === '--install' || args[0] === '--set-version') {
    return runCommand('wsl.exe', args, options);
  }
  return runWsl(args, options);
}

async function runKaliSetupCommand(args) {
  const options = parseSetupOptions(args);
  if (options.help) {
    process.stdout.write('Usage: npm run ctf-agent -- setup (--plan|--apply) [--profile full] [--json]\n');
    return;
  }

  const manifest = loadManifest();
  const doctorReport = await doctor({ manifest });
  const profilePackages = packagesForProfile(manifest, options.profile);
  let packageAvailability = { state: 'deferred', reason: 'Kali WSL2 is not ready.' };
  if (doctorReport.kali.status === 'ready' && profilePackages.length > 0) {
    packageAvailability = await probeAptPackages(profilePackages, runWsl);
  }
  const plan = buildSetupPlan({ doctorReport, manifest, profile: options.profile, packageAvailability });
  plan.packageAvailability = packageAvailability;

  if (options.mode === 'plan') {
    displaySetupResult(plan, options.json);
    return;
  }

  const result = await applySetupPlan(plan, {
    executeAction: executeSetupAction,
    checkPackages: (packages) => probeAptPackages(packages, runWsl),
  });
  if (result.status === 'ready') {
    result.readiness = await doctor({ manifest });
    const issues = setupReadinessIssues(result.readiness, manifest, options.profile);
    if (issues.length > 0) {
      result.status = 'failed';
      result.failedAction = 'readiness_check';
      result.detail = `Setup actions completed but readiness is incomplete: ${issues.join('; ')}`;
    }
  }
  const output = {
    ...result,
    profile: options.profile,
    packages: plan.packages,
    pythonPackages: plan.pythonPackages,
  };
  displaySetupResult(output, options.json);
  if (['failed', 'blocked'].includes(result.status)) process.exitCode = 1;
}

function parseIdeSetupOptions(args) {
  const options = { clients: [], dryRun: false, installSkills: true, yes: false, allDetected: false };
  for (let index = 0; index < args.length; index += 1) {
    const option = args[index];
    if (option === '--help' || option === '-h') return { help: true };
    if (option === '--client') {
      const client = args[index + 1];
      if (!client || client.startsWith('--')) throw new TypeError('--client requires a client ID');
      options.clients.push(client);
      index += 1;
    } else if (option === '--all-detected') {
      if (options.allDetected) throw new TypeError('duplicate option: --all-detected');
      options.allDetected = true;
    } else if (option === '--dry-run') {
      if (options.dryRun) throw new TypeError('duplicate option: --dry-run');
      options.dryRun = true;
    } else if (option === '--skills=false') {
      options.installSkills = false;
    } else if (option === '--yes') {
      if (options.yes) throw new TypeError('duplicate option: --yes');
      options.yes = true;
    } else {
      throw new TypeError(`unknown IDE setup option: ${option}`);
    }
  }
  if (options.clients.length > 0 && options.allDetected) throw new TypeError('choose --client or --all-detected, not both');
  if (options.dryRun && options.yes) throw new TypeError('choose --dry-run or --yes, not both');
  return options;
}

function selectedClients(options, homeDir) {
  if (options.allDetected) {
    const candidates = [
      ['opencode', path.join(homeDir, '.config', 'opencode')],
      ['claude-code', path.join(homeDir, '.claude')],
      ['codex', path.join(homeDir, '.codex')],
      ['antigravity', path.join(homeDir, '.gemini')],
    ];
    const detected = candidates.filter(([, directory]) => existsSync(directory)).map(([client]) => client);
    if (detected.length === 0) throw new TypeError('no supported IDE configuration directories detected; use --client');
    return detected;
  }
  if (options.clients.length > 0) return [...new Set(options.clients)];
  if (!stdin.isTTY || !stdout.isTTY) throw new TypeError('setup requires an interactive client choice or --client <id>');
  return null;
}

async function promptForClients() {
  const prompt = createInterface({ input: stdin, output: stdout });
  try {
    const answer = await prompt.question('Choose IDEs (comma-separated: opencode, claude-code, codex, antigravity): ');
    return answer.split(',').map((client) => client.trim()).filter(Boolean);
  } finally {
    prompt.close();
  }
}

function displayIdeSetupPlan(plan, dryRun) {
  process.stdout.write(`CTF-Agent IDE setup ${dryRun ? '(dry run)' : 'plan'}\n`);
  for (const operation of plan.filter((item) => item.action === 'merge')) {
    const status = operation.originalContent === operation.content ? 'already configured' : 'update MCP config';
    process.stdout.write(`- ${operation.client}: ${status} ${operation.path}${operation.originalContent === null ? '' : ' (backup existing file)'}\n`);
  }
  const skills = plan.filter((item) => item.action === 'copy');
  if (skills.length > 0) {
    const roots = new Map();
    for (const operation of skills) {
      const client = operation.clients.join(',');
      const root = operation.path.split(`${path.sep}skills${path.sep}`)[0] + `${path.sep}skills`;
      roots.set(`${client}:${root}`, { client, root, count: (roots.get(`${client}:${root}`)?.count ?? 0) + 1 });
    }
    for (const { client, root, count } of roots.values()) process.stdout.write(`- ${client}: install ${count} skill files under ${root}\n`);
  }
  process.stdout.write(`Total file operations: ${plan.length}\n`);
}

async function runIdeSetupCommand(args) {
  const options = parseIdeSetupOptions(args);
  if (options.help) {
    process.stdout.write('Usage: npx ctf-agent setup [--client opencode|claude-code|codex|antigravity ...] [--all-detected] [--dry-run] [--skills=false] [--yes]\n');
    return;
  }

  const homeDir = process.env.CTF_AGENT_WINDOWS_HOME || process.env.USERPROFILE || homedir();
  const clients = selectedClients(options, homeDir) ?? await promptForClients();
  const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const plan = buildIdeSetupPlan({
    clients,
    homeDir,
    packageVersion: packageJson.version,
    installSkills: options.installSkills,
    windowsLauncher: process.env.CTF_AGENT_WINDOWS_LAUNCHER || undefined,
  });
  displayIdeSetupPlan(plan, options.dryRun);
  if (options.dryRun) return;

  let confirm = options.yes;
  if (!confirm) {
    if (!stdin.isTTY || !stdout.isTTY) throw new TypeError('non-interactive setup requires --dry-run or --yes');
    const prompt = createInterface({ input: stdin, output: stdout });
    try {
      confirm = /^y(?:es)?$/i.test((await prompt.question('Apply these changes? [y/N] ')).trim());
    } finally {
      prompt.close();
    }
  }
  const result = applyIdeSetupPlan(plan, { confirm });
  process.stdout.write(result.applied ? `Applied ${result.written.length} file operations; backups: ${result.backups.length}\n` : 'No changes applied.\n');
}

async function runSetupCommand(args) {
  if (args.includes('--plan') || args.includes('--apply')) return runKaliSetupCommand(args);
  return runIdeSetupCommand(args);
}

async function main() {
  if (!command || command === '--help' || command === '-h') {
    printHelp();
    return;
  }

  if (command === 'mcp') {
    if (process.platform === 'linux') assertMcpAccount();
    await startMcpServer({
      manifest: loadManifest(),
      projectRoot: process.env.CTF_AGENT_PROJECT_ROOT ?? process.cwd(),
    });
    return;
  }

  if (command === 'scope') {
    runScopeCommand(args);
    return;
  }

  if (command === 'doctor') {
    await runDoctorCommand(args);
    return;
  }

  if (command === 'setup') {
    await runSetupCommand(args);
    return;
  }

  if (command === 'learn') {
    runLearnCommand(args);
    return;
  }

  if (args.includes('--help') || args.includes('-h')) {
    printHelp();
    return;
  }

  process.stderr.write(`Command not implemented: ${command}\nRun npm run ctf-agent -- --help for usage.\n`);
  process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`ctf-agent: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = error instanceof TypeError ? 2 : 1;
});
