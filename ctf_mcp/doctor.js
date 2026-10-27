import { readFileSync } from 'node:fs';
import { parseWslDistroTable, runWsl as defaultRunWsl } from './wsl.js';

const DOCTOR_WORKER_SOURCE = readFileSync(new URL('./tools/doctor_worker.py', import.meta.url), 'utf8');

function isNodeSupported(version) {
  const [major, minor] = String(version).split('.').map(Number);
  return Number.isInteger(major)
    && Number.isInteger(minor)
    && (major > 24 || (major === 24 && minor >= 11));
}

async function safeRunWsl(runWsl, args, options) {
  try {
    return await runWsl(args, options);
  } catch (error) {
    return {
      exitCode: null,
      stdout: '',
      stderr: error instanceof Error ? error.message : String(error),
      timedOut: false,
      truncated: false,
    };
  }
}

function unavailableProbe(id, detail) {
  return { id, exitCode: null, stdout: '', stderr: detail, timedOut: false, truncated: false };
}

async function runProbeBatch(runWsl, user, probes) {
  if (probes.length === 0) return new Map();
  const timeoutMs = Math.min(120_000, 5_000 + probes.length * 30_000);
  const result = await safeRunWsl(runWsl, [
    '--distribution', 'kali-linux', '--user', user, '--exec', 'python3', '-c', DOCTOR_WORKER_SOURCE,
  ], {
    input: JSON.stringify({ probes }),
    timeoutMs,
    maxOutputBytes: 1_048_576,
  });
  try {
    const parsed = JSON.parse(result.stdout);
    if (result.exitCode !== 0 || !Array.isArray(parsed.results)) {
      throw new Error(parsed.error || result.stderr || 'Doctor probe worker failed.');
    }
    return new Map(parsed.results.map((probe) => [probe.id, {
      ...probe,
      stdout: Buffer.from(probe.stdoutBase64, 'base64').toString('utf8'),
      stderr: Buffer.from(probe.stderrBase64, 'base64').toString('utf8'),
    }]));
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return new Map(probes.map((probe) => [probe.id, unavailableProbe(probe.id, detail)]));
  }
}

function probeState(probe) {
  return probe?.exitCode === 0 && !probe.timedOut && !probe.truncated ? 'ready' : 'missing_dependency';
}

function versionLine(probe) {
  return probe?.stdout.trim().split(/\r?\n/)[0] || null;
}

export async function doctor({
  runWsl = defaultRunWsl,
  manifest = { categories: [] },
  nodeVersion = process.versions.node,
} = {}) {
  const node = {
    version: nodeVersion,
    status: isNodeSupported(nodeVersion) ? 'ready' : 'unsupported',
  };

  const statusResult = await safeRunWsl(runWsl, ['--status']);
  const versionMatch = String(statusResult.stdout).match(/Default\s+Version\s*:\s*(\d+)/i);
  const version = versionMatch ? Number(versionMatch[1]) : null;
  const wsl = {
    status: statusResult.exitCode === 0 && version === 2 ? 'ready' : 'unsupported',
    version,
    detail: statusResult.exitCode === 0 ? null : statusResult.stderr,
  };

  const distroResult = await safeRunWsl(runWsl, ['--list', '--verbose']);
  const distributions = distroResult.exitCode === 0
    ? parseWslDistroTable(distroResult.stdout)
    : [];
  const kaliDistro = distributions.find((distro) => distro.name.toLowerCase() === 'kali-linux');
  const kaliInstalled = Boolean(kaliDistro);
  const kali = {
    status: distroResult.exitCode !== 0
      ? 'unknown'
      : (!kaliDistro ? 'missing' : (kaliDistro.version === 2 ? 'ready' : 'unsupported')),
    distribution: kaliDistro?.name ?? null,
    version: kaliDistro?.version ?? null,
    state: kaliDistro?.state ?? null,
  };

  let account = { status: 'not_checked', groups: [] };
  if (kali.status === 'ready') {
    const accountProbes = await runProbeBatch(runWsl, 'root', [
      { id: 'account.uid', argv: ['id', '-u', 'ctfagent'] },
      { id: 'account.groups', argv: ['id', '-nG', 'ctfagent'], ifPreviousExitCode: 0 },
    ]);
    const uidResult = accountProbes.get('account.uid');
    const groupsResult = accountProbes.get('account.groups');
    if (uidResult?.exitCode !== 0 || !/^\d+\s*$/.test(uidResult.stdout)) {
      account = { status: 'missing', groups: [] };
    } else {
      const groups = groupsResult.stdout.trim().split(/\s+/).filter(Boolean);
      const unsafe = Number(uidResult.stdout.trim()) === 0 || groups.some((group) => ['sudo', 'wheel', 'root'].includes(group));
      account = {
        status: unsafe ? 'unsafe' : (groupsResult.exitCode !== 0 || groupsResult.skipped ? 'unknown' : 'ready'),
        groups,
      };
    }
  }

  const executableProbes = [];
  const executableProbeIds = new Map();
  const addExecutableProbe = (id, executable, args) => {
    const probeId = `executable.${executableProbes.length}`;
    executableProbes.push({ id: probeId, argv: [executable, ...args] });
    executableProbeIds.set(id, probeId);
  };
  const baseExecutables = (manifest.baseExecutables ?? []).map((executable, index) => {
    if (!kaliInstalled) return { id: executable, status: 'missing_dependency', version: null, detail: 'Kali Linux is not installed.' };
    if (kali.status !== 'ready' || account.status !== 'ready') return { id: executable, status: 'blocked', version: null, detail: 'Kali WSL2 and the non-sudo ctfagent account must be ready.' };
    const id = `base.${index}`;
    addExecutableProbe(id, executable, ['--version']);
    return { id: executable, probeId: id };
  });

  const categories = [];
  for (const category of manifest.categories ?? []) {
    const tools = [];
    for (const tool of category.tools ?? []) {
      if (tool.builtin === true) {
        tools.push({ id: tool.id, status: 'ready', detail: null });
        continue;
      }
      if (!kaliInstalled) {
        tools.push({ id: tool.id, status: 'missing_dependency', detail: 'Kali Linux is not installed.' });
        continue;
      }
      if (kali.status !== 'ready') {
        tools.push({ id: tool.id, status: 'blocked', detail: 'Kali Linux must run as WSL2.' });
        continue;
      }
      if (account.status !== 'ready') {
        tools.push({ id: tool.id, status: 'blocked', detail: 'The non-sudo ctfagent account is not ready.' });
        continue;
      }
      const primaryProbeId = `tool.${category.id}.${tool.id}.${tools.length}`;
      addExecutableProbe(primaryProbeId, tool.executable, tool.probeArgs ?? ['--version']);
      const dependencyProbeIds = (tool.requiredExecutables ?? []).map((executable, index) => {
        const id = `${primaryProbeId}.required.${index}`;
        addExecutableProbe(id, executable, ['--version']);
        return { executable, id };
      });
      tools.push({ id: tool.id, primaryProbeId, dependencyProbeIds });
    }
    categories.push({ id: category.id, tools });
  }

  const executableResults = account.status === 'ready'
    ? await runProbeBatch(runWsl, 'ctfagent', executableProbes)
    : new Map();
  for (const executable of baseExecutables) {
    if (!executable.probeId) continue;
    const probe = executableResults.get(executableProbeIds.get(executable.probeId));
    const ready = probeState(probe) === 'ready';
    executable.status = ready ? 'ready' : 'missing_dependency';
    executable.version = versionLine(probe);
    executable.detail = ready ? null : (probe?.stderr || 'Base executable probe failed.');
    delete executable.probeId;
  }
  for (const category of categories) {
    for (const tool of category.tools) {
      if (!tool.primaryProbeId) continue;
      const probe = executableResults.get(executableProbeIds.get(tool.primaryProbeId));
      const missingExecutables = tool.dependencyProbeIds
        .filter(({ id }) => probeState(executableResults.get(executableProbeIds.get(id))) !== 'ready')
        .map(({ executable }) => executable);
      const ready = probeState(probe) === 'ready' && missingExecutables.length === 0;
      tool.status = ready ? 'ready' : 'missing_dependency';
      tool.version = versionLine(probe);
      tool.detail = ready
        ? null
        : (probeState(probe) !== 'ready'
          ? (probe?.stderr || 'Executable probe failed.')
          : `Missing required executable(s): ${missingExecutables.join(', ')}`);
      delete tool.primaryProbeId;
      delete tool.dependencyProbeIds;
    }
    const readyCount = category.tools.filter((tool) => tool.status === 'ready').length;
    category.status = category.tools.length === 0 || readyCount === 0
      ? 'missing_dependency'
      : (readyCount === category.tools.length ? 'ready' : 'partial');
  }

  const requiredToolsReady = (manifest.categories ?? []).every((category) => {
    const reportCategory = categories.find((item) => item.id === category.id);
    return (category.tools ?? [])
      .filter((tool) => tool.optionalProfile === undefined)
      .every((tool) => reportCategory?.tools.find((item) => item.id === tool.id)?.status === 'ready');
  });

  return {
    healthy: node.status === 'ready'
      && wsl.status === 'ready'
      && kali.status === 'ready'
      && account.status === 'ready'
      && baseExecutables.every((executable) => executable.status === 'ready')
      && requiredToolsReady,
    node,
    wsl,
    distributions,
    kali,
    account,
    baseExecutables,
    categories,
  };
}
