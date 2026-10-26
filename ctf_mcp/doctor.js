import { parseWslDistroTable, runWsl as defaultRunWsl } from './wsl.js';

function isNodeSupported(version) {
  const [major, minor] = String(version).split('.').map(Number);
  return Number.isInteger(major)
    && Number.isInteger(minor)
    && (major > 24 || (major === 24 && minor >= 11));
}

async function safeRunWsl(runWsl, args) {
  try {
    return await runWsl(args);
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

function resultState(result) {
  return result?.exitCode === 0 && !result.timedOut ? 'ready' : 'missing_dependency';
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
    const uidResult = await safeRunWsl(runWsl, [
      '--distribution', 'kali-linux', '--user', 'root', '--exec', 'id', '-u', 'ctfagent',
    ]);
    if (uidResult.exitCode !== 0 || !/^\d+\s*$/.test(uidResult.stdout)) {
      account = { status: 'missing', groups: [] };
    } else {
      const groupsResult = await safeRunWsl(runWsl, [
        '--distribution', 'kali-linux', '--user', 'root', '--exec', 'id', '-nG', 'ctfagent',
      ]);
      const groups = groupsResult.stdout.trim().split(/\s+/).filter(Boolean);
      const unsafe = Number(uidResult.stdout.trim()) === 0 || groups.includes('sudo');
      account = {
        status: unsafe ? 'unsafe' : (groupsResult.exitCode !== 0 ? 'unknown' : 'ready'),
        groups,
      };
    }
  }

  const baseExecutables = [];
  for (const executable of manifest.baseExecutables ?? []) {
    if (!kaliInstalled) {
      baseExecutables.push({ id: executable, status: 'missing_dependency', version: null, detail: 'Kali Linux is not installed.' });
      continue;
    }
    if (kali.status !== 'ready' || account.status !== 'ready') {
      baseExecutables.push({ id: executable, status: 'blocked', version: null, detail: 'Kali WSL2 and the non-sudo ctfagent account must be ready.' });
      continue;
    }
    const probe = await safeRunWsl(runWsl, [
      '--distribution', 'kali-linux', '--user', 'ctfagent', '--exec', executable, '--version',
    ]);
    const ready = resultState(probe) === 'ready';
    baseExecutables.push({
      id: executable,
      status: ready ? 'ready' : 'missing_dependency',
      version: probe.stdout.trim().split(/\r?\n/)[0] || null,
      detail: ready ? null : (probe.stderr || 'Base executable probe failed.'),
    });
  }

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

      const probe = await safeRunWsl(runWsl, [
        '--distribution', 'kali-linux', '--user', 'ctfagent', '--exec',
        tool.executable, ...(tool.probeArgs ?? ['--version']),
      ]);
      const missingExecutables = [];
      for (const executable of tool.requiredExecutables ?? []) {
        const dependencyProbe = await safeRunWsl(runWsl, [
          '--distribution', 'kali-linux', '--user', 'ctfagent', '--exec', executable, '--version',
        ]);
        if (resultState(dependencyProbe) !== 'ready') missingExecutables.push(executable);
      }
      const ready = resultState(probe) === 'ready' && missingExecutables.length === 0;
      tools.push({
        id: tool.id,
        status: ready ? 'ready' : 'missing_dependency',
        version: probe.stdout.trim().split(/\r?\n/)[0] || null,
        detail: ready
          ? null
          : (probe.exitCode !== 0 || probe.timedOut
            ? (probe.stderr || 'Executable probe failed.')
            : `Missing required executable(s): ${missingExecutables.join(', ')}`),
      });
    }

    const readyCount = tools.filter((tool) => tool.status === 'ready').length;
    categories.push({
      id: category.id,
      status: tools.length === 0 || readyCount === 0
        ? 'missing_dependency'
        : (readyCount === tools.length ? 'ready' : 'partial'),
      tools,
    });
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
