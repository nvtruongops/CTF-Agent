import { FRIDA_PYTHON, FRIDA_VENV } from './frida-runtime.js';

function wslCommand(args, distro = 'kali-linux', user = 'root') {
  return ['wsl.exe', '--distribution', distro, '--user', user, '--exec', ...args];
}

export async function probeAptPackages(packages, runWsl) {
  if (!Array.isArray(packages) || packages.some((name) => typeof name !== 'string' || !/^[a-z0-9][a-z0-9+.-]*$/i.test(name))) {
    throw new TypeError('packages must contain valid apt package names');
  }
  if (typeof runWsl !== 'function') throw new TypeError('runWsl is required to check apt packages');

  const result = { available: [], unavailable: [], unknown: [] };
  for (const name of packages) {
    let probe;
    try {
      probe = await runWsl([
        '--distribution', 'kali-linux', '--user', 'root', '--exec', 'apt-cache', 'policy', name,
      ], { timeoutMs: 10_000, maxOutputBytes: 32_768 });
    } catch (error) {
      result.unknown.push({ name, detail: error instanceof Error ? error.message : String(error) });
      continue;
    }

    const candidate = String(probe.stdout ?? '').match(/^\s*Candidate:\s*(\S+)/mi)?.[1];
    if (probe.exitCode !== 0 || !candidate) {
      result.unknown.push({ name, detail: probe.stderr || probe.stdout || 'apt-cache returned no candidate information' });
    } else if (candidate === '(none)') {
      result.unavailable.push(name);
    } else {
      result.available.push({ name, candidate });
    }
  }
  return result;
}

function hasMissingCtfTools(report, manifest, profile) {
  if ((report.baseExecutables ?? []).some((executable) => executable.status !== 'ready')) return true;

  const categories = manifest?.categories;
  if (!Array.isArray(categories) || categories.length === 0) {
    return (report.categories ?? [])
      .filter((category) => profile === 'full' || category.id === profile)
      .some((category) => category.status !== 'ready');
  }

  return categories
    .filter((category) => profile === 'full' || category.id === profile)
    .some((category) => {
      const observed = report.categories?.find((item) => item.id === category.id);
      return (category.tools ?? [])
        .filter((tool) => tool.optionalProfile === undefined || tool.optionalProfile === profile)
        .some((tool) => observed?.tools?.find((item) => item.id === tool.id)?.status !== 'ready');
    });
}

function packageCandidatesAreCurrent(packages, availability) {
  if (!availability || availability.unavailable?.length || availability.unknown?.length) return false;
  const available = new Set((availability.available ?? []).map((entry) => entry.name));
  return packages.every((packageName) => available.has(packageName));
}

export function buildSetupPlan({ doctorReport, manifest, profile = 'full', packageAvailability = null } = {}) {
  if (!doctorReport || !manifest?.profiles?.[profile]) {
    throw new TypeError(`Unknown setup profile: ${profile}`);
  }
  const packages = packagesForProfile(manifest, profile);
  const pythonPackages = [...new Set(manifest.profiles[profile].python ?? [])];
  const actions = [];

  if (doctorReport.wsl?.status !== 'ready') {
    actions.push({
      id: 'install_kali',
      command: ['wsl.exe', '--install', '--distribution', 'kali-linux', '--no-launch'],
      requiresWindowsAdmin: true,
      interactive: false,
    });
    return { status: 'pending_kali', profile, packages, pythonPackages, packageAvailability, actions };
  }

  if (doctorReport.kali?.status === 'missing') {
    actions.push({
      id: 'install_kali',
      command: ['wsl.exe', '--install', '--distribution', 'kali-linux', '--no-launch'],
      requiresWindowsAdmin: true,
      interactive: false,
    });
    return { status: 'pending_kali', profile, packages, pythonPackages, packageAvailability, actions };
  }

  if (doctorReport.kali?.status === 'unsupported') {
    actions.push({
      id: 'upgrade_kali_wsl2',
      command: ['wsl.exe', '--set-version', doctorReport.kali.distribution ?? 'kali-linux', '2'],
      requiresWindowsAdmin: true,
      interactive: false,
    });
    return { status: 'pending_wsl2', profile, packages, pythonPackages, packageAvailability, actions };
  }

  if (doctorReport.kali?.status !== 'ready') {
    return { status: 'blocked', profile, packages, pythonPackages, packageAvailability, actions, reason: 'Kali WSL readiness is unknown.' };
  }

  if (doctorReport.account?.status === 'unsafe') {
    return { status: 'blocked', profile, packages, pythonPackages, actions, reason: 'ctfagent belongs to the sudo group.' };
  }
  if (doctorReport.account?.status === 'unknown') {
    return { status: 'blocked', profile, packages, pythonPackages, actions, reason: 'ctfagent account state could not be verified.' };
  }
  if (!['ready', 'missing'].includes(doctorReport.account?.status)) {
    return { status: 'blocked', profile, packages, pythonPackages, packageAvailability, actions, reason: 'ctfagent account state is unavailable.' };
  }
  if (doctorReport.account?.status === 'missing') {
    actions.push({
      id: 'create_ctfagent',
      command: wslCommand(['/usr/sbin/useradd', '--create-home', '--shell', '/bin/bash', 'ctfagent']),
    });
  }

  if (hasMissingCtfTools(doctorReport, manifest, profile) && packages.length > 0) {
    if (!packageCandidatesAreCurrent(packages, packageAvailability)) {
      actions.push({ id: 'apt_update', command: wslCommand(['apt-get', 'update']) });
    }
    actions.push({
      id: 'install_packages',
      packages,
      command: wslCommand([
        'env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', '-o', 'Dpkg::Use-Pty=0',
        'install', '--yes', '--no-install-recommends', ...packages,
      ]),
    });
  }

  if (hasMissingCtfTools(doctorReport, manifest, profile) && pythonPackages.length > 0) {
    actions.push({
      id: 'create_python_venv',
      command: wslCommand(['python3', '-m', 'venv', FRIDA_VENV], 'kali-linux', 'ctfagent'),
    });
    actions.push({
      id: 'install_python_packages',
      packages: pythonPackages,
      command: wslCommand([
        FRIDA_PYTHON, '-m', 'pip', 'install', '--require-virtualenv',
        '--no-input', '--disable-pip-version-check', ...pythonPackages,
      ], 'kali-linux', 'ctfagent'),
    });
  }

  actions.push({
    id: 'ensure_workspace',
    command: wslCommand([
      'install', '-d', '-m', '700', '-o', 'ctfagent', '-g', 'ctfagent',
      '/home/ctfagent/ctf-workspaces',
    ]),
  });

  return {
    status: actions.length === 0 ? 'ready' : 'ready_to_apply',
    profile,
    packages,
    pythonPackages,
    packageAvailability,
    actions,
  };
}

export function packagesForProfile(manifest, profile = 'full') {
  const selected = manifest?.profiles?.[profile];
  if (profile === 'base' || !selected || !Array.isArray(selected.apt)) {
    throw new TypeError(`Unknown setup profile: ${profile}`);
  }
  const base = manifest.profiles.base?.apt ?? [];
  return [...new Set([...selected.apt, ...base])];
}

export function setupReadinessIssues(report, manifest, profile = 'full') {
  const issues = [];
  for (const [label, status] of [
    ['Node.js', report?.node?.status],
    ['WSL2', report?.wsl?.status],
    ['Kali', report?.kali?.status],
    ['ctfagent account', report?.account?.status],
  ]) {
    if (status !== 'ready') issues.push(`${label}: ${status ?? 'unknown'}`);
  }
  for (const executable of report?.baseExecutables ?? []) {
    if (executable.status !== 'ready') issues.push(`base ${executable.id}: ${executable.status ?? 'unknown'}`);
  }

  const categories = manifest?.categories ?? [];
  const requiredCategories = profile === 'full'
    ? categories
    : categories.filter((category) => category.id === profile);
  if (requiredCategories.length === 0) issues.push(`profile ${profile}: no matching category`);
  for (const category of requiredCategories) {
    const current = report?.categories?.find((item) => item.id === category.id);
    const categoryTools = category.tools ?? [];
    const tools = categoryTools
      .filter((tool) => tool.optionalProfile === undefined || tool.optionalProfile === profile);
    if (!Array.isArray(categoryTools) || categoryTools.length === 0) {
      if (current?.status !== 'ready') issues.push(`${category.id}: ${current?.status ?? 'missing'}`);
      continue;
    }
    for (const tool of tools) {
      const status = current?.tools?.find((item) => item.id === tool.id)?.status;
      if (status !== 'ready') issues.push(`${category.id} ${tool.id}: ${status ?? 'missing'}`);
    }
  }
  return issues;
}

export async function applySetupPlan(plan, { executeAction, checkPackages } = {}) {
  if (!plan || !Array.isArray(plan.actions)) throw new TypeError('a setup plan is required');
  if (plan.status === 'blocked') return { status: 'blocked', reason: plan.reason, appliedActions: [] };

  const appliedActions = [];
  for (const action of plan.actions) {
    if (typeof executeAction !== 'function') throw new TypeError('executeAction is required to apply a setup plan');

    if (action.id === 'install_packages') {
      const packageCheck = typeof checkPackages === 'function'
        ? await checkPackages(action.packages)
        : null;
      if (!packageCheck) {
        return {
          status: 'blocked',
          reason: 'Package availability must be checked after apt-get update and before installation.',
          appliedActions,
        };
      }
      if (packageCheck.unavailable?.length || packageCheck.unknown?.length) {
        return { status: 'blocked', reason: 'Some apt packages are unavailable.', packageCheck, appliedActions };
      }
    }

    const result = await executeAction(action);
    if (result?.exitCode !== 0 || result?.timedOut || result?.truncated) {
      if (action.requiresWindowsAdmin && (result?.exitCode === 740 || /requires elevation|administrator|access is denied/i.test(result?.stderr ?? ''))) {
        return { status: 'pending_admin', nextAction: action.command, appliedActions };
      }
      return {
        status: 'failed',
        failedAction: action.id,
        detail: result?.stderr || (result?.timedOut
          ? 'Setup action timed out.'
          : (result?.truncated ? 'Setup action output was truncated.' : 'Setup action failed.')),
        appliedActions,
      };
    }
    appliedActions.push(action.id);

    if (action.id === 'install_kali') {
      return {
        status: 'pending_recheck',
        appliedActions,
      };
    }
    if (action.id === 'upgrade_kali_wsl2') {
      return { status: 'pending_recheck', appliedActions };
    }
  }

  return { status: 'ready', appliedActions };
}
