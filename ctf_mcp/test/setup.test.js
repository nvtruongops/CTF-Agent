import assert from 'node:assert/strict';
import { applySetupPlan, buildSetupPlan, probeAptPackages, setupReadinessIssues } from '../setup.js';
import test from 'node:test';

const manifest = { profiles: { full: { apt: ['nmap', 'sqlmap', 'z3'] } } };

function doctorReport({
  wsl = 'ready',
  kali = 'missing',
  kaliVersion = null,
  account = 'not_checked',
  categoryStatus = 'missing_dependency',
} = {}) {
  return {
    wsl: { status: wsl },
    kali: { status: kali, version: kaliVersion },
    account: { status: account },
    categories: [{ id: 'web', status: categoryStatus }],
  };
}

test('setup plan installs Kali first and retains the selected package list', () => {
  const plan = buildSetupPlan({ doctorReport: doctorReport(), manifest, profile: 'full' });
  assert.equal(plan.status, 'pending_kali');
  assert.deepEqual(plan.packages, ['nmap', 'sqlmap', 'z3']);
  assert.deepEqual(plan.actions, [{
    id: 'install_kali',
    command: ['wsl.exe', '--install', '--distribution', 'kali-linux', '--no-launch'],
    requiresWindowsAdmin: true,
    interactive: false,
  }]);
});

test('setup plan merges base runtime packages into the selected category profile', () => {
  const profileManifest = {
    profiles: {
      base: { apt: ['python3'] },
      full: { apt: ['python3', 'nmap'] },
      web: { apt: ['nmap'] },
    },
  };
  const plan = buildSetupPlan({
    doctorReport: doctorReport({ kali: 'ready', kaliVersion: 2, account: 'ready' }),
    manifest: profileManifest,
    profile: 'web',
  });

  assert.deepEqual(plan.packages, ['nmap', 'python3']);
});

test('setup plan upgrades a Kali WSL1 distro before account or package changes', () => {
  const plan = buildSetupPlan({
    doctorReport: doctorReport({ kali: 'unsupported', kaliVersion: 1 }),
    manifest,
    profile: 'full',
  });
  assert.equal(plan.status, 'pending_wsl2');
  assert.deepEqual(plan.actions, [{
    id: 'upgrade_kali_wsl2',
    command: ['wsl.exe', '--set-version', 'kali-linux', '2'],
    requiresWindowsAdmin: true,
    interactive: false,
  }]);
});

test('setup plan creates a non-sudo user and installs only the selected profile packages', () => {
  const plan = buildSetupPlan({
    doctorReport: doctorReport({ kali: 'ready', kaliVersion: 2, account: 'missing' }),
    manifest,
    profile: 'full',
  });
  const createUser = plan.actions.find((action) => action.id === 'create_ctfagent');
  const install = plan.actions.find((action) => action.id === 'install_packages');
  assert.equal(plan.status, 'ready_to_apply');
  assert.ok(createUser);
  assert.ok(install);
  assert.deepEqual(createUser.command, [
    'wsl.exe', '--distribution', 'kali-linux', '--user', 'root', '--exec',
    '/usr/sbin/useradd', '--create-home', '--shell', '/bin/bash', 'ctfagent',
  ]);
  assert.deepEqual(install.packages, ['nmap', 'sqlmap', 'z3']);
  assert.equal(plan.actions.some((action) => action.command?.includes('sudo')), false);
});

test('setup plan skips apt-get update when all selected package candidates are current', () => {
  const packageAvailability = {
    available: manifest.profiles.full.apt.map((name) => ({ name, candidate: '1.0' })),
    unavailable: [],
    unknown: [],
  };
  const plan = buildSetupPlan({
    doctorReport: doctorReport({ kali: 'ready', kaliVersion: 2, account: 'ready' }),
    manifest,
    profile: 'full',
    packageAvailability,
  });

  assert.equal(plan.actions.some((action) => action.id === 'apt_update'), false);
  assert.equal(plan.actions.some((action) => action.id === 'install_packages'), true);
});

test('setup readiness checks only the selected profile categories plus base environment', () => {
  const report = {
    node: { status: 'ready' },
    wsl: { status: 'ready' },
    kali: { status: 'ready' },
    account: { status: 'ready' },
    categories: [
      { id: 'web', status: 'ready' },
      { id: 'reverse', status: 'missing_dependency' },
    ],
  };

  assert.deepEqual(setupReadinessIssues(report, { categories: report.categories }, 'web'), []);
  assert.deepEqual(setupReadinessIssues(report, { categories: report.categories }, 'full'), [
    'reverse: missing_dependency',
  ]);
  assert.deepEqual(setupReadinessIssues({ ...report, account: { status: 'unsafe' } }, {
    categories: report.categories,
  }, 'web'), ['ctfagent account: unsafe']);
});

test('full readiness ignores missing optional tools but selected profiles require and install them', () => {
  const optionalManifest = {
    profiles: {
      base: { apt: ['python3'] },
      full: { apt: ['nmap', 'python3'] },
      web: { apt: ['nmap'] },
      exploitation: { apt: ['hydra'] },
    },
    categories: [
      { id: 'web', tools: [{ id: 'ctf_nmap_scan' }] },
      { id: 'exploitation', tools: [{ id: 'ctf_hydra_audit', optionalProfile: 'exploitation' }] },
    ],
  };
  const report = {
    node: { status: 'ready' },
    wsl: { status: 'ready' },
    kali: { status: 'ready' },
    account: { status: 'ready' },
    baseExecutables: [{ id: 'python3', status: 'ready' }],
    categories: [
      { id: 'web', status: 'ready', tools: [{ id: 'ctf_nmap_scan', status: 'ready' }] },
      {
        id: 'exploitation',
        status: 'missing_dependency',
        tools: [{ id: 'ctf_hydra_audit', status: 'missing_dependency' }],
      },
    ],
  };
  const fullAvailability = {
    available: [{ name: 'nmap', candidate: '1.0' }, { name: 'python3', candidate: '1.0' }],
    unavailable: [],
    unknown: [],
  };
  const topicAvailability = {
    available: [{ name: 'hydra', candidate: '1.0' }, { name: 'python3', candidate: '1.0' }],
    unavailable: [],
    unknown: [],
  };

  assert.deepEqual(setupReadinessIssues(report, optionalManifest, 'full'), []);
  assert.deepEqual(setupReadinessIssues(report, optionalManifest, 'exploitation'), [
    'exploitation ctf_hydra_audit: missing_dependency',
  ]);
  assert.deepEqual(
    buildSetupPlan({ doctorReport: report, manifest: optionalManifest, profile: 'full', packageAvailability: fullAvailability })
      .actions.map((action) => action.id),
    ['ensure_workspace'],
  );

  const topicPlan = buildSetupPlan({
    doctorReport: report,
    manifest: optionalManifest,
    profile: 'exploitation',
    packageAvailability: topicAvailability,
  });
  assert.deepEqual(topicPlan.packages, ['hydra', 'python3']);
  assert.deepEqual(topicPlan.actions.map((action) => action.id), ['install_packages', 'ensure_workspace']);
});

test('setup readiness includes base executable probes', () => {
  const report = {
    node: { status: 'ready' },
    wsl: { status: 'ready' },
    kali: { status: 'ready' },
    account: { status: 'ready' },
    baseExecutables: [{ id: 'python3', status: 'missing_dependency' }],
    categories: [{ id: 'web', status: 'ready' }],
  };

  assert.deepEqual(setupReadinessIssues(report, { categories: report.categories }, 'web'), [
    'base python3: missing_dependency',
  ]);
});

test('setup plan installs pinned Python tools in a ctfagent virtual environment after APT', () => {
  const pythonManifest = {
    profiles: { full: { apt: ['python3-venv'], python: ['frida==17.24.3'] } },
  };
  const packageAvailability = {
    available: [{ name: 'python3-venv', candidate: '3.14.7-3' }],
    unavailable: [],
    unknown: [],
  };
  const plan = buildSetupPlan({
    doctorReport: doctorReport({ kali: 'ready', kaliVersion: 2, account: 'ready' }),
    manifest: pythonManifest,
    profile: 'full',
    packageAvailability,
  });

  assert.deepEqual(plan.pythonPackages, ['frida==17.24.3']);
  assert.deepEqual(plan.actions.map((action) => action.id), [
    'install_packages', 'create_python_venv', 'install_python_packages', 'ensure_workspace',
  ]);
  assert.deepEqual(plan.actions[1].command, [
    'wsl.exe', '--distribution', 'kali-linux', '--user', 'ctfagent', '--exec',
    'python3', '-m', 'venv', '/home/ctfagent/.local/share/ctf-agent/frida-venv',
  ]);
  assert.deepEqual(plan.actions[2].command, [
    'wsl.exe', '--distribution', 'kali-linux', '--user', 'ctfagent', '--exec',
    '/home/ctfagent/.local/share/ctf-agent/frida-venv/bin/python', '-m', 'pip',
    'install', '--require-virtualenv', '--no-input', '--disable-pip-version-check', 'frida==17.24.3',
  ]);
});

test('setup plan installs packages without waiting for interactive debconf input', () => {
  const packageAvailability = {
    available: manifest.profiles.full.apt.map((name) => ({ name, candidate: '1.0' })),
    unavailable: [],
    unknown: [],
  };
  const plan = buildSetupPlan({
    doctorReport: doctorReport({ kali: 'ready', kaliVersion: 2, account: 'ready' }),
    manifest,
    profile: 'full',
    packageAvailability,
  });
  const install = plan.actions.find((action) => action.id === 'install_packages');

  assert.deepEqual(install.command, [
    'wsl.exe', '--distribution', 'kali-linux', '--user', 'root', '--exec',
    'env', 'DEBIAN_FRONTEND=noninteractive', 'apt-get', '-o', 'Dpkg::Use-Pty=0',
    'install', '--yes', '--no-install-recommends', 'nmap', 'sqlmap', 'z3',
  ]);
});

test('setup plan refreshes apt indexes when package candidates are unknown', () => {
  const plan = buildSetupPlan({
    doctorReport: doctorReport({ kali: 'ready', kaliVersion: 2, account: 'ready' }),
    manifest,
    profile: 'full',
    packageAvailability: { available: [], unavailable: [], unknown: [{ name: 'nmap', detail: 'empty apt index' }] },
  });

  assert.equal(plan.actions[0].id, 'apt_update');
  assert.equal(plan.actions[1].id, 'install_packages');
});

test('setup plan blocks an existing ctfagent account with sudo', () => {
  const plan = buildSetupPlan({
    doctorReport: doctorReport({ kali: 'ready', kaliVersion: 2, account: 'unsafe' }),
    manifest,
    profile: 'full',
  });
  assert.equal(plan.status, 'blocked');
  assert.deepEqual(plan.actions, []);
});

test('setup apply runs noninteractive distro installation and asks for a readiness recheck', async () => {
  const plan = buildSetupPlan({ doctorReport: doctorReport(), manifest, profile: 'full' });
  const invoked = [];
  const result = await applySetupPlan(plan, {
    interactive: false,
    executeAction: async (action) => { invoked.push(action.id); return { exitCode: 0 }; },
  });
  assert.equal(result.status, 'pending_recheck');
  assert.deepEqual(invoked, ['install_kali']);
});

test('setup apply reports administrator requirement without self-elevation', async () => {
  const plan = buildSetupPlan({ doctorReport: doctorReport(), manifest, profile: 'full' });
  const invoked = [];
  const result = await applySetupPlan(plan, {
    interactive: true,
    executeAction: async (action) => {
      invoked.push(action.id);
      return { exitCode: 740, stderr: 'The requested operation requires elevation.' };
    },
  });
  assert.deepEqual(invoked, ['install_kali']);
  assert.equal(result.status, 'pending_admin');
});

test('setup apply does not treat timed-out or truncated actions as successful', async () => {
  const plan = buildSetupPlan({
    doctorReport: doctorReport({ kali: 'ready', kaliVersion: 2, account: 'ready' }),
    manifest,
    profile: 'full',
  });
  const result = await applySetupPlan(plan, {
    executeAction: async (action) => action.id === 'apt_update'
      ? { exitCode: 0 }
      : { exitCode: 0, timedOut: true, truncated: false },
    checkPackages: async () => ({ available: [{ name: 'nmap', candidate: '1.0' }], unavailable: [], unknown: [] }),
  });

  assert.equal(result.status, 'failed');
  assert.equal(result.failedAction, 'install_packages');
});

test('package readiness distinguishes available, unavailable, and unknown apt candidates', async () => {
  const result = await probeAptPackages(['nmap', 'missing-tool', 'apt-error'], async (args) => {
    const packageName = args.at(-1);
    if (packageName === 'nmap') {
      return { exitCode: 0, stdout: 'nmap:\n  Candidate: 7.99-1\n', stderr: '' };
    }
    if (packageName === 'missing-tool') {
      return { exitCode: 0, stdout: 'missing-tool:\n  Candidate: (none)\n', stderr: '' };
    }
    return { exitCode: 1, stdout: '', stderr: 'apt-cache failed' };
  });

  assert.deepEqual(result, {
    available: [{ name: 'nmap', candidate: '7.99-1' }],
    unavailable: ['missing-tool'],
    unknown: [{ name: 'apt-error', detail: 'apt-cache failed' }],
  });
});

test('setup apply verifies package candidates after apt update and stops before missing packages', async () => {
  const plan = buildSetupPlan({
    doctorReport: doctorReport({ kali: 'ready', kaliVersion: 2, account: 'ready' }),
    manifest,
    profile: 'full',
  });
  const invoked = [];
  const result = await applySetupPlan(plan, {
    interactive: true,
    executeAction: async (action) => {
      invoked.push(action.id);
      return { exitCode: 0 };
    },
    checkPackages: async () => ({
      available: [{ name: 'nmap', candidate: '1.0' }],
      unavailable: ['sqlmap'],
      unknown: [],
    }),
  });

  assert.equal(result.status, 'blocked');
  assert.deepEqual(invoked, ['apt_update']);
  assert.deepEqual(result.packageCheck.unavailable, ['sqlmap']);
});
