import assert from 'node:assert/strict';
import { doctor } from '../doctor.js';
import test from 'node:test';

const manifest = {
  categories: [
    {
      id: 'web',
      provider: 'ctf-mcp',
      tools: [{ id: 'nmap', executable: 'nmap', probeArgs: ['--version'] }],
    },
    { id: 'reverse', provider: 'ctf-mcp', tools: [{ id: 'reverse_stub', builtin: true }] },
  ],
};

const ok = (stdout = '') => ({
  exitCode: 0,
  stdout,
  stderr: '',
  timedOut: false,
  truncated: false,
});

function fakeWsl({ listOutput, userExists = false, uid = '1001', groups = '', missing = [] }) {
  const calls = [];
  const runWsl = async (args, options = {}) => {
    calls.push(args);
    if (args[0] === '--status') return ok('Default Version: 2\n');
    if (args[0] === '--list' && args[1] === '--verbose') return ok(listOutput);

    if (args.includes('python3') && args.includes('-c')) {
      const request = JSON.parse(options.input);
      const isRoot = args.includes('root');
      const results = request.probes.map((probe) => {
        if (probe.id === 'account.uid') {
          return userExists
            ? { id: probe.id, exitCode: 0, stdoutBase64: Buffer.from(`${uid}\n`).toString('base64'), stderrBase64: '', timedOut: false, truncated: false }
            : { id: probe.id, exitCode: 1, stdoutBase64: '', stderrBase64: Buffer.from('no such user').toString('base64'), timedOut: false, truncated: false };
        }
        if (probe.id === 'account.groups') {
          return { id: probe.id, exitCode: userExists ? 0 : 1, stdoutBase64: Buffer.from(`${groups}\n`).toString('base64'), stderrBase64: '', timedOut: false, truncated: false };
        }
        const executable = probe.argv[0];
        const missingExecutable = missing.includes(executable);
        const stdout = executable === 'python3'
          ? 'Python 3.14.7\n'
          : (executable === 'nmap' ? 'Nmap version 7.99\n' : `${executable} version 1.0\n`);
        return {
          id: probe.id,
          exitCode: missingExecutable ? 127 : 0,
          stdoutBase64: Buffer.from(missingExecutable ? '' : stdout).toString('base64'),
          stderrBase64: Buffer.from(missingExecutable ? 'not found' : '').toString('base64'),
          timedOut: false,
          truncated: false,
        };
      });
      return ok(JSON.stringify({ results, root: isRoot }));
    }

    if (args.includes('id') && args.includes('-u')) {
      return userExists ? ok(`${uid}\n`) : { ...ok(''), exitCode: 1, stderr: 'no such user' };
    }
    if (args.includes('id') && args.includes('-nG')) return ok(`${groups}\n`);

    const executable = args.at(-2);
    if (missing.includes(executable)) return { ...ok(''), exitCode: 127, stderr: 'not found' };
    if (executable === 'python3') return ok('Python 3.14.7\n');
    if (executable === 'nmap') return ok('Nmap version 7.99\n');
    if (executable === 'hydra') return ok('Hydra version 9.7\n');
    throw new Error(`Unexpected WSL probe: ${args.join(' ')}`);
  };
  runWsl.calls = calls;
  return runWsl;
}

test('doctor batches account and executable probes without changing readiness results', async () => {
  const listOutput = 'NAME                    STATE           VERSION\n  kali-linux              Stopped         2\n';
  const readyManifest = {
    baseExecutables: ['python3'],
    categories: [{
      id: 'reverse',
      tools: [{ id: 'inspect', executable: 'readelf', requiredExecutables: ['strings'] }],
    }],
  };
  const readyWsl = fakeWsl({ listOutput, userExists: true, groups: 'ctfagent' });
  const ready = await doctor({ runWsl: readyWsl, manifest: readyManifest, nodeVersion: '24.19.0' });

  assert.equal(ready.healthy, true);
  assert.deepEqual(ready.baseExecutables, [{ id: 'python3', status: 'ready', version: 'Python 3.14.7', detail: null }]);
  assert.equal(ready.categories[0].tools[0].status, 'ready');
  assert.equal(readyWsl.calls.length, 4);

  const optionalManifest = {
    categories: [{ id: 'exploitation', tools: [{
      id: 'hydra', executable: 'hydra', optionalProfile: 'exploitation',
    }] }],
  };
  const optionalWsl = fakeWsl({ listOutput, userExists: true, groups: 'ctfagent', missing: ['hydra'] });
  const optional = await doctor({ runWsl: optionalWsl, manifest: optionalManifest, nodeVersion: '24.19.0' });

  assert.equal(optional.healthy, true);
  assert.equal(optional.categories[0].tools[0].status, 'missing_dependency');
  assert.equal(optionalWsl.calls.length, 4);

  const missingAccountWsl = fakeWsl({ listOutput });
  const missingAccount = await doctor({ runWsl: missingAccountWsl, manifest: readyManifest, nodeVersion: '24.19.0' });

  assert.equal(missingAccount.account.status, 'missing');
  assert.equal(missingAccount.baseExecutables[0].status, 'blocked');
  assert.equal(missingAccount.categories[0].tools[0].status, 'blocked');
  assert.equal(missingAccountWsl.calls.length, 3);
});

test('doctor does not mark worker transport failures ready', async () => {
  const runWsl = async (args) => {
    if (args[0] === '--status') return ok('Default Version: 2\n');
    if (args[0] === '--list') return ok('NAME                    STATE           VERSION\n  kali-linux              Running         2\n');
    return { ...ok('{"error":"worker unavailable"}'), exitCode: 1, stderr: 'worker unavailable' };
  };
  const result = await doctor({
    runWsl,
    manifest: { baseExecutables: ['python3'], categories: [] },
    nodeVersion: '24.19.0',
  });

  assert.equal(result.healthy, false);
  assert.equal(result.account.status, 'missing');
  assert.equal(result.baseExecutables[0].status, 'blocked');
});

test('doctor reports Kali and its tools missing when WSL has only Docker Desktop', async () => {
  const result = await doctor({
    runWsl: fakeWsl({
      listOutput: 'NAME                    STATE           VERSION\n'
        + '* docker-desktop         Running         2\n'
        + '  Ubuntu-24.04            Stopped         2\n',
    }),
    manifest,
    nodeVersion: '24.19.0',
  });

  assert.equal(result.wsl?.status, 'ready');
  assert.equal(result.wsl?.version, 2);
  assert.equal(result.kali?.status, 'missing');
  assert.equal(result.account?.status, 'not_checked');
  assert.deepEqual(result.distributions?.map((distro) => distro.name), ['docker-desktop', 'Ubuntu-24.04']);
  assert.equal(result.categories?.[0]?.tools?.[0]?.status, 'missing_dependency');
  assert.equal(result.categories?.[1]?.status, 'ready');
});

test('doctor rejects a Kali WSL1 distro before checking its user or tools', async () => {
  const result = await doctor({
    runWsl: fakeWsl({
      listOutput: 'NAME                    STATE           VERSION\n'
        + '* docker-desktop         Running         2\n'
        + '  kali-linux              Stopped         1\n',
    }),
    manifest,
    nodeVersion: '24.19.0',
  });

  assert.equal(result.kali?.status, 'unsupported');
  assert.equal(result.kali?.version, 1);
  assert.equal(result.account?.status, 'not_checked');
  assert.equal(result.categories?.[0]?.tools?.[0]?.status, 'blocked');
});

test('doctor reports a missing ctfagent account without running tool probes', async () => {
  const result = await doctor({
    runWsl: fakeWsl({
      listOutput: 'NAME                    STATE           VERSION\n'
        + '* docker-desktop         Running         2\n'
        + '  kali-linux              Stopped         2\n',
      userExists: false,
    }),
    manifest,
    nodeVersion: '24.19.0',
  });

  assert.equal(result.kali?.status, 'ready');
  assert.equal(result.account?.status, 'missing');
  assert.equal(result.categories?.[0]?.tools?.[0]?.status, 'blocked');
});

test('doctor reports a ready non-sudo ctfagent and probes installed tools', async () => {
  const result = await doctor({
    runWsl: fakeWsl({
      listOutput: 'NAME                    STATE           VERSION\n'
        + '* docker-desktop         Running         2\n'
        + '  kali-linux              Stopped         2\n',
      userExists: true,
      groups: 'ctfagent',
    }),
    manifest,
    nodeVersion: '24.19.0',
  });

  assert.equal(result.account?.status, 'ready');
  assert.equal(result.categories?.[0]?.tools?.[0]?.status, 'ready');
  assert.equal(result.categories?.[0]?.tools?.[0]?.version, 'Nmap version 7.99');
});

test('doctor reports missing optional tools without making baseline health fail', async () => {
  const optionalManifest = {
    baseExecutables: ['python3'],
    categories: [
      manifest.categories[0],
      {
        id: 'exploitation',
        provider: 'ctf-mcp',
        tools: [{
          id: 'ctf_hydra_audit',
          optionalProfile: 'exploitation',
          executable: 'hydra',
          probeArgs: ['-h'],
        }],
      },
    ],
  };
  const result = await doctor({
    runWsl: fakeWsl({
      listOutput: 'NAME                    STATE           VERSION\n'
        + '  kali-linux              Running         2\n',
      userExists: true,
      groups: 'ctfagent',
      missing: ['hydra'],
    }),
    manifest: optionalManifest,
    nodeVersion: '24.19.0',
  });

  assert.equal(result.healthy, true);
  assert.equal(result.categories[1].tools[0].status, 'missing_dependency');
  assert.equal(result.categories[1].status, 'missing_dependency');
});

test('doctor marks wheel and root group memberships unsafe', async () => {
  for (const group of ['wheel', 'root']) {
    const result = await doctor({ manifest, runWsl: fakeWsl({ listOutput: 'kali-linux Running 2', userExists: true, groups: `ctfagent ${group}` }) });
    assert.equal(result.account.status, 'unsafe');
  }
});

test('doctor marks a root-UID ctfagent unsafe even without the sudo group', async () => {
  const result = await doctor({
    runWsl: fakeWsl({
      listOutput: 'NAME                    STATE           VERSION\n'
        + '  kali-linux              Stopped         2\n',
      userExists: true,
      uid: '0',
      groups: 'ctfagent',
    }),
    manifest,
    nodeVersion: '24.19.0',
  });

  assert.equal(result.account?.status, 'unsafe');
  assert.equal(result.healthy, false);
  assert.equal(result.categories?.[0]?.tools?.[0]?.status, 'blocked');
});

test('doctor is healthy without REA configuration and does not report REA state', async () => {
  const result = await doctor({
    runWsl: fakeWsl({
      listOutput: 'NAME                    STATE           VERSION\n'
        + '* docker-desktop         Running         2\n'
        + '  kali-linux              Stopped         2\n',
      userExists: true,
      groups: 'ctfagent',
    }),
    manifest,
    projectConfig: {},
    nodeVersion: '24.19.0',
  });

  assert.equal(result.healthy, true);
  assert.equal(Object.hasOwn(result, 'rea'), false);
});

test('doctor requires every auxiliary executable used by a multi-command tool', async () => {
  const result = await doctor({
    runWsl: async (args, options = {}) => {
      if (args[0] === '--status') return ok('Default Version: 2\n');
      if (args[0] === '--list' && args[1] === '--verbose') {
        return ok('NAME                    STATE           VERSION\n'
          + '  kali-linux              Stopped         2\n');
      }
      const { probes } = JSON.parse(options.input);
      const results = probes.map((probe) => {
        if (probe.id === 'account.uid') return { id: probe.id, exitCode: 0, stdoutBase64: Buffer.from('1001\n').toString('base64'), stderrBase64: '', timedOut: false, truncated: false };
        if (probe.id === 'account.groups') return { id: probe.id, exitCode: 0, stdoutBase64: Buffer.from('ctfagent\n').toString('base64'), stderrBase64: '', timedOut: false, truncated: false };
        const executable = probe.argv[0];
        const missing = executable === 'strings';
        return {
          id: probe.id,
          exitCode: missing ? 127 : 0,
          stdoutBase64: Buffer.from(missing ? '' : `${executable} version 1.0\n`).toString('base64'),
          stderrBase64: Buffer.from(missing ? 'not found' : '').toString('base64'),
          timedOut: false,
          truncated: false,
        };
      });
      return ok(JSON.stringify({ results }));
    },
    manifest: {
      categories: [{
        id: 'reverse',
        provider: 'ctf-mcp',
        tools: [{
          id: 'ctf_reverse_inspect',
          executable: 'readelf',
          probeArgs: ['--version'],
          requiredExecutables: ['file', 'strings'],
          timeoutMs: 30_000,
          maxOutputBytes: 1_048_576,
        }],
      }],
    },
    nodeVersion: '24.19.0',
  });

  assert.equal(result.categories[0].tools[0].status, 'missing_dependency');
  assert.match(result.categories[0].tools[0].detail, /strings/);
});

test('doctor probes base runtime executables required by workspace operations', async () => {
  const result = await doctor({
    runWsl: fakeWsl({
      listOutput: 'NAME                    STATE           VERSION\n'
        + '  kali-linux              Running         2\n',
      userExists: true,
      groups: 'ctfagent',
    }),
    manifest: { baseExecutables: ['python3'], categories: [] },
    nodeVersion: '24.19.0',
  });

  assert.deepEqual(result.baseExecutables, [{ id: 'python3', status: 'ready', version: 'Python 3.14.7', detail: null }]);
});

test('doctor marks built-in decoders ready without Kali', async () => {
  const result = await doctor({
    runWsl: fakeWsl({
      listOutput: 'NAME                    STATE           VERSION\n'
        + '* docker-desktop         Running         2\n'
        + '  Ubuntu-24.04            Stopped         2\n',
    }),
    manifest: {
      categories: [
        { id: 'misc', tools: [{ id: 'ctf_decode', builtin: true }] },
        { id: 'competition', tools: [{ id: 'ctf_ctfd_list_challenges', builtin: true }] },
      ],
    },
    nodeVersion: '24.19.0',
  });

  assert.equal(result.categories?.[0]?.status, 'ready');
  assert.equal(result.categories?.[0]?.tools?.[0]?.status, 'ready');
  assert.equal(result.categories?.[1]?.status, 'ready');
  assert.equal(result.categories?.[1]?.tools?.[0]?.status, 'ready');
});
