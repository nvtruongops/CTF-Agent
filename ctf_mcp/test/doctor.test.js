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
  return async (args) => {
    if (args[0] === '--status') return ok('Default Version: 2\n');
    if (args[0] === '--list' && args[1] === '--verbose') return ok(listOutput);

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
}

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
    runWsl: async (args) => {
      if (args[0] === '--status') return ok('Default Version: 2\n');
      if (args[0] === '--list' && args[1] === '--verbose') {
        return ok('NAME                    STATE           VERSION\n'
          + '  kali-linux              Stopped         2\n');
      }
      if (args.includes('id') && args.includes('-u')) return ok('1001\n');
      if (args.includes('id') && args.includes('-nG')) return ok('ctfagent\n');
      const executable = args.at(-2);
      if (executable === 'strings') return { ...ok(''), exitCode: 127, stderr: 'not found' };
      return ok(`${executable} version 1.0\n`);
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
