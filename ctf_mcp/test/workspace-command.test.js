import test from 'node:test';
import assert from 'node:assert/strict';
import { runWorkspaceWorker } from '../tools/workspace-command.js';
import { runWsl, runWslTool } from '../wsl.js';

test('runWorkspaceWorker sends JSON and decodes bounded worker output', async () => {
  let observed;
  const response = await runWorkspaceWorker(
    { mode: 'command', executable: 'strings' },
    async (executable, args, options) => {
      observed = { executable, args, options };
      return {
        exitCode: 0,
        stdout: JSON.stringify({
          executable: 'strings',
          exitCode: 0,
          stdoutBase64: Buffer.from('candidate\n').toString('base64'),
          stderrBase64: '',
          timedOut: false,
          truncated: false,
        }),
        stderr: '',
        timedOut: false,
        truncated: false,
      };
    },
    { timeoutMs: 5000, maxOutputBytes: 1024 },
  );

  assert.equal(observed.executable, 'python3');
  assert.deepEqual(observed.args.slice(0, 1), ['-c']);
  assert.deepEqual(JSON.parse(observed.options.input), { mode: 'command', executable: 'strings' });
  assert.equal(observed.options.timeoutMs, 15_000);
  assert.equal(response.result.stdout, 'candidate\n');
  assert.equal(response.result.stderr, '');
  assert.equal(response.transport.exitCode, 0);
  assert.equal(response.transport.timedOut, false);
});

test('runWorkspaceWorker crosses the real Windows-to-WSL boundary', {
  skip: process.env.CTF_AGENT_RUN_WSL_INTEGRATION !== '1',
}, async () => {
  const workspace = `/home/ctfagent/ctf-workspaces/mcp-worker-smoke-${process.pid}-${Date.now()}`;
  const wslPrefix = ['--distribution', 'kali-linux', '--user', 'ctfagent', '--exec'];
  const setup = await runWsl([
    ...wslPrefix,
    'python3', '-c', "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.mkdir(mode=0o700); (p/'sample.txt').write_text('CTF_WORKER_NODE_SMOKE')",
    workspace,
  ]);
  assert.equal(setup.exitCode, 0, setup.stderr);
  try {
    const artifactPath = `${workspace}/sample.txt`;
    const response = await runWorkspaceWorker({
      mode: 'command',
      workspace,
      executable: 'strings',
      args: ['-a', '-n', '4', artifactPath],
      filePaths: [artifactPath],
      timeoutMs: 10_000,
      maxOutputBytes: 65_536,
    }, runWslTool, { timeoutMs: 10_000, maxOutputBytes: 65_536 });
    assert.equal(response.transport.exitCode, 0, response.transport.stderr);
    assert.equal(response.result.exitCode, 0, response.result.stderr);
    assert.match(response.result.stdout, /CTF_WORKER_NODE_SMOKE/);
  } finally {
    const cleanup = await runWsl([
      ...wslPrefix,
      'python3', '-c', 'import shutil,sys; shutil.rmtree(sys.argv[1])',
      workspace,
    ]);
    assert.equal(cleanup.exitCode, 0, cleanup.stderr);
  }
});
