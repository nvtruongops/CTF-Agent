import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

assert.equal(process.platform, 'win32', 'Run the Windows-to-installed-WSL check on Windows.');
const launcher = path.join(process.env.LOCALAPPDATA, 'CTF-Agent', 'ctf-agent.ps1');
const project = mkdtempSync(path.join(os.tmpdir(), 'opencode', 'ctf WSL thử nghiệm '));
const challenge = `clone-smoke-${process.pid}-${Date.now()}`;
const workspace = `/home/ctfagent/ctf-workspaces/${challenge}`;
const args = ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', launcher];
const env = { ...process.env, CTF_MCP_CTFD_URL: '', CTF_MCP_CTFD_TOKEN: '' };
function run(command, commandArgs) {
  const result = spawnSync(command, commandArgs, { cwd: project, env, encoding: 'utf8', timeout: 60_000 });
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
  return result.stdout;
}
const client = new Client({ name: 'ctf-windows-wsl-verifier', version: '1.0.0' });
const transport = new StdioClientTransport({ command: 'powershell.exe', args: [...args, 'mcp'], cwd: project, env });
try {
  const inputs = path.join(project, 'challenge inputs');
  mkdirSync(inputs);
  const fixture = path.join(inputs, 'sample.txt');
  const bytes = Buffer.from('CTF_WSL_CLONE_SMOKE\n');
  writeFileSync(fixture, bytes);
  const scope = JSON.parse(run('powershell.exe', [...args, 'scope', 'init', '--challenge', challenge, '--workspace', `.ctf-workspaces/${challenge}`, '--source-root', inputs, '--target', 'challenge.example:8080']));
  assert.equal(scope.wslWorkspace, workspace);
  await client.connect(transport);
  const text = (response) => response.content.find(({ type }) => type === 'text')?.text;
  const call = async (name, arguments_) => {
    const response = await client.callTool({ name, arguments: arguments_ });
    assert.notEqual(response.isError, true, `${name}: ${text(response)}`);
    return JSON.parse(text(response));
  };
  const { tools } = await client.listTools();
  assert.equal(tools.length, 38);
  const health = await call('ctf_mcp_health', {});
  assert.equal(health.version, '0.1.0');
  const status = await call('ctf_tool_status', {});
  assert.equal(status.healthy, true);
  const imported = await call('ctf_workspace_import', { sourcePath: fixture });
  assert.equal(imported.sha256, createHash('sha256').update(bytes).digest('hex'));
  const cyclic = await call('ctf_pwn_cyclic', { length: 32, wordSize: 4 });
  assert.match(cyclic.stdout, /aaaabaaacaaadaaa/);
  const solved = await call('ctf_smt_solve', { smtlib: '(set-logic QF_LIA)\n(declare-const x Int)\n(assert (= x 7))\n(check-sat)\n(get-model)\n' });
  assert.match(solved.stdout, /^sat/m);
  await call('ctf_forensics_metadata', { artifactPath: imported.destinationPath });
  const rejected = await client.callTool({ name: 'ctf_nmap_scan', arguments: { target: 'outside.example:8080', serviceDetection: false } });
  assert.equal(rejected.isError, true);
  assert.match(text(rejected), /scope/i);
  console.log(JSON.stringify({ status: 'passed', version: health.version, tools: tools.length, node: status.node.version, python: status.baseExecutables.find(({ id }) => id === 'python3')?.version, checks: ['Windows PowerShell launcher', 'Unicode/spaces cwd', 'MCP stdio', 'file import SHA-256', 'native pwntools', 'Z3', 'ExifTool', 'scope rejection'] }));
} finally {
  await client.close();
  await transport.close();
  // WSL-created private scope files must also be removed by their Linux owner.
  run('wsl.exe', ['--distribution', 'kali-linux', '--user', 'ctfagent', '--exec', '/usr/bin/python3', '-c', 'import shutil,sys;[shutil.rmtree(p,ignore_errors=True) for p in [sys.argv[1],".ctf-agent",".ctf-workspaces"]]', workspace]);
  rmSync(project, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}
