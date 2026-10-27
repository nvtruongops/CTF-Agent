import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Client, InMemoryTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import test from 'node:test';
import { createServer } from '../server.js';

const { version } = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));

test('stdio MCP exposes a health tool with a verifiable server identity', async () => {
  const client = new Client({ name: 'ctf-agent-test', version: '0.1.0' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ['ctf_mcp/cli.js', 'mcp'],
  });

  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    assert.ok(tools.some((tool) => tool.name === 'ctf_mcp_health'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_tool_status'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_nmap_scan'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_scoped_http_request'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_smt_solve'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_decode'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_crypto_candidates'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_pwn_run'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_forensics_pcap'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_forensics_pcap_follow_stream'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_reverse_inspect'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_reverse_disassemble'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_reverse_gdb_info'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_game_frida_spawn'));
    assert.equal(tools.some((tool) => tool.name.startsWith('rea_')), false);
    assert.ok(tools.some((tool) => tool.name === 'ctf_stego_steghide'));
    const stegoMetadataTool = tools.find((tool) => tool.name === 'ctf_stego_metadata');
    assert.ok(stegoMetadataTool);
    assert.deepEqual(Object.keys(stegoMetadataTool.inputSchema.properties), ['artifactPath']);
    assert.ok(tools.some((tool) => tool.name === 'ctf_hardware_decode_signal'));
    assert.ok(tools.some((tool) => tool.name === 'ctf_workspace_import'));
    for (const name of [
      'ctf_ctfd_list_challenges',
      'ctf_ctfd_get_challenge',
      'ctf_ctfd_download_attachment',
      'ctf_ctfd_auth_status',
      'ctf_ctfd_progress',
    ]) assert.ok(tools.some((tool) => tool.name === name));

    const result = await client.callTool({ name: 'ctf_mcp_health', arguments: {} });
    const text = result.content.find((block) => block.type === 'text')?.text;
    assert.deepEqual(JSON.parse(text), {
      name: 'ctf-agent',
      status: 'alive',
      version,
    });

    const cryptoResult = await client.callTool({
      name: 'ctf_crypto_candidates',
      arguments: { value: 'ZmxhZ3tva30=', encoding: 'auto', includeSingleByteXor: false },
    });
    const cryptoText = cryptoResult.content.find((block) => block.type === 'text')?.text;
    assert.ok(JSON.parse(cryptoText).candidates.some((candidate) => candidate.text === 'flag{ok}'));

    const statusResult = await client.callTool({ name: 'ctf_tool_status', arguments: {} });
    const statusText = statusResult.content.find((block) => block.type === 'text')?.text;
    const status = JSON.parse(statusText);
    assert.ok(status.node);
    assert.ok(status.wsl);
    assert.ok(status.kali);
    assert.ok(Array.isArray(status.categories));
    const competition = status.categories.find((category) => category.id === 'competition');
    assert.equal(competition.status, 'ready');
    assert.equal(competition.tools.every((tool) => tool.status === 'ready'), true);
    assert.equal(Object.hasOwn(status, 'rea'), false);

    const rejected = await client.callTool({
      name: 'ctf_nmap_scan',
      arguments: { target: 'outside.example:8080', serviceDetection: false },
    });
    assert.equal(rejected.isError, true);
    assert.match(rejected.content.find((block) => block.type === 'text')?.text ?? '', /scope/i);
  } finally {
    await client.close();
  }
});

test('health reports liveness without probing WSL readiness', async () => {
  let wslCalls = 0;
  const server = createServer({
    runWsl: async () => {
      wslCalls += 1;
      throw new Error('health must not probe WSL');
    },
  });
  const client = new Client({ name: 'ctf-agent-test', version: '0.1.0' });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const result = await client.callTool({ name: 'ctf_mcp_health', arguments: {} });
    const text = result.content.find((block) => block.type === 'text')?.text;

    assert.deepEqual(JSON.parse(text), {
      name: 'ctf-agent',
      status: 'alive',
      version,
    });
    assert.equal(wslCalls, 0);
  } finally {
    await client.close();
    await server.close();
  }
});
