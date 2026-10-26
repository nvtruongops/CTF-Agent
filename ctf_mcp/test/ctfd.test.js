import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { initScope } from '../scope.js';
import { createCtfdClient, registerCtfdTools } from '../tools/ctfd.js';
import { writeWorkspaceBytes } from '../tools/workspace.js';
import test from 'node:test';

const baseUrl = 'https://ctf.example/ctf';

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify({ success: status < 400, data }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function queueFetch(responses) {
  const calls = [];
  return {
    calls,
    fetchImpl: async (url, options) => {
      calls.push({ url: String(url), options });
      const response = responses.shift();
      if (!response) throw new Error('unexpected fetch');
      return response;
    },
  };
}

function challengeDetail(files) {
  return jsonResponse({
    id: 8,
    type: 'standard',
    name: 'Forensics 1',
    value: 250,
    category: 'forensics',
    description: 'untrusted',
    solves: 0,
    solved_by_me: false,
    tags: [],
    files,
  });
}

test('CTFd client rejects unsafe base URLs before making requests', () => {
  const fetchImpl = async () => { throw new Error('must not fetch'); };
  for (const url of [
    'http://ctf.example',
    'https://user:password@ctf.example',
    'https://ctf.example/?token=secret',
    'https://ctf.example/#fragment',
    'ftp://ctf.example',
  ]) {
    assert.throws(() => createCtfdClient({ url, fetchImpl }), (error) => error.code === 'CTFD_INVALID_CONFIG', url);
  }
  assert.doesNotThrow(() => createCtfdClient({ url: 'http://localhost:8000/ctf', fetchImpl }));
});

test('challenge listing uses the fixed API path and returns only allowlisted fields', async () => {
  const fixture = [{
    id: 7,
    type: 'standard',
    name: 'Web 1',
    value: 100,
    category: 'web',
    solves: 5,
    solved_by_me: true,
    tags: [{ value: 'sql' }],
    template: 'do not return',
    script: 'do not return',
    module_id: 4,
  }];
  const { calls, fetchImpl } = queueFetch([jsonResponse(fixture)]);
  const client = createCtfdClient({ url: baseUrl, fetchImpl });

  const result = await client.listChallenges();

  assert.deepEqual(result, [{
    id: 7,
    type: 'standard',
    name: 'Web 1',
    value: 100,
    category: 'web',
    solves: 5,
    solved_by_me: true,
    tags: ['sql'],
  }]);
  assert.equal(calls[0].url, 'https://ctf.example/ctf/api/v1/challenges');
  assert.equal(calls[0].options.method, 'GET');
  assert.equal(calls[0].options.redirect, 'manual');
  assert.equal(calls[0].options.headers.authorization, undefined);
});

test('authenticated challenge listing uses JSON Content-Type and never returns the token', async () => {
  const { calls, fetchImpl } = queueFetch([jsonResponse([])]);
  const client = createCtfdClient({ url: baseUrl, token: 'secret-token', fetchImpl });

  const result = await client.listChallenges();

  assert.deepEqual(result, []);
  assert.equal(calls[0].options.headers.authorization, 'Token secret-token');
  assert.equal(calls[0].options.headers['content-type'], 'application/json');
  assert.equal(JSON.stringify(result).includes('secret-token'), false);
});

test('challenge details are anonymous and omit templates, hints, solutions, and file URLs', async () => {
  const detail = {
    id: 8,
    type: 'standard',
    name: 'Forensics 1',
    value: 250,
    category: 'forensics',
    description: '<p>Untrusted challenge text</p>',
    solves: 2,
    solved_by_me: false,
    tags: ['pcap'],
    files: ['/ctf/files/captures/trace%20one.pcap'],
    hints: [{ id: 1, title: 'secret hint', content: 'hidden' }],
    solution_id: 99,
    view: '<script>do not return</script>',
    template: 'do not return',
    script: 'do not return',
  };
  const { calls, fetchImpl } = queueFetch([jsonResponse(detail)]);
  const client = createCtfdClient({ url: baseUrl, token: 'secret-token', fetchImpl });

  const result = await client.getChallenge(8);

  assert.deepEqual(result, {
    id: 8,
    type: 'standard',
    name: 'Forensics 1',
    value: 250,
    category: 'forensics',
    description: '<p>Untrusted challenge text</p>',
    solves: 2,
    solved_by_me: false,
    tags: ['pcap'],
    attachments: [{ index: 0, name: 'trace one.pcap' }],
  });
  assert.equal(calls[0].url, 'https://ctf.example/ctf/api/v1/challenges/8');
  assert.equal(calls[0].options.headers.authorization, undefined);
  assert.equal(JSON.stringify(result).includes('/files/'), false);
  assert.equal(JSON.stringify(result).includes('secret hint'), false);
});

test('private challenge details fail closed without an authenticated retry', async () => {
  const { calls, fetchImpl } = queueFetch([new Response('private', { status: 403 })]);
  const client = createCtfdClient({ url: baseUrl, token: 'secret-token', fetchImpl });

  await assert.rejects(client.getChallenge(8), (error) => error.code === 'CTFD_FORBIDDEN');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.headers.authorization, undefined);
});

test('auth status does not contact CTFd when no token is configured', async () => {
  let called = false;
  const client = createCtfdClient({ url: baseUrl, fetchImpl: async () => { called = true; } });

  assert.deepEqual(await client.authStatus(), { status: 'not_configured' });
  assert.equal(called, false);
});

test('auth status returns only non-sensitive identity fields and redacts 401 bodies', async () => {
  const valid = queueFetch([jsonResponse({ id: 12, name: 'player', email: 'private@example.test', password: 'hash', score: 80, place: 3 })]);
  const client = createCtfdClient({ url: baseUrl, token: 'secret-token', fetchImpl: valid.fetchImpl });

  assert.deepEqual(await client.authStatus(), {
    status: 'authenticated',
    user: { id: 12, name: 'player' },
  });
  assert.equal(valid.calls[0].options.headers.authorization, 'Token secret-token');
  assert.equal(valid.calls[0].options.headers['content-type'], 'application/json');

  const invalid = queueFetch([new Response('secret-token leaked here', { status: 401 })]);
  const rejectedClient = createCtfdClient({ url: baseUrl, token: 'secret-token', fetchImpl: invalid.fetchImpl });
  const status = await rejectedClient.authStatus();
  assert.deepEqual(status, { status: 'unauthorized', httpStatus: 401 });
  assert.equal(JSON.stringify(status).includes('secret-token'), false);
});

test('progress returns only current user summary and solved challenge IDs', async () => {
  const { calls, fetchImpl } = queueFetch([
    jsonResponse({ id: 12, name: 'player', email: 'private@example.test', password: 'hash', score: 80, place: 3 }),
    new Response(JSON.stringify({
      success: true,
      data: [
        { id: 1, challenge_id: 7, submission: 'flag{secret}', user_id: 12 },
        { id: 2, challenge_id: 8, submission: 'another-secret', user_id: 12 },
      ],
      meta: { count: 2 },
    }), { headers: { 'content-type': 'application/json' } }),
  ]);
  const client = createCtfdClient({ url: baseUrl, token: 'secret-token', fetchImpl });

  const result = await client.progress();

  assert.deepEqual(result, {
    user: { id: 12, name: 'player', score: 80, place: 3 },
    solveCount: 2,
    solvedChallengeIds: [7, 8],
  });
  assert.deepEqual(calls.map((call) => new URL(call.url).pathname), [
    '/ctf/api/v1/users/me',
    '/ctf/api/v1/users/me/solves',
  ]);
  for (const { options } of calls) {
    assert.equal(options.method, 'GET');
    assert.equal(options.headers.authorization, 'Token secret-token');
    assert.equal(options.headers['content-type'], 'application/json');
  }
  assert.equal(JSON.stringify(result).includes('secret'), false);
});

test('CTFd API rejects malformed and oversized JSON without exposing its body', async () => {
  const malformed = createCtfdClient({
    url: baseUrl,
    fetchImpl: async () => new Response('not-json-secret', { headers: { 'content-type': 'application/json' } }),
  });
  await assert.rejects(malformed.listChallenges(), (error) => (
    error.code === 'CTFD_INVALID_RESPONSE' && !error.message.includes('not-json-secret')
  ));

  const oversized = createCtfdClient({
    url: baseUrl,
    fetchImpl: async () => new Response(' '.repeat(2 * 1024 * 1024 + 1), {
      headers: { 'content-type': 'application/json' },
    }),
  });
  await assert.rejects(oversized.listChallenges(), (error) => error.code === 'CTFD_RESPONSE_TOO_LARGE');
});

test('attachment download resolves an anonymous same-origin file and follows a bounded local redirect', async () => {
  const payload = Buffer.from('capture bytes');
  const { calls, fetchImpl } = queueFetch([
    challengeDetail(['/ctf/files/captures/trace.pcap']),
    new Response(null, { status: 302, headers: { location: '/ctf/files/captures/renamed.pcap' } }),
    new Response(payload, { headers: { 'content-length': String(payload.length) } }),
  ]);
  const client = createCtfdClient({ url: baseUrl, token: 'secret-token', fetchImpl });

  const result = await client.downloadAttachment(8, 0);

  assert.equal(result.name, 'renamed.pcap');
  assert.deepEqual(result.bytes, payload);
  assert.deepEqual(calls.map(({ url }) => url), [
    'https://ctf.example/ctf/api/v1/challenges/8',
    'https://ctf.example/ctf/files/captures/trace.pcap',
    'https://ctf.example/ctf/files/captures/renamed.pcap',
  ]);
  assert.equal(calls.every(({ options }) => options.method === 'GET' && options.redirect === 'manual'), true);
  assert.equal(calls.every(({ options }) => options.headers.authorization === undefined), true);
});

test('attachment download stops after three same-origin redirects', async () => {
  const redirects = [
    challengeDetail(['/ctf/files/0.bin']),
    ...Array.from({ length: 4 }, (_, index) => new Response(null, {
      status: 302,
      headers: { location: `/ctf/files/${index + 1}.bin` },
    })),
  ];
  const { calls, fetchImpl } = queueFetch(redirects);
  const client = createCtfdClient({ url: baseUrl, fetchImpl });

  await assert.rejects(client.downloadAttachment(8, 0), (error) => error.code === 'CTFD_REDIRECT_LIMIT');
  assert.equal(calls.length, 5);
});

test('attachment download accepts a body exactly at the 64 MiB limit', async () => {
  const maxBytes = 64 * 1024 * 1024;
  const chunk = new Uint8Array(1024 * 1024);
  const stream = new ReadableStream({
    start(controller) {
      for (let index = 0; index < 64; index += 1) controller.enqueue(chunk);
      controller.close();
    },
  });
  const { fetchImpl } = queueFetch([
    challengeDetail(['/ctf/files/exact-limit.bin']),
    new Response(stream, { headers: { 'content-length': String(maxBytes) } }),
  ]);
  const client = createCtfdClient({ url: baseUrl, fetchImpl });

  const result = await client.downloadAttachment(8, 0);

  assert.equal(result.bytes.length, maxBytes);
  assert.equal(result.name, 'exact-limit.bin');
});

test('attachment download rejects cross-origin file URLs and redirects without following them', async () => {
  const externalFile = queueFetch([challengeDetail(['https://evil.example/files/secret.bin'])]);
  const externalClient = createCtfdClient({ url: baseUrl, fetchImpl: externalFile.fetchImpl });
  await assert.rejects(externalClient.downloadAttachment(8, 0), (error) => error.code === 'CTFD_INVALID_RESPONSE');
  assert.equal(externalFile.calls.length, 1);

  const redirect = queueFetch([
    challengeDetail(['/ctf/files/secret.bin']),
    new Response(null, { status: 302, headers: { location: 'https://evil.example/secret.bin' } }),
  ]);
  const redirectClient = createCtfdClient({ url: baseUrl, fetchImpl: redirect.fetchImpl });
  await assert.rejects(redirectClient.downloadAttachment(8, 0), (error) => error.code === 'CTFD_INVALID_ATTACHMENT');
  assert.equal(redirect.calls.length, 2);
});

test('attachment byte caps do not trust Content-Length', async () => {
  const stream = new ReadableStream({
    start(controller) {
      const chunk = new Uint8Array(1024 * 1024);
      for (let index = 0; index < 64; index += 1) controller.enqueue(chunk);
      controller.enqueue(new Uint8Array([1]));
      controller.close();
    },
  });
  const { fetchImpl } = queueFetch([
    challengeDetail(['/ctf/files/large.bin']),
    new Response(stream, { headers: { 'content-length': '1' } }),
  ]);
  const client = createCtfdClient({ url: baseUrl, fetchImpl });

  await assert.rejects(client.downloadAttachment(8, 0), (error) => error.code === 'CTFD_ATTACHMENT_TOO_LARGE');
});

test('attachment declared length above the cap is rejected before reading the body', async () => {
  const { fetchImpl } = queueFetch([
    challengeDetail(['/ctf/files/large.bin']),
    new Response(null, { status: 200, headers: { 'content-length': String(64 * 1024 * 1024 + 1) } }),
  ]);
  const client = createCtfdClient({ url: baseUrl, fetchImpl });

  await assert.rejects(client.downloadAttachment(8, 0), (error) => error.code === 'CTFD_ATTACHMENT_TOO_LARGE');
});

test('workspace byte writer verifies digest and rejects invalid or oversized destinations before WSL', async () => {
  const bytes = Buffer.from('attachment bytes');
  const digest = '2508f58332a50c3fee16cc39d28bd45b17d7c3d65ec32b7ebd024d55b7a1393d';
  const scope = {
    challengeId: 'ctfd-01',
    wslWorkspace: '/home/ctfagent/ctf-workspaces/ctfd-01',
  };
  const calls = [];
  const runWsl = async (args, options) => {
    calls.push({ args, options });
    return {
      exitCode: 0,
      stdout: JSON.stringify({ sha256: digest, bytes: bytes.length }),
      stderr: '',
      timedOut: false,
      truncated: false,
    };
  };

  const result = await writeWorkspaceBytes({
    bytes,
    destinationPath: `${scope.wslWorkspace}/attachments/trace.bin`,
    scope,
    runWsl,
    maxBytes: 128,
  });
  assert.deepEqual(result, {
    destinationPath: `${scope.wslWorkspace}/attachments/trace.bin`,
    bytes: bytes.length,
    sha256: digest,
  });
  assert.deepEqual(calls[0].options.input, bytes);
  assert.equal(calls[0].args.at(-4), 'write');

  await assert.rejects(writeWorkspaceBytes({
    bytes: Buffer.alloc(129),
    destinationPath: `${scope.wslWorkspace}/too-large.bin`,
    scope,
    maxBytes: 128,
    runWsl,
  }), /limit/i);
  await assert.rejects(writeWorkspaceBytes({
    bytes,
    destinationPath: '/tmp/outside.bin',
    scope,
    maxBytes: 128,
    runWsl,
  }), /outside/i);
  assert.equal(calls.length, 1);
});

test('CTFd tool registration exposes only the five read-only tools with bounded schemas', () => {
  const tools = new Map();
  const server = { registerTool: (name, config, handler) => tools.set(name, { config, handler }) };
  registerCtfdTools(server, { projectRoot: 'D:\\ctf', env: {} });

  assert.deepEqual([...tools.keys()].sort(), [
    'ctf_ctfd_auth_status',
    'ctf_ctfd_download_attachment',
    'ctf_ctfd_get_challenge',
    'ctf_ctfd_list_challenges',
    'ctf_ctfd_progress',
  ]);
  assert.equal(tools.get('ctf_ctfd_get_challenge').config.inputSchema.safeParse({ challengeId: 0 }).success, false);
  assert.equal(tools.get('ctf_ctfd_download_attachment').config.inputSchema.safeParse({
    challengeId: 8,
    attachmentIndex: 0,
    outputPath: '/home/ctfagent/ctf-workspaces/ctfd-01/file.bin',
  }).success, true);
});

test('attachment tool writes verified bytes only to the active workspace and validates paths before fetch', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'ctfd-workspace-'));
  const workspace = '/home/ctfagent/ctf-workspaces/ctfd-01';
  const payload = Buffer.from('public attachment');
  const digest = createHash('sha256').update(payload).digest('hex');
  const { calls, fetchImpl } = queueFetch([
    challengeDetail(['/ctf/files/attachments/public.bin']),
    new Response(payload),
  ]);
  const tools = new Map();
  const server = { registerTool: (name, config, handler) => tools.set(name, { config, handler }) };
  const writes = [];
  const runWsl = async (args, options) => {
    writes.push({ args, options });
    return {
      exitCode: 0,
      stdout: JSON.stringify({ bytes: payload.length, sha256: digest }),
      stderr: '',
      timedOut: false,
      truncated: false,
    };
  };

  try {
    initScope({
      projectRoot,
      challengeId: 'ctfd-01',
      sourceRoots: [join(projectRoot, '.ctf-workspaces', 'ctfd-01')],
    });
    registerCtfdTools(server, {
      projectRoot,
      runWsl,
      fetchImpl,
      env: { CTF_MCP_CTFD_URL: baseUrl, CTF_MCP_CTFD_TOKEN: 'secret-token' },
    });
    const download = tools.get('ctf_ctfd_download_attachment').handler;

    const invalidPath = await download({
      challengeId: 8,
      attachmentIndex: 0,
      outputPath: `${workspace}/../outside.bin`,
    });
    assert.equal(invalidPath.isError, true);
    assert.equal(calls.length, 0);

    const result = await download({
      challengeId: 8,
      attachmentIndex: 0,
      outputPath: `${workspace}/attachments/public.bin`,
    });
    assert.deepEqual(JSON.parse(result.content[0].text), {
      destinationPath: `${workspace}/attachments/public.bin`,
      bytes: payload.length,
      sha256: digest,
    });
    assert.deepEqual(writes[0].options.input, payload);
    assert.equal(writes[0].args.at(-1), String(64 * 1024 * 1024));
    assert.equal(calls.every(({ options }) => options.headers.authorization === undefined), true);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});
