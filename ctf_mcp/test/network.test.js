import assert from 'node:assert/strict';
import {
  buildCurlCommand,
  buildDnsCommand,
  buildFfufCommand,
  buildHydraAuditCommand,
  buildNcatCommand,
  buildNmapCommand,
  parseCurlOutput,
  buildSqlmapCommand,
  buildWhoisCommand,
  executeNetworkCommand,
  registerNetworkTools,
} from '../tools/network.js';
import test from 'node:test';

const scope = {
  challengeId: 'web-01',
  wslWorkspace: '/home/ctfagent/ctf-workspaces/web-01',
  targets: [
    { host: 'challenge.example', port: 80 },
    { host: 'challenge.example', port: 443 },
    { host: 'challenge.example', port: 8080 },
    { host: 'pwn.example', port: 1337 },
  ],
};

test('Hydra builder requires explicit authorization and fixes one scoped, delayed task', () => {
  const passwordListPath = `${scope.wslWorkspace}/lists/passwords.txt`;
  const built = buildHydraAuditCommand({
    target: 'pwn.example:1337',
    service: 'ssh',
    username: 'ctf',
    passwordListPath,
    confirmAuthorized: true,
  }, scope);

  assert.deepEqual(built, {
    executable: 'hydra',
    args: ['-I', '-f', '-t', '1', '-c', '1', '-s', '1337', '-l', 'ctf', '-P', passwordListPath, 'pwn.example', 'ssh'],
    timeoutMs: 30_000,
    maxOutputBytes: 262_144,
    workspace: scope.wslWorkspace,
    filePaths: [passwordListPath],
    temporaryWorkingDirectory: true,
  });

  const rejected = [
    [{ target: 'pwn.example:1337', service: 'ssh', username: 'ctf', passwordListPath }, /confirmAuthorized/i],
    [{ target: 'pwn.example:1337', service: 'ssh', username: 'ctf', passwordListPath, confirmAuthorized: false }, /confirmAuthorized/i],
    [{ target: 'pwn.example:1336', service: 'ssh', username: 'ctf', passwordListPath, confirmAuthorized: true }, /outside/i],
    [{ target: 'outside.example:1337', service: 'ssh', username: 'ctf', passwordListPath, confirmAuthorized: true }, /outside/i],
    [{ target: 'pwn.example:1337', service: 'http-get', username: 'ctf', passwordListPath, confirmAuthorized: true }, /service/i],
    [{ target: 'pwn.example:1337', service: 'ftp', username: 'ctf\nadmin', passwordListPath, confirmAuthorized: true }, /username/i],
    [{ target: 'pwn.example:1337', service: 'ftp', username: 'ctf', passwordListPath: '/etc/passwd', confirmAuthorized: true }, /workspace/i],
  ];
  for (const [input, message] of rejected) assert.throws(() => buildHydraAuditCommand(input, scope), message);
});

test('Hydra MCP schema requires literal authorization and the wrapper reports missing optional dependency', async () => {
  const tools = new Map();
  registerNetworkTools({ registerTool(name, config, handler) { tools.set(name, { config, handler }); } });
  const tool = tools.get('ctf_hydra_audit');
  assert.ok(tool);
  const validInput = {
    target: 'pwn.example:1337',
    service: 'ssh',
    username: 'ctf',
    passwordListPath: `${scope.wslWorkspace}/lists/passwords.txt`,
    confirmAuthorized: true,
  };
  assert.equal(tool.config.inputSchema.safeParse(validInput).success, true);
  assert.equal(tool.config.inputSchema.safeParse({ ...validInput, confirmAuthorized: false }).success, false);

  let observed;
  const response = await executeNetworkCommand('ctf_hydra_audit', validInput, scope, async (executable, args, options) => {
    observed = { executable, args, options };
    return {
      exitCode: 0,
      stdout: JSON.stringify({
        executable: 'hydra',
        exitCode: 127,
        stdoutBase64: '',
        stderrBase64: Buffer.from("[Errno 2] No such file or directory: 'hydra'").toString('base64'),
        timedOut: false,
        truncated: false,
      }),
      stderr: '',
      timedOut: false,
      truncated: false,
    };
  });
  const request = JSON.parse(observed.options.input);
  assert.equal(observed.executable, 'python3');
  assert.equal(request.mode, 'command');
  assert.equal(request.executable, 'hydra');
  assert.equal(request.temporaryWorkingDirectory, true);
  assert.deepEqual(request.filePaths, [validInput.passwordListPath]);
  assert.equal(response.exitCode, 127);
  assert.match(response.error, /setup --apply --profile exploitation/i);

  for (const [input, message] of [
    [{ ...validInput, confirmAuthorized: false }, /confirmAuthorized/i],
    [{ ...validInput, target: 'pwn.example:1336' }, /outside/i],
    [{ ...validInput, target: 'outside.example:1337' }, /outside/i],
    [{ ...validInput, service: 'http' }, /service/i],
    [{ ...validInput, passwordListPath: '/etc/passwd' }, /workspace/i],
  ]) {
    let invoked = false;
    await assert.rejects(executeNetworkCommand('ctf_hydra_audit', input, scope, async () => {
      invoked = true;
      return { exitCode: 0, stdout: '', stderr: '', timedOut: false, truncated: false };
    }), message);
    assert.equal(invoked, false);
  }
});

test('Nmap builder scans only the explicit in-scope TCP port as a non-root user', () => {
  assert.deepEqual(buildNmapCommand({ target: 'challenge.example:8080', serviceDetection: true }, scope), {
    executable: 'nmap',
    args: ['-sT', '-Pn', '-n', '-T3', '-p', '8080', '-sV', 'challenge.example'],
    timeoutMs: 120_000,
    maxOutputBytes: 1_048_576,
  });
  assert.throws(() => buildNmapCommand({ target: 'other.example:8080' }, scope), /outside/i);
});

test('SQLmap builder fixes batch, redirect, risk, retry, and duration settings', () => {
  const command = buildSqlmapCommand({
    url: 'http://challenge.example:8080/item?id=1',
    parameter: 'id',
  }, scope);
  assert.ok(command);
  assert.equal(command.executable, 'sqlmap');
  assert.deepEqual(command.args.slice(0, 4), ['-u', 'http://challenge.example:8080/item?id=1', '-p', 'id']);
  assert.ok(command.args.includes('--batch'));
  assert.ok(command.args.includes('--ignore-redirects'));
  assert.ok(command.args.includes('--risk=1'));
  assert.ok(command.args.includes('--level=1'));
  assert.ok(command.args.includes('--time-limit=120'));
  assert.equal(command.args.some((arg) => arg.startsWith('--os-')), false);
  assert.deepEqual(command.directoryPaths, [`${scope.wslWorkspace}/sqlmap`]);
  assert.equal(command.workspace, scope.wslWorkspace);
  assert.throws(() => buildSqlmapCommand({
    url: 'http://outside.example:8080/item?id=1',
    parameter: 'id',
  }, scope), /outside/i);
  assert.throws(() => buildSqlmapCommand({
    url: 'http://challenge.example:8080/item?id=1',
    parameter: 'id;--os-cmd=whoami',
  }, scope), /parameter/i);
});

test('FFUF builder requires one FUZZ marker and an in-workspace wordlist', () => {
  const command = buildFfufCommand({
    urlTemplate: 'http://challenge.example:8080/FUZZ',
    wordlistPath: `${scope.wslWorkspace}/lists/common.txt`,
  }, scope);
  assert.ok(command);
  assert.deepEqual(command.args, [
    '-u', 'http://challenge.example:8080/FUZZ',
    '-w', `${scope.wslWorkspace}/lists/common.txt`,
    '-t', '10', '-rate', '50', '-s', '-maxtime', '120',
  ]);
  assert.deepEqual(command.filePaths, [`${scope.wslWorkspace}/lists/common.txt`]);
  assert.equal(command.workspace, scope.wslWorkspace);
  assert.throws(() => buildFfufCommand({
    urlTemplate: 'http://challenge.example:8080/FUZZ/FUZZ',
    wordlistPath: `${scope.wslWorkspace}/lists/common.txt`,
  }, scope), /one FUZZ/i);
  assert.throws(() => buildFfufCommand({
    urlTemplate: 'http://challenge.example:8080/FUZZ',
    wordlistPath: '/home/ctfagent/private/wordlist.txt',
  }, scope), /workspace/i);
});

test('FFUF executes through the workspace worker with an explicitly opened wordlist', async () => {
  let observed;
  const result = await executeNetworkCommand('ctf_ffuf_discover', {
    urlTemplate: 'http://challenge.example:8080/FUZZ',
    wordlistPath: `${scope.wslWorkspace}/lists/common.txt`,
  }, scope, async (executable, args, options) => {
    observed = { executable, args, options };
    return {
      exitCode: 0,
      stdout: JSON.stringify({
        executable: 'ffuf',
        exitCode: 0,
        stdoutBase64: Buffer.from('found path\n').toString('base64'),
        stderrBase64: '',
        timedOut: false,
        truncated: false,
      }),
      stderr: '',
      timedOut: false,
      truncated: false,
    };
  });

  assert.equal(observed.executable, 'python3');
  const request = JSON.parse(observed.options.input);
  assert.equal(request.mode, 'command');
  assert.equal(request.executable, 'ffuf');
  assert.deepEqual(request.filePaths, [`${scope.wslWorkspace}/lists/common.txt`]);
  assert.equal(result.stdout, 'found path\n');
  assert.equal(result.exitCode, 0);
});

test('curl builder sends body on stdin and does not follow redirects', () => {
  const command = buildCurlCommand({
    url: 'https://challenge.example/login',
    method: 'POST',
    body: '{"user":"ctf"}',
    bodyFormat: 'json',
  }, scope);
  assert.ok(command);
  assert.equal(command.executable, 'curl');
  assert.deepEqual(command.input, Buffer.from('{"user":"ctf"}'));
  assert.ok(command.args.includes('--data-binary'));
  assert.ok(command.args.includes('@-'));
  assert.equal(command.args.includes('--include'), false);
  assert.ok(command.args.includes('--write-out'));
  assert.ok(command.args.includes('--max-redirs'));
  assert.equal(command.args.includes('--location'), false);
  assert.throws(() => buildCurlCommand({
    url: 'http://outside.example:8080/',
    method: 'GET',
  }, scope), /outside/i);
  assert.throws(() => buildCurlCommand({
    url: 'http://challenge.example:8080/',
    method: 'TRACE',
  }, scope), /method/i);
});

test('curl builder sends custom request headers as separate curl arguments', () => {
  const value = 'middleware:middleware:middleware:middleware:middleware';
  const command = buildCurlCommand({
    url: 'https://challenge.example/private.png',
    headers: { 'X-Middleware-Subrequest': value },
  }, scope);
  const headerIndex = command.args.indexOf('--header');

  assert.notEqual(headerIndex, -1);
  assert.deepEqual(command.args.slice(headerIndex, headerIndex + 2), [
    '--header', `X-Middleware-Subrequest: ${value}`,
  ]);
  assert.ok(command.args.includes('--max-redirs'));
  assert.equal(command.args.includes('--location'), false);
});

test('curl builder rejects invalid HTTP header names', () => {
  assert.throws(() => buildCurlCommand({
    url: 'https://challenge.example/',
    headers: { 'Bad Header': 'value' },
  }, scope), /header name/i);
});

test('curl builder rejects authority, framing, and content-type headers', () => {
  for (const name of ['hOsT', 'Content-Length', 'Transfer-Encoding', 'Content-Type']) {
    assert.throws(() => buildCurlCommand({
      url: 'https://challenge.example/',
      headers: { [name]: 'value' },
    }, scope), /header/i, name);
  }
});

test('curl builder rejects CR, LF, and NUL in header values', () => {
  for (const value of ['before\rafter', 'before\nafter', 'before\0after']) {
    assert.throws(() => buildCurlCommand({
      url: 'https://challenge.example/',
      headers: { 'X-Test': value },
    }, scope), /header value/i);
  }
});

test('curl builder bounds header count and UTF-8 byte sizes', () => {
  const tooMany = Object.fromEntries(Array.from({ length: 33 }, (_, index) => [`X-${index}`, 'v']));
  const tooLargeTotal = {
    'X-A': 'a'.repeat(6_000),
    'X-B': 'b'.repeat(6_000),
    'X-C': 'c'.repeat(6_000),
  };
  const cases = [
    { headers: tooMany, message: /count|too many/i },
    { headers: { ['x'.repeat(129)]: 'v' }, message: /name.*(limit|long|bytes)/i },
    { headers: { 'X-Test': 'v'.repeat(8_193) }, message: /value.*(limit|long|bytes)/i },
    { headers: tooLargeTotal, message: /total|aggregate|size/i },
  ];

  for (const { headers, message } of cases) {
    assert.throws(() => buildCurlCommand({ url: 'https://challenge.example/', headers }, scope), message);
  }
});

test('scoped HTTP MCP schema preserves valid headers and rejects invalid or oversized maps', () => {
  const schemas = new Map();
  registerNetworkTools({ registerTool: (name, config) => schemas.set(name, config.inputSchema) });
  const schema = schemas.get('ctf_scoped_http_request');
  const validHeaders = { 'X-Middleware-Subrequest': 'middleware' };
  const valid = schema.safeParse({ url: 'https://challenge.example/', headers: validHeaders });

  assert.equal(valid.success, true);
  assert.deepEqual(valid.data.headers, validHeaders);
  assert.equal(schema.safeParse({ url: 'https://challenge.example/', headers: { Host: 'other.example' } }).success, false);
  assert.equal(schema.safeParse({
    url: 'https://challenge.example/',
    headers: Object.fromEntries(Array.from({ length: 33 }, (_, index) => [`X-${index}`, 'v'])),
  }).success, false);
});

test('parseCurlOutput returns body/status metadata without response headers', () => {
  assert.deepEqual(parseCurlOutput('{"ok":true}\n\nCTF_MCP_META:200\tapplication/json\n'), {
    status: 200,
    contentType: 'application/json',
    body: '{"ok":true}\n',
  });
  assert.throws(() => parseCurlOutput('no metadata marker'), /metadata/i);
});

test('Ncat exchange and passive DNS/WHOIS lookups require exact scoped hosts', () => {
  const tcp = buildNcatCommand({ target: 'pwn.example:1337', input: 'ping\n' }, scope);
  assert.ok(tcp);
  assert.deepEqual(tcp.args, ['-w', '10', 'pwn.example', '1337']);
  assert.deepEqual(tcp.input, Buffer.from('ping\n'));

  assert.deepEqual(buildDnsCommand({ domain: 'challenge.example', recordType: 'TXT' }, scope).args, [
    '+time=3', '+tries=1', 'challenge.example', 'TXT',
  ]);
  assert.deepEqual(buildWhoisCommand({ domainOrIp: 'challenge.example' }, scope).args, ['challenge.example']);
  assert.throws(() => buildDnsCommand({ domain: 'outside.example', recordType: 'A' }, scope), /outside/i);
  assert.throws(() => buildWhoisCommand({ domainOrIp: 'outside.example' }, scope), /outside/i);
});

test('executeNetworkCommand rejects out-of-scope targets before starting a WSL tool', async () => {
  let invoked = false;
  await assert.rejects(
    executeNetworkCommand('ctf_nmap_scan', { target: 'outside.example:8080' }, scope, async () => {
      invoked = true;
      return { exitCode: 0, stdout: '', stderr: '', timedOut: false, truncated: false };
    }),
    /outside/i,
  );
  assert.equal(invoked, false);
});

test('executeNetworkCommand rejects out-of-scope HTTP URLs before starting curl', async () => {
  let invoked = false;
  await assert.rejects(
    executeNetworkCommand('ctf_scoped_http_request', {
      url: 'https://outside.example/private',
      headers: { 'X-Test': 'value' },
    }, scope, async () => {
      invoked = true;
      return { exitCode: 0, stdout: '', stderr: '', timedOut: false, truncated: false };
    }),
    /outside/i,
  );
  assert.equal(invoked, false);
});

test('SQLmap output directory is passed through the secure workspace worker', async () => {
  let observed;
  const result = await executeNetworkCommand('ctf_sqlmap_test', {
    url: 'http://challenge.example:8080/item?id=1',
    parameter: 'id',
  }, scope, async (executable, args, options) => {
    observed = { executable, args, options };
    return {
      exitCode: 0,
      stdout: JSON.stringify({
        executable: 'sqlmap',
        exitCode: 0,
        stdoutBase64: Buffer.from('finished\n').toString('base64'),
        stderrBase64: '',
        timedOut: false,
        truncated: false,
      }),
      stderr: '',
      timedOut: false,
      truncated: false,
    };
  });

  assert.equal(observed.executable, 'python3');
  const request = JSON.parse(observed.options.input);
  assert.equal(request.mode, 'command');
  assert.equal(request.executable, 'sqlmap');
  assert.deepEqual(request.directoryPaths, [`${scope.wslWorkspace}/sqlmap`]);
  assert.ok(request.args.includes(`${scope.wslWorkspace}/sqlmap`));
  assert.equal(result.stdout, 'finished\n');
  assert.equal(result.exitCode, 0);
});

test('executeNetworkCommand parses HTTP status/body without returning response headers', async () => {
  let sentInput;
  const result = await executeNetworkCommand('ctf_scoped_http_request', {
    url: 'https://challenge.example/login',
    method: 'POST',
    body: '{"user":"ctf"}',
    bodyFormat: 'json',
  }, scope, async (_executable, _args, options) => {
    sentInput = options.input;
    return {
      exitCode: 0,
      stdout: '{"ok":true}\n\nCTF_MCP_META:200\tapplication/json\n',
      stderr: '',
      timedOut: false,
      truncated: false,
    };
  });

  assert.deepEqual(sentInput, Buffer.from('{"user":"ctf"}'));
  assert.equal(result.status, 200);
  assert.equal(result.contentType, 'application/json');
  assert.equal(result.body, '{"ok":true}\n');
  assert.equal(Object.hasOwn(result, 'headers'), false);
});
