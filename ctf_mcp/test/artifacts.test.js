import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  buildBinwalkCommand,
  buildChecksecCommand,
  buildCyclicCommand,
  buildExiftoolCommand,
  buildJohnCommand,
  buildPcapFollowStreamCommand,
  buildRopgadgetCommand,
  buildRunBinaryCommand,
  buildSigrokCommand,
  buildSteghideCommand,
  buildSteghideExtractRequest,
  buildStegseekExtractRequest,
  buildTsharkCommand,
  buildYaraScanCommand,
  registerArtifactTools,
} from '../tools/artifacts.js';
import test from 'node:test';

const scope = {
  challengeId: 'rev-01',
  wslWorkspace: '/home/ctfagent/ctf-workspaces/rev-01',
};
const binary = `${scope.wslWorkspace}/sample.elf`;

test('PWN builders restrict binary paths, debugger input, and cyclic sizes', () => {
  assert.deepEqual(buildChecksecCommand({ artifactPath: binary }, scope), {
    executable: 'checksec',
    args: [`--file=${binary}`],
    timeoutMs: 30_000,
    maxOutputBytes: 262_144,
    workspace: scope.wslWorkspace,
    filePaths: [binary],
  });
  assert.deepEqual(buildCyclicCommand({ length: 128, wordSize: 8 }), {
    executable: 'pwn',
    args: ['cyclic', '-n', '8', '128'],
    timeoutMs: 30_000,
    maxOutputBytes: 262_144,
  });
  const run = buildRunBinaryCommand({ artifactPath: binary, argv: ['--check'], stdin: 'test', timeoutMs: 5000 }, scope);
  assert.equal(run.mode, 'execute');
  assert.equal(run.workspace, scope.wslWorkspace);
  assert.equal(run.artifactPath, binary);
  assert.deepEqual(run.argv, ['--check']);
  assert.equal(run.stdinBase64, Buffer.from('test').toString('base64'));
  assert.equal(run.timeoutMs, 5000);
  assert.throws(() => buildChecksecCommand({ artifactPath: '/etc/passwd' }, scope), /workspace/i);
  assert.throws(() => buildCyclicCommand({ length: 0 }), /length/i);
});

test('forensics builders use file-only commands and an allowlisted TShark field set', () => {
  const tshark = buildTsharkCommand({
    artifactPath: `${scope.wslWorkspace}/capture.pcap`,
    fields: ['frame.number', 'ip.src', 'dns.qry.name'],
    displayFilter: 'dns',
  }, scope);
  assert.ok(tshark);
  assert.deepEqual(tshark.args, [
    '-r', `${scope.wslWorkspace}/capture.pcap`,
    '-T', 'fields', '-E', 'separator=\\t',
    '-e', 'frame.number', '-e', 'ip.src', '-e', 'dns.qry.name', '-Y', 'dns',
  ]);
  assert.deepEqual(tshark.filePaths, [`${scope.wslWorkspace}/capture.pcap`]);
  assert.equal(tshark.workspace, scope.wslWorkspace);
  const binwalk = buildBinwalkCommand({ artifactPath: binary }, scope);
  const exiftool = buildExiftoolCommand({ artifactPath: binary }, scope);
  assert.ok(binwalk);
  assert.ok(exiftool);
  assert.deepEqual(binwalk.args, [binary]);
  assert.deepEqual(exiftool.args, ['-json', binary]);
  assert.deepEqual(binwalk.filePaths, [binary]);
  assert.deepEqual(exiftool.filePaths, [binary]);
  assert.throws(() => buildTsharkCommand({
    artifactPath: `${scope.wslWorkspace}/capture.pcap`,
    fields: ['frame.number', 'tcp contains'],
  }, scope), /field/i);
});

test('PCAP follow-stream builder restricts protocol and stream index and marks the artifact path', () => {
  const file = `${scope.wslWorkspace}/capture.pcap`;
  const command = buildPcapFollowStreamCommand({ artifactPath: file, protocol: 'tcp', streamIndex: 3 }, scope);
  assert.deepEqual(command.args, ['-r', file, '-q', '-z', 'follow,tcp,ascii,3']);
  assert.deepEqual(command.filePaths, [file]);
  assert.equal(command.workspace, scope.wslWorkspace);
  assert.equal(command.timeoutMs, 120_000);
  assert.equal(command.maxOutputBytes, 1_048_576);
  assert.throws(() => buildPcapFollowStreamCommand({ artifactPath: file, protocol: 'invalid', streamIndex: 0 }, scope), /protocol/i);
  assert.throws(() => buildPcapFollowStreamCommand({ artifactPath: file, protocol: 'tcp', streamIndex: -1 }, scope), /streamIndex/i);
  assert.throws(() => buildPcapFollowStreamCommand({ artifactPath: '/etc/passwd', protocol: 'tcp', streamIndex: 0 }, scope), /workspace/i);
});

test('stego and hardware builders use workspace files and never start live acquisition', () => {
  const image = `${scope.wslWorkspace}/hidden.png`;
  const steghide = buildSteghideCommand({ artifactPath: image }, scope);
  const sigrok = buildSigrokCommand({
    artifactPath: `${scope.wslWorkspace}/uart.sr`,
    decoder: 'uart',
    channels: { rx: 'D0', baudrate: 9600 },
  }, scope);
  assert.ok(steghide);
  assert.ok(sigrok);
  assert.deepEqual(steghide.args, [
    'info', '-sf', image, '-p', '',
  ]);
  assert.deepEqual(steghide.filePaths, [image]);
  assert.deepEqual(sigrok.args, [
    '-i', `${scope.wslWorkspace}/uart.sr`, '-P', 'uart:rx=D0:baudrate=9600',
  ]);
  assert.deepEqual(sigrok.filePaths, [`${scope.wslWorkspace}/uart.sr`]);
  assert.throws(() => buildSigrokCommand({
    artifactPath: `${scope.wslWorkspace}/uart.sr`,
    decoder: 'uart',
    channels: { rx: 'D0;rm', baudrate: 9600 },
  }, scope), /channel/i);
  assert.throws(() => buildSteghideCommand({ artifactPath: 'D:\\outside.png' }, scope), /workspace/i);
});

test('Steghide extraction builder requires scoped distinct paths and a bounded passphrase', () => {
  const artifactPath = `${scope.wslWorkspace}/hidden.png`;
  const outputPath = `${scope.wslWorkspace}/recovered.bin`;
  assert.deepEqual(buildSteghideExtractRequest({ artifactPath, outputPath, passphrase: 'secret phrase' }, scope), {
    mode: 'steghide_extract',
    workspace: scope.wslWorkspace,
    artifactPath,
    outputPath,
    passphrase: 'secret phrase',
    timeoutMs: 60_000,
    maxOutputBytes: 262_144,
  });
  assert.equal(buildSteghideExtractRequest({ artifactPath, outputPath, passphrase: '' }, scope).passphrase, '');
  const unicodePassphrase = '😀'.repeat(1024);
  assert.equal(buildSteghideExtractRequest({ artifactPath, outputPath, passphrase: unicodePassphrase }, scope).passphrase, unicodePassphrase);
  assert.throws(() => buildSteghideExtractRequest({ artifactPath, outputPath, passphrase: `${unicodePassphrase}😀` }, scope), /passphrase/i);
  assert.throws(() => buildSteghideExtractRequest({ artifactPath, outputPath: artifactPath, passphrase: '' }, scope), /differ/i);
  assert.throws(() => buildSteghideExtractRequest({ artifactPath: '/etc/passwd', outputPath, passphrase: '' }, scope), /workspace/i);
  assert.throws(() => buildSteghideExtractRequest({ artifactPath, outputPath, passphrase: 'bad\0phrase' }, scope), /passphrase/i);
  assert.throws(() => buildSteghideExtractRequest({ artifactPath, outputPath, passphrase: 'x'.repeat(1025) }, scope), /passphrase/i);
  assert.throws(() => buildSteghideExtractRequest({ artifactPath, outputPath, passphrase: undefined }, scope), /passphrase/i);
});

test('optional artifact builders pin tools, options, bounds, and workspace paths', () => {
  const artifactPath = `${scope.wslWorkspace}/sample.bin`;
  const rulesPath = `${scope.wslWorkspace}/rules.yar`;
  const hashPath = `${scope.wslWorkspace}/hashes.txt`;
  const wordlistPath = `${scope.wslWorkspace}/words.txt`;
  const outputPath = `${scope.wslWorkspace}/recovered.bin`;

  assert.deepEqual(buildYaraScanCommand({ artifactPath, rulesPath }, scope), {
    executable: 'yara',
    args: [rulesPath, artifactPath],
    timeoutMs: 30_000,
    maxOutputBytes: 262_144,
    workspace: scope.wslWorkspace,
    filePaths: [rulesPath, artifactPath],
  });
  assert.deepEqual(buildYaraScanCommand({ artifactPath: rulesPath, rulesPath }, scope).filePaths, [rulesPath]);
  assert.deepEqual(buildJohnCommand({ hashPath, wordlistPath }, scope), {
    executable: 'john',
    args: ['--wordlist', wordlistPath, '--pot=/dev/null', '--no-log', '--max-run-time=30', '--session=@ctf-agent-ephemeral', hashPath],
    timeoutMs: 30_000,
    maxOutputBytes: 262_144,
    workspace: scope.wslWorkspace,
    filePaths: [hashPath, wordlistPath],
    ephemeralSession: true,
  });
  assert.deepEqual(buildJohnCommand({ hashPath }, scope).args, [
    '--single', '--pot=/dev/null', '--no-log', '--max-run-time=30', '--session=@ctf-agent-ephemeral', hashPath,
  ]);
  assert.deepEqual(buildRopgadgetCommand({ artifactPath }, scope), {
    executable: 'ROPgadget',
    args: ['--binary', artifactPath, '--depth', '10'],
    timeoutMs: 30_000,
    maxOutputBytes: 262_144,
    workspace: scope.wslWorkspace,
    filePaths: [artifactPath],
  });
  assert.throws(() => buildRopgadgetCommand({ artifactPath, depth: 0 }, scope), /depth/i);
  assert.throws(() => buildYaraScanCommand({ artifactPath: '/etc/passwd', rulesPath }, scope), /workspace/i);
  assert.throws(() => buildJohnCommand({ hashPath, wordlistPath: '/etc/passwd' }, scope), /workspace/i);

  assert.deepEqual(buildStegseekExtractRequest({ artifactPath, wordlistPath, outputPath }, scope), {
    mode: 'stegseek_extract',
    workspace: scope.wslWorkspace,
    artifactPath,
    wordlistPath,
    outputPath,
    timeoutMs: 60_000,
    maxOutputBytes: 262_144,
    maxFileBytes: 64 * 1024 * 1024,
  });
  assert.throws(() => buildStegseekExtractRequest({ artifactPath, wordlistPath, outputPath: artifactPath }, scope), /differ/i);
  assert.throws(() => buildStegseekExtractRequest({ artifactPath, wordlistPath: '/etc/passwd', outputPath }, scope), /workspace/i);
});

test('registered file tools send scoped paths to the workspace worker', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'ctf-artifact-worker-'));
  try {
    const workspace = join(projectRoot, '.ctf-workspaces', 'rev-01');
    const sourceRoot = join(projectRoot, 'inputs');
    mkdirSync(workspace, { recursive: true });
    mkdirSync(sourceRoot);
    mkdirSync(join(projectRoot, '.ctf-agent'));
    writeFileSync(join(projectRoot, '.ctf-agent', 'scope.json'), JSON.stringify({
      schemaVersion: 1,
      challengeId: 'rev-01',
      workspace: '.ctf-workspaces/rev-01',
      wslWorkspace: '/home/ctfagent/ctf-workspaces/rev-01',
      sourceRoots: [sourceRoot],
      targets: [],
    }));

    const tools = new Map();
    const requests = [];
    registerArtifactTools({
      registerTool(name, config, handler) { tools.set(name, { config, handler }); },
    }, {
      projectRoot,
      runWslTool: async (executable, args, options) => {
        assert.equal(executable, 'python3');
        const request = JSON.parse(options.input);
        requests.push(request);
        return {
          exitCode: 0,
          stdout: JSON.stringify(request.mode === 'steghide_extract' ? {
            mode: 'steghide_extract',
            exitCode: 0,
            timedOut: false,
            truncated: false,
            outputPath: request.outputPath,
            bytes: 4,
            sha256: 'a'.repeat(64),
            stdoutBase64: Buffer.from('hidden payload').toString('base64'),
            stderrBase64: Buffer.from(request.passphrase).toString('base64'),
          } : {
            executable: 'tshark',
            exitCode: 0,
            stdoutBase64: Buffer.from('stream output').toString('base64'),
            stderrBase64: '',
            timedOut: false,
            truncated: false,
          }),
          stderr: '',
          timedOut: false,
          truncated: false,
        };
      },
    });

    const pwnResponse = await tools.get('ctf_pwn_run').handler({
      artifactPath: '/home/ctfagent/ctf-workspaces/rev-01/sample',
      argv: ['--safe'],
      stdin: 'input',
    });
    assert.equal(pwnResponse.isError, false);
    assert.equal(requests[0].mode, 'execute');
    assert.equal(requests[0].artifactPath, '/home/ctfagent/ctf-workspaces/rev-01/sample');
    assert.equal(requests[0].stdinBase64, Buffer.from('input').toString('base64'));

    const pcapResponse = await tools.get('ctf_forensics_pcap_follow_stream').handler({
      artifactPath: '/home/ctfagent/ctf-workspaces/rev-01/trace.pcap',
      protocol: 'tcp',
      streamIndex: 3,
    });
    assert.equal(pcapResponse.isError, false);
    assert.equal(requests[1].mode, 'command');
    assert.equal(requests[1].executable, 'tshark');
    assert.deepEqual(requests[1].filePaths, ['/home/ctfagent/ctf-workspaces/rev-01/trace.pcap']);
    assert.ok(requests[1].args.includes('follow,tcp,ascii,3'));

    const extractionInput = {
      artifactPath: '/home/ctfagent/ctf-workspaces/rev-01/hidden.png',
      outputPath: '/home/ctfagent/ctf-workspaces/rev-01/recovered.bin',
      passphrase: 'private passphrase',
    };
    const extractionTool = tools.get('ctf_stego_steghide_extract');
    assert.ok(extractionTool);
    assert.equal(extractionTool.config.inputSchema.safeParse(extractionInput).success, true);
    assert.equal(extractionTool.config.inputSchema.safeParse({ ...extractionInput, passphrase: '' }).success, true);
    assert.equal(extractionTool.config.inputSchema.safeParse({ ...extractionInput, passphrase: '😀'.repeat(1024) }).success, true);
    assert.equal(extractionTool.config.inputSchema.safeParse({ ...extractionInput, passphrase: '😀'.repeat(1025) }).success, false);
    assert.equal(extractionTool.config.inputSchema.safeParse({ ...extractionInput, passphrase: undefined }).success, false);
    assert.equal(extractionTool.config.inputSchema.safeParse({ ...extractionInput, passphrase: 'x'.repeat(1025) }).success, false);

    const extractionResponse = await extractionTool.handler(extractionInput);
    assert.equal(extractionResponse.isError, false);
    assert.deepEqual(requests[2], {
      mode: 'steghide_extract',
      workspace: scope.wslWorkspace,
      ...extractionInput,
      timeoutMs: 60_000,
      maxOutputBytes: 262_144,
    });
    const extractionResult = JSON.parse(extractionResponse.content[0].text);
    assert.deepEqual(extractionResult, {
      exitCode: 0,
      timedOut: false,
      truncated: false,
      outputPath: extractionInput.outputPath,
      bytes: 4,
      sha256: 'a'.repeat(64),
    });
    assert.doesNotMatch(JSON.stringify(extractionResult), /private passphrase|hidden payload|stdout|stderr/i);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test('optional artifact tools expose bounded schemas and never return Stegseek payload bytes', async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), 'ctf-optional-artifact-'));
  try {
    const workspace = join(projectRoot, '.ctf-workspaces', 'rev-01');
    mkdirSync(workspace, { recursive: true });
    mkdirSync(join(projectRoot, '.ctf-agent'));
    writeFileSync(join(projectRoot, '.ctf-agent', 'scope.json'), JSON.stringify({
      schemaVersion: 1,
      challengeId: 'rev-01',
      workspace: '.ctf-workspaces/rev-01',
      wslWorkspace: scope.wslWorkspace,
      sourceRoots: [],
      targets: [],
    }));

    const tools = new Map();
    const requests = [];
    let stegseekExitCode = 0;
    registerArtifactTools({
      registerTool(name, config, handler) { tools.set(name, { config, handler }); },
    }, {
      projectRoot,
      runWslTool: async (_executable, _args, options) => {
        const request = JSON.parse(options.input);
        requests.push(request);
        const response = request.mode === 'stegseek_extract'
          ? {
            exitCode: stegseekExitCode,
            timedOut: false,
            truncated: false,
            outputPath: request.outputPath,
            bytes: 4,
            sha256: 'b'.repeat(64),
            stdoutBase64: Buffer.from('hidden bytes').toString('base64'),
          }
          : {
            executable: request.executable,
            exitCode: 127,
            stdoutBase64: '',
            stderrBase64: Buffer.from(`[Errno 2] No such file or directory: '${request.executable}'`).toString('base64'),
            timedOut: false,
            truncated: false,
          };
        return { exitCode: 0, stdout: JSON.stringify(response), stderr: '', timedOut: false, truncated: false };
      },
    });

    const yara = tools.get('ctf_forensics_yara_scan');
    const john = tools.get('ctf_crypto_john');
    const ropgadget = tools.get('ctf_pwn_ropgadget');
    const stegseek = tools.get('ctf_stegseek_crack');
    assert.ok(yara && john && ropgadget && stegseek);
    assert.equal(yara.config.inputSchema.safeParse({ artifactPath: `${scope.wslWorkspace}/x`, rulesPath: `${scope.wslWorkspace}/r.yar` }).success, true);
    assert.equal(ropgadget.config.inputSchema.safeParse({ artifactPath: `${scope.wslWorkspace}/x`, depth: 11 }).success, false);

    const missing = await yara.handler({
      artifactPath: `${scope.wslWorkspace}/sample.bin`,
      rulesPath: `${scope.wslWorkspace}/rules.yar`,
    });
    assert.equal(missing.isError, true);
    assert.match(missing.content[0].text, /setup --apply --profile forensics/i);

    const missingJohn = await john.handler({
      hashPath: `${scope.wslWorkspace}/hashes.txt`,
      wordlistPath: `${scope.wslWorkspace}/words.txt`,
    });
    assert.equal(missingJohn.isError, true);
    assert.match(missingJohn.content[0].text, /setup --apply --profile crypto/i);
    assert.equal(requests[1].ephemeralSession, true);

    const missingRopgadget = await ropgadget.handler({
      artifactPath: `${scope.wslWorkspace}/sample.elf`,
      depth: 5,
    });
    assert.equal(missingRopgadget.isError, true);
    assert.match(missingRopgadget.content[0].text, /setup --apply --profile pwn/i);

    const outputPath = `${scope.wslWorkspace}/recovered.bin`;
    const extracted = await stegseek.handler({
      artifactPath: `${scope.wslWorkspace}/carrier.png`,
      wordlistPath: `${scope.wslWorkspace}/words.txt`,
      outputPath,
    });
    assert.equal(extracted.isError, false);
    assert.deepEqual(JSON.parse(extracted.content[0].text), {
      exitCode: 0,
      timedOut: false,
      truncated: false,
      outputPath,
      bytes: 4,
      sha256: 'b'.repeat(64),
    });
    assert.doesNotMatch(extracted.content[0].text, /hidden bytes|stdoutBase64/i);
    assert.equal(requests[3].mode, 'stegseek_extract');

    stegseekExitCode = 127;
    const unavailable = await stegseek.handler({
      artifactPath: `${scope.wslWorkspace}/carrier.png`,
      wordlistPath: `${scope.wslWorkspace}/words.txt`,
      outputPath,
    });
    assert.equal(unavailable.isError, true);
    assert.match(unavailable.content[0].text, /setup --apply --profile steganography/i);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});
