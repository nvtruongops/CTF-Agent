import * as z from 'zod/v4';
import { assertWorkspacePath, loadScope } from '../scope.js';
import { runWslTool as defaultRunWslTool } from '../wsl.js';
import { runWorkspaceWorker, workspaceCommandResult } from './workspace-command.js';

const MAX_PROCESS_INPUT_BYTES = 65_536;
const MAX_STEGHIDE_OUTPUT_BYTES = 64 * 1024 * 1024;
const MAX_STEGSEEK_OUTPUT_BYTES = 64 * 1024 * 1024;
const MAX_PROCESS_ARGS = 32;
const MAX_PCAP_FIELDS = 16;
const ALLOWED_PCAP_FIELDS = new Set([
  'frame.number', 'frame.time_epoch', 'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst',
  'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'dns.qry.name',
  'http.host', 'http.request.method', 'http.request.uri', 'tls.handshake.extensions_server_name',
]);
const CHANNEL_NAME = /^[A-Za-z0-9_.-]{1,32}$/;
const OPTIONAL_TOOL_PROFILES = {
  yara: 'forensics',
  john: 'crypto',
  ROPgadget: 'pwn',
  stegseek: 'steganography',
};

function command(executable, args, timeoutMs, maxOutputBytes, input) {
  return { executable, args, timeoutMs, maxOutputBytes, ...(input === undefined ? {} : { input }) };
}

function artifactPath(value, scope) {
  return assertWorkspacePath(value, scope);
}

function artifactCommand(executable, args, timeoutMs, maxOutputBytes, scope, filePaths) {
  return {
    ...command(executable, args, timeoutMs, maxOutputBytes),
    workspace: scope.wslWorkspace,
    filePaths,
  };
}

function validateArgs(argv) {
  if (!Array.isArray(argv) || argv.length > MAX_PROCESS_ARGS || argv.some((arg) => typeof arg !== 'string' || arg.length > 2048)) {
    throw new TypeError(`argv must contain at most ${MAX_PROCESS_ARGS} strings of at most 2048 characters`);
  }
  return argv;
}

export function buildChecksecCommand({ artifactPath: sourcePath } = {}, scope) {
  const file = artifactPath(sourcePath, scope);
  return artifactCommand('checksec', [`--file=${file}`], 30_000, 262_144, scope, [file]);
}

export function buildCyclicCommand({ length, wordSize = 8 } = {}) {
  if (!Number.isInteger(length) || length < 1 || length > 4096) {
    throw new RangeError('length must be an integer from 1 to 4096');
  }
  if (!Number.isInteger(wordSize) || wordSize < 4 || wordSize > 32) {
    throw new RangeError('wordSize must be an integer from 4 to 32');
  }
  return command('pwn', ['cyclic', '-n', String(wordSize), String(length)], 30_000, 262_144);
}

export function buildRunBinaryCommand({ artifactPath: sourcePath, argv = [], stdin = '', timeoutMs = 10_000 } = {}, scope) {
  const file = artifactPath(sourcePath, scope);
  const args = validateArgs(argv);
  const input = Buffer.isBuffer(stdin) ? stdin : Buffer.from(String(stdin), 'utf8');
  if (input.length > MAX_PROCESS_INPUT_BYTES) {
    throw new RangeError(`stdin exceeds the ${MAX_PROCESS_INPUT_BYTES}-byte limit`);
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
    throw new RangeError('timeoutMs must be from 1 to 120000');
  }
  return {
    mode: 'execute',
    workspace: scope.wslWorkspace,
    artifactPath: file,
    argv: args,
    stdinBase64: input.toString('base64'),
    timeoutMs,
    maxOutputBytes: 1_048_576,
  };
}

export function buildTsharkCommand({ artifactPath: sourcePath, fields, displayFilter } = {}, scope) {
  const file = artifactPath(sourcePath, scope);
  if (!Array.isArray(fields) || fields.length < 1 || fields.length > MAX_PCAP_FIELDS) {
    throw new TypeError(`fields must contain 1 to ${MAX_PCAP_FIELDS} items`);
  }
  if (fields.some((field) => !ALLOWED_PCAP_FIELDS.has(field))) throw new TypeError('fields contains an unsupported TShark field');
  if (displayFilter !== undefined && (typeof displayFilter !== 'string' || displayFilter.length > 512)) {
    throw new TypeError('displayFilter must be at most 512 characters');
  }

  const args = ['-r', file, '-T', 'fields', '-E', 'separator=\\t'];
  for (const field of fields) args.push('-e', field);
  if (displayFilter) args.push('-Y', displayFilter);
  return artifactCommand('tshark', args, 120_000, 1_048_576, scope, [file]);
}

export function buildPcapFollowStreamCommand({ artifactPath: sourcePath, protocol = 'tcp', streamIndex } = {}, scope) {
  const file = artifactPath(sourcePath, scope);
  if (!['tcp', 'udp', 'http', 'http2', 'tls', 'quic', 'sip', 'websocket'].includes(protocol)) {
    throw new TypeError('protocol is not a supported TShark follow-stream protocol');
  }
  if (!Number.isInteger(streamIndex) || streamIndex < 0 || streamIndex > 100_000) {
    throw new RangeError('streamIndex must be an integer from 0 to 100000');
  }
  return artifactCommand('tshark', [
    '-r', file,
    '-q',
    '-z', `follow,${protocol},ascii,${streamIndex}`,
  ], 120_000, 1_048_576, scope, [file]);
}

export function buildBinwalkCommand({ artifactPath: sourcePath } = {}, scope) {
  const file = artifactPath(sourcePath, scope);
  return artifactCommand('binwalk', [file], 120_000, 1_048_576, scope, [file]);
}

export function buildExiftoolCommand({ artifactPath: sourcePath } = {}, scope) {
  const file = artifactPath(sourcePath, scope);
  return artifactCommand('exiftool', ['-json', file], 30_000, 1_048_576, scope, [file]);
}

export function buildSteghideCommand({ artifactPath: sourcePath } = {}, scope) {
  const file = artifactPath(sourcePath, scope);
  return artifactCommand('steghide', ['info', '-sf', file, '-p', ''], 30_000, 262_144, scope, [file]);
}

export function buildSteghideExtractRequest({ artifactPath: sourcePath, outputPath: destinationPath, passphrase } = {}, scope) {
  const file = artifactPath(sourcePath, scope);
  const output = artifactPath(destinationPath, scope);
  if (file === output) throw new TypeError('outputPath must differ from artifactPath');
  if (typeof passphrase !== 'string' || passphrase.includes('\0') || Array.from(passphrase).length > 1024) {
    throw new TypeError('passphrase must be a NUL-free string of at most 1024 characters');
  }
  return {
    mode: 'steghide_extract',
    workspace: scope.wslWorkspace,
    artifactPath: file,
    outputPath: output,
    passphrase,
    timeoutMs: 60_000,
    maxOutputBytes: 262_144,
  };
}

export function buildYaraScanCommand({ artifactPath: sourcePath, rulesPath: sourceRulesPath } = {}, scope) {
  const file = artifactPath(sourcePath, scope);
  const rules = artifactPath(sourceRulesPath, scope);
  return artifactCommand('yara', [rules, file], 30_000, 262_144, scope, [...new Set([rules, file])]);
}

export function buildJohnCommand({ hashPath: sourceHashPath, wordlistPath: sourceWordlistPath } = {}, scope) {
  const hashFile = artifactPath(sourceHashPath, scope);
  const wordlist = sourceWordlistPath === undefined ? undefined : artifactPath(sourceWordlistPath, scope);
  const args = wordlist ? ['--wordlist', wordlist] : ['--single'];
  args.push('--pot=/dev/null', '--no-log', '--max-run-time=30', '--session=@ctf-agent-ephemeral', hashFile);
  return {
    ...artifactCommand('john', args, 30_000, 262_144, scope, [...new Set([hashFile, ...(wordlist ? [wordlist] : [])])]),
    ephemeralSession: true,
  };
}

export function buildRopgadgetCommand({ artifactPath: sourcePath, depth = 10 } = {}, scope) {
  const file = artifactPath(sourcePath, scope);
  if (!Number.isInteger(depth) || depth < 1 || depth > 10) {
    throw new RangeError('depth must be an integer from 1 to 10');
  }
  return artifactCommand('ROPgadget', ['--binary', file, '--depth', String(depth)], 30_000, 262_144, scope, [file]);
}

export function buildStegseekExtractRequest({ artifactPath: sourcePath, wordlistPath: sourceWordlistPath, outputPath: destinationPath } = {}, scope) {
  const file = artifactPath(sourcePath, scope);
  const wordlist = artifactPath(sourceWordlistPath, scope);
  const output = artifactPath(destinationPath, scope);
  if (output === file || output === wordlist) throw new TypeError('outputPath must differ from artifactPath and wordlistPath');
  return {
    mode: 'stegseek_extract',
    workspace: scope.wslWorkspace,
    artifactPath: file,
    wordlistPath: wordlist,
    outputPath: output,
    timeoutMs: 60_000,
    maxOutputBytes: 262_144,
    maxFileBytes: MAX_STEGSEEK_OUTPUT_BYTES,
  };
}

function channelValue(value, name) {
  if (typeof value !== 'string' || !CHANNEL_NAME.test(value)) {
    throw new TypeError(`${name} must be a channel name containing only letters, digits, _, . or -`);
  }
  return value;
}

export function buildSigrokCommand({ artifactPath: sourcePath, decoder, channels = {} } = {}, scope) {
  const file = artifactPath(sourcePath, scope);
  let decoderSpec;
  if (decoder === 'uart') {
    const rx = channelValue(channels.rx, 'rx');
    const baudrate = channels.baudrate ?? 9600;
    if (!Number.isInteger(baudrate) || baudrate < 50 || baudrate > 10_000_000) {
      throw new RangeError('baudrate must be from 50 to 10000000');
    }
    decoderSpec = `uart:rx=${rx}:baudrate=${baudrate}`;
  } else if (decoder === 'i2c') {
    decoderSpec = `i2c:scl=${channelValue(channels.scl, 'scl')}:sda=${channelValue(channels.sda, 'sda')}`;
  } else if (decoder === 'spi') {
    decoderSpec = [
      'spi',
      `cs=${channelValue(channels.cs, 'cs')}`,
      `clk=${channelValue(channels.clk, 'clk')}`,
      `mosi=${channelValue(channels.mosi, 'mosi')}`,
      `miso=${channelValue(channels.miso, 'miso')}`,
    ].join(':');
  } else {
    throw new TypeError('decoder must be uart, i2c, or spi');
  }
  return artifactCommand('sigrok-cli', ['-i', file, '-P', decoderSpec], 120_000, 1_048_576, scope, [file]);
}

function toolError(error) {
  return {
    isError: true,
    content: [{ type: 'text', text: JSON.stringify({ code: error?.code ?? 'CTF_TOOL_ERROR', message: error instanceof Error ? error.message : String(error) }) }],
  };
}

function optionalToolUnavailable(executable) {
  return {
    isError: true,
    content: [{
      type: 'text',
      text: JSON.stringify({
        code: 'OPTIONAL_TOOL_UNAVAILABLE',
        message: `${executable} is unavailable; install it with setup --apply --profile ${OPTIONAL_TOOL_PROFILES[executable]}.`,
      }),
    }],
  };
}

function registerTool(server, name, description, inputSchema, handler) {
  server.registerTool(name, { description, inputSchema }, async (input) => {
    try {
      return await handler(input);
    } catch (error) {
      return toolError(error);
    }
  });
}

export function registerArtifactTools(server, { projectRoot, runWslTool = defaultRunWslTool } = {}) {
  const getScope = () => loadScope(projectRoot);
  const run = async (built) => {
    let result;
    if (built.mode === 'execute') {
      result = workspaceCommandResult(await runWorkspaceWorker(built, runWslTool, built));
    } else if (built.filePaths) {
      result = workspaceCommandResult(await runWorkspaceWorker({ ...built, mode: 'command' }, runWslTool, built));
    } else {
      result = await runWslTool(built.executable, built.args, built);
    }
    if (OPTIONAL_TOOL_PROFILES[built.executable] && result.exitCode === 127 && result.executable === built.executable
      && /No such file or directory/i.test(result.stderr ?? '')) {
      return optionalToolUnavailable(built.executable);
    }
    const isError = Boolean(result.error)
      || result.exitCode !== 0
      || result.timedOut
      || result.truncated;
    return {
      isError,
      content: [{ type: 'text', text: JSON.stringify(result) }],
    };
  };
  const runSteghideExtract = async (built) => {
    const worker = await runWorkspaceWorker(built, runWslTool, built);
    const result = worker?.result ?? {};
    const transport = worker?.transport ?? {};
    const status = {
      exitCode: result.exitCode ?? transport.exitCode ?? 1,
      timedOut: Boolean(result.timedOut || transport.timedOut),
      truncated: Boolean(result.truncated || transport.truncated),
    };
    const validOutput = !result.error
      && status.exitCode === 0
      && !status.timedOut
      && !status.truncated
      && (transport.exitCode === undefined || transport.exitCode === 0)
      && result.outputPath === built.outputPath
      && Number.isInteger(result.bytes)
      && result.bytes >= 0
      && result.bytes <= MAX_STEGHIDE_OUTPUT_BYTES
      && typeof result.sha256 === 'string'
      && /^[a-f0-9]{64}$/.test(result.sha256);
    const response = validOutput
      ? { ...status, outputPath: result.outputPath, bytes: result.bytes, sha256: result.sha256 }
      : { ...status, error: 'Steghide extraction failed' };
    return {
      isError: !validOutput,
      content: [{ type: 'text', text: JSON.stringify(response) }],
    };
  };
  const runStegseekExtract = async (built) => {
    const worker = await runWorkspaceWorker(built, runWslTool, built);
    const result = worker?.result ?? {};
    const transport = worker?.transport ?? {};
    const status = {
      exitCode: result.exitCode ?? transport.exitCode ?? 1,
      timedOut: Boolean(result.timedOut || transport.timedOut),
      truncated: Boolean(result.truncated || transport.truncated),
    };
    if (status.exitCode === 127) return optionalToolUnavailable('stegseek');
    const validOutput = !result.error
      && status.exitCode === 0
      && !status.timedOut
      && !status.truncated
      && (transport.exitCode === undefined || transport.exitCode === 0)
      && result.outputPath === built.outputPath
      && Number.isInteger(result.bytes)
      && result.bytes >= 0
      && result.bytes <= MAX_STEGSEEK_OUTPUT_BYTES
      && typeof result.sha256 === 'string'
      && /^[a-f0-9]{64}$/.test(result.sha256);
    const response = validOutput
      ? { ...status, outputPath: result.outputPath, bytes: result.bytes, sha256: result.sha256 }
      : { ...status, error: 'Stegseek extraction failed' };
    return {
      isError: !validOutput,
      content: [{ type: 'text', text: JSON.stringify(response) }],
    };
  };

  registerTool(server, 'ctf_pwn_checksec', 'Inspect security properties of a challenge binary in the active workspace.',
    z.object({ artifactPath: z.string().min(1).max(2048) }),
    async (input) => run(buildChecksecCommand(input, await getScope())));
  registerTool(server, 'ctf_pwn_cyclic', 'Generate a bounded cyclic pattern for an authorized local PWN challenge.',
    z.object({ length: z.number().int().min(1).max(4096), wordSize: z.number().int().min(4).max(32).optional() }),
    async (input) => run(buildCyclicCommand(input)));
  registerTool(server, 'ctf_pwn_run', 'Run one challenge binary from the workspace with bounded argv, stdin, time, and output.',
    z.object({ artifactPath: z.string().min(1).max(2048), argv: z.array(z.string().max(2048)).max(MAX_PROCESS_ARGS).optional(), stdin: z.string().max(MAX_PROCESS_INPUT_BYTES).optional(), timeoutMs: z.number().int().min(1).max(120_000).optional() }),
    async (input) => {
      return run(buildRunBinaryCommand(input, await getScope()));
    });
  registerTool(server, 'ctf_forensics_pcap', 'Read selected fields from an in-scope PCAP challenge artifact.',
    z.object({ artifactPath: z.string().min(1).max(2048), fields: z.array(z.string()).min(1).max(MAX_PCAP_FIELDS), displayFilter: z.string().max(512).optional() }),
    async (input) => run(buildTsharkCommand(input, await getScope())));
  registerTool(server, 'ctf_forensics_pcap_follow_stream', 'Follow one selected stream from an in-scope PCAP without replaying traffic or writing extracted files.',
    z.object({
      artifactPath: z.string().min(1).max(2048),
      protocol: z.enum(['tcp', 'udp', 'http', 'http2', 'tls', 'quic', 'sip', 'websocket']).optional(),
      streamIndex: z.number().int().min(0).max(100_000),
    }),
    async (input) => run(buildPcapFollowStreamCommand(input, await getScope())));
  registerTool(server, 'ctf_forensics_firmware', 'Scan a firmware artifact for embedded signatures without extracting or modifying it.',
    z.object({ artifactPath: z.string().min(1).max(2048) }),
    async (input) => run(buildBinwalkCommand(input, await getScope())));
  registerTool(server, 'ctf_forensics_metadata', 'Read metadata from a challenge artifact using ExifTool.',
    z.object({ artifactPath: z.string().min(1).max(2048) }),
    async (input) => run(buildExiftoolCommand(input, await getScope())));
  registerTool(server, 'ctf_stego_steghide', 'Inspect steghide metadata for a challenge artifact without prompting for a passphrase.',
    z.object({ artifactPath: z.string().min(1).max(2048) }),
    async (input) => run(buildSteghideCommand(input, await getScope())));
  registerTool(server, 'ctf_stego_steghide_extract', 'Extract up to 64 MiB to an explicit workspace output path without overwriting; extracted data is untrusted and never executed. The passphrase is not returned but may be visible in process argv to same-user or privileged observers.',
    z.object({
      artifactPath: z.string().min(1).max(2048),
      outputPath: z.string().min(1).max(2048),
      passphrase: z.string().refine((value) => Array.from(value).length <= 1024),
    }),
    async (input) => runSteghideExtract(buildSteghideExtractRequest(input, await getScope())));
  registerTool(server, 'ctf_stego_metadata', 'Read image/audio metadata from a steganography challenge artifact.',
    z.object({ artifactPath: z.string().min(1).max(2048) }),
    async (input) => run(buildExiftoolCommand(input, await getScope())));
  registerTool(server, 'ctf_forensics_yara_scan', 'Scan one in-scope artifact with one in-scope source YARA rule file.',
    z.object({ artifactPath: z.string().min(1).max(2048), rulesPath: z.string().min(1).max(2048) }),
    async (input) => run(buildYaraScanCommand(input, await getScope())));
  registerTool(server, 'ctf_crypto_john', 'Audit one in-scope hash file with John in a bounded single or wordlist mode; session state is temporary and pot/log files are not persisted.',
    z.object({ hashPath: z.string().min(1).max(2048), wordlistPath: z.string().min(1).max(2048).optional() }),
    async (input) => run(buildJohnCommand(input, await getScope())));
  registerTool(server, 'ctf_pwn_ropgadget', 'Find ROP/JOP gadgets in one in-scope binary with depth capped at 10.',
    z.object({ artifactPath: z.string().min(1).max(2048), depth: z.number().int().min(1).max(10).optional() }),
    async (input) => run(buildRopgadgetCommand(input, await getScope())));
  registerTool(server, 'ctf_stegseek_crack', 'Try one in-scope carrier against one in-scope wordlist; extract at most 64 MiB to a new workspace file without overwriting. Extracted data is untrusted and never executed.',
    z.object({
      artifactPath: z.string().min(1).max(2048),
      wordlistPath: z.string().min(1).max(2048),
      outputPath: z.string().min(1).max(2048),
    }),
    async (input) => runStegseekExtract(buildStegseekExtractRequest(input, await getScope())));
  registerTool(server, 'ctf_hardware_decode_signal', 'Decode a caller-supplied signal recording; this tool does not acquire live hardware data.',
    z.object({
      artifactPath: z.string().min(1).max(2048),
      decoder: z.enum(['uart', 'i2c', 'spi']),
      channels: z.object({
        rx: z.string().max(32).optional(),
        baudrate: z.number().int().optional(),
        scl: z.string().max(32).optional(),
        sda: z.string().max(32).optional(),
        cs: z.string().max(32).optional(),
        clk: z.string().max(32).optional(),
        mosi: z.string().max(32).optional(),
        miso: z.string().max(32).optional(),
      }),
    }),
    async (input) => run(buildSigrokCommand(input, await getScope())));
}
