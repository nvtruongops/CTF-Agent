import { spawn } from 'node:child_process';

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_OUTPUT_BYTES = 1_048_576;

export function decodeWslText(value) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value ?? '');
  if (buffer.length === 0) return '';

  let text;
  if (buffer[0] === 0xff && buffer[1] === 0xfe) {
    text = buffer.subarray(2).toString('utf16le');
  } else if (buffer[0] === 0xfe && buffer[1] === 0xff) {
    const swapped = Buffer.from(buffer.subarray(2));
    for (let index = 0; index + 1 < swapped.length; index += 2) {
      const byte = swapped[index];
      swapped[index] = swapped[index + 1];
      swapped[index + 1] = byte;
    }
    text = swapped.toString('utf16le');
  } else {
    let oddNulls = 0;
    let evenNulls = 0;
    for (let index = 0; index < buffer.length; index += 1) {
      if (buffer[index] === 0) {
        if (index % 2 === 0) evenNulls += 1;
        else oddNulls += 1;
      }
    }
    const likelyUtf16Le = buffer.length > 4
      && oddNulls > buffer.length / 6
      && evenNulls < buffer.length / 10;
    text = buffer.toString(likelyUtf16Le ? 'utf16le' : 'utf8');
  }

  return text.replaceAll('\uFEFF', '').replaceAll('\0', '');
}

export function parseWslDistroTable(value) {
  const text = decodeWslText(value);
  const distributions = [];

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    const isDefault = line.startsWith('*');
    const normalized = line.replace(/^\*\s*/, '');
    const match = normalized.match(/^(.+?)\s+(Running|Stopped|Installing|Converting|Uninstalling)\s+([12])$/i);
    if (!match) continue;

    distributions.push({
      name: match[1].trim(),
      state: match[2],
      version: Number(match[3]),
      isDefault,
    });
  }

  return distributions;
}

function validateLimits(timeoutMs, maxOutputBytes) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1) {
    throw new RangeError('timeoutMs must be a positive integer');
  }
  if (!Number.isInteger(maxOutputBytes) || maxOutputBytes < 1) {
    throw new RangeError('maxOutputBytes must be a positive integer');
  }
}

export function runCommand(command, args, options = {}) {
  const {
    input,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES,
    decode = (buffer) => buffer.toString('utf8'),
    cwd,
    env,
  } = options;

  if (typeof command !== 'string' || command.length === 0) {
    throw new TypeError('command must be a non-empty string');
  }
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) {
    throw new TypeError('args must be an array of strings');
  }
  validateLimits(timeoutMs, maxOutputBytes);

  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(command, args, {
        cwd,
        env,
        shell: false,
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (error) {
      reject(error);
      return;
    }

    const output = { stdout: [], stderr: [], totalBytes: 0 };
    let timedOut = false;
    let truncated = false;
    let killSent = false;
    let settled = false;

    const terminate = () => {
      if (killSent || settled) return;
      killSent = true;
      child.kill();
    };

    const capture = (name) => (chunk) => {
      const remaining = Math.max(0, maxOutputBytes - output.totalBytes);
      const retained = chunk.subarray(0, remaining);
      if (retained.length > 0) {
        output[name].push(retained);
        output.totalBytes += retained.length;
      }
      if (retained.length < chunk.length) {
        truncated = true;
        terminate();
      }
    };

    child.stdout.on('data', capture('stdout'));
    child.stderr.on('data', capture('stderr'));
    child.stdin.on('error', (error) => {
      if (error.code !== 'EPIPE') reject(error);
    });

    const timer = setTimeout(() => {
      timedOut = true;
      terminate();
    }, timeoutMs);

    child.once('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });

    child.once('close', (exitCode) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        exitCode,
        stdout: decode(Buffer.concat(output.stdout)),
        stderr: decode(Buffer.concat(output.stderr)),
        timedOut,
        truncated,
      });
    });

    if (input === undefined) child.stdin.end();
    else child.stdin.end(input);
  });
}

export function runWsl(args, options = {}) {
  return runCommand('wsl.exe', args, { ...options, decode: decodeWslText });
}

export async function runWslTool(executable, args, options = {}) {
  const {
    input,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES,
    runWsl: executeWsl = runWsl,
  } = options;

  if (typeof executable !== 'string' || executable.length === 0) {
    throw new TypeError('executable must be a non-empty string');
  }
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) {
    throw new TypeError('args must be an array of strings');
  }
  validateLimits(timeoutMs, maxOutputBytes);

  const timeoutSeconds = Math.max(1, Math.ceil(timeoutMs / 1000));
  const result = await executeWsl([
    '--distribution', 'kali-linux', '--user', 'ctfagent', '--exec',
    'timeout', '--signal=TERM', '--kill-after=5s', `${timeoutSeconds}s`,
    executable, ...args,
  ], {
    input,
    timeoutMs: timeoutMs + 7000,
    maxOutputBytes,
  });

  return {
    ...result,
    timedOut: result.timedOut || result.exitCode === 124 || result.exitCode === 137,
  };
}
