import { execFileSync, spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { userInfo } from 'node:os';

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_OUTPUT_BYTES = 1_048_576;

export function assertMcpAccount(account = {
  uid: process.getuid(), username: userInfo().username,
  groups: execFileSync('/usr/bin/id', ['-nG'], { encoding: 'utf8', timeout: 5000 }).trim().split(/\s+/),
}) {
  if (!Number.isInteger(account.uid) || account.uid === 0 || account.username !== 'ctfagent'
    || !Array.isArray(account.groups) || account.groups.some((group) => ['sudo', 'wheel', 'root'].includes(group))) {
    throw new Error('MCP requires the non-privileged ctfagent account, without sudo/wheel/root groups.');
  }
}

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
        detached: process.platform === 'linux',
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
    let killTimer;

    const signal = (name) => {
      try {
        if (process.platform === 'linux') process.kill(-child.pid, name);
        else child.kill(name);
      } catch (error) {
        if (error.code !== 'ESRCH') child.kill(name);
      }
    };

    const terminate = () => {
      if (killSent || settled) return;
      killSent = true;
      signal('SIGTERM');
      killTimer = setTimeout(() => signal('SIGKILL'), 250);
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
      clearTimeout(killTimer);
      reject(error);
    });

    child.once('close', (exitCode) => {
      if (settled) return;
      if (killSent && process.platform === 'linux') signal('SIGKILL');
      settled = true;
      clearTimeout(timer);
      clearTimeout(killTimer);
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

export async function runWsl(args, options = {}) {
  if (process.platform === 'linux') {
    if (args[0] === '--status' || args[0] === '--list') {
      const kernel = readFileSync('/proc/sys/kernel/osrelease', 'utf8');
      const kali = /^ID=kali$/m.test(readFileSync('/etc/os-release', 'utf8'));
      const wsl2 = /microsoft.*wsl2/i.test(kernel);
      return { exitCode: 0, stdout: args[0] === '--status'
        ? `Default Version: ${wsl2 ? 2 : 1}\n`
        : (kali ? `NAME STATE VERSION\nkali-linux Running ${wsl2 ? 2 : 1}\n` : 'NAME STATE VERSION\n'), stderr: '', timedOut: false, truncated: false };
    }
    const index = args.indexOf('--exec');
    if (index < 0 || args[args.indexOf('--distribution') + 1] !== 'kali-linux') {
      throw new TypeError('Run WSL installation/conversion from the Windows bootstrap.');
    }
    const user = args[args.indexOf('--user') + 1];
    const [executable, ...commandArgs] = args.slice(index + 1);
    const env = { ...process.env, ...options.env, PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' };
    if (user === 'ctfagent' && userInfo().username !== 'ctfagent') {
      if (process.getuid() !== 0) throw new Error('Tool execution requires the non-sudo ctfagent account.');
      return runCommand('/usr/sbin/runuser', ['-u', 'ctfagent', '--', executable, ...commandArgs], { ...options, env });
    }
    if (user === 'root' && process.getuid() !== 0 && !['apt-cache', 'python3', 'id', 'install'].includes(executable)) {
      throw new Error('Provisioning requires root; run setup.ps1 -Apply from Windows.');
    }
    return runCommand(executable, commandArgs, { ...options, env });
  }
  const prefix = args.slice(0, args.indexOf('--exec') + 1);
  const translated = [];
  for (const arg of args) {
    if (/^[a-z]:[\\/]/i.test(arg)) {
      const conversion = await runCommand('wsl.exe', [...prefix, 'wslpath', '-a', '-u', arg], { timeoutMs: 10_000, maxOutputBytes: 8192, decode: decodeWslText });
      if (conversion.exitCode !== 0 || conversion.timedOut || conversion.truncated) throw new Error('Windows path could not be translated to WSL.');
      translated.push(conversion.stdout.trim());
    } else translated.push(arg);
  }
  return runCommand('wsl.exe', translated, { ...options, decode: decodeWslText });
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
