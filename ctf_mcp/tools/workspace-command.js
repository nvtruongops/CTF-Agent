import { readFileSync } from 'node:fs';

export const WORKSPACE_WORKER_SOURCE = readFileSync(new URL('./workspace_worker.py', import.meta.url), 'utf8');

function decodeWorkerResult(result) {
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    throw new TypeError('workspace worker returned a non-object result');
  }

  const decodeOutput = (item) => {
    if (typeof item.stdoutBase64 === 'string') {
      item.stdout = Buffer.from(item.stdoutBase64, 'base64').toString('utf8');
      delete item.stdoutBase64;
    }
    if (typeof item.stderrBase64 === 'string') {
      item.stderr = Buffer.from(item.stderrBase64, 'base64').toString('utf8');
      delete item.stderrBase64;
    }
    return item;
  };

  if (Array.isArray(result.observations)) result.observations = result.observations.map(decodeOutput);
  return decodeOutput(result);
}

export async function runWorkspaceWorker(request, runWslTool, { timeoutMs, maxOutputBytes } = {}) {
  if (typeof runWslTool !== 'function') throw new TypeError('runWslTool is required');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1) throw new RangeError('timeoutMs must be a positive integer');
  if (!Number.isInteger(maxOutputBytes) || maxOutputBytes < 1) {
    throw new RangeError('maxOutputBytes must be a positive integer');
  }

  const transport = await runWslTool('python3', ['-c', WORKSPACE_WORKER_SOURCE], {
    input: `${JSON.stringify(request)}\n`,
    timeoutMs: timeoutMs + 10_000,
    maxOutputBytes: Math.ceil(maxOutputBytes * 4 / 3) + 8192,
  });

  let result;
  try {
    result = decodeWorkerResult(JSON.parse(transport.stdout.trim()));
  } catch (error) {
    result = { error: transport.stderr || transport.stdout || error.message };
  }
  return {
    result,
    transport: {
      exitCode: transport.exitCode,
      stderr: transport.stderr,
      timedOut: transport.timedOut,
      truncated: transport.truncated,
    },
  };
}

export function workspaceCommandResult(worker) {
  const result = worker?.result ?? {};
  const transport = worker?.transport ?? {};
  return {
    ...result,
    exitCode: result.exitCode ?? transport.exitCode ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? transport.stderr ?? '',
    timedOut: Boolean(result.timedOut || transport.timedOut),
    truncated: Boolean(result.truncated || transport.truncated),
    worker: transport,
  };
}
