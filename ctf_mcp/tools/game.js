import { fileURLToPath } from 'node:url';
import * as z from 'zod/v4';
import { FRIDA_PYTHON } from '../frida-runtime.js';
import { assertWorkspacePath, loadScope } from '../scope.js';
import { runWslTool as defaultRunWslTool } from '../wsl.js';

const MAX_SCRIPT_BYTES = 65_536;
const MAX_OUTPUT_BYTES = 1_048_576;
const MAX_TIMEOUT_MS = 120_000;
const MAX_ARGS = 32;
const MAX_ARG_LENGTH = 2048;
const FRIDA_WORKER_PATH = fileURLToPath(new URL('./frida_worker.py', import.meta.url));

function workspaceRoot(scope) {
  const root = scope?.wslWorkspace;
  if (typeof root !== 'string' || !root.startsWith('/home/ctfagent/ctf-workspaces/')) {
    throw new TypeError('active scope has an invalid WSL workspace root');
  }
  return root;
}

function scriptSource(value) {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError('script must be non-empty text');
  if (value.includes('\0')) throw new TypeError('script cannot contain NUL characters');
  if (Buffer.byteLength(value, 'utf8') > MAX_SCRIPT_BYTES) {
    throw new RangeError(`script exceeds the ${MAX_SCRIPT_BYTES}-byte limit`);
  }
  return value;
}

function timeoutValue(value = 10_000) {
  if (!Number.isInteger(value) || value < 1 || value > MAX_TIMEOUT_MS) {
    throw new RangeError(`timeoutMs must be from 1 to ${MAX_TIMEOUT_MS}`);
  }
  return value;
}

function validateArgv(argv = []) {
  if (!Array.isArray(argv) || argv.length > MAX_ARGS
    || argv.some((arg) => typeof arg !== 'string' || arg.length > MAX_ARG_LENGTH || arg.includes('\0'))) {
    throw new TypeError(`argv must contain at most ${MAX_ARGS} NUL-free strings of at most ${MAX_ARG_LENGTH} characters`);
  }
  return argv;
}

export function buildGameFridaSpawnRequest({ artifactPath: sourcePath, argv = [], script, timeoutMs } = {}, scope) {
  const executable = assertWorkspacePath(sourcePath, scope);
  return {
    mode: 'spawn',
    artifactPath: executable,
    argv: validateArgv(argv),
    script: scriptSource(script),
    timeoutMs: timeoutValue(timeoutMs),
    workspace: workspaceRoot(scope),
  };
}

async function executeRequest(request, runWslTool) {
  const timeoutMs = request.timeoutMs ?? 30_000;
  const result = await runWslTool(FRIDA_PYTHON, [FRIDA_WORKER_PATH], {
    input: `${JSON.stringify(request)}\n`,
    timeoutMs: timeoutMs + 15_000,
    maxOutputBytes: MAX_OUTPUT_BYTES,
  });
  return {
    isError: result.exitCode !== 0 || result.timedOut || result.truncated,
    content: [{ type: 'text', text: JSON.stringify(result) }],
  };
}

function toolError(error) {
  return {
    isError: true,
    content: [{
      type: 'text',
      text: JSON.stringify({
        code: error?.code ?? 'CTF_GAME_HACKING_ERROR',
        message: error instanceof Error ? error.message : String(error),
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

export function registerGameTools(server, { projectRoot, runWslTool = defaultRunWslTool } = {}) {
  const getScope = () => loadScope(projectRoot);
  registerTool(server, 'ctf_game_frida_spawn', 'Stage a private copy of a scoped workspace executable, spawn it under Frida for one bounded script run, then stop the child; the workspace source remains unchanged.',
    z.object({
      artifactPath: z.string().min(1).max(2048),
      argv: z.array(z.string().max(MAX_ARG_LENGTH)).max(MAX_ARGS).optional(),
      script: z.string().min(1).max(MAX_SCRIPT_BYTES),
      timeoutMs: z.number().int().min(1).max(MAX_TIMEOUT_MS).optional(),
    }),
    async (input) => executeRequest(buildGameFridaSpawnRequest(input, await getScope()), runWslTool));
}
