import * as z from 'zod/v4';
import { assertWorkspacePath, loadScope } from '../scope.js';
import { runWslTool as defaultRunWslTool } from '../wsl.js';
import { runWorkspaceWorker } from './workspace-command.js';

const MAX_OUTPUT_BYTES = 1_048_576;
const TIMEOUT_MS = { inspect: 100_000, disassemble: 40_000, gdb_info: 40_000 };
const SYMBOL_NAME = /^[A-Za-z_.$][A-Za-z0-9_.$@+-]{0,127}$/;
export function buildReverseRequest({ mode, artifactPath: sourcePath, symbol } = {}, scope) {
  if (!Object.hasOwn(TIMEOUT_MS, mode)) throw new TypeError('mode must be inspect, disassemble, or gdb_info');
  const path = assertWorkspacePath(sourcePath, scope);
  if (mode === 'inspect' && symbol !== undefined) throw new TypeError('inspect mode does not accept a symbol');
  if (symbol !== undefined && (typeof symbol !== 'string' || !SYMBOL_NAME.test(symbol))) {
    throw new TypeError('symbol must be a simple symbol name');
  }
  return {
    mode,
    workspace: scope.wslWorkspace,
    artifactPath: path,
    ...(symbol === undefined ? {} : { symbol }),
  };
}

async function runRequest(request, runWslTool) {
  const { result: workerResult, transport } = await runWorkspaceWorker(request, runWslTool, {
    timeoutMs: TIMEOUT_MS[request.mode],
    maxOutputBytes: MAX_OUTPUT_BYTES,
  });
  const isError = transport.exitCode !== 0 || transport.timedOut || transport.truncated || Boolean(workerResult.error);
  return {
    isError,
    content: [{
      type: 'text',
      text: JSON.stringify({
        ...workerResult,
        worker: transport,
      }),
    }],
  };
}

function toolError(error) {
  return {
    isError: true,
    content: [{
      type: 'text',
      text: JSON.stringify({
        code: error?.code ?? 'CTF_REVERSE_ERROR',
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

export function registerReverseTools(server, { projectRoot, runWslTool = defaultRunWslTool } = {}) {
  const getScope = () => loadScope(projectRoot);
  registerTool(server, 'ctf_reverse_inspect', 'Inspect file type, ELF headers, sections, symbols, and printable strings for one challenge artifact.',
    z.object({ artifactPath: z.string().min(1).max(2048) }),
    async (input) => runRequest(buildReverseRequest({ ...input, mode: 'inspect' }, await getScope()), runWslTool));
  registerTool(server, 'ctf_reverse_disassemble', 'Disassemble a challenge artifact with objdump; an optional symbol limits output to one function.',
    z.object({ artifactPath: z.string().min(1).max(2048), symbol: z.string().min(1).max(128).optional() }),
    async (input) => runRequest(buildReverseRequest({ ...input, mode: 'disassemble' }, await getScope()), runWslTool));
  registerTool(server, 'ctf_reverse_gdb_info', 'Inspect symbols and disassembly with GDB in batch/no-init mode without running the challenge artifact.',
    z.object({ artifactPath: z.string().min(1).max(2048), symbol: z.string().min(1).max(128).optional() }),
    async (input) => runRequest(buildReverseRequest({ ...input, mode: 'gdb_info' }, await getScope()), runWslTool));
}
