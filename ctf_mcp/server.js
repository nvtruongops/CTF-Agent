import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import * as z from 'zod/v4';
import { doctor } from './doctor.js';
import { loadManifest } from './manifest.js';
import { registerArtifactTools } from './tools/artifacts.js';
import { registerReverseTools } from './tools/reverse.js';
import { registerGameTools } from './tools/game.js';
import { registerLocalTools } from './tools/local.js';
import { registerNetworkTools } from './tools/network.js';
import { registerWorkspaceTool } from './tools/workspace.js';
import { registerCtfdTools } from './tools/ctfd.js';

export function createServer({
  manifest = loadManifest(),
  projectRoot = process.cwd(),
  runWsl,
  runWslTool,
  fetchImpl,
  env,
} = {}) {
  const server = new McpServer({ name: 'ctf-agent', version: '0.1.0' });

  server.registerTool(
    'ctf_mcp_health',
    {
      description: 'Return the identity and liveness of the CTF-Agent MCP server.',
      inputSchema: z.object({}),
    },
    async () => ({
      content: [{
        type: 'text',
        text: JSON.stringify({ name: 'ctf-agent', status: 'alive', version: '0.1.0' }),
      }],
    }),
  );

  server.registerTool(
    'ctf_tool_status',
    {
      description: 'Check CTF MCP, WSL, and local category tool readiness without installing anything.',
      inputSchema: z.object({}),
    },
    async () => {
      const report = await doctor({ manifest, runWsl });
      return { content: [{ type: 'text', text: JSON.stringify(report, null, 2) }] };
    },
  );

  registerNetworkTools(server, { projectRoot, runWslTool });
  registerLocalTools(server, { runWslTool });
  registerArtifactTools(server, { projectRoot, runWslTool });
  registerReverseTools(server, { projectRoot, runWslTool });
  registerGameTools(server, { projectRoot, runWslTool });
  registerWorkspaceTool(server, { projectRoot, runWsl });
  registerCtfdTools(server, { projectRoot, runWsl, fetchImpl, env });

  return server;
}

export function startMcpServer(dependencies = {}) {
  return serveStdio(() => createServer(dependencies));
}
