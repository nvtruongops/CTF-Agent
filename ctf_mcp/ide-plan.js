import { createHash } from 'node:crypto';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { buildIdeSetupPlan } from './ide-setup.js';

// Private bootstrap IPC: the caller captures this plan in memory, never in logs.
const homeDir = process.env.CTF_AGENT_WINDOWS_HOME;
const windowsHome = process.env.CTF_AGENT_WINDOWS_HOME_NATIVE;
if (!homeDir || !windowsHome || !path.win32.isAbsolute(windowsHome)) throw new Error('Windows home mapping is required.');
const args = process.argv.slice(2);
if (args[0] !== '--scope' || !['global', 'workspace'].includes(args[1])) throw new Error('An explicit global or workspace scope is required.');
const scope = args[1];
const clients = args.slice(2);
const workspaceDir = process.env.CTF_AGENT_WINDOWS_WORKSPACE;
const windowsWorkspace = process.env.CTF_AGENT_WINDOWS_WORKSPACE_NATIVE;
if (scope === 'workspace' && (!workspaceDir || !path.isAbsolute(workspaceDir) || !windowsWorkspace || !path.win32.isAbsolute(windowsWorkspace))) {
  throw new Error('Windows workspace mapping is required.');
}
const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const sourceRoot = scope === 'workspace' ? workspaceDir : homeDir;
const windowsRoot = scope === 'workspace' ? windowsWorkspace : windowsHome;
const plan = buildIdeSetupPlan({ clients, homeDir, workspaceDir, scope, packageVersion: version, windowsLauncher: process.env.CTF_AGENT_WINDOWS_LAUNCHER });
const result = plan.map(({ path: destination, content, originalContent }) => {
  const relative = path.relative(sourceRoot, destination);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error('IDE destination escapes the selected Windows root.');
  return { path: path.win32.join(windowsRoot, ...relative.split(path.sep)), content, originalHash: originalContent === null ? null : createHash('sha256').update(originalContent, 'utf8').digest('hex') };
});
process.stdout.write(JSON.stringify(result).replace(/[^\x00-\x7f]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`));
