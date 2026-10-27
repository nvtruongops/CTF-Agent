import { createHash } from 'node:crypto';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { buildIdeSetupPlan } from './ide-setup.js';

// Private bootstrap IPC: the caller captures this plan in memory, never in logs.
const homeDir = process.env.CTF_AGENT_WINDOWS_HOME;
const windowsHome = process.env.CTF_AGENT_WINDOWS_HOME_NATIVE;
if (!homeDir || !windowsHome || !path.win32.isAbsolute(windowsHome)) throw new Error('Windows home mapping is required.');
const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const plan = buildIdeSetupPlan({ clients: process.argv.slice(2), homeDir, packageVersion: version, windowsLauncher: process.env.CTF_AGENT_WINDOWS_LAUNCHER });
const result = plan.map(({ path: destination, content, originalContent }) => {
  const relative = path.relative(homeDir, destination);
  if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error('IDE destination escapes the Windows home.');
  return { path: path.win32.join(windowsHome, ...relative.split(path.sep)), content, originalHash: originalContent === null ? null : createHash('sha256').update(originalContent, 'utf8').digest('hex') };
});
process.stdout.write(JSON.stringify(result).replace(/[^\x00-\x7f]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`));
