import { readFileSync } from 'node:fs';

export const CTF_CATEGORY_IDS = Object.freeze([
  'web',
  'reverse',
  'crypto',
  'pwn',
  'forensics',
  'exploitation',
  'game_hacking',
  'misc',
  'osint',
  'steganography',
  'hardware',
  'competition',
]);

const PINNED_PYTHON_REQUIREMENT = /^[a-z0-9][a-z0-9_.-]*==[0-9][a-z0-9.+!-]*$/i;

function addError(errors, message) {
  if (!errors.includes(message)) errors.push(message);
}

export function validateManifest(manifest, requiredCategories = CTF_CATEGORY_IDS) {
  const errors = [];
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return { valid: false, errors: ['manifest must be an object'] };
  }
  if (manifest.schemaVersion !== 1) addError(errors, 'schemaVersion must be 1');
  if (!manifest.profiles?.full || !Array.isArray(manifest.profiles.full.apt)) {
    addError(errors, 'profiles.full.apt must be an array');
  }
  if (manifest.profiles?.full?.python !== undefined && (
    !Array.isArray(manifest.profiles.full.python)
    || manifest.profiles.full.python.some((name) => typeof name !== 'string' || !PINNED_PYTHON_REQUIREMENT.test(name))
  )) {
    addError(errors, 'profiles.full.python must contain pinned Python requirements');
  }
  if (manifest.profiles?.base !== undefined && (
    !manifest.profiles.base || !Array.isArray(manifest.profiles.base.apt)
    || manifest.profiles.base.apt.some((name) => typeof name !== 'string' || !name)
  )) {
    addError(errors, 'profiles.base.apt must contain package names');
  }
  if (manifest.baseExecutables !== undefined && (
    !Array.isArray(manifest.baseExecutables)
    || manifest.baseExecutables.some((name) => typeof name !== 'string' || !/^[a-z0-9][a-z0-9_.+-]*$/i.test(name))
  )) {
    addError(errors, 'baseExecutables must contain simple executable names');
  }
  if (!Array.isArray(manifest.categories)) {
    addError(errors, 'categories must be an array');
    return { valid: false, errors };
  }

  const fullPackages = new Set(manifest.profiles?.full?.apt ?? []);
  const fullPythonPackages = new Set(manifest.profiles?.full?.python ?? []);
  for (const packageName of manifest.profiles?.base?.apt ?? []) {
    if (!fullPackages.has(packageName)) addError(errors, `profiles.full.apt is missing base package ${packageName}`);
  }
  for (const executable of manifest.baseExecutables ?? []) {
    if (!fullPackages.has(executable)) addError(errors, `profiles.full.apt is missing base executable package ${executable}`);
  }
  const categoryIds = new Set();
  const toolIds = new Set();
  for (const category of manifest.categories) {
    if (!category || typeof category.id !== 'string' || category.id.length === 0) {
      addError(errors, 'every category needs a non-empty id');
      continue;
    }
    if (categoryIds.has(category.id)) addError(errors, `duplicate category id: ${category.id}`);
    categoryIds.add(category.id);
    if (!CTF_CATEGORY_IDS.includes(category.id)) addError(errors, `unknown category id: ${category.id}`);
    if (category.provider !== 'ctf-mcp') {
      addError(errors, `category ${category.id} has an invalid provider`);
    }
    if (Object.hasOwn(category, 'externalTools')) {
      addError(errors, `category ${category.id} cannot declare externalTools`);
    }
    if (!Array.isArray(category.tools)) {
      addError(errors, `category ${category.id} tools must be an array`);
      continue;
    }

    if (category.tools.length === 0) {
      addError(errors, `category ${category.id} needs at least one CTF MCP tool`);
    }

    for (const tool of category.tools) {
      if (!tool || typeof tool.id !== 'string' || tool.id.length === 0) {
        addError(errors, `category ${category.id} has a tool without an id`);
        continue;
      }
      if (toolIds.has(tool.id)) addError(errors, `duplicate tool id: ${tool.id}`);
      toolIds.add(tool.id);
      if (tool.builtin !== true && (typeof tool.executable !== 'string' || tool.executable.length === 0)) {
        addError(errors, `tool ${tool.id} needs an executable or builtin: true`);
      }
      if (tool.builtin !== true && (!Array.isArray(tool.probeArgs) || tool.probeArgs.some((arg) => typeof arg !== 'string'))) {
        addError(errors, `tool ${tool.id} probeArgs must be an array of strings`);
      }
      if (!Number.isInteger(tool.timeoutMs) || tool.timeoutMs < 1) {
        addError(errors, `tool ${tool.id} timeoutMs must be a positive integer`);
      }
      if (!Number.isInteger(tool.maxOutputBytes) || tool.maxOutputBytes < 1) {
        addError(errors, `tool ${tool.id} maxOutputBytes must be a positive integer`);
      }
      if (tool.requiredExecutables !== undefined && (
        !Array.isArray(tool.requiredExecutables)
        || tool.requiredExecutables.some((name) => typeof name !== 'string' || !/^[a-z0-9][a-z0-9_.+-]*$/i.test(name))
      )) {
        addError(errors, `tool ${tool.id} requiredExecutables must contain simple executable names`);
      }
      const optionalProfile = tool.optionalProfile;
      if (optionalProfile !== undefined && (
        typeof optionalProfile !== 'string'
        || !CTF_CATEGORY_IDS.includes(optionalProfile)
        || optionalProfile !== category.id
      )) {
        addError(errors, `tool ${tool.id} optionalProfile must match its topic category`);
      }
      const optionalProfileManifest = optionalProfile === undefined
        ? null
        : manifest.profiles?.[optionalProfile];
      if (optionalProfile !== undefined && !Array.isArray(optionalProfileManifest?.apt)) {
        addError(errors, `tool ${tool.id} optionalProfile must name a profile with an apt package list`);
      }
      const packages = tool.packages?.apt ?? [];
      if (!Array.isArray(packages) || packages.some((name) => typeof name !== 'string' || !name)) {
        addError(errors, `tool ${tool.id} packages.apt must contain package names`);
      } else {
        const profilePackages = optionalProfile === undefined
          ? fullPackages
          : new Set(optionalProfileManifest?.apt ?? []);
        const profileName = optionalProfile ?? 'full';
        for (const packageName of packages) {
          if (!profilePackages.has(packageName)) {
            addError(errors, `profiles.${profileName}.apt is missing package ${packageName}`);
          }
        }
      }
      const pythonPackages = tool.packages?.python ?? [];
      if (!Array.isArray(pythonPackages) || pythonPackages.some((name) => (
        typeof name !== 'string' || !PINNED_PYTHON_REQUIREMENT.test(name)
      ))) {
        addError(errors, `tool ${tool.id} packages.python must contain pinned Python requirements`);
      } else {
        const profilePythonPackages = optionalProfile === undefined
          ? fullPythonPackages
          : new Set(optionalProfileManifest?.python ?? []);
        const profileName = optionalProfile ?? 'full';
        for (const packageName of pythonPackages) {
          if (!profilePythonPackages.has(packageName)) {
            addError(errors, `profiles.${profileName}.python is missing package ${packageName}`);
          }
        }
      }
    }
  }

  for (const categoryId of requiredCategories) {
    if (!categoryIds.has(categoryId)) addError(errors, `missing category ${categoryId}`);
  }

  return { valid: errors.length === 0, errors };
}

export function loadManifest(manifestUrl = new URL('./tool-manifest.json', import.meta.url)) {
  const manifest = JSON.parse(readFileSync(manifestUrl, 'utf8'));
  const validation = validateManifest(manifest);
  if (!validation.valid) throw new Error(`Invalid CTF tool manifest: ${validation.errors.join('; ')}`);
  return manifest;
}
