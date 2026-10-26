import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateManifest } from '../manifest.js';
import test from 'node:test';

const validWebManifest = {
  schemaVersion: 1,
  profiles: { full: { apt: ['nmap'] } },
  categories: [{
    id: 'web',
    provider: 'ctf-mcp',
    tools: [{
      id: 'ctf_nmap_scan',
      executable: 'nmap',
      probeArgs: ['--version'],
      packages: { apt: ['nmap'] },
      timeoutMs: 60_000,
      maxOutputBytes: 65_536,
    }],
  }],
};

function splitMarkdownTableRow(line) {
  const cells = [];
  let cell = '';
  let escaped = false;
  for (const character of line) {
    if (character === '|' && !escaped) {
      cells.push(cell.trim());
      cell = '';
      continue;
    }
    cell += character;
    if (character === '\\') escaped = !escaped;
    else escaped = false;
  }
  cells.push(cell.trim());
  if (cells[0] === '') cells.shift();
  if (cells.at(-1) === '') cells.pop();
  return cells;
}

function parseToolMapCategories(markdown) {
  const routing = markdown.split('## Category routing')[1]?.split('\n## ')[0] ?? '';
  return routing.split(/\r?\n/)
    .map(splitMarkdownTableRow)
    .filter((cells) => cells.length === 4 && /^`?[a-z_]+`?$/.test(cells[1]))
    .map(([, categoryCell, toolCell]) => [
      categoryCell.replaceAll('`', ''),
      [...toolCell.matchAll(/`(ctf_[a-z0-9_]+)`/g)].map((match) => match[1]).sort(),
  ]);
}

test('tool map parser preserves escaped pipes inside Markdown table cells', () => {
  const markdown = [
    '## Category routing',
    '| Category | Manifest category | Tool IDs | First operations |',
    '| --- | --- | --- | --- |',
    '| Example | `web` | `ctf_example` | Preserve a literal escaped \\| pipe. |',
    '## Utility tools',
  ].join('\n');

  assert.deepEqual(parseToolMapCategories(markdown), [['web', ['ctf_example']]]);
});

test('validateManifest accepts a typed tool whose dependencies are in the full profile', () => {
  const result = validateManifest(validWebManifest, ['web']);
  assert.deepEqual(result, { valid: true, errors: [] });
});

test('validateManifest accepts an optional tool installed only by its matching topic profile', () => {
  const manifest = {
    schemaVersion: 1,
    profiles: {
      full: { apt: ['nmap'] },
      web: { apt: ['nmap', 'ffuf'] },
    },
    categories: [{
      id: 'web',
      provider: 'ctf-mcp',
      tools: [
        validWebManifest.categories[0].tools[0],
        {
          id: 'ctf_optional_example',
          optionalProfile: 'web',
          executable: 'ffuf',
          probeArgs: ['-V'],
          packages: { apt: ['ffuf'] },
          timeoutMs: 30_000,
          maxOutputBytes: 65_536,
        },
      ],
    }],
  };

  assert.deepEqual(validateManifest(manifest, ['web']), { valid: true, errors: [] });
});

test('validateManifest rejects optional tools assigned to the wrong profile or missing its package', () => {
  const manifest = {
    schemaVersion: 1,
    profiles: {
      full: { apt: ['nmap'] },
      web: { apt: ['nmap', 'ffuf'] },
      crypto: { apt: ['ffuf'] },
    },
    categories: [{
      id: 'web',
      provider: 'ctf-mcp',
      tools: [{
        id: 'ctf_optional_example',
        optionalProfile: 'crypto',
        executable: 'ffuf',
        probeArgs: ['-V'],
        packages: { apt: ['ffuf'] },
        timeoutMs: 30_000,
        maxOutputBytes: 65_536,
      }],
    }],
  };

  const wrongProfile = validateManifest(manifest, ['web']);
  assert.equal(wrongProfile.valid, false);
  assert.match(wrongProfile.errors.join('\n'), /optionalProfile/i);

  manifest.categories[0].tools[0].optionalProfile = 'unknown-topic';
  const unknownProfile = validateManifest(manifest, ['web']);
  assert.equal(unknownProfile.valid, false);
  assert.match(unknownProfile.errors.join('\n'), /optionalProfile/i);

  manifest.categories[0].tools[0].optionalProfile = 'web';
  manifest.profiles.web.apt = ['nmap'];
  const missingPackage = validateManifest(manifest, ['web']);
  assert.equal(missingPackage.valid, false);
  assert.match(missingPackage.errors.join('\n'), /profiles\.web\.apt is missing package ffuf/i);
});

test('optional tool packages stay out of full and map to their existing topic profiles', () => {
  const manifest = JSON.parse(readFileSync(new URL('../tool-manifest.json', import.meta.url), 'utf8'));
  const expected = [
    ['exploitation', 'ctf_hydra_audit', 'hydra'],
    ['forensics', 'ctf_forensics_yara_scan', 'yara'],
    ['crypto', 'ctf_crypto_john', 'john'],
    ['pwn', 'ctf_pwn_ropgadget', 'python3-ropgadget'],
    ['steganography', 'ctf_stegseek_crack', 'stegseek'],
  ];
  const fullPackages = new Set(manifest.profiles.full.apt);

  assert.equal(manifest.categories.length, 12);
  for (const [profile, id, packageName] of expected) {
    const tool = manifest.categories.find((category) => category.id === profile)
      ?.tools.find((entry) => entry.id === id);
    assert.equal(tool?.optionalProfile, profile, `${id} optional profile`);
    assert.ok(tool?.packages.apt.includes(packageName), `${id} package declaration`);
    assert.ok(manifest.profiles[profile].apt.includes(packageName), `${packageName} in ${profile}`);
    assert.ok(!fullPackages.has(packageName), `${packageName} must stay out of full`);
  }
});

test('validateManifest rejects missing categories, duplicate tool IDs, and uninstalled packages', () => {
  const invalid = structuredClone(validWebManifest);
  invalid.categories[0].tools.push({
    id: 'ctf_nmap_scan',
    executable: 'nmap',
    probeArgs: ['--version'],
    packages: { apt: ['not-in-full'] },
    timeoutMs: 1000,
    maxOutputBytes: 4096,
  });

  const result = validateManifest(invalid, ['web', 'crypto']);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /missing category crypto/i);
  assert.match(result.errors.join('\n'), /duplicate tool id/i);
  assert.match(result.errors.join('\n'), /not-in-full/);
});

test('validateManifest rejects external REA providers and external tool references', () => {
  const reaProvider = structuredClone(validWebManifest);
  reaProvider.categories[0].provider = 'rea';
  reaProvider.categories[0].tools = [];
  reaProvider.categories[0].externalTools = ['analyze_function'];

  const externalTools = structuredClone(validWebManifest);
  externalTools.categories[0].externalTools = ['analyze_function'];

  assert.equal(validateManifest(reaProvider, ['web']).valid, false);
  assert.equal(validateManifest(externalTools, ['web']).valid, false);
});

test('validateManifest requires pinned Python requirements listed in the full profile', () => {
  const unpinnedPython = structuredClone(validWebManifest);
  unpinnedPython.profiles.full.python = ['frida'];
  unpinnedPython.categories[0].tools[0].packages.python = ['frida'];

  const result = validateManifest(unpinnedPython, ['web']);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /pinned Python requirement/i);
});

test('validateManifest accepts only simple required executable names', () => {
  const invalid = structuredClone(validWebManifest);
  invalid.categories[0].tools[0].requiredExecutables = ['strings;touch /tmp/bad'];

  const result = validateManifest(invalid, ['web']);
  assert.equal(result.valid, false);
  assert.match(result.errors.join('\n'), /requiredExecutables/i);
});

test('validateManifest validates base runtime executables and their full-profile packages', () => {
  const manifest = structuredClone(validWebManifest);
  manifest.profiles.base = { apt: ['python3'] };
  manifest.profiles.full.apt.push('python3');
  manifest.baseExecutables = ['python3'];
  assert.equal(validateManifest(manifest, ['web']).valid, true);

  manifest.profiles.full.apt = ['nmap'];
  const missingPackage = validateManifest(manifest, ['web']);
  assert.equal(missingPackage.valid, false);
  assert.match(missingPackage.errors.join('\n'), /profiles\.full\.apt is missing base executable package python3/i);

  manifest.profiles.full.apt.push('python3');
  manifest.baseExecutables = ['python3;touch /tmp/bad'];
  const invalidName = validateManifest(manifest, ['web']);
  assert.equal(invalidName.valid, false);
  assert.match(invalidName.errors.join('\n'), /baseExecutables/i);
});

test('the shipped tool manifest covers every requested CTF category', () => {
  const manifest = JSON.parse(readFileSync(new URL('../tool-manifest.json', import.meta.url), 'utf8'));
  const result = validateManifest(manifest);
  assert.deepEqual(result, { valid: true, errors: [] });
  const toolIds = new Set(manifest.categories.flatMap((category) => category.tools.map((tool) => tool.id)));
  assert.ok(toolIds.has('ctf_crypto_candidates'));
  assert.ok(toolIds.has('ctf_forensics_pcap_follow_stream'));
  assert.ok(toolIds.has('ctf_stego_steghide_extract'));
  for (const id of [
    'ctf_ctfd_list_challenges',
    'ctf_ctfd_get_challenge',
    'ctf_ctfd_download_attachment',
    'ctf_ctfd_auth_status',
    'ctf_ctfd_progress',
  ]) assert.ok(toolIds.has(id));
  assert.deepEqual(
    manifest.categories.map((category) => category.id).sort(),
    ['competition', 'crypto', 'exploitation', 'forensics', 'game_hacking', 'hardware', 'misc', 'osint', 'pwn', 'reverse', 'steganography', 'web'].sort(),
  );
});

test('CTFd tools are built-ins with no Kali package dependencies', () => {
  const manifest = JSON.parse(readFileSync(new URL('../tool-manifest.json', import.meta.url), 'utf8'));
  const category = manifest.categories.find((entry) => entry.id === 'competition');
  assert.deepEqual(manifest.profiles.competition, { apt: [] });
  assert.deepEqual(category.tools.map((tool) => tool.id).sort(), [
    'ctf_ctfd_auth_status',
    'ctf_ctfd_download_attachment',
    'ctf_ctfd_get_challenge',
    'ctf_ctfd_list_challenges',
    'ctf_ctfd_progress',
  ]);
  assert.ok(category.tools.every((tool) => tool.builtin === true && tool.packages.apt.length === 0));
});

test('Steghide extraction uses the existing executable and bounded worker limits', () => {
  const manifest = JSON.parse(readFileSync(new URL('../tool-manifest.json', import.meta.url), 'utf8'));
  const tool = manifest.categories
    .find((category) => category.id === 'steganography')
    .tools.find((entry) => entry.id === 'ctf_stego_steghide_extract');

  assert.deepEqual(tool, {
    id: 'ctf_stego_steghide_extract',
    executable: 'steghide',
    probeArgs: ['--version'],
    requiredExecutables: ['python3'],
    packages: { apt: ['python3', 'steghide'] },
    timeoutMs: 60_000,
    maxOutputBytes: 262_144,
  });
});

test('the tool map mirrors manifest categories, IDs, utilities, and package profiles', () => {
  const manifest = JSON.parse(readFileSync(new URL('../tool-manifest.json', import.meta.url), 'utf8'));
  const toolMap = readFileSync(new URL('../../.agents/references/ctf-mcp-tool-map.md', import.meta.url), 'utf8');
  const mappedCategories = parseToolMapCategories(toolMap);
  assert.deepEqual(mappedCategories.map(([id]) => id).sort(), manifest.categories.map(({ id }) => id).sort());

  for (const category of manifest.categories) {
    const mappedIds = mappedCategories.find(([id]) => id === category.id)?.[1] ?? [];
    assert.deepEqual(mappedIds, category.tools.map(({ id }) => id).sort(), category.id);
    const profile = manifest.profiles[category.id];
    assert.ok(profile, `missing setup profile for ${category.id}`);
    const apt = new Set([...(manifest.profiles.base?.apt ?? []), ...(profile?.apt ?? [])]);
    const python = new Set(profile?.python ?? []);
    for (const tool of category.tools) {
      for (const dependency of tool.packages?.apt ?? []) {
        assert.ok(apt.has(dependency), `${tool.id} requires ${dependency} in profile ${category.id}`);
      }
      for (const dependency of tool.packages?.python ?? []) {
        assert.ok(python.has(dependency), `${tool.id} requires ${dependency} in profile ${category.id}`);
      }
    }
  }

  const utilitySection = toolMap.split('## Utility tools')[1]?.split('\n## ')[0] ?? '';
  const utilityIds = [...utilitySection.matchAll(/`(ctf_[a-z0-9_]+)`/g)].map((match) => match[1]).sort();
  assert.deepEqual(utilityIds, ['ctf_mcp_health', 'ctf_tool_status', 'ctf_workspace_import']);
});

test('the full and exploitation profiles install the standalone ncat package', () => {
  const manifest = JSON.parse(readFileSync(new URL('../tool-manifest.json', import.meta.url), 'utf8'));

  assert.ok(manifest.profiles.full.apt.includes('ncat'));
  assert.ok(manifest.profiles.exploitation.apt.includes('ncat'));
});

test('OpenCode passes CTFd connection values from the parent environment', () => {
  const config = JSON.parse(readFileSync(new URL('../../opencode.jsonc', import.meta.url), 'utf8'));
  assert.deepEqual(config.mcp.servers['ctf-agent'].environment, {
    CTF_MCP_CTFD_URL: '{env:CTF_MCP_CTFD_URL}',
    CTF_MCP_CTFD_TOKEN: '{env:CTF_MCP_CTFD_TOKEN}',
  });
});

test('the Frida readiness probe requires the pinned virtual-environment version', () => {
  const manifest = JSON.parse(readFileSync(new URL('../tool-manifest.json', import.meta.url), 'utf8'));
  const gameTool = manifest.categories
    .find((category) => category.id === 'game_hacking')
    .tools.find((tool) => tool.id === 'ctf_game_frida_spawn');

  assert.deepEqual(gameTool.probeArgs, [
    '-c', "import frida,sys; print(frida.__version__); sys.exit(frida.__version__ != '17.24.3')",
  ]);
});

test('the firmware tool uses Binwalk’s supported help probe', () => {
  const manifest = JSON.parse(readFileSync(new URL('../tool-manifest.json', import.meta.url), 'utf8'));
  const firmware = manifest.categories
    .find((category) => category.id === 'forensics')
    .tools.find((tool) => tool.id === 'ctf_forensics_firmware');

  assert.deepEqual(firmware.probeArgs, ['--help']);
});

test('the exploitation category has fixed HTTP and TCP client executables', () => {
  const manifest = JSON.parse(readFileSync(new URL('../tool-manifest.json', import.meta.url), 'utf8'));
  const exploitation = manifest.categories.find((category) => category.id === 'exploitation');
  const tools = new Map(exploitation.tools.map((tool) => [tool.id, tool]));

  assert.equal(tools.get('ctf_scoped_http_request')?.executable, 'curl');
  assert.deepEqual(tools.get('ctf_scoped_http_request')?.packages.apt, ['curl']);
  assert.equal(tools.get('ctf_scoped_tcp_exchange')?.executable, 'ncat');
  assert.deepEqual(tools.get('ctf_scoped_tcp_exchange')?.packages.apt, ['ncat']);
});
