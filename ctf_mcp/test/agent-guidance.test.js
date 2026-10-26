import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

const casesUrl = new URL('./ctf-behavior-cases.json', import.meta.url);
const rootUrl = new URL('../../', import.meta.url);
const expectedCases = {
  'flag-provenance': {
    policy: 'flag-provenance',
    guidance: ['.agents/skills/ctf-solve-report/SKILL.md'],
  },
  'generic-low-cost': {
    policy: 'low-cost-first',
    guidance: ['.agents/references/ctf-triage-ladder.md'],
  },
  'hint-first': {
    policy: 'hint-first',
    guidance: ['.agents/skills/ctf-solve-challenge/SKILL.md'],
  },
  'no-progress-stop': {
    policy: 'no-progress-stop',
    guidance: [
      '.agents/references/ctf-triage-ladder.md',
      '.agents/skills/ctf-solve-challenge/SKILL.md',
    ],
  },
  'scope-refusal': {
    policy: 'scope-refusal',
    guidance: ['.agents/references/ctf-mcp-tool-map.md'],
  },
  'truncation-incomplete': {
    policy: 'truncation-incomplete',
    guidance: ['.agents/references/ctf-mcp-tool-map.md'],
  },
};

test('offline behavior scenarios have unique IDs and case-specific policy guidance', () => {
  const fixture = JSON.parse(readFileSync(casesUrl, 'utf8'));
  assert.equal(fixture.version, 1);
  assert.deepEqual(fixture.cases.map((item) => item.id).sort(), Object.keys(expectedCases).sort());
  for (const item of fixture.cases) {
    const expected = expectedCases[item.id];
    assert.ok(expected, item.id);
    assert.equal(typeof item.prompt, 'string');
    assert.equal(item.policy, expected.policy);
    assert.ok(Array.isArray(item.guidance) && item.guidance.length > 0, item.id);
    assert.deepEqual([...item.guidance].sort(), [...expected.guidance].sort(), item.id);
    for (const file of item.guidance) assert.equal(existsSync(new URL(file, rootUrl)), true, file);
  }
});

test('triage guidance requires new evidence before escalation or pivot', () => {
  const ladder = readFileSync(new URL('../../.agents/references/ctf-triage-ladder.md', import.meta.url), 'utf8');
  const router = readFileSync(new URL('../../.agents/skills/ctf-solve-challenge/SKILL.md', import.meta.url), 'utf8');
  assert.match(ladder.toLowerCase(), /two consecutive attempts/);
  assert.match(ladder.toLowerCase(), /new relevant evidence/);
  assert.match(ladder.toLowerCase(), /escalate only when a recorded observation supports the next tier/);
  assert.match(ladder.toLowerCase(), /escalate only with recorded evidence/);
  assert.match(ladder.toLowerCase(), /next probe remains within declared scope/);
  assert.match(ladder.toLowerCase(), /host refusal ends that path/);
  assert.match(router.toLowerCase(), /failed probe alone is not evidence/);
});

test('tool guidance treats truncated output as incomplete evidence', () => {
  const toolMap = readFileSync(new URL('../../.agents/references/ctf-mcp-tool-map.md', import.meta.url), 'utf8');
  assert.match(toolMap.toLowerCase(), /truncated output is incomplete evidence/);
  assert.match(toolMap.toLowerCase(), /do not infer absence/);
});

test('write-up guidance requires evidence provenance and direct flag verification', () => {
  const writeup = readFileSync(new URL('../../.agents/skills/ctf-solve-report/SKILL.md', import.meta.url), 'utf8');
  assert.match(writeup, /Evidence & Reproducibility/);
  assert.match(writeup, /SHA-256/);
  assert.match(writeup.toLowerCase(), /tool\/mcp operation and version/);
  assert.match(writeup.toLowerCase(), /directly verified/);
  assert.match(writeup.toLowerCase(), /supplied challenge folder/);
  assert.match(writeup.toLowerCase(), /if `writeup.md` already exists, ask before writing/);
  assert.match(writeup.toLowerCase(), /do not move, delete, or reorganize challenge files/);
});
