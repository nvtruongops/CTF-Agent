import {
  closeSync,
  fstatSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CTF_CATEGORY_IDS } from './manifest.js';

const MAX_LEARNING_INPUT_BYTES = 64 * 1024;
const ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const CONFIDENCE_LEVELS = new Set(['low', 'medium', 'high']);
const SECRET_KEY_PATTERN = /(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|credential)/i;
const RAW_DATA_KEY_PATTERN = /(?:payload|body|transcript|raw[_-]?(?:request|response|output)|exploit|shellcode|command|script|flag)/i;
const SAFE_PARAMETER_KEYS = new Set([
  'method', 'contentType', 'encoding', 'requestCount', 'protocol', 'port', 'format', 'algorithm',
  'operation', 'mode', 'fileType', 'inputLength', 'responseStatus', 'attemptCount', 'durationMs',
  'timeoutSeconds', 'maxBytes', 'decoder',
]);
const SAFE_PARAMETER_VALUE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._:/+-]{0,63}$/;
const FLAG_PATTERN = /\b[A-Za-z0-9][A-Za-z0-9_.-]{0,31}\{[^{}\r\n]{1,256}\}/;
const SECRET_VALUE_PATTERN = /\b(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key)\s*[:=]\s*(?:"[^"]+"|'[^']+'|[^\s,;]+)/i;
const BEARER_PATTERN = /\bbearer\s+[A-Za-z0-9._~+/-]+=*/i;
// shortcut: reject common raw-content shapes; arbitrary plaintext still must be sanitized before submission.
const RAW_CONTENT_PATTERN = /<\s*\/?\s*[!?a-z][^>]*>|\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP\/\d(?:\.\d)?\b|\b(?:curl|wget|bash|sh|python3?|nc|ncat|powershell)\s+-[A-Za-z]/i;
const ALLOWED_FIELDS = new Set([
  'schemaVersion', 'id', 'title', 'topic', 'parentId', 'principle', 'mechanism',
  'appliesWhen', 'doesNotApplyWhen', 'confidence', 'actions', 'evidence', 'relatedLabs',
]);
const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const LEARN_USAGE = 'Usage: ctf-agent learn --propose --input <json-file> | --list [--topic <topic>] | --show <id> | --promote <id>\n';

function addError(errors, field, message) {
  if (!errors.some((error) => error.field === field && error.message === message)) errors.push({ field, message });
}

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function checkString(value, field, errors, { max = 2048, allowEmpty = false } = {}) {
  if (typeof value !== 'string') {
    addError(errors, field, 'must be a string');
    return false;
  }
  if ((!allowEmpty && value.trim().length === 0) || value.length > max || /[\u0000-\u001f\u007f]/u.test(value)) {
    addError(errors, field, `must be ${allowEmpty ? 'at most' : 'a non-empty string of at most'} ${max} characters without control characters or line breaks`);
    return false;
  }
  return true;
}

function checkStringList(value, field, errors, { min = 1, maxItems = 20, maxChars = 1000 } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > maxItems) {
    addError(errors, field, `must be an array with ${min} to ${maxItems} items`);
    return;
  }
  value.forEach((item, index) => checkString(item, `${field}[${index}]`, errors, { max: maxChars }));
}

function checkParameters(value, field, errors, seen = new WeakSet(), depth = 0) {
  if (!isRecord(value)) {
    addError(errors, field, 'must be a JSON object');
    return;
  }
  if (seen.has(value)) {
    addError(errors, field, 'must not contain circular data');
    return;
  }
  if (depth > 8) {
    addError(errors, field, 'must not be nested more than 8 levels');
    return;
  }
  seen.add(value);
  for (const [key, child] of Object.entries(value)) {
    const childField = `${field}.${key}`;
    if (!SAFE_PARAMETER_KEYS.has(key)) addError(errors, childField, 'must be a sanitized operational parameter');
    if (SECRET_KEY_PATTERN.test(key)) addError(errors, childField, 'must not contain credentials or secrets');
    if (RAW_DATA_KEY_PATTERN.test(key)) addError(errors, childField, 'must not contain raw bodies, transcripts, flags, or executable payloads');
    if (typeof child === 'string') {
      if (!SAFE_PARAMETER_VALUE_PATTERN.test(child)) addError(errors, childField, 'must be a short sanitized label');
    } else if (typeof child === 'number') {
      if (!Number.isFinite(child)) addError(errors, childField, 'must be a finite number');
    } else if (typeof child === 'boolean' || child === null) {
      continue;
    } else if (Array.isArray(child)) {
      if (child.length > 64) addError(errors, childField, 'must contain no more than 64 items');
      else child.forEach((item, index) => {
        if (isRecord(item)) checkParameters(item, `${childField}[${index}]`, errors, seen, depth + 1);
        else if (typeof item === 'string' && !SAFE_PARAMETER_VALUE_PATTERN.test(item)) addError(errors, `${childField}[${index}]`, 'must be a short sanitized label');
        else if (item !== null && typeof item !== 'boolean' && (typeof item !== 'number' || !Number.isFinite(item))) {
          addError(errors, `${childField}[${index}]`, 'must be JSON data');
        }
      });
    } else if (isRecord(child)) {
      checkParameters(child, childField, errors, seen, depth + 1);
    } else {
      addError(errors, childField, 'must be JSON data');
    }
  }
  seen.delete(value);
}

function checkSensitiveText(value, field, errors) {
  if (typeof value !== 'string') return;
  if (FLAG_PATTERN.test(value)) addError(errors, field, 'must not contain a flag-shaped value');
  if (SECRET_VALUE_PATTERN.test(value) || BEARER_PATTERN.test(value)) addError(errors, field, 'must not contain credentials or secrets');
  if (RAW_CONTENT_PATTERN.test(value)) addError(errors, field, 'must not contain raw bodies, request lines, or executable payloads');
}

export function validateLearningProposal(value) {
  const errors = [];
  if (!isRecord(value)) return { valid: false, errors: [{ field: '$', message: 'must be an object' }] };

  for (const key of Object.keys(value)) {
    if (!ALLOWED_FIELDS.has(key)) addError(errors, key, 'is not an allowed proposal field');
  }
  if (value.schemaVersion !== 1) addError(errors, 'schemaVersion', 'must be 1');
  if (typeof value.id !== 'string' || value.id.length > 64 || !ID_PATTERN.test(value.id)) {
    addError(errors, 'id', 'must be a lowercase slug of at most 64 characters');
  }
  checkString(value.title, 'title', errors, { max: 160 });
  if (!CTF_CATEGORY_IDS.includes(value.topic)) addError(errors, 'topic', 'must be one of the 12 CTF topics');
  if (value.parentId !== null && (
    typeof value.parentId !== 'string' || value.parentId.length > 64 || !ID_PATTERN.test(value.parentId)
  )) addError(errors, 'parentId', 'must be null or a lowercase slug of at most 64 characters');
  checkString(value.principle, 'principle', errors, { max: 1000 });
  checkString(value.mechanism, 'mechanism', errors, { max: 2000 });
  checkStringList(value.appliesWhen, 'appliesWhen', errors, { maxItems: 20, maxChars: 1000 });
  checkStringList(value.doesNotApplyWhen, 'doesNotApplyWhen', errors, { maxItems: 20, maxChars: 1000 });
  if (!CONFIDENCE_LEVELS.has(value.confidence)) addError(errors, 'confidence', 'must be low, medium, or high');

  if (!Array.isArray(value.actions) || value.actions.length > 20) {
    addError(errors, 'actions', 'must be an array with no more than 20 items');
  } else {
    value.actions.forEach((action, index) => {
      const field = `actions[${index}]`;
      if (!isRecord(action)) {
        addError(errors, field, 'must be an object');
        return;
      }
      for (const key of Object.keys(action)) {
        if (!['tool', 'parameters', 'observation'].includes(key)) addError(errors, `${field}.${key}`, 'is not an allowed action field');
      }
      if (typeof action.tool !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(action.tool)) {
        addError(errors, `${field}.tool`, 'must be a tool name');
      }
      checkParameters(action.parameters, `${field}.parameters`, errors);
      checkString(action.observation, `${field}.observation`, errors, { max: 1000 });
    });
  }

  if (!Array.isArray(value.evidence) || value.evidence.length < 1 || value.evidence.length > 20) {
    addError(errors, 'evidence', 'must be an array with 1 to 20 items');
  } else {
    value.evidence.forEach((item, index) => {
      const field = `evidence[${index}]`;
      if (!isRecord(item)) {
        addError(errors, field, 'must be an object');
        return;
      }
      for (const key of Object.keys(item)) {
        if (!['kind', 'reference', 'observation'].includes(key)) addError(errors, `${field}.${key}`, 'is not an allowed evidence field');
      }
      checkString(item.kind, `${field}.kind`, errors, { max: 40 });
      checkString(item.reference, `${field}.reference`, errors, { max: 300 });
      checkString(item.observation, `${field}.observation`, errors, { max: 1000 });
    });
  }
  checkStringList(value.relatedLabs, 'relatedLabs', errors, { min: 0, maxItems: 20, maxChars: 100 });

  const seen = new WeakSet();
  const inspectSensitive = (item, field, depth = 0) => {
    if (typeof item === 'string') {
      checkSensitiveText(item, field, errors);
      return;
    }
    if (!item || typeof item !== 'object' || depth > 12 || seen.has(item)) return;
    seen.add(item);
    if (Array.isArray(item)) item.forEach((child, index) => inspectSensitive(child, `${field}[${index}]`, depth + 1));
    else for (const [key, child] of Object.entries(item)) inspectSensitive(child, `${field}.${key}`, depth + 1);
    seen.delete(item);
  };
  inspectSensitive(value, '$');
  return { valid: errors.length === 0, errors };
}

function rootPaths(rootDir = REPOSITORY_ROOT) {
  const root = resolve(rootDir);
  const agents = join(root, '.agents');
  const tree = join(agents, 'skill-tree');
  return { root, agents, tree, proposals: join(tree, 'proposals'), patterns: join(tree, 'patterns') };
}

function ensureDirectory(path) {
  try {
    mkdirSync(path, { mode: 0o700 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
  const stats = lstatSync(path);
  if (!stats.isDirectory() || stats.isSymbolicLink()) throw new TypeError(`learning storage path is not a safe directory: ${path}`);
}

function ensureTree(paths, topic) {
  ensureDirectory(paths.root);
  ensureDirectory(paths.agents);
  ensureDirectory(paths.tree);
  ensureDirectory(paths.proposals);
  ensureDirectory(paths.patterns);
  if (topic !== undefined) ensureDirectory(join(paths.patterns, topic));
}

function isSafeRegularFile(path) {
  try {
    const stats = lstatSync(path);
    if (!stats.isFile() || stats.isSymbolicLink()) throw new TypeError(`learning entry is not a regular file: ${path}`);
    return stats;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function isSameFile(left, right) {
  const leftStats = isSafeRegularFile(left);
  const rightStats = isSafeRegularFile(right);
  return Boolean(leftStats && rightStats && leftStats.dev === rightStats.dev && leftStats.ino !== 0 && leftStats.ino === rightStats.ino);
}

function directoryEntries(path) {
  try {
    const stats = lstatSync(path);
    if (!stats.isDirectory() || stats.isSymbolicLink()) throw new TypeError(`learning storage path is not a safe directory: ${path}`);
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  return readdirSync(path, { withFileTypes: true })
    .filter((entry) => entry.name.endsWith('.json'))
    .map((entry) => join(path, entry.name));
}

function readEntry(path, expectedId) {
  const stats = isSafeRegularFile(path);
  if (!stats) return null;
  if (stats.size > MAX_LEARNING_INPUT_BYTES) throw new TypeError('stored learning entry exceeds the 64 KiB limit');
  const value = JSON.parse(readFileSync(path, 'utf8'));
  const validation = validateLearningProposal(value);
  if (!validation.valid) throw new TypeError(`invalid stored learning entry: ${validation.errors.map(({ field, message }) => `${field}: ${message}`).join('; ')}`);
  if (value.id !== expectedId) throw new TypeError('stored learning entry ID does not match its filename');
  return value;
}

function validateId(id) {
  if (typeof id !== 'string' || id.length > 64 || !ID_PATTERN.test(id)) throw new TypeError('id must be a lowercase slug of at most 64 characters');
}

function assertNoExistingId(paths, id) {
  if (isSafeRegularFile(join(paths.proposals, `${id}.json`))) throw new TypeError(`learning proposal ID already exists: ${id}`);
  for (const topic of CTF_CATEGORY_IDS) {
    if (isSafeRegularFile(join(paths.patterns, topic, `${id}.json`))) throw new TypeError(`learning proposal ID already exists: ${id}`);
  }
}

function validatedProposal(value) {
  const validation = validateLearningProposal(value);
  if (!validation.valid) {
    throw new TypeError(`invalid learning proposal: ${validation.errors.map(({ field, message }) => `${field}: ${message}`).join('; ')}`);
  }
  let serialized;
  try {
    serialized = JSON.stringify(value, null, 2);
  } catch {
    throw new TypeError('learning proposal must contain JSON data');
  }
  if (Buffer.byteLength(serialized, 'utf8') > MAX_LEARNING_INPUT_BYTES) throw new TypeError('learning proposal exceeds the 64 KiB limit');
  return serialized;
}

export function proposeLearning(value, { rootDir = REPOSITORY_ROOT } = {}) {
  const serialized = validatedProposal(value);
  const paths = rootPaths(rootDir);
  ensureTree(paths);
  assertNoExistingId(paths, value.id);
  writeFileSync(join(paths.proposals, `${value.id}.json`), `${serialized}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  return value;
}

function safeExistingDirectory(path) {
  try {
    const stats = lstatSync(path);
    if (!stats.isDirectory() || stats.isSymbolicLink()) throw new TypeError(`learning storage path is not a safe directory: ${path}`);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

export function listLearningEntries({ rootDir = REPOSITORY_ROOT, topic } = {}) {
  if (topic !== undefined && !CTF_CATEGORY_IDS.includes(topic)) throw new TypeError('topic must be one of the 12 CTF topics');
  const paths = rootPaths(rootDir);
  const topics = topic === undefined ? CTF_CATEGORY_IDS : [topic];
  const entries = [];
  if (!safeExistingDirectory(paths.agents) || !safeExistingDirectory(paths.tree)) return entries;
  if (safeExistingDirectory(paths.proposals)) {
    for (const path of directoryEntries(paths.proposals)) {
      const id = basename(path, '.json');
      validateId(id);
      const value = readEntry(path, id);
      if (value && (topic === undefined || value.topic === topic)) entries.push({ proposal: value, status: 'pending' });
    }
  }
  if (safeExistingDirectory(paths.patterns)) {
    for (const currentTopic of topics) {
      const directory = join(paths.patterns, currentTopic);
      if (!safeExistingDirectory(directory)) continue;
      for (const path of directoryEntries(directory)) {
        const id = basename(path, '.json');
        validateId(id);
        const value = readEntry(path, id);
        if (value?.topic !== currentTopic) throw new TypeError(`approved learning entry ${id} is stored under the wrong topic`);
        const pendingIndex = entries.findIndex((entry) => entry.proposal.id === id && entry.status === 'pending');
        if (pendingIndex !== -1 && isSameFile(join(paths.proposals, `${id}.json`), path)) entries.splice(pendingIndex, 1);
        entries.push({ proposal: value, status: 'approved' });
      }
    }
  }
  entries.sort((left, right) => left.proposal.id.localeCompare(right.proposal.id));
  return entries;
}

export function showLearningEntry({ rootDir = REPOSITORY_ROOT, id } = {}) {
  validateId(id);
  const matches = listLearningEntries({ rootDir }).filter((entry) => entry.proposal.id === id);
  if (matches.length === 0) throw new TypeError(`learning entry not found: ${id}`);
  if (matches.length > 1) throw new TypeError(`learning entry ID exists in more than one state: ${id}`);
  return matches[0];
}

export function promoteLearningEntry({ rootDir = REPOSITORY_ROOT, id } = {}) {
  validateId(id);
  const paths = rootPaths(rootDir);
  if (!safeExistingDirectory(paths.agents) || !safeExistingDirectory(paths.tree) || !safeExistingDirectory(paths.proposals)) {
    throw new TypeError(`pending learning proposal not found: ${id}`);
  }
  safeExistingDirectory(paths.patterns);
  const proposalPath = join(paths.proposals, `${id}.json`);
  const stats = isSafeRegularFile(proposalPath);
  if (!stats) throw new TypeError(`pending learning proposal not found: ${id}`);
  const value = readEntry(proposalPath, id);
  ensureTree(paths, value.topic);
  const approvedPath = join(paths.patterns, value.topic, `${id}.json`);
  if (isSameFile(proposalPath, approvedPath)) {
    unlinkSync(proposalPath);
    return { proposal: value, status: 'approved' };
  }
  if (CTF_CATEGORY_IDS.some((topic) => topic !== value.topic && isSafeRegularFile(join(paths.patterns, topic, `${id}.json`)))) {
    throw new TypeError(`approved learning entry ID already exists: ${id}`);
  }
  try {
    // Publishing the hard link is the commit point; readers collapse interrupted source cleanup.
    linkSync(proposalPath, approvedPath);
  } catch (error) {
    if (error.code === 'EEXIST') throw new TypeError(`approved learning entry already exists: ${id}`);
    throw error;
  }
  try {
    unlinkSync(proposalPath);
  } catch (error) {
    try {
      unlinkSync(approvedPath);
    } catch {
      // Preserve the original failure; the approved link is still the same validated file.
    }
    throw error;
  }
  return { proposal: value, status: 'approved' };
}

function readBoundedInput(path) {
  const descriptor = openSync(path, 'r');
  try {
    const stats = fstatSync(descriptor);
    if (!stats.isFile()) throw new TypeError('proposal input must be a regular file');
    if (stats.size > MAX_LEARNING_INPUT_BYTES) throw new TypeError('proposal input exceeds the 64 KiB limit');
    const chunks = [];
    const buffer = Buffer.alloc(8192);
    let total = 0;
    while (true) {
      const count = readSync(descriptor, buffer, 0, Math.min(buffer.length, MAX_LEARNING_INPUT_BYTES + 1 - total), null);
      if (count === 0) break;
      total += count;
      if (total > MAX_LEARNING_INPUT_BYTES) throw new TypeError('proposal input exceeds the 64 KiB limit');
      chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, total));
  } finally {
    closeSync(descriptor);
  }
}

function writeJson(write, value) {
  write(`${JSON.stringify(value, null, 2)}\n`);
  return value;
}

export function runLearnCommand(args, { rootDir = REPOSITORY_ROOT, write = (text) => process.stdout.write(text) } = {}) {
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) throw new TypeError('learn arguments must be strings');
  if (args.length === 1 && ['--help', '-h'].includes(args[0])) {
    write(LEARN_USAGE);
    return;
  }
  if (args[0] === '--propose' && args.length === 3 && args[1] === '--input') {
    const input = readBoundedInput(args[2]);
    let value;
    try {
      value = JSON.parse(input);
    } catch {
      throw new TypeError('proposal input must contain valid JSON');
    }
    return writeJson(write, { proposal: proposeLearning(value, { rootDir }), status: 'pending' });
  }
  if (args[0] === '--list' && (args.length === 1 || (args.length === 3 && args[1] === '--topic'))) {
    const topic = args[2];
    return writeJson(write, listLearningEntries({ rootDir, ...(topic === undefined ? {} : { topic }) }));
  }
  if (args[0] === '--show' && args.length === 2) return writeJson(write, showLearningEntry({ rootDir, id: args[1] }));
  if (args[0] === '--promote' && args.length === 2) return writeJson(write, promoteLearningEntry({ rootDir, id: args[1] }));
  throw new TypeError(LEARN_USAGE.trim());
}
