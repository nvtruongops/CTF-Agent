import { createHash } from 'node:crypto';
import * as z from 'zod/v4';
import { runWslTool as defaultRunWslTool } from '../wsl.js';

const MAX_DECODE_BYTES = 256 * 1024;
const MAX_SMT_BYTES = 128 * 1024;
const MAX_CRYPTO_CANDIDATE_BYTES = 32 * 1024;
const MAX_CANDIDATE_TEXT_CHARS = 2048;
const MAX_CANDIDATES = 10;
const FLAG_PATTERN = /(?:flag|ctf|htb|picoctf)\{[^\r\n}]{1,256}\}/i;

function decodeHex(value) {
  if (value.length % 2 !== 0) throw new TypeError('hex input must have even-length digits');
  if (!/^[0-9a-f]*$/i.test(value)) throw new TypeError('hex input contains invalid digits');
  return Buffer.from(value, 'hex');
}

export function decodeCtfValue({ encoding, value, key } = {}) {
  if (typeof value !== 'string') throw new TypeError('value must be a string');
  if (Buffer.byteLength(value, 'utf8') > MAX_DECODE_BYTES) {
    throw new RangeError(`value exceeds the ${MAX_DECODE_BYTES}-byte limit`);
  }

  let bytes;
  switch (encoding) {
    case 'base64':
      if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
        throw new TypeError('base64 input is invalid');
      }
      bytes = Buffer.from(value, 'base64');
      break;
    case 'hex':
      bytes = decodeHex(value);
      break;
    case 'url': {
      let decoded;
      try {
        decoded = decodeURIComponent(value.replaceAll('+', ' '));
      } catch {
        throw new TypeError('URL-encoded input is invalid');
      }
      bytes = Buffer.from(decoded, 'utf8');
      break;
    }
    case 'rot13': {
      const output = value.replace(/[a-zA-Z]/g, (letter) => {
        const base = letter <= 'Z' ? 65 : 97;
        return String.fromCharCode(((letter.charCodeAt(0) - base + 13) % 26) + base);
      });
      bytes = Buffer.from(output, 'utf8');
      break;
    }
    case 'xor-byte': {
      if (!Number.isInteger(key) || key < 0 || key > 255) {
        throw new RangeError('XOR key must be an integer from 0 to 255');
      }
      bytes = decodeHex(value);
      for (let index = 0; index < bytes.length; index += 1) bytes[index] ^= key;
      break;
    }
    default:
      throw new TypeError('encoding must be base64, hex, url, rot13, or xor-byte');
  }

  if (bytes.length > MAX_DECODE_BYTES) throw new RangeError(`decoded value exceeds the ${MAX_DECODE_BYTES}-byte limit`);
  return { encoding, output: bytes.toString('utf8'), outputHex: bytes.toString('hex') };
}

function decodeCryptoInput(value, encoding) {
  if (encoding === 'text') return [{ encoding, bytes: Buffer.from(value, 'utf8') }];
  if (encoding === 'hex') return [{ encoding, bytes: decodeHex(value) }];
  if (encoding === 'base64') {
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
      throw new TypeError('base64 input is invalid');
    }
    return [{ encoding, bytes: Buffer.from(value, 'base64') }];
  }
  if (encoding === 'url') {
    const decoded = decodeCtfValue({ encoding: 'url', value });
    return [{ encoding, bytes: Buffer.from(decoded.outputHex, 'hex') }];
  }

  const candidates = [{ encoding: 'text', bytes: Buffer.from(value, 'utf8') }];
  for (const [name, decode] of [
    ['hex', () => decodeHex(value)],
    ['base64', () => {
      if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
        throw new TypeError('not base64');
      }
      return Buffer.from(value, 'base64');
    }],
    ['url', () => Buffer.from(decodeCtfValue({ encoding: 'url', value }).outputHex, 'hex')],
  ]) {
    try {
      candidates.push({ encoding: name, bytes: decode() });
    } catch {
      // Auto mode skips decoders that do not accept the complete input.
    }
  }
  return candidates;
}

function readabilityScore(bytes) {
  if (bytes.length === 0) return 0;
  let printable = 0;
  for (const byte of bytes) {
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09 || byte === 0x0a || byte === 0x0d) printable += 1;
  }
  return printable / bytes.length;
}

export function buildCryptoCandidates({ value, encoding = 'auto', includeSingleByteXor = true, limit = 10 } = {}) {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError('value must be non-empty text');
  const inputBytes = Buffer.byteLength(value, 'utf8');
  if (inputBytes > MAX_CRYPTO_CANDIDATE_BYTES) {
    throw new RangeError(`value exceeds the ${MAX_CRYPTO_CANDIDATE_BYTES}-byte limit`);
  }
  if (!['auto', 'text', 'hex', 'base64', 'url'].includes(encoding)) {
    throw new TypeError('encoding must be auto, text, hex, base64, or url');
  }
  if (typeof includeSingleByteXor !== 'boolean') throw new TypeError('includeSingleByteXor must be a boolean');
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_CANDIDATES) {
    throw new RangeError(`limit must be an integer from 1 to ${MAX_CANDIDATES}`);
  }

  const candidatesByDigest = new Map();
  const addCandidate = (bytes, sourceEncoding, operation, keyByte) => {
    const digest = createHash('sha256').update(bytes).digest('hex');
    const text = bytes.toString('utf8');
    const candidate = {
      encoding: sourceEncoding,
      operation,
      ...(keyByte === undefined ? {} : { keyByte }),
      score: readabilityScore(bytes),
      text: text.slice(0, MAX_CANDIDATE_TEXT_CHARS),
      truncated: text.length > MAX_CANDIDATE_TEXT_CHARS,
      flagLike: FLAG_PATTERN.test(text),
    };
    const previous = candidatesByDigest.get(digest);
    if (!previous || Number(candidate.flagLike) > Number(previous.flagLike)
      || (candidate.flagLike === previous.flagLike && candidate.score > previous.score)) {
      candidatesByDigest.set(digest, candidate);
    }
  };

  const decodedInputs = decodeCryptoInput(value, encoding);
  for (const decoded of decodedInputs) {
    addCandidate(decoded.bytes, decoded.encoding, 'decode');
    if (!includeSingleByteXor) continue;
    for (let keyByte = 1; keyByte < 256; keyByte += 1) {
      const transformed = Buffer.allocUnsafe(decoded.bytes.length);
      for (let index = 0; index < decoded.bytes.length; index += 1) {
        transformed[index] = decoded.bytes[index] ^ keyByte;
      }
      if (readabilityScore(transformed) >= 0.65) {
        addCandidate(transformed, decoded.encoding, 'single-byte-xor', keyByte);
      }
    }
  }

  const ranked = [...candidatesByDigest.values()].sort((left, right) => (
    Number(right.flagLike) - Number(left.flagLike)
      || right.score - left.score
      || left.encoding.localeCompare(right.encoding)
      || (left.keyByte ?? 0) - (right.keyByte ?? 0)
  ));
  const selected = ranked.slice(0, limit).map(({ flagLike, ...candidate }) => candidate);
  return {
    inputBytes,
    candidates: selected,
    omittedCandidates: Math.max(0, ranked.length - selected.length),
  };
}

export function buildSmtCommand({ smtlib, timeoutMs = 30_000 } = {}) {
  if (typeof smtlib !== 'string' || smtlib.trim() === '') throw new TypeError('smtlib must be non-empty text');
  const input = Buffer.from(smtlib, 'utf8');
  if (input.length > MAX_SMT_BYTES) throw new RangeError(`SMT-LIB input exceeds the ${MAX_SMT_BYTES}-byte limit`);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) {
    throw new RangeError('timeoutMs must be from 1 to 120000');
  }
  return { executable: 'z3', args: ['-in'], input, timeoutMs, maxOutputBytes: 1_048_576 };
}

function toolError(error) {
  return {
    isError: true,
    content: [{
      type: 'text',
      text: JSON.stringify({ code: error?.code ?? 'CTF_TOOL_ERROR', message: error instanceof Error ? error.message : String(error) }),
    }],
  };
}

export function registerLocalTools(server, { runWslTool = defaultRunWslTool } = {}) {
  server.registerTool(
    'ctf_crypto_candidates',
    {
      description: 'Try bounded common decodings and rank single-byte XOR candidates offline; scores are heuristic.',
      inputSchema: z.object({
        value: z.string().min(1).max(MAX_CRYPTO_CANDIDATE_BYTES),
        encoding: z.enum(['auto', 'text', 'hex', 'base64', 'url']).optional(),
        includeSingleByteXor: z.boolean().optional(),
        limit: z.number().int().min(1).max(MAX_CANDIDATES).optional(),
      }),
    },
    async (input) => {
      try {
        return { content: [{ type: 'text', text: JSON.stringify(buildCryptoCandidates(input)) }] };
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    'ctf_decode',
    {
      description: 'Decode one bounded CTF value using a named local encoding operation.',
      inputSchema: z.object({
        encoding: z.enum(['base64', 'hex', 'url', 'rot13', 'xor-byte']),
        value: z.string().max(MAX_DECODE_BYTES),
        key: z.number().int().min(0).max(255).optional(),
      }),
    },
    async (input) => {
      try {
        return { content: [{ type: 'text', text: JSON.stringify(decodeCtfValue(input)) }] };
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    'ctf_smt_solve',
    {
      description: 'Run bounded SMT-LIB through Z3 stdin; does not execute arbitrary Python or shell code.',
      inputSchema: z.object({
        smtlib: z.string().min(1).max(MAX_SMT_BYTES),
        timeoutMs: z.number().int().min(1).max(120_000).optional(),
      }),
    },
    async (input) => {
      try {
        const command = buildSmtCommand(input);
        const result = await runWslTool(command.executable, command.args, command);
        return {
          isError: result.exitCode !== 0 || result.timedOut || result.truncated,
          content: [{ type: 'text', text: JSON.stringify(result) }],
        };
      } catch (error) {
        return toolError(error);
      }
    },
  );
}
