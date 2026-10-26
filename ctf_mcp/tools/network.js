import { assertHostAllowed, assertTargetAllowed, assertWorkspacePath } from '../scope.js';
import { loadScope } from '../scope.js';
import { runWslTool as defaultRunWslTool } from '../wsl.js';
import { runWorkspaceWorker, workspaceCommandResult } from './workspace-command.js';
import * as z from 'zod/v4';

export function parseCurlOutput(output) {
  const text = String(output ?? '');
  const marker = '\nCTF_MCP_META:';
  const markerIndex = text.lastIndexOf(marker);
  if (markerIndex < 0) throw new Error('curl output is missing its response metadata marker');

  const metadataLine = text.slice(markerIndex + marker.length).split(/\r?\n/, 1)[0];
  const separator = metadataLine.indexOf('\t');
  const statusText = separator < 0 ? metadataLine : metadataLine.slice(0, separator);
  const contentType = separator < 0 ? '' : metadataLine.slice(separator + 1);
  if (!/^\d{3}$/.test(statusText)) throw new Error('curl response metadata has an invalid status');

  return {
    status: Number(statusText),
    contentType,
    body: text.slice(0, markerIndex),
  };
}

const MAX_TEXT_BODY_BYTES = 65_536;
const MAX_HTTP_HEADERS = 32;
const MAX_HTTP_HEADER_NAME_BYTES = 128;
const MAX_HTTP_HEADER_VALUE_BYTES = 8_192;
const MAX_HTTP_HEADERS_BYTES = 16_384;
const HTTP_HEADER_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const RESERVED_HTTP_HEADERS = new Set(['host', 'content-length', 'transfer-encoding', 'content-type']);

function checkedHttpHeaders(headers) {
  if (headers === undefined) return [];
  if (headers === null || typeof headers !== 'object' || Array.isArray(headers)) {
    throw new TypeError('headers must be a string record');
  }

  const entries = Object.entries(headers);
  if (entries.length > MAX_HTTP_HEADERS) throw new RangeError(`HTTP header count exceeds ${MAX_HTTP_HEADERS}`);

  let totalBytes = 0;
  return entries.map(([name, value]) => {
    if (!HTTP_HEADER_NAME_PATTERN.test(name)) throw new TypeError('invalid HTTP header name');
    const nameBytes = Buffer.byteLength(name, 'utf8');
    if (nameBytes > MAX_HTTP_HEADER_NAME_BYTES) {
      throw new RangeError(`HTTP header name exceeds ${MAX_HTTP_HEADER_NAME_BYTES} UTF-8 bytes`);
    }
    if (RESERVED_HTTP_HEADERS.has(name.toLowerCase())) throw new TypeError(`HTTP header ${name} cannot be set`);
    if (typeof value !== 'string') throw new TypeError('HTTP header value must be a string');
    if (/[\r\n\0]/.test(value)) throw new TypeError('HTTP header value cannot contain CR, LF, or NUL');

    const valueBytes = Buffer.byteLength(value, 'utf8');
    if (valueBytes > MAX_HTTP_HEADER_VALUE_BYTES) {
      throw new RangeError(`HTTP header value exceeds ${MAX_HTTP_HEADER_VALUE_BYTES} UTF-8 bytes`);
    }
    totalBytes += nameBytes + valueBytes + 4;
    if (totalBytes > MAX_HTTP_HEADERS_BYTES) {
      throw new RangeError(`HTTP headers exceed the ${MAX_HTTP_HEADERS_BYTES}-byte aggregate limit`);
    }
    return [name, value];
  });
}

function validHttpHeaders(headers) {
  try {
    checkedHttpHeaders(headers);
    return true;
  } catch {
    return false;
  }
}

const HTTP_HEADERS_SCHEMA = z.record(z.string(), z.string())
  .optional()
  .refine(validHttpHeaders);

function checkedHttpUrl(value, scope) {
  if (typeof value !== 'string') throw new TypeError('url must be a string');
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError('url must be a valid HTTP or HTTPS URL');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new TypeError('only HTTP and HTTPS URLs are supported');
  if (url.username || url.password || url.hash) throw new TypeError('URL credentials and fragments are not allowed');
  assertTargetAllowed(url.href, scope);
  return url;
}

function safeParameter(value) {
  if (typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(value)) {
    throw new TypeError('parameter must be a plain parameter name');
  }
  return value;
}

function command(executable, args, timeoutMs, maxOutputBytes, input) {
  return { executable, args, timeoutMs, maxOutputBytes, ...(input === undefined ? {} : { input }) };
}

export function buildNmapCommand({ target, serviceDetection = true } = {}, scope) {
  const parsed = assertTargetAllowed(target, scope);
  const args = ['-sT', '-Pn', '-n', '-T3', '-p', String(parsed.port)];
  if (serviceDetection) args.push('-sV');
  args.push(parsed.host);
  return command('nmap', args, 120_000, 1_048_576);
}

export function buildSqlmapCommand({ url: value, parameter, level = 1, risk = 1 } = {}, scope) {
  const url = checkedHttpUrl(value, scope);
  const checkedParameter = safeParameter(parameter);
  if (!Number.isInteger(level) || level < 1 || level > 5) throw new RangeError('level must be an integer from 1 to 5');
  if (!Number.isInteger(risk) || risk < 1 || risk > 3) throw new RangeError('risk must be an integer from 1 to 3');

  const outputDirectory = `${scope.wslWorkspace}/sqlmap`;
  return {
    ...command('sqlmap', [
      '-u', url.href,
      '-p', checkedParameter,
      '--batch',
      '--ignore-redirects',
      `--risk=${risk}`,
      `--level=${level}`,
      '--threads=1',
      '--timeout=5',
      '--retries=1',
      '--time-limit=120',
      '--output-dir', outputDirectory,
    ], 125_000, 1_048_576),
    workspace: scope.wslWorkspace,
    directoryPaths: [outputDirectory],
  };
}

export function buildFfufCommand({ urlTemplate, wordlistPath } = {}, scope) {
  if (typeof urlTemplate !== 'string' || (urlTemplate.match(/FUZZ/g) ?? []).length !== 1) {
    throw new TypeError('urlTemplate must contain exactly one FUZZ marker');
  }
  checkedHttpUrl(urlTemplate.replace('FUZZ', 'ctf-agent-probe'), scope);
  const wordlist = assertWorkspacePath(wordlistPath, scope);
  return {
    ...command('ffuf', [
      '-u', urlTemplate,
      '-w', wordlist,
      '-t', '10',
      '-rate', '50',
      '-s',
      '-maxtime', '120',
    ], 125_000, 1_048_576),
    workspace: scope.wslWorkspace,
    filePaths: [wordlist],
  };
}

export function buildHydraAuditCommand({ target, service, username, passwordListPath, confirmAuthorized } = {}, scope) {
  if (confirmAuthorized !== true) throw new TypeError('confirmAuthorized must be true for an authorized Hydra audit');
  if (!['ssh', 'ftp'].includes(service)) throw new TypeError('service must be ssh or ftp');
  if (typeof username !== 'string' || !/^[^\u0000-\u001f\u007f]{1,64}$/u.test(username)) {
    throw new TypeError('username must be 1 to 64 characters without control characters');
  }
  if (typeof target !== 'string' || target.trim() !== target || /^https?:\/\//i.test(target)) {
    throw new TypeError('target must be an explicit host:port string');
  }
  const parsed = assertTargetAllowed(target, scope);
  const wordlist = assertWorkspacePath(passwordListPath, scope);
  const args = [
    ...(parsed.host.includes(':') ? ['-6'] : []),
    '-I', '-f', '-t', '1', '-c', '1', '-s', String(parsed.port),
    '-l', username, '-P', wordlist, parsed.host, service,
  ];
  return {
    ...command('hydra', args, 30_000, 262_144),
    workspace: scope.wslWorkspace,
    filePaths: [wordlist],
    temporaryWorkingDirectory: true,
  };
}

export function buildCurlCommand({ url: value, method = 'GET', body, bodyFormat = 'text', headers } = {}, scope) {
  const url = checkedHttpUrl(value, scope);
  const checkedHeaders = checkedHttpHeaders(headers);
  const checkedMethod = String(method).toUpperCase();
  if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(checkedMethod)) {
    throw new TypeError('method must be GET, HEAD, POST, PUT, PATCH, or DELETE');
  }
  if (body !== undefined && typeof body !== 'string') throw new TypeError('body must be text');
  if (body !== undefined && Buffer.byteLength(body, 'utf8') > MAX_TEXT_BODY_BYTES) {
    throw new RangeError(`body exceeds the ${MAX_TEXT_BODY_BYTES}-byte limit`);
  }
  if (body !== undefined && ['GET', 'HEAD'].includes(checkedMethod)) {
    throw new TypeError(`${checkedMethod} requests cannot include a body`);
  }

  const args = [
    '--disable', '--silent', '--show-error',
    '--max-time', '30', '--max-redirs', '0', '--proto', '=http,https',
    '--request', checkedMethod,
    '--write-out', '\nCTF_MCP_META:%{http_code}\t%{content_type}\n',
  ];
  if (body !== undefined) {
    const contentType = {
      json: 'application/json',
      form: 'application/x-www-form-urlencoded',
      text: 'text/plain',
    }[bodyFormat];
    if (!contentType) throw new TypeError('bodyFormat must be json, form, or text');
    args.push('--header', `Content-Type: ${contentType}`, '--data-binary', '@-');
  }
  for (const [name, value] of checkedHeaders) args.push('--header', `${name}: ${value}`);
  args.push('--url', url.href);
  return command('curl', args, 35_000, 1_048_576, body === undefined ? undefined : Buffer.from(body));
}

export function buildNcatCommand({ target, input = '' } = {}, scope) {
  const parsed = assertTargetAllowed(target, scope);
  if (typeof input !== 'string' && !Buffer.isBuffer(input)) throw new TypeError('input must be text or bytes');
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  if (bytes.length > MAX_TEXT_BODY_BYTES) throw new RangeError(`input exceeds the ${MAX_TEXT_BODY_BYTES}-byte limit`);
  return command('ncat', ['-w', '10', parsed.host, String(parsed.port)], 15_000, 262_144, bytes);
}

export function buildDnsCommand({ domain, recordType = 'A' } = {}, scope) {
  const host = assertHostAllowed(domain, scope);
  const checkedType = String(recordType).toUpperCase();
  if (!['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT'].includes(checkedType)) {
    throw new TypeError('recordType is not supported');
  }
  return command('dig', ['+time=3', '+tries=1', host, checkedType], 10_000, 262_144);
}

export function buildWhoisCommand({ domainOrIp } = {}, scope) {
  const host = assertHostAllowed(domainOrIp, scope);
  return command('whois', [host], 15_000, 262_144);
}

export async function executeNetworkCommand(toolId, input, scope, runWslTool = defaultRunWslTool) {
  const builders = {
    ctf_nmap_scan: buildNmapCommand,
    ctf_sqlmap_test: buildSqlmapCommand,
    ctf_ffuf_discover: buildFfufCommand,
    ctf_hydra_audit: buildHydraAuditCommand,
    ctf_scoped_http_request: buildCurlCommand,
    ctf_scoped_tcp_exchange: buildNcatCommand,
    ctf_dns_lookup: buildDnsCommand,
    ctf_whois_lookup: buildWhoisCommand,
  };
  const builder = builders[toolId];
  if (!builder) throw new TypeError(`unknown network tool: ${toolId}`);

  const built = builder(input, scope);
  const result = built.filePaths || built.directoryPaths
    ? workspaceCommandResult(await runWorkspaceWorker({ ...built, mode: 'command' }, runWslTool, built))
    : await runWslTool(built.executable, built.args, {
      input: built.input,
      timeoutMs: built.timeoutMs,
      maxOutputBytes: built.maxOutputBytes,
    });

  if (toolId === 'ctf_hydra_audit' && result.exitCode === 127 && result.executable === 'hydra'
    && /No such file or directory/i.test(result.stderr ?? '')) {
    return {
      toolId,
      ...result,
      error: 'Hydra is unavailable; install it with setup --apply --profile exploitation.',
    };
  }

  if (toolId !== 'ctf_scoped_http_request') return { toolId, ...result };
  if (result.timedOut || result.truncated) {
    return {
      toolId,
      ...result,
      status: null,
      contentType: null,
      body: result.stdout,
      partialResponse: true,
    };
  }
  try {
    return { toolId, ...result, ...parseCurlOutput(result.stdout), partialResponse: false };
  } catch (error) {
    return {
      toolId,
      ...result,
      status: null,
      contentType: null,
      body: result.stdout,
      parseError: error instanceof Error ? error.message : String(error),
      partialResponse: true,
    };
  }
}

function toolError(error) {
  const code = error?.code ?? 'CTF_TOOL_ERROR';
  const message = error instanceof Error ? error.message : String(error);
  return {
    isError: true,
    content: [{ type: 'text', text: JSON.stringify({ code, message }) }],
  };
}

function registerNetworkTool(server, name, description, schema, handler) {
  server.registerTool(name, { description, inputSchema: schema }, async (input) => {
    try {
      return await handler(input);
    } catch (error) {
      return toolError(error);
    }
  });
}

export function registerNetworkTools(server, { projectRoot, runWslTool } = {}) {
  const scope = () => loadScope(projectRoot);
  const call = (toolId) => async (input) => {
    const result = await executeNetworkCommand(toolId, input, scope(), runWslTool);
    return {
      isError: result.exitCode !== 0 || result.timedOut || result.truncated,
      content: [{ type: 'text', text: JSON.stringify(result) }],
    };
  };

  registerNetworkTool(
    server,
    'ctf_nmap_scan',
    'Scan one explicitly scoped CTF host and port with a TCP connect scan.',
    z.object({ target: z.string().min(1).max(255), serviceDetection: z.boolean().optional() }),
    call('ctf_nmap_scan'),
  );
  registerNetworkTool(
    server,
    'ctf_sqlmap_test',
    'Test one explicitly scoped URL parameter with bounded SQL injection checks.',
    z.object({
      url: z.string().url().max(2048),
      parameter: z.string().min(1).max(64),
      level: z.number().int().min(1).max(5).optional(),
      risk: z.number().int().min(1).max(3).optional(),
    }),
    call('ctf_sqlmap_test'),
  );
  registerNetworkTool(
    server,
    'ctf_ffuf_discover',
    'Fuzz one in-scope URL template with FUZZ and a workspace wordlist.',
    z.object({ urlTemplate: z.string().min(1).max(2048), wordlistPath: z.string().min(1).max(2048) }),
    call('ctf_ffuf_discover'),
  );
  registerNetworkTool(
    server,
    'ctf_hydra_audit',
    'Audit one explicitly authorized in-scope SSH/FTP login against one workspace password list; one task, one-second per-attempt delay, first-hit stop, and 30-second timeout.',
    z.object({
      target: z.string().min(1).max(255),
      service: z.enum(['ssh', 'ftp']),
      username: z.string().min(1).max(64).refine((value) => !/[\u0000-\u001f\u007f]/u.test(value)),
      passwordListPath: z.string().min(1).max(2048),
      confirmAuthorized: z.literal(true),
    }),
    call('ctf_hydra_audit'),
  );
  registerNetworkTool(
    server,
    'ctf_scoped_http_request',
    'Send one bounded HTTP request to an explicitly scoped challenge target without following redirects.',
    z.object({
      url: z.string().url().max(2048),
      method: z.enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']).optional(),
      body: z.string().max(MAX_TEXT_BODY_BYTES).optional(),
      bodyFormat: z.enum(['json', 'form', 'text']).optional(),
      headers: HTTP_HEADERS_SCHEMA,
    }),
    call('ctf_scoped_http_request'),
  );
  registerNetworkTool(
    server,
    'ctf_scoped_tcp_exchange',
    'Exchange bounded text with one explicitly scoped CTF host and port.',
    z.object({ target: z.string().min(1).max(255), input: z.string().max(MAX_TEXT_BODY_BYTES).optional() }),
    call('ctf_scoped_tcp_exchange'),
  );
  registerNetworkTool(
    server,
    'ctf_dns_lookup',
    'Perform a bounded passive DNS lookup for an explicitly scoped challenge host.',
    z.object({
      domain: z.string().min(1).max(253),
      recordType: z.enum(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT']).optional(),
    }),
    call('ctf_dns_lookup'),
  );
  registerNetworkTool(
    server,
    'ctf_whois_lookup',
    'Perform a bounded WHOIS lookup for an explicitly scoped challenge host.',
    z.object({ domainOrIp: z.string().min(1).max(253) }),
    call('ctf_whois_lookup'),
  );
}
