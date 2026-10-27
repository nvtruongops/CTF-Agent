import { execFileSync } from 'node:child_process';

export function nativePath(value) {
  if (typeof value !== 'string' || value.includes('\0')) throw new TypeError('path must be NUL-free text');
  if (/^(?:\\\\|\/\/)/.test(value)) throw new TypeError('UNC/network paths are not supported; use a local drive.');
  if (process.platform === 'linux' && /^[a-z]:[\\/]/i.test(value)) {
    return execFileSync('/usr/bin/wslpath', ['-a', '-u', value], { encoding: 'utf8', timeout: 5000, maxBuffer: 8192 }).trim();
  }
  if (process.platform === 'linux' && value.includes('\\')) throw new TypeError('Windows-relative paths require forward slashes, for example ./challenge-inputs.');
  return value;
}
