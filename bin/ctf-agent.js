#!/usr/bin/env node
/**
 * CTF-Agent Node.js & NPX Launcher
 * Zero-dependency bridge from npm/npx ecosystems to CTF-Agent initialization engine.
 */

const { spawn, spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');

function findPython() {
  const candidates = process.platform === 'win32'
    ? ['python', 'py', 'python3']
    : ['python3', 'python'];

  for (const cmd of candidates) {
    try {
      const res = spawnSync(cmd, ['--version'], {
        encoding: 'utf-8',
        timeout: 3000,
        stdio: ['ignore', 'pipe', 'pipe']
      });
      if (res.status === 0 && (res.stdout || res.stderr)) {
        return cmd;
      }
    } catch (e) {
      // Continue search
    }
  }
  return null;
}

function main() {
  const args = process.argv.slice(2);

  // Check version flag directly
  if (args.length === 1 && (args[0] === '-v' || args[0] === '--version')) {
    const pkgPath = path.join(__dirname, '..', 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      console.log(`ctf-agent v${pkg.version || '1.0.0'}`);
      process.exit(0);
    }
  }

  const pythonBin = findPython();
  if (!pythonBin) {
    console.error('=================================================================');
    console.error('ERROR: Python 3 runtime not found on your system.');
    console.error('-----------------------------------------------------------------');
    console.error('CTF-Agent requires Python 3 (>= 3.9) to execute security tools,');
    console.error('preflight checks, and agent orchestration.');
    console.error('');
    console.error('Installation instructions:');
    if (process.platform === 'win32') {
      console.error('  Windows: Install from https://www.python.org/ or winget:');
      console.error('           winget install Python.Python.3.12');
    } else if (process.platform === 'darwin') {
      console.error('  macOS:   Install via Homebrew:');
      console.error('           brew install python3');
    } else {
      console.error('  Linux:   Install via package manager:');
      console.error('           sudo apt-get install python3 python3-pip');
    }
    console.error('=================================================================');
    process.exit(1);
  }

  const scriptPath = path.join(__dirname, '..', 'scripts', 'ctf_init.py');
  if (!fs.existsSync(scriptPath)) {
    console.error(`ERROR: Initialization script not found at ${scriptPath}`);
    process.exit(1);
  }

  // Normalize arguments: if first argument is "init", strip it for ctf_init.py
  let forwardArgs = [scriptPath];
  if (args.length > 0 && args[0] === 'init') {
    forwardArgs = forwardArgs.concat(args.slice(1));
  } else {
    forwardArgs = forwardArgs.concat(args);
  }

  const child = spawn(pythonBin, forwardArgs, {
    stdio: 'inherit',
    windowsHide: false
  });

  child.on('error', (err) => {
    console.error(`ERROR: Failed to launch python process: ${err.message}`);
    process.exit(1);
  });

  child.on('close', (code) => {
    process.exit(code !== null ? code : 0);
  });
}

main();
