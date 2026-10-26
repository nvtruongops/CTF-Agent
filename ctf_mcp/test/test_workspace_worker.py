import base64
import hashlib
import io
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from ctf_mcp.tools import workspace_worker


FD_PATH = '/proc/self/fd/17'


def _pcap_with_http_stream():
    client_ip = socket.inet_aton('192.0.2.10')
    server_ip = socket.inet_aton('192.0.2.20')
    client_port = 12345
    server_port = 80

    def packet(source_ip, destination_ip, source_port, destination_port, sequence, acknowledgement, flags, payload):
        tcp = struct.pack(
            '!HHLLBBHHH', source_port, destination_port, sequence, acknowledgement,
            0x50, flags, 65535, 0, 0,
        ) + payload
        total_length = 20 + len(tcp)
        ipv4 = struct.pack(
            '!BBHHHBBH4s4s', 0x45, 0, total_length, 1, 0x4000, 64, 6, 0,
            source_ip, destination_ip,
        )
        ethernet = b'\x00' * 12 + b'\x08\x00'
        frame = ethernet + ipv4 + tcp
        return frame

    request = b'GET /flag HTTP/1.1\r\nHost: challenge\r\n\r\n'
    response = b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nflag{ok}'
    frames = [
        packet(client_ip, server_ip, client_port, server_port, 100, 0, 0x02, b''),
        packet(server_ip, client_ip, server_port, client_port, 200, 101, 0x12, b''),
        packet(client_ip, server_ip, client_port, server_port, 101, 201, 0x10, b''),
        packet(client_ip, server_ip, client_port, server_port, 101, 201, 0x18, request),
        packet(server_ip, client_ip, server_port, client_port, 201, 101 + len(request), 0x18, response),
    ]
    pcap = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for timestamp, frame in enumerate(frames, start=1):
        pcap.extend(struct.pack('<IIII', timestamp, 0, len(frame), len(frame)))
        pcap.extend(frame)
    return bytes(pcap)


def _steghide_request(workspace, artifact, output, passphrase='secret', **overrides):
    request = {
        'mode': 'steghide_extract',
        'workspace': workspace,
        'artifactPath': str(artifact),
        'outputPath': str(output),
        'passphrase': passphrase,
        'timeoutMs': 60_000,
        'maxOutputBytes': 262_144,
    }
    request.update(overrides)
    return request


def _stegseek_request(workspace, artifact, wordlist, output, **overrides):
    request = {
        'mode': 'stegseek_extract',
        'workspace': workspace,
        'artifactPath': str(artifact),
        'wordlistPath': str(wordlist),
        'outputPath': str(output),
        'timeoutMs': 60_000,
        'maxOutputBytes': 262_144,
        'maxFileBytes': 64 * 1024 * 1024,
    }
    request.update(overrides)
    return request


def _fake_steghide(payload=b'', exit_code=0, delay=0, stderr=b''):
    command = []
    script = (
        'import sys,time\n'
        f'time.sleep({delay!r})\n'
        f"sys.stdout.buffer.write(bytes.fromhex('{payload.hex()}'))\n"
        f"sys.stderr.buffer.write(bytes.fromhex('{stderr.hex()}'))\n"
        'sys.stdout.flush()\n'
        f'sys.exit({exit_code})\n'
    )

    def popen(argv, **options):
        command.extend(argv)
        return subprocess.Popen([sys.executable, '-c', script], **options)

    return popen, command


def _fake_stegseek(payload=b'', exit_code=0, delay=0):
    command = []

    def popen(argv, **options):
        command.extend(argv)
        output_path = argv[argv.index('-xf') + 1]
        script = (
            'import pathlib,time\n'
            f'time.sleep({delay!r})\n'
            f"pathlib.Path({output_path!r}).write_bytes(bytes.fromhex('{payload.hex()}'))\n"
            f'exit({exit_code})\n'
        )
        return subprocess.Popen([sys.executable, '-c', script], **options)

    return popen, command


class WorkspaceWorkerTests(unittest.TestCase):
    def test_inspect_mode_uses_only_fixed_commands_and_a_descriptor_path(self):
        commands = workspace_worker.commands_for({'mode': 'inspect'}, FD_PATH)

        self.assertEqual([command[0] for command in commands], ['file', 'readelf', 'strings'])
        self.assertEqual(commands[0][1], ['-L', '--', FD_PATH])
        self.assertEqual(commands[1][1], ['-h', '-W', '-S', '-s', '--', FD_PATH])
        self.assertEqual(commands[2][1], ['-a', '-t', 'x', '-n', '4', '--', FD_PATH])
        self.assertTrue(all(command[2] == 100_000 for command in commands))

    def test_disassembly_and_gdb_modes_use_fixed_arguments_and_validate_symbols(self):
        disassembly = workspace_worker.commands_for({'mode': 'disassemble', 'symbol': 'main'}, FD_PATH)
        gdb_info = workspace_worker.commands_for({'mode': 'gdb_info', 'symbol': '_start'}, FD_PATH)

        self.assertEqual(disassembly[0][1], ['-d', '-M', 'intel', '--disassemble=main', '--', FD_PATH])
        self.assertEqual(gdb_info[0][1], [
            '--batch', '--nx', '--quiet', '-iex', 'set auto-load off',
            '-ex', 'set debuginfod enabled off', '-ex', 'info files', '-ex', 'info functions',
            '-ex', 'disassemble _start', FD_PATH,
        ])
        with patch.object(workspace_worker.os.path, 'isfile', return_value=True):
            with self.assertRaisesRegex(ValueError, 'symbol'):
                workspace_worker.validate_request({
                    'mode': 'gdb_info',
                    'workspace': '/home/ctfagent/ctf-workspaces/chal1',
                    'artifactPath': '/home/ctfagent/ctf-workspaces/chal1/game',
                    'symbol': 'main;quit',
                })

    def test_artifact_path_segments_must_be_strictly_inside_workspace(self):
        workspace = '/home/ctfagent/ctf-workspaces/chal1'

        self.assertEqual(workspace_worker.artifact_segments(workspace, f'{workspace}/bin/challenge'), ['bin', 'challenge'])
        with self.assertRaisesRegex(ValueError, 'workspace'):
            workspace_worker.artifact_segments(workspace, '/home/ctfagent/.ssh/id_rsa')
        with self.assertRaisesRegex(ValueError, 'workspace'):
            workspace_worker.artifact_segments(workspace, f'{workspace}/../.ssh/id_rsa')

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_openat_reads_only_regular_workspace_files_and_rejects_symlinks(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        os.makedirs(workspace_base, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='reverse-worker-', dir=workspace_base) as workspace:
            regular_file = Path(workspace) / 'challenge.bin'
            regular_file.write_bytes(b'ELF-like fixture bytes')
            fd = workspace_worker.open_workspace_artifact(workspace, str(regular_file))
            try:
                self.assertEqual(os.read(fd, 64), b'ELF-like fixture bytes')
            finally:
                os.close(fd)

            outside_file = Path(workspace) / 'outside-link'
            outside_file.symlink_to('/etc/passwd')
            with self.assertRaisesRegex(PermissionError, 'symlink'):
                workspace_worker.open_workspace_artifact(workspace, str(outside_file))

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_worker_executes_fixed_inspection_commands_using_the_open_descriptor(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        os.makedirs(workspace_base, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='reverse-worker-', dir=workspace_base) as workspace:
            artifact = Path(workspace) / 'fixture.txt'
            artifact.write_text('CTF sample string\n', encoding='utf-8')
            result = workspace_worker.execute({
                'mode': 'inspect',
                'workspace': workspace,
                'artifactPath': str(artifact),
            })

        self.assertEqual([item['executable'] for item in result['observations']], ['file', 'readelf', 'strings'])
        self.assertIn('ASCII text', base64.b64decode(result['observations'][0]['stdoutBase64']).decode('utf-8'))
        self.assertNotEqual(result['observations'][1]['exitCode'], 0)
        self.assertIn('CTF sample string', base64.b64decode(result['observations'][2]['stdoutBase64']).decode('utf-8'))

    @unittest.skipUnless(shutil.which('tshark'), 'requires the installed TShark executable')
    def test_tshark_follow_stream_reads_workspace_pcap_through_descriptor(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-pcap-', dir=workspace_base) as workspace:
            capture = Path(workspace) / 'stream.pcap'
            capture.write_bytes(_pcap_with_http_stream())
            result = workspace_worker.execute({
                'mode': 'command',
                'workspace': workspace,
                'executable': 'tshark',
                'args': ['-r', str(capture), '-q', '-z', 'follow,tcp,ascii,0'],
                'filePaths': [str(capture)],
                'timeoutMs': 10_000,
                'maxOutputBytes': 65_536,
            })

        output = base64.b64decode(result['stdoutBase64']).decode('utf-8', errors='replace')
        self.assertEqual(result['exitCode'], 0, result['stderrBase64'])
        self.assertIn('GET /flag HTTP/1.1', output)
        self.assertIn('flag{ok}', output)

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_command_mode_uses_open_descriptor_for_path_arguments(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-worker-', dir=workspace_base) as workspace:
            artifact = Path(workspace) / 'sample.txt'
            artifact.write_text('CTF_WORKER_DESCRIPTOR_SENTINEL\n', encoding='utf-8')
            result = workspace_worker.execute({
                'mode': 'command',
                'workspace': workspace,
                'executable': 'strings',
                'args': ['-a', '-n', '4', str(artifact)],
                'filePaths': [str(artifact)],
                'timeoutMs': 5_000,
                'maxOutputBytes': 65_536,
            })

        output = base64.b64decode(result['stdoutBase64']).decode('utf-8')
        self.assertEqual(result['exitCode'], 0)
        self.assertIn('CTF_WORKER_DESCRIPTOR_SENTINEL', output)

    def test_command_mode_rejects_unscoped_absolute_option_values(self):
        with self.assertRaisesRegex(ValueError, 'absolute argv paths'):
            workspace_worker.validate_request({
                'mode': 'command',
                'workspace': f'{workspace_worker.WORKSPACE_BASE}/rev-01',
                'executable': 'checksec',
                'args': ['--file=/etc/passwd'],
                'filePaths': [],
                'directoryPaths': [],
                'timeoutMs': 1_000,
                'maxOutputBytes': 1_024,
            })

    def test_john_command_requires_an_ephemeral_session_and_workspace_inputs(self):
        workspace = f'{workspace_worker.WORKSPACE_BASE}/rev-01'
        hash_path = f'{workspace}/hashes.txt'
        wordlist_path = f'{workspace}/words.txt'
        request = {
            'mode': 'command',
            'workspace': workspace,
            'executable': 'john',
            'args': [
                '--wordlist', wordlist_path, '--pot=/dev/null', '--no-log',
                '--max-run-time=30', '--session=@ctf-agent-ephemeral', hash_path,
            ],
            'filePaths': [hash_path, wordlist_path],
            'directoryPaths': [],
            'timeoutMs': 30_000,
            'maxOutputBytes': 262_144,
            'ephemeralSession': True,
        }

        validated = workspace_worker.validate_request(request)
        self.assertTrue(validated['ephemeralSession'])
        with self.assertRaisesRegex(ValueError, 'ephemeralSession'):
            workspace_worker.validate_request({**request, 'ephemeralSession': False})

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_john_session_files_are_created_only_in_a_cleaned_temporary_directory(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        session_paths = []

        def popen(argv, **options):
            session_arg = next(arg for arg in argv if arg.startswith('--session='))
            session_path = session_arg.split('=', 1)[1]
            session_paths.append(session_path)
            script = (
                'from pathlib import Path\n'
                f"Path({(session_path + '.rec')!r}).write_text('temporary', encoding='utf-8')\n"
            )
            return subprocess.Popen([sys.executable, '-c', script], **options)

        with tempfile.TemporaryDirectory(prefix='workspace-john-', dir=workspace_base) as workspace:
            hashes = Path(workspace) / 'hashes.txt'
            wordlist = Path(workspace) / 'words.txt'
            hashes.write_text('hash fixture\n', encoding='utf-8')
            wordlist.write_text('candidate\n', encoding='utf-8')
            result = workspace_worker.execute({
                'mode': 'command',
                'workspace': workspace,
                'executable': 'john',
                'args': [
                    '--wordlist', str(wordlist), '--pot=/dev/null', '--no-log',
                    '--max-run-time=30', '--session=@ctf-agent-ephemeral', str(hashes),
                ],
                'filePaths': [str(hashes), str(wordlist)],
                'directoryPaths': [],
                'timeoutMs': 30_000,
                'maxOutputBytes': 262_144,
                'ephemeralSession': True,
            }, popen=popen)

            self.assertEqual(result['exitCode'], 0)
            self.assertEqual(len(session_paths), 1)
            self.assertNotEqual(session_paths[0], '@ctf-agent-ephemeral')
            self.assertFalse(Path(session_paths[0] + '.rec').exists())

    def test_hydra_command_requires_a_temporary_working_directory(self):
        workspace = f'{workspace_worker.WORKSPACE_BASE}/rev-01'
        wordlist = f'{workspace}/words.txt'
        request = {
            'mode': 'command',
            'workspace': workspace,
            'executable': 'hydra',
            'args': ['-I', '-f', '-t', '1', '-c', '1', '-s', '1337', '-l', 'ctf', '-P', wordlist, 'pwn.example', 'ssh'],
            'filePaths': [wordlist],
            'directoryPaths': [],
            'timeoutMs': 30_000,
            'maxOutputBytes': 262_144,
            'temporaryWorkingDirectory': True,
        }

        self.assertTrue(workspace_worker.validate_request(request)['temporaryWorkingDirectory'])
        with self.assertRaisesRegex(ValueError, 'temporaryWorkingDirectory'):
            workspace_worker.validate_request({**request, 'temporaryWorkingDirectory': False})

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_hydra_runs_with_proxy_environment_removed_in_a_cleaned_working_directory(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        observed = {}

        def popen(argv, **options):
            observed.update(argv=argv, cwd=options.get('cwd'), env=options.get('env'))
            script = "from pathlib import Path; Path('hydra.restore').write_text('temporary'); print('finished')"
            return subprocess.Popen([sys.executable, '-c', script], **options)

        with tempfile.TemporaryDirectory(prefix='workspace-hydra-', dir=workspace_base) as workspace:
            wordlist = Path(workspace) / 'words.txt'
            wordlist.write_text('candidate\n', encoding='utf-8')
            request = {
                'mode': 'command',
                'workspace': workspace,
                'executable': 'hydra',
                'args': ['-I', '-f', '-t', '1', '-c', '1', '-s', '1337', '-l', 'ctf', '-P', str(wordlist), 'pwn.example', 'ssh'],
                'filePaths': [str(wordlist)],
                'directoryPaths': [],
                'timeoutMs': 30_000,
                'maxOutputBytes': 262_144,
                'temporaryWorkingDirectory': True,
            }
            with patch.dict(os.environ, {
                'HYDRA_PROXY': 'socks5://127.0.0.1:1080',
                'HYDRA_PROXY_HTTP': 'http://127.0.0.1:8080',
            }):
                result = workspace_worker.execute(request, popen=popen)

        self.assertEqual(result['exitCode'], 0)
        self.assertEqual(observed['argv'][0], 'hydra')
        self.assertEqual(observed['argv'][1:7], ['-I', '-f', '-t', '1', '-c', '1'])
        self.assertEqual(observed['argv'][-2:], ['pwn.example', 'ssh'])
        password_index = observed['argv'].index('-P') + 1
        self.assertTrue(observed['argv'][password_index].startswith('/proc/self/fd/'))
        self.assertNotIn('HYDRA_PROXY', observed['env'])
        self.assertNotIn('HYDRA_PROXY_HTTP', observed['env'])
        self.assertTrue(observed['cwd'].startswith(tempfile.gettempdir()))
        self.assertFalse(Path(observed['cwd']).exists())

    @unittest.skipUnless(shutil.which('checksec'), 'requires the installed checksec executable')
    def test_checksec_can_read_a_descriptor_backed_binary(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-checksec-', dir=workspace_base) as workspace:
            artifact = Path(workspace) / 'true'
            shutil.copyfile('/usr/bin/true', artifact)
            result = workspace_worker.execute({
                'mode': 'command',
                'workspace': workspace,
                'executable': 'checksec',
                'args': [f'--file={artifact}'],
                'filePaths': [str(artifact)],
                'timeoutMs': 10_000,
                'maxOutputBytes': 65_536,
            })

        output = base64.b64decode(result['stdoutBase64']).decode('utf-8', errors='replace')
        self.assertEqual(result['exitCode'], 0, output)
        self.assertIn('NX', output)
        self.assertIn('/proc/self/fd/', output)
        self.assertNotIn(str(artifact), output)

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_execute_mode_runs_staged_binary_without_chmodding_workspace_source(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-worker-', dir=workspace_base) as workspace:
            artifact = Path(workspace) / 'cat'
            shutil.copyfile('/usr/bin/cat', artifact)
            artifact.chmod(0o600)
            original_bytes = artifact.read_bytes()
            stdin = b'private staged stdin\n'
            result = workspace_worker.execute({
                'mode': 'execute',
                'workspace': workspace,
                'artifactPath': str(artifact),
                'argv': [],
                'stdinBase64': base64.b64encode(stdin).decode('ascii'),
                'timeoutMs': 5_000,
                'maxOutputBytes': 65_536,
            })

            self.assertEqual(artifact.read_bytes(), original_bytes)
            self.assertEqual(artifact.stat().st_mode & 0o111, 0)
        self.assertEqual(result['exitCode'], 0)
        self.assertEqual(base64.b64decode(result['stdoutBase64']), stdin)

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_steghide_extract_streams_payload_to_a_private_workspace_file(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        payload = b'literal hidden payload\x00\xff'
        passphrase = 'correct horse battery staple'
        with tempfile.TemporaryDirectory(prefix='workspace-steghide-', dir=workspace_base) as workspace:
            artifact = Path(workspace) / 'cover.bmp'
            artifact.write_bytes(b'cover fixture')
            output = Path(workspace) / 'nested' / 'recovered.bin'
            popen, command = _fake_steghide(payload, stderr=passphrase.encode())

            result = workspace_worker.execute(
                _steghide_request(workspace, artifact, output, passphrase),
                popen=popen,
            )

            self.assertEqual(output.read_bytes(), payload)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result, {
                'exitCode': 0,
                'timedOut': False,
                'truncated': False,
                'outputPath': str(output),
                'bytes': len(payload),
                'sha256': hashlib.sha256(payload).hexdigest(),
            })
            self.assertNotIn(passphrase, repr(result))
            self.assertEqual(command[:2], ['steghide', 'extract'])
            self.assertEqual(command[2], '-sf')
            self.assertTrue(command[3].startswith('/proc/self/fd/'))
            self.assertEqual(command[4:], ['-xf', '-', '-p', passphrase, '-q'])
            self.assertEqual(list(Path(workspace).rglob('.ctf-steghide-*')), [])

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_steghide_extract_supports_an_empty_payload(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-steghide-', dir=workspace_base) as workspace:
            artifact = Path(workspace) / 'cover.bmp'
            artifact.write_bytes(b'cover fixture')
            output = Path(workspace) / 'empty.bin'
            popen, _ = _fake_steghide(b'')

            result = workspace_worker.execute(
                _steghide_request(workspace, artifact, output, ''),
                popen=popen,
            )

            self.assertEqual(output.read_bytes(), b'')
            self.assertEqual(result['bytes'], 0)
            self.assertEqual(result['sha256'], hashlib.sha256(b'').hexdigest())

    def test_steghide_extract_validates_scoped_paths_and_passphrase(self):
        workspace = f'{workspace_worker.WORKSPACE_BASE}/rev-01'
        artifact = f'{workspace}/cover.bmp'
        output = f'{workspace}/recovered.bin'
        valid = _steghide_request(workspace, artifact, output, '')

        self.assertEqual(workspace_worker.validate_request(valid)['passphrase'], '')
        invalid_requests = [
            ({'outputPath': artifact}, 'outputPath'),
            ({'outputPath': '/tmp/recovered.bin'}, 'workspace'),
            ({'passphrase': 'bad\0phrase'}, 'passphrase'),
            ({'passphrase': 'x' * 1025}, 'passphrase'),
            ({'passphrase': None}, 'passphrase'),
        ]
        for updates, message in invalid_requests:
            with self.subTest(updates=updates), self.assertRaisesRegex(ValueError, message):
                workspace_worker.validate_request({**valid, **updates})

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_steghide_extract_never_overwrites_an_existing_output(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-steghide-', dir=workspace_base) as workspace:
            artifact = Path(workspace) / 'cover.bmp'
            artifact.write_bytes(b'cover fixture')
            output = Path(workspace) / 'recovered.bin'
            output.write_bytes(b'keep existing bytes')
            popen, _ = _fake_steghide(b'new payload')

            with self.assertRaises(FileExistsError):
                workspace_worker.execute(_steghide_request(workspace, artifact, output), popen=popen)

            self.assertEqual(output.read_bytes(), b'keep existing bytes')
            self.assertEqual(list(Path(workspace).rglob('.ctf-steghide-*')), [])

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_steghide_extract_rejects_a_symlinked_output_parent(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-steghide-', dir=workspace_base) as workspace, \
                tempfile.TemporaryDirectory(prefix='workspace-outside-') as outside:
            artifact = Path(workspace) / 'cover.bmp'
            artifact.write_bytes(b'cover fixture')
            (Path(workspace) / 'redirect').symlink_to(outside, target_is_directory=True)
            output = Path(workspace) / 'redirect' / 'escaped.bin'
            popen, command = _fake_steghide(b'payload')

            with self.assertRaisesRegex(PermissionError, 'symlink'):
                workspace_worker.execute(_steghide_request(workspace, artifact, output), popen=popen)

            self.assertEqual(command, [])
            self.assertFalse((Path(outside) / 'escaped.bin').exists())

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_steghide_extract_cleans_up_on_process_failure_timeout_and_size_limit(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-steghide-', dir=workspace_base) as workspace:
            artifact = Path(workspace) / 'cover.bmp'
            artifact.write_bytes(b'cover fixture')
            output = Path(workspace) / 'recovered.bin'

            popen, _ = _fake_steghide(b'partial', exit_code=7)
            failed = workspace_worker.execute(_steghide_request(workspace, artifact, output), popen=popen)
            self.assertEqual(failed['exitCode'], 7)
            self.assertNotIn('outputPath', failed)
            self.assertFalse(output.exists())

            popen, _ = _fake_steghide(delay=0.5)
            timed_out = workspace_worker.execute(
                _steghide_request(workspace, artifact, output, timeoutMs=10),
                popen=popen,
            )
            self.assertTrue(timed_out['timedOut'])
            self.assertNotIn('outputPath', timed_out)
            self.assertFalse(output.exists())

            popen, _ = _fake_steghide(b'x' * 32)
            with patch.object(workspace_worker, 'MAX_STEGHIDE_OUTPUT_BYTES', 8, create=True):
                oversized = workspace_worker.execute(
                    _steghide_request(workspace, artifact, output),
                    popen=popen,
                )
            self.assertTrue(oversized['truncated'])
            self.assertNotIn('outputPath', oversized)
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(workspace).rglob('.ctf-steghide-*')), [])

    def test_stegseek_extract_validates_workspace_paths_and_limits(self):
        workspace = f'{workspace_worker.WORKSPACE_BASE}/rev-01'
        artifact = f'{workspace}/cover.png'
        wordlist = f'{workspace}/words.txt'
        output = f'{workspace}/recovered.bin'
        valid = _stegseek_request(workspace, artifact, wordlist, output)

        self.assertEqual(workspace_worker.validate_request(valid)['wordlistPath'], wordlist)
        invalid_requests = [
            ({'outputPath': f'{workspace}/../escaped.bin'}, 'canonical path'),
            ({'artifactPath': '/tmp/cover.png'}, 'workspace'),
            ({'wordlistPath': '/tmp/words.txt'}, 'workspace'),
            ({'outputPath': artifact}, 'differ'),
            ({'outputPath': wordlist}, 'differ'),
            ({'timeoutMs': 60_001}, 'timeoutMs'),
            ({'maxFileBytes': 64 * 1024 * 1024 + 1}, 'maxFileBytes'),
        ]
        for updates, message in invalid_requests:
            with self.subTest(updates=updates), self.assertRaisesRegex(ValueError, message):
                workspace_worker.validate_request({**valid, **updates})

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_stegseek_extract_reads_descriptor_paths_and_publishes_only_metadata(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        payload = b'extracted but never returned'
        with tempfile.TemporaryDirectory(prefix='workspace-stegseek-', dir=workspace_base) as workspace:
            artifact = Path(workspace) / 'cover.png'
            wordlist = Path(workspace) / 'words.txt'
            artifact.write_bytes(b'cover fixture')
            wordlist.write_text('one\ntwo\n', encoding='utf-8')
            output = Path(workspace) / 'nested' / 'recovered.bin'
            popen, command = _fake_stegseek(payload)

            result = workspace_worker.execute(
                _stegseek_request(workspace, artifact, wordlist, output),
                popen=popen,
            )

            self.assertEqual(output.read_bytes(), payload)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result, {
                'exitCode': 0,
                'timedOut': False,
                'truncated': False,
                'outputPath': str(output),
                'bytes': len(payload),
                'sha256': hashlib.sha256(payload).hexdigest(),
            })
            self.assertEqual(command[:2], ['stegseek', '-sf'])
            self.assertTrue(command[2].startswith('/proc/self/fd/'))
            self.assertEqual(command[3], '-wl')
            self.assertTrue(command[4].startswith('/proc/self/fd/'))
            self.assertEqual(command[5], '-xf')
            self.assertTrue(command[6].startswith('/proc/self/fd/'))
            self.assertEqual(command[7:], ['-t', '1', '-q'])
            self.assertNotIn(payload.decode(), repr(result))
            self.assertEqual(list(Path(workspace).rglob('.ctf-stegseek-*')), [])

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_stegseek_extract_never_overwrites_or_follows_output_symlinks(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-stegseek-', dir=workspace_base) as workspace, \
                tempfile.TemporaryDirectory(prefix='workspace-stegseek-outside-') as outside:
            artifact = Path(workspace) / 'cover.png'
            wordlist = Path(workspace) / 'words.txt'
            artifact.write_bytes(b'cover fixture')
            wordlist.write_text('guess\n', encoding='utf-8')
            output = Path(workspace) / 'recovered.bin'
            output.write_bytes(b'keep existing bytes')
            popen, _ = _fake_stegseek(b'new payload')

            with self.assertRaises(FileExistsError):
                workspace_worker.execute(_stegseek_request(workspace, artifact, wordlist, output), popen=popen)
            self.assertEqual(output.read_bytes(), b'keep existing bytes')

            (Path(workspace) / 'redirect').symlink_to(outside, target_is_directory=True)
            escaped = Path(workspace) / 'redirect' / 'escaped.bin'
            popen, command = _fake_stegseek(b'payload')
            with self.assertRaisesRegex(PermissionError, 'symlink'):
                workspace_worker.execute(_stegseek_request(workspace, artifact, wordlist, escaped), popen=popen)
            self.assertEqual(command, [])
            self.assertFalse((Path(outside) / 'escaped.bin').exists())
            self.assertEqual(list(Path(workspace).rglob('.ctf-stegseek-*')), [])

            linked_wordlist = Path(workspace) / 'linked-words.txt'
            linked_wordlist.symlink_to(wordlist)
            popen, command = _fake_stegseek(b'payload')
            with self.assertRaisesRegex(PermissionError, 'symlink'):
                workspace_worker.execute(
                    _stegseek_request(workspace, artifact, linked_wordlist, Path(workspace) / 'linked-output.bin'),
                    popen=popen,
                )
            self.assertEqual(command, [])
            self.assertEqual(list(Path(workspace).rglob('.ctf-stegseek-*')), [])

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_stegseek_extract_cleans_up_after_timeout_and_file_size_cap(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-stegseek-', dir=workspace_base) as workspace:
            artifact = Path(workspace) / 'cover.png'
            wordlist = Path(workspace) / 'words.txt'
            artifact.write_bytes(b'cover fixture')
            wordlist.write_text('guess\n', encoding='utf-8')
            output = Path(workspace) / 'recovered.bin'

            popen, _ = _fake_stegseek(b'payload', delay=0.5)
            timed_out = workspace_worker.execute(
                _stegseek_request(workspace, artifact, wordlist, output, timeoutMs=10),
                popen=popen,
            )
            self.assertTrue(timed_out['timedOut'])
            self.assertNotIn('outputPath', timed_out)
            self.assertFalse(output.exists())

            popen, _ = _fake_stegseek(b'x' * 32)
            request = _stegseek_request(workspace, artifact, wordlist, output, maxFileBytes=8)
            oversized = workspace_worker.execute(request, popen=popen)
            self.assertTrue(oversized['truncated'], oversized)
            self.assertNotIn('outputPath', oversized)
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(workspace).rglob('.ctf-stegseek-*')), [])

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_staging_rejects_executables_over_the_size_limit(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-stage-', dir=workspace_base) as workspace:
            artifact = Path(workspace) / 'large'
            artifact.write_bytes(b'12345')
            staged = None
            try:
                with patch.object(workspace_worker, 'MAX_STAGED_EXECUTABLE_BYTES', 4, create=True):
                    with self.assertRaisesRegex(ValueError, 'staging size limit'):
                        staged = workspace_worker._stage_workspace_executable(workspace, str(artifact))
            finally:
                if staged is not None:
                    staged[0].cleanup()

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_execute_subtracts_staging_time_from_the_command_timeout(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        elapsed = [0.0]
        timeouts = []

        def stage(_workspace, _artifact, deadline=None, clock=None):
            elapsed[0] += 0.025
            return tempfile.TemporaryDirectory(prefix='workspace-stage-test-'), 'staged-target'

        def run(_executable, _args, timeout_ms, *_positional, **_keywords):
            timeouts.append(timeout_ms)
            return {
                'exitCode': 0,
                'stdoutBase64': '',
                'stderrBase64': '',
                'timedOut': False,
                'truncated': False,
            }

        with tempfile.TemporaryDirectory(prefix='workspace-stage-', dir=workspace_base) as workspace:
            artifact = Path(workspace) / 'challenge'
            artifact.write_bytes(b'ELF-like fixture')
            with patch.object(workspace_worker, '_stage_workspace_executable', side_effect=stage), \
                    patch.object(workspace_worker, 'run_command', side_effect=run):
                result = workspace_worker.execute({
                    'mode': 'execute',
                    'workspace': workspace,
                    'artifactPath': str(artifact),
                    'argv': [],
                    'stdinBase64': '',
                    'timeoutMs': 100,
                    'maxOutputBytes': 1024,
                }, clock=lambda: elapsed[0])

        self.assertEqual(result['exitCode'], 0)
        self.assertEqual(timeouts, [75])

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_write_mode_rejects_symlinked_destination_parent(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-worker-', dir=workspace_base) as workspace, \
                tempfile.TemporaryDirectory(prefix='workspace-outside-') as outside:
            link = Path(workspace) / 'redirect'
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(PermissionError, 'symlink'):
                workspace_worker.write_workspace_file(
                    workspace,
                    f'{workspace}/redirect/escaped.bin',
                    io.BytesIO(b'not written outside'),
                    max_bytes=1024,
                )
            self.assertFalse((Path(outside) / 'escaped.bin').exists())

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_write_mode_creates_nested_file_and_reports_digest(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        payload = b'workspace import fixture'
        with tempfile.TemporaryDirectory(prefix='workspace-worker-', dir=workspace_base) as workspace:
            destination = Path(workspace) / 'nested' / 'fixture.bin'
            result = workspace_worker.write_workspace_file(
                workspace,
                str(destination),
                io.BytesIO(payload),
                max_bytes=1024,
            )
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(result['bytes'], len(payload))
            self.assertEqual(result['sha256'], hashlib.sha256(payload).hexdigest())

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_write_mode_never_overwrites_an_existing_file(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-worker-', dir=workspace_base) as workspace:
            destination = Path(workspace) / 'existing.bin'
            destination.write_bytes(b'preserve this content')
            with self.assertRaises(FileExistsError):
                workspace_worker.write_workspace_file(
                    workspace,
                    str(destination),
                    io.BytesIO(b'do not replace it'),
                    max_bytes=1024,
                )
            self.assertEqual(destination.read_bytes(), b'preserve this content')

    def test_write_mode_rejects_a_zero_byte_limit_before_creating_the_file(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-worker-', dir=workspace_base) as workspace:
            destination = Path(workspace) / 'empty.bin'
            with self.assertRaisesRegex(ValueError, 'max_bytes'):
                workspace_worker.write_workspace_file(
                    workspace,
                    str(destination),
                    io.BytesIO(b''),
                    max_bytes=0,
                )
            self.assertFalse(destination.exists())

    @unittest.skipUnless(os.name == 'posix' and os.open in os.supports_dir_fd, 'requires Linux openat/O_NOFOLLOW')
    def test_output_directory_open_creates_nested_directories_and_rejects_symlinks(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-worker-', dir=workspace_base) as workspace, \
                tempfile.TemporaryDirectory(prefix='workspace-outside-') as outside:
            output_path = f'{workspace}/reports/sqlmap'
            descriptor = workspace_worker.open_workspace_directory(workspace, output_path, create=True)
            try:
                self.assertTrue(os.path.isdir(f'/proc/self/fd/{descriptor}'))
            finally:
                os.close(descriptor)
            self.assertTrue(Path(output_path).is_dir())

            link = Path(workspace) / 'redirect'
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(PermissionError, 'symlink'):
                workspace_worker.open_workspace_directory(workspace, f'{workspace}/redirect/escaped', create=True)

    @unittest.skipUnless(shutil.which('sqlmap'), 'requires the installed SQLmap executable')
    def test_sqlmap_output_directory_is_created_and_passed_as_directory_fd(self):
        workspace_base = '/home/ctfagent/ctf-workspaces'
        with tempfile.TemporaryDirectory(prefix='workspace-sqlmap-', dir=workspace_base) as workspace:
            output_directory = f'{workspace}/sqlmap-output'
            result = workspace_worker.execute({
                'mode': 'command',
                'workspace': workspace,
                'executable': 'sqlmap',
                'args': ['--output-dir', output_directory, '--version'],
                'directoryPaths': [output_directory],
                'timeoutMs': 5_000,
                'maxOutputBytes': 65_536,
            })
            self.assertTrue(Path(output_directory).is_dir())

        output = base64.b64decode(result['stdoutBase64']).decode('utf-8', errors='replace')
        self.assertEqual(result['exitCode'], 0, output)
        self.assertIn('1.10.8', output)

    def test_timeout_kills_process_group_after_command_leader_exits(self):
        result = workspace_worker.run_command(
            sys.executable,
            ['-c', "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(1)'])"],
            50,
            1024,
        )

        self.assertTrue(result['timedOut'])

    def test_process_group_is_cleaned_when_command_leader_exits(self):
        with tempfile.TemporaryDirectory(prefix='worker-child-') as directory:
            marker = os.path.join(directory, 'survived')
            child = f"import time; time.sleep(0.2); open({marker!r}, 'w').write('alive')"
            parent = (
                'import subprocess,sys; '
                f"subprocess.Popen([sys.executable, '-c', {child!r}], "
                'stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)'
            )
            result = workspace_worker.run_command(sys.executable, ['-c', parent], 1_000, 1024)
            time.sleep(0.3)

            self.assertEqual(result['exitCode'], 0)
            self.assertFalse(result['timedOut'])
            self.assertFalse(os.path.exists(marker))


if __name__ == '__main__':
    unittest.main()
