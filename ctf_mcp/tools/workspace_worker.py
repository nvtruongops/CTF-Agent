import base64
import hashlib
import json
import os
import posixpath
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time


WORKSPACE_BASE = '/home/ctfagent/ctf-workspaces'
SYMBOL_NAME = re.compile(r'^[A-Za-z_.$][A-Za-z0-9_.$@+-]{0,127}$')
COMMAND_EXECUTABLES = frozenset({
    'checksec', 'tshark', 'binwalk', 'exiftool', 'steghide', 'sigrok-cli', 'ffuf', 'strings', 'sqlmap',
    'yara', 'john', 'ROPgadget', 'hydra',
})
INSPECT_OUTPUT_BYTES = 100_000
COMMAND_OUTPUT_BYTES = 1_048_576
COMMAND_TIMEOUT_MS = 30_000
STEGHIDE_TIMEOUT_MS = 60_000
STEGHIDE_DIAGNOSTIC_BYTES = 262_144
MAX_STEGHIDE_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_STEGHIDE_PASSPHRASE_CHARS = 1024
STEGSEEK_TIMEOUT_MS = 60_000
STEGSEEK_DIAGNOSTIC_BYTES = 262_144
MAX_STEGSEEK_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_INPUT_BYTES = 65_536
MAX_COMMAND_ARGS = 64
MAX_COMMAND_ARG_LENGTH = 8192
MAX_BINARY_ARGS = 32
MAX_BINARY_ARG_LENGTH = 2048
MAX_WORKSPACE_IMPORT_BYTES = 256 * 1024 * 1024
MAX_STAGED_EXECUTABLE_BYTES = 256 * 1024 * 1024
READ_CHUNK_BYTES = 8192
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0)
FILE_FLAGS = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)


def _workspace_segments(workspace):
    if not isinstance(workspace, str) or posixpath.dirname(workspace) != WORKSPACE_BASE:
        raise ValueError('workspace must be one direct child of the ctfagent workspace root')
    challenge_id = posixpath.basename(workspace)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', challenge_id):
        raise ValueError('workspace has an invalid challenge ID')
    return ('home', 'ctfagent', 'ctf-workspaces', challenge_id)


def artifact_segments(workspace, artifact_path):
    _workspace_segments(workspace)
    if (
        not isinstance(artifact_path, str)
        or '\0' in artifact_path
        or '\\' in artifact_path
        or not posixpath.isabs(artifact_path)
        or posixpath.normpath(artifact_path) != artifact_path
    ):
        raise ValueError('artifactPath must be a canonical path strictly inside the workspace')
    relative_path = posixpath.relpath(artifact_path, workspace)
    segments = relative_path.split('/')
    if relative_path in ('', '.', '..') or any(segment in ('', '.', '..') for segment in segments):
        raise ValueError('artifactPath must be strictly inside the active workspace')
    return segments


def _open_workspace_directory(workspace, relative_segments=(), create=False):
    workspace_parts = _workspace_segments(workspace)
    if any(not isinstance(part, str) or part in ('', '.', '..') or '/' in part or '\0' in part
           for part in relative_segments):
        raise ValueError('workspace directory contains an invalid component')

    current_fd = os.open('/', DIRECTORY_FLAGS)
    try:
        for component in (*workspace_parts, *relative_segments):
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
            next_fd = os.open(component, DIRECTORY_FLAGS, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except OSError as error:
        os.close(current_fd)
        raise PermissionError('workspace path contains a symlink or is not safely accessible') from error
    except Exception:
        os.close(current_fd)
        raise


def open_workspace_artifact(workspace, artifact_path):
    segments = artifact_segments(workspace, artifact_path)
    parent_fd = _open_workspace_directory(workspace, segments[:-1])
    artifact_fd = None
    try:
        artifact_fd = os.open(segments[-1], FILE_FLAGS, dir_fd=parent_fd)
        if not stat.S_ISREG(os.fstat(artifact_fd).st_mode):
            raise PermissionError('artifactPath must reference a regular file')
        return artifact_fd
    except OSError as error:
        if artifact_fd is not None:
            os.close(artifact_fd)
        raise PermissionError('artifactPath contains a symlink or cannot be opened safely') from error
    except Exception:
        if artifact_fd is not None:
            os.close(artifact_fd)
        raise
    finally:
        os.close(parent_fd)


def _argument_path(arg):
    _, separator, value = arg.partition('=')
    return value if separator else arg


def _replace_argument_path(arg, descriptor_paths):
    option, separator, value = arg.partition('=')
    descriptor_path = descriptor_paths.get(value if separator else arg)
    if descriptor_path is None:
        return arg
    return f'{option}={descriptor_path}' if separator else descriptor_path


def open_workspace_directory(workspace, directory_path, create=False):
    segments = artifact_segments(workspace, directory_path)
    descriptor = _open_workspace_directory(workspace, segments, create=create)
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise PermissionError('directoryPath must reference a workspace directory')
    return descriptor


def _write_all(descriptor, data):
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError('workspace write made no progress')
        remaining = remaining[written:]


def write_workspace_file(workspace, destination_path, source, max_bytes):
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 1 <= max_bytes <= MAX_WORKSPACE_IMPORT_BYTES:
        raise ValueError(f'max_bytes must be from 1 to {MAX_WORKSPACE_IMPORT_BYTES}')
    segments = artifact_segments(workspace, destination_path)
    parent_fd = _open_workspace_directory(workspace, segments[:-1], create=True)
    descriptor = None
    created = False
    digest = hashlib.sha256()
    total_bytes = 0
    try:
        descriptor = os.open(
            segments[-1],
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0),
            0o600,
            dir_fd=parent_fd,
        )
        created = True
        while True:
            chunk = source.read(min(READ_CHUNK_BYTES, max_bytes - total_bytes + 1))
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                raise ValueError(f'import exceeds the {max_bytes}-byte limit')
            digest.update(chunk)
            _write_all(descriptor, chunk)
    except Exception:
        if created:
            os.unlink(segments[-1], dir_fd=parent_fd)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)
    return {'sha256': digest.hexdigest(), 'bytes': total_bytes}


def validate_request(request):
    if not isinstance(request, dict):
        raise TypeError('request must be a JSON object')
    mode = request.get('mode')
    if mode not in ('inspect', 'disassemble', 'gdb_info', 'command', 'execute', 'steghide_extract', 'stegseek_extract'):
        raise ValueError('mode must be inspect, disassemble, gdb_info, command, execute, steghide_extract, or stegseek_extract')
    workspace = request.get('workspace')
    _workspace_segments(workspace)

    if mode == 'stegseek_extract':
        artifact_path = request.get('artifactPath')
        wordlist_path = request.get('wordlistPath')
        output_path = request.get('outputPath')
        artifact_segments(workspace, artifact_path)
        artifact_segments(workspace, wordlist_path)
        artifact_segments(workspace, output_path)
        if output_path in (artifact_path, wordlist_path):
            raise ValueError('outputPath must differ from artifactPath and wordlistPath')
        timeout_ms = request.get('timeoutMs', STEGSEEK_TIMEOUT_MS)
        output_limit = request.get('maxOutputBytes', STEGSEEK_DIAGNOSTIC_BYTES)
        file_limit = request.get('maxFileBytes', MAX_STEGSEEK_OUTPUT_BYTES)
        if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or not 1 <= timeout_ms <= STEGSEEK_TIMEOUT_MS:
            raise ValueError(f'timeoutMs must be from 1 to {STEGSEEK_TIMEOUT_MS}')
        if not isinstance(output_limit, int) or isinstance(output_limit, bool) or not 1 <= output_limit <= STEGSEEK_DIAGNOSTIC_BYTES:
            raise ValueError(f'maxOutputBytes must be from 1 to {STEGSEEK_DIAGNOSTIC_BYTES}')
        if not isinstance(file_limit, int) or isinstance(file_limit, bool) or not 1 <= file_limit <= MAX_STEGSEEK_OUTPUT_BYTES:
            raise ValueError(f'maxFileBytes must be from 1 to {MAX_STEGSEEK_OUTPUT_BYTES}')
        return {
            'mode': mode, 'workspace': workspace, 'artifactPath': artifact_path,
            'wordlistPath': wordlist_path, 'outputPath': output_path,
            'timeoutMs': timeout_ms, 'maxOutputBytes': output_limit,
            'maxFileBytes': file_limit,
        }

    if mode == 'steghide_extract':
        artifact_path = request.get('artifactPath')
        output_path = request.get('outputPath')
        artifact_segments(workspace, artifact_path)
        artifact_segments(workspace, output_path)
        if artifact_path == output_path:
            raise ValueError('outputPath must differ from artifactPath')
        passphrase = request.get('passphrase')
        if not isinstance(passphrase, str) or '\0' in passphrase or len(passphrase) > MAX_STEGHIDE_PASSPHRASE_CHARS:
            raise ValueError(f'passphrase must be a NUL-free string of at most {MAX_STEGHIDE_PASSPHRASE_CHARS} characters')
        timeout_ms = request.get('timeoutMs', STEGHIDE_TIMEOUT_MS)
        output_limit = request.get('maxOutputBytes', STEGHIDE_DIAGNOSTIC_BYTES)
        if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or not 1 <= timeout_ms <= STEGHIDE_TIMEOUT_MS:
            raise ValueError(f'timeoutMs must be from 1 to {STEGHIDE_TIMEOUT_MS}')
        if not isinstance(output_limit, int) or isinstance(output_limit, bool) or not 1 <= output_limit <= STEGHIDE_DIAGNOSTIC_BYTES:
            raise ValueError(f'maxOutputBytes must be from 1 to {STEGHIDE_DIAGNOSTIC_BYTES}')
        return {
            'mode': mode, 'workspace': workspace, 'artifactPath': artifact_path,
            'outputPath': output_path, 'passphrase': passphrase,
            'timeoutMs': timeout_ms, 'maxOutputBytes': output_limit,
        }

    if mode in ('inspect', 'disassemble', 'gdb_info'):
        artifact_path = request.get('artifactPath')
        artifact_segments(workspace, artifact_path)
        symbol = request.get('symbol')
        if symbol is not None and (not isinstance(symbol, str) or not SYMBOL_NAME.fullmatch(symbol)):
            raise ValueError('symbol must be a simple symbol name')
        if mode == 'inspect' and symbol is not None:
            raise ValueError('inspect mode does not accept a symbol')
        return {'mode': mode, 'workspace': workspace, 'artifactPath': artifact_path, 'symbol': symbol}

    timeout_ms = request.get('timeoutMs', COMMAND_TIMEOUT_MS)
    output_limit = request.get('maxOutputBytes', COMMAND_OUTPUT_BYTES)
    if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or not 1 <= timeout_ms <= 120_000:
        raise ValueError('timeoutMs must be from 1 to 120000')
    if not isinstance(output_limit, int) or isinstance(output_limit, bool) or not 1 <= output_limit <= COMMAND_OUTPUT_BYTES:
        raise ValueError(f'maxOutputBytes must be from 1 to {COMMAND_OUTPUT_BYTES}')

    if mode == 'command':
        executable = request.get('executable')
        args = request.get('args')
        paths = request.get('filePaths', [])
        directory_paths = request.get('directoryPaths', [])
        if not isinstance(executable, str) or executable not in COMMAND_EXECUTABLES:
            raise ValueError('executable is not an approved workspace file tool')
        if not isinstance(args, list) or len(args) > MAX_COMMAND_ARGS or any(
            not isinstance(arg, str) or '\0' in arg or len(arg) > MAX_COMMAND_ARG_LENGTH for arg in args
        ):
            raise ValueError('args must contain bounded NUL-free strings')
        ephemeral_session = request.get('ephemeralSession', False)
        session_placeholder = '--session=@ctf-agent-ephemeral'
        if not isinstance(ephemeral_session, bool):
            raise ValueError('ephemeralSession must be a boolean')
        if executable == 'john':
            if not ephemeral_session or args.count(session_placeholder) != 1:
                raise ValueError('john requires one ephemeralSession placeholder')
        elif ephemeral_session or session_placeholder in args:
            raise ValueError('ephemeralSession is only supported for John')
        temporary_working_directory = request.get('temporaryWorkingDirectory', False)
        if not isinstance(temporary_working_directory, bool):
            raise ValueError('temporaryWorkingDirectory must be a boolean')
        if executable == 'hydra' and not temporary_working_directory:
            raise ValueError('hydra requires a temporaryWorkingDirectory')
        if executable != 'hydra' and temporary_working_directory:
            raise ValueError('temporaryWorkingDirectory is only supported for Hydra')
        if not isinstance(paths, list) or len(paths) > 8 or any(not isinstance(path, str) for path in paths):
            raise ValueError('filePaths must be a list of at most eight workspace paths')
        if len(set(paths)) != len(paths):
            raise ValueError('filePaths must not contain duplicates')
        for file_path in paths:
            artifact_segments(workspace, file_path)
            if not any(_argument_path(arg) == file_path for arg in args):
                raise ValueError('every filePath must appear as an argv path argument')
        if not isinstance(directory_paths, list) or len(directory_paths) > 8 or any(
            not isinstance(path, str) for path in directory_paths
        ):
            raise ValueError('directoryPaths must be a list of at most eight workspace paths')
        if len(set(directory_paths)) != len(directory_paths) or set(directory_paths) & set(paths):
            raise ValueError('directoryPaths must be unique and distinct from filePaths')
        for directory_path in directory_paths:
            artifact_segments(workspace, directory_path)
            if not any(_argument_path(arg) == directory_path for arg in args):
                raise ValueError('every directoryPath must appear as an argv path argument')
        unscoped_absolute_paths = [
            arg for arg in args
            if posixpath.isabs(_argument_path(arg))
            and _argument_path(arg) not in paths
            and _argument_path(arg) not in directory_paths
            and not (executable == 'john' and arg == '--pot=/dev/null')
        ]
        if unscoped_absolute_paths:
            raise ValueError('absolute argv paths must be declared in filePaths or directoryPaths')
        input_b64 = request.get('inputBase64')
        input_data = None
        if input_b64 is not None:
            if not isinstance(input_b64, str) or len(input_b64) > ((MAX_INPUT_BYTES + 2) // 3) * 4:
                raise ValueError('inputBase64 exceeds the input limit')
            try:
                input_data = base64.b64decode(input_b64, validate=True)
            except ValueError as error:
                raise ValueError('inputBase64 is invalid') from error
            if len(input_data) > MAX_INPUT_BYTES:
                raise ValueError('input exceeds the input limit')
        return {
            'mode': mode, 'workspace': workspace, 'executable': executable,
            'args': args, 'filePaths': paths, 'timeoutMs': timeout_ms,
            'directoryPaths': directory_paths,
            'maxOutputBytes': output_limit, 'inputData': input_data,
            'ephemeralSession': ephemeral_session,
            'temporaryWorkingDirectory': temporary_working_directory,
        }

    artifact_path = request.get('artifactPath')
    artifact_segments(workspace, artifact_path)
    argv = request.get('argv', [])
    if not isinstance(argv, list) or len(argv) > MAX_BINARY_ARGS or any(
        not isinstance(arg, str) or '\0' in arg or len(arg) > MAX_BINARY_ARG_LENGTH for arg in argv
    ):
        raise ValueError(f'argv must contain at most {MAX_BINARY_ARGS} bounded NUL-free strings')
    input_b64 = request.get('stdinBase64', '')
    if not isinstance(input_b64, str) or len(input_b64) > ((MAX_INPUT_BYTES + 2) // 3) * 4:
        raise ValueError('stdinBase64 exceeds the input limit')
    try:
        input_data = base64.b64decode(input_b64, validate=True)
    except ValueError as error:
        raise ValueError('stdinBase64 is invalid') from error
    if len(input_data) > MAX_INPUT_BYTES:
        raise ValueError('stdin exceeds the input limit')
    return {
        'mode': mode, 'workspace': workspace, 'artifactPath': artifact_path,
        'argv': argv, 'inputData': input_data, 'timeoutMs': timeout_ms,
        'maxOutputBytes': output_limit,
    }


def commands_for(request, descriptor_path):
    mode = request['mode']
    symbol = request.get('symbol')
    if mode == 'inspect':
        return [
            ('file', ['-L', '--', descriptor_path], INSPECT_OUTPUT_BYTES, COMMAND_TIMEOUT_MS),
            ('readelf', ['-h', '-W', '-S', '-s', '--', descriptor_path], INSPECT_OUTPUT_BYTES, COMMAND_TIMEOUT_MS),
            ('strings', ['-a', '-t', 'x', '-n', '4', '--', descriptor_path], INSPECT_OUTPUT_BYTES, COMMAND_TIMEOUT_MS),
        ]
    if mode == 'disassemble':
        args = ['-d', '-M', 'intel']
        if symbol:
            args.append(f'--disassemble={symbol}')
        args.extend(['--', descriptor_path])
        return [('objdump', args, COMMAND_OUTPUT_BYTES, COMMAND_TIMEOUT_MS)]
    args = [
        '--batch', '--nx', '--quiet', '-iex', 'set auto-load off',
        '-ex', 'set debuginfod enabled off',
        '-ex', 'info files', '-ex', 'info functions',
    ]
    if symbol:
        args.extend(['-ex', f'disassemble {symbol}'])
    args.append(descriptor_path)
    return [('gdb', args, COMMAND_OUTPUT_BYTES, COMMAND_TIMEOUT_MS)]


def _kill_command_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_command(executable, args, timeout_ms, output_limit, *, pass_fds=(), input_data=None,
                stream_output_fd=None, stream_output_limit=None, file_size_limit=None, cwd=None, env=None, popen=subprocess.Popen,
                clock=time.monotonic):
    if (stream_output_fd is None) != (stream_output_limit is None):
        raise ValueError('stream_output_fd and stream_output_limit must be provided together')
    if stream_output_fd is not None and (
        not isinstance(stream_output_limit, int) or isinstance(stream_output_limit, bool) or stream_output_limit < 1
    ):
        raise ValueError('stream_output_limit must be a positive integer')
    preexec_fn = None
    if file_size_limit is not None:
        if not isinstance(file_size_limit, int) or isinstance(file_size_limit, bool) or file_size_limit < 1:
            raise ValueError('file_size_limit must be a positive integer')
        import resource

        def limit_file_size():
            _, hard_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
            effective_limit = file_size_limit if hard_limit == resource.RLIM_INFINITY else min(file_size_limit, hard_limit)
            resource.setrlimit(resource.RLIMIT_FSIZE, (effective_limit, hard_limit))

        preexec_fn = limit_file_size
    try:
        process = popen(
            [executable, *args],
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            pass_fds=tuple(pass_fds),
            start_new_session=True,
            preexec_fn=preexec_fn,
            cwd=cwd,
            env=env,
        )
    except OSError as error:
        return {
            'executable': executable,
            'exitCode': 127,
            'stdoutBase64': '',
            'stderrBase64': base64.b64encode(str(error).encode('utf-8')).decode('ascii'),
            'timedOut': False,
            'truncated': False,
        }

    selector = selectors.DefaultSelector()
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    total_bytes = 0
    streamed_bytes = 0
    streamed_digest = hashlib.sha256()
    timed_out = False
    truncated = False
    deadline = clock() + timeout_ms / 1000
    input_view = memoryview(input_data) if input_data is not None else None
    try:
        for name, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if process.stdin is not None:
            os.set_blocking(process.stdin.fileno(), False)
            if input_view:
                selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
            else:
                process.stdin.close()

        while selector.get_map():
            if not timed_out and clock() >= deadline:
                timed_out = True
                _kill_command_group(process)
            for key, mask in selector.select(timeout=0.1):
                if key.data == 'stdin':
                    try:
                        written = os.write(key.fd, input_view[:READ_CHUNK_BYTES])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        input_view = memoryview(b'')
                        continue
                    input_view = input_view[written:]
                    if not input_view:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue

                try:
                    chunk = os.read(key.fd, READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if key.data == 'stdout' and stream_output_fd is not None:
                    available = max(0, stream_output_limit - streamed_bytes)
                    retained = chunk[:available]
                    if retained:
                        _write_all(stream_output_fd, retained)
                        streamed_digest.update(retained)
                        streamed_bytes += len(retained)
                    if len(chunk) > available and not truncated:
                        truncated = True
                        _kill_command_group(process)
                    continue
                available = max(0, output_limit - total_bytes)
                if available:
                    retained = chunk[:available]
                    output[key.data].extend(retained)
                    total_bytes += len(retained)
                if len(chunk) > available and not truncated:
                    truncated = True
                    _kill_command_group(process)
        try:
            exit_code = process.wait(timeout=max(0, deadline - clock()))
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_command_group(process)
            exit_code = process.wait()
        else:
            _kill_command_group(process)
    except Exception:
        _kill_command_group(process)
        process.wait()
        raise
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()

    result = {
        'executable': executable,
        'exitCode': exit_code,
        'stdoutBase64': base64.b64encode(output['stdout']).decode('ascii'),
        'stderrBase64': base64.b64encode(output['stderr']).decode('ascii'),
        'timedOut': timed_out,
        'truncated': truncated,
    }
    if stream_output_fd is not None:
        result['streamedBytes'] = streamed_bytes
        result['streamedSha256'] = streamed_digest.hexdigest()
    return result


def _open_workspace_artifacts(workspace, paths):
    descriptors = {}
    try:
        for artifact_path in paths:
            if artifact_path not in descriptors:
                descriptors[artifact_path] = open_workspace_artifact(workspace, artifact_path)
        return descriptors
    except Exception:
        for descriptor in descriptors.values():
            os.close(descriptor)
        raise


def _stage_workspace_executable(workspace, executable, deadline=None, clock=time.monotonic):
    source_descriptor = open_workspace_artifact(workspace, executable)
    staging_directory = None
    staged_descriptor = None
    try:
        if deadline is not None and clock() >= deadline:
            raise TimeoutError('workspace executable staging deadline exceeded')
        if os.fstat(source_descriptor).st_size > MAX_STAGED_EXECUTABLE_BYTES:
            raise ValueError(f'workspace executable exceeds the {MAX_STAGED_EXECUTABLE_BYTES}-byte staging size limit')
        staging_directory = tempfile.TemporaryDirectory(prefix='ctf-binary-')
        staged_path = os.path.join(staging_directory.name, 'target')
        staged_descriptor = os.open(
            staged_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0),
            0o700,
        )
        total_bytes = 0
        while True:
            if deadline is not None and clock() >= deadline:
                raise TimeoutError('workspace executable staging deadline exceeded')
            chunk = os.read(source_descriptor, 1_048_576)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_STAGED_EXECUTABLE_BYTES:
                raise ValueError(f'workspace executable exceeds the {MAX_STAGED_EXECUTABLE_BYTES}-byte staging size limit')
            _write_all(staged_descriptor, chunk)
        os.fchmod(staged_descriptor, 0o700)
        if deadline is not None and clock() >= deadline:
            raise TimeoutError('workspace executable staging deadline exceeded')
        return staging_directory, staged_path
    except Exception:
        if staging_directory is not None:
            staging_directory.cleanup()
        raise
    finally:
        if staged_descriptor is not None:
            os.close(staged_descriptor)
        os.close(source_descriptor)


def _extract_steghide(validated, popen, clock):
    workspace = validated['workspace']
    artifact_fd = open_workspace_artifact(workspace, validated['artifactPath'])
    output_segments = artifact_segments(workspace, validated['outputPath'])
    output_directory_fd = None
    output_fd = None
    temporary_name = None
    try:
        output_directory_fd = _open_workspace_directory(workspace, output_segments[:-1], create=True)
        output_fd, temporary_path = tempfile.mkstemp(
            prefix='.ctf-steghide-', dir=f'/proc/self/fd/{output_directory_fd}',
        )
        temporary_name = os.path.basename(temporary_path)
        command = run_command(
            'steghide', [
                'extract', '-sf', f'/proc/self/fd/{artifact_fd}',
                '-xf', '-', '-p', validated['passphrase'], '-q',
            ],
            validated['timeoutMs'], validated['maxOutputBytes'],
            pass_fds=(artifact_fd,), stream_output_fd=output_fd,
            stream_output_limit=MAX_STEGHIDE_OUTPUT_BYTES, popen=popen, clock=clock,
        )
        status = {
            'exitCode': command['exitCode'],
            'timedOut': command['timedOut'],
            'truncated': command['truncated'],
        }
        if command['exitCode'] != 0 or command['timedOut'] or command['truncated']:
            return status

        os.fsync(output_fd)
        os.close(output_fd)
        output_fd = None
        os.link(
            temporary_name, output_segments[-1],
            src_dir_fd=output_directory_fd, dst_dir_fd=output_directory_fd,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=output_directory_fd)
        temporary_name = None
        return {
            **status,
            'outputPath': validated['outputPath'],
            'bytes': command['streamedBytes'],
            'sha256': command['streamedSha256'],
        }
    finally:
        if output_fd is not None:
            os.close(output_fd)
        if temporary_name is not None and output_directory_fd is not None:
            try:
                os.unlink(temporary_name, dir_fd=output_directory_fd)
            except FileNotFoundError:
                pass
        if output_directory_fd is not None:
            os.close(output_directory_fd)
        os.close(artifact_fd)


def _extract_stegseek(validated, popen, clock):
    workspace = validated['workspace']
    artifact_fd = open_workspace_artifact(workspace, validated['artifactPath'])
    wordlist_fd = None
    output_segments = artifact_segments(workspace, validated['outputPath'])
    output_directory_fd = None
    staging_directory_fd = None
    staging_name = None
    extracted_fd = None
    try:
        wordlist_fd = open_workspace_artifact(workspace, validated['wordlistPath'])
        output_directory_fd = _open_workspace_directory(workspace, output_segments[:-1], create=True)
        staging_path = tempfile.mkdtemp(prefix='.ctf-stegseek-', dir=f'/proc/self/fd/{output_directory_fd}')
        staging_name = os.path.basename(staging_path)
        staging_directory_fd = os.open(staging_name, DIRECTORY_FLAGS, dir_fd=output_directory_fd)
        command = run_command(
            'stegseek', [
                '-sf', f'/proc/self/fd/{artifact_fd}',
                '-wl', f'/proc/self/fd/{wordlist_fd}',
                '-xf', f'/proc/self/fd/{staging_directory_fd}/extracted',
                '-t', '1', '-q',
            ],
            validated['timeoutMs'], validated['maxOutputBytes'],
            pass_fds=(artifact_fd, wordlist_fd, staging_directory_fd),
            file_size_limit=validated['maxFileBytes'], popen=popen, clock=clock,
        )
        status = {
            'exitCode': command['exitCode'],
            'timedOut': command['timedOut'],
            'truncated': command['truncated'] or command['exitCode'] == -getattr(signal, 'SIGXFSZ', 25),
        }
        if status['exitCode'] != 0 or status['timedOut'] or status['truncated']:
            if not status['timedOut'] and not status['truncated']:
                try:
                    partial_fd = os.open('extracted', FILE_FLAGS, dir_fd=staging_directory_fd)
                except FileNotFoundError:
                    pass
                else:
                    try:
                        status['truncated'] = os.fstat(partial_fd).st_size >= validated['maxFileBytes']
                    finally:
                        os.close(partial_fd)
            return status

        extracted_fd = os.open('extracted', FILE_FLAGS, dir_fd=staging_directory_fd)
        if not stat.S_ISREG(os.fstat(extracted_fd).st_mode):
            raise PermissionError('Stegseek output must be a regular file')
        os.fchmod(extracted_fd, 0o600)
        digest = hashlib.sha256()
        total_bytes = 0
        while True:
            chunk = os.read(extracted_fd, READ_CHUNK_BYTES)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > validated['maxFileBytes']:
                return {**status, 'truncated': True}
            digest.update(chunk)

        os.fsync(extracted_fd)
        os.close(extracted_fd)
        extracted_fd = None
        os.link(
            'extracted', output_segments[-1],
            src_dir_fd=staging_directory_fd, dst_dir_fd=output_directory_fd,
            follow_symlinks=False,
        )
        return {
            **status,
            'outputPath': validated['outputPath'],
            'bytes': total_bytes,
            'sha256': digest.hexdigest(),
        }
    finally:
        if extracted_fd is not None:
            os.close(extracted_fd)
        if staging_directory_fd is not None:
            try:
                os.unlink('extracted', dir_fd=staging_directory_fd)
            except FileNotFoundError:
                pass
            os.close(staging_directory_fd)
        if staging_name is not None and output_directory_fd is not None:
            try:
                os.rmdir(staging_name, dir_fd=output_directory_fd)
            except FileNotFoundError:
                pass
        if output_directory_fd is not None:
            os.close(output_directory_fd)
        if wordlist_fd is not None:
            os.close(wordlist_fd)
        os.close(artifact_fd)


def execute(request, popen=subprocess.Popen, clock=time.monotonic):
    validated = validate_request(request)
    mode = validated['mode']
    if mode == 'stegseek_extract':
        return _extract_stegseek(validated, popen, clock)
    if mode == 'steghide_extract':
        return _extract_steghide(validated, popen, clock)
    if mode in ('inspect', 'disassemble', 'gdb_info'):
        artifact_fd = open_workspace_artifact(validated['workspace'], validated['artifactPath'])
        descriptor_path = f'/proc/self/fd/{artifact_fd}'
        try:
            observations = [
                run_command(executable, args, timeout_ms, output_limit,
                            pass_fds=(artifact_fd,), popen=popen, clock=clock)
                for executable, args, output_limit, timeout_ms in commands_for(validated, descriptor_path)
            ]
        finally:
            os.close(artifact_fd)
        return {'mode': mode, 'artifactPath': validated['artifactPath'], 'observations': observations}

    if mode == 'command':
        descriptors = _open_workspace_artifacts(validated['workspace'], validated['filePaths'])
        directory_descriptors = {}
        try:
            for directory_path in validated['directoryPaths']:
                directory_descriptors[directory_path] = open_workspace_directory(
                    validated['workspace'], directory_path, create=True,
                )
        except Exception:
            for descriptor in descriptors.values():
                os.close(descriptor)
            for descriptor in directory_descriptors.values():
                os.close(descriptor)
            raise
        all_descriptors = {**descriptors, **directory_descriptors}
        descriptor_paths = {path: f'/proc/self/fd/{fd}' for path, fd in all_descriptors.items()}
        args = [_replace_argument_path(arg, descriptor_paths) for arg in validated['args']]
        try:
            if validated['ephemeralSession']:
                with tempfile.TemporaryDirectory(prefix='ctf-john-') as session_directory:
                    session_path = os.path.join(session_directory, 'session')
                    args = [
                        f'--session={session_path}' if arg == '--session=@ctf-agent-ephemeral' else arg
                        for arg in args
                    ]
                    return run_command(
                        validated['executable'], args, validated['timeoutMs'], validated['maxOutputBytes'],
                        pass_fds=tuple(all_descriptors.values()), input_data=validated['inputData'],
                        popen=popen, clock=clock,
                    )
            if validated['temporaryWorkingDirectory']:
                with tempfile.TemporaryDirectory(prefix='ctf-hydra-') as working_directory:
                    environment = os.environ.copy()
                    environment.pop('HYDRA_PROXY', None)
                    environment.pop('HYDRA_PROXY_HTTP', None)
                    return run_command(
                        validated['executable'], args, validated['timeoutMs'], validated['maxOutputBytes'],
                        pass_fds=tuple(all_descriptors.values()), input_data=validated['inputData'],
                        cwd=working_directory, env=environment, popen=popen, clock=clock,
                    )
            return run_command(
                validated['executable'], args, validated['timeoutMs'], validated['maxOutputBytes'],
                pass_fds=tuple(all_descriptors.values()), input_data=validated['inputData'],
                popen=popen, clock=clock,
            )
        finally:
            for descriptor in all_descriptors.values():
                os.close(descriptor)

    deadline = clock() + (validated['timeoutMs'] / 1000)
    staging_directory, staged_path = _stage_workspace_executable(
        validated['workspace'], validated['artifactPath'], deadline=deadline, clock=clock,
    )
    try:
        remaining_ms = int((deadline - clock()) * 1000)
        if remaining_ms < 1:
            raise TimeoutError('workspace executable staging deadline exceeded')
        return run_command(
            staged_path, validated['argv'], remaining_ms, validated['maxOutputBytes'],
            input_data=validated['inputData'], popen=popen, clock=clock,
        )
    finally:
        staging_directory.cleanup()


def _main_write(args):
    if len(args) != 3:
        raise ValueError('write mode requires workspace, destinationPath, and maxBytes')
    workspace, destination_path, max_bytes_text = args
    max_bytes = int(max_bytes_text)
    return write_workspace_file(workspace, destination_path, sys.stdin.buffer, max_bytes)


def main():
    try:
        if len(sys.argv) > 1 and sys.argv[1] == 'write':
            result = _main_write(sys.argv[2:])
            print(json.dumps(result, ensure_ascii=True))
            return 0
        result = execute(json.loads(sys.stdin.read()))
    except Exception as error:
        print(json.dumps({'error': str(error)}, ensure_ascii=True))
        return 1

    failed = result.get('exitCode') != 0 or result.get('timedOut') or result.get('truncated')
    if 'observations' in result:
        failed = any(item['exitCode'] != 0 or item['timedOut'] or item['truncated'] for item in result['observations'])
    print(json.dumps(result, ensure_ascii=True))
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
