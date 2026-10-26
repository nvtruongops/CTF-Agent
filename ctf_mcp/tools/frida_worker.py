import base64
import itertools
import json
import os
import posixpath
import re
import signal
import tempfile
import stat
import sys
import threading
import time


MAX_SCRIPT_BYTES = 65_536
MAX_TIMEOUT_MS = 120_000
MAX_ARGV = 32
MAX_ARG_LENGTH = 2048
MAX_MESSAGES = 64
MAX_MESSAGE_BYTES = 4096
MAX_RETAINED_MESSAGE_BYTES = 262_144
MAX_MESSAGE_NODES = 32
MAX_MESSAGE_DEPTH = 4
MAX_MESSAGE_ITEMS = 16
MAX_STAGED_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_MESSAGE_STRING_CHARS = 128
MAX_BINARY_MESSAGE_BYTES = 2048


def is_within_workspace(workspace, candidate):
    root = posixpath.realpath(workspace)
    path = posixpath.realpath(candidate)
    try:
        relative = posixpath.relpath(path, root)
    except ValueError:
        return False
    return relative not in ('', posixpath.curdir, posixpath.pardir) and not relative.startswith(posixpath.pardir + '/') and not posixpath.isabs(relative)


def validate_request(request):
    if not isinstance(request, dict):
        raise TypeError('request must be a JSON object')
    mode = request.get('mode')
    if mode != 'spawn':
        raise ValueError('mode must be spawn')
    workspace = request.get('workspace')
    if (
        not isinstance(workspace, str)
        or posixpath.dirname(workspace) != '/home/ctfagent/ctf-workspaces'
        or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', posixpath.basename(workspace))
    ):
        raise ValueError('workspace is outside the ctfagent challenge workspace root')
    if posixpath.realpath(workspace) != workspace:
        raise ValueError('workspace must be canonical and must not resolve through a symlink')
    script = request.get('script')
    if not isinstance(script, str) or not script:
        raise ValueError('script must be non-empty text')
    if '\0' in script:
        raise ValueError('script cannot contain NUL characters')
    if len(script.encode('utf-8')) > MAX_SCRIPT_BYTES:
        raise ValueError(f'script exceeds the {MAX_SCRIPT_BYTES}-byte limit')
    timeout_ms = request.get('timeoutMs', 10_000)
    if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or not 1 <= timeout_ms <= MAX_TIMEOUT_MS:
        raise ValueError(f'timeoutMs must be from 1 to {MAX_TIMEOUT_MS}')
    argv = request.get('argv', [])
    if not isinstance(argv, list) or len(argv) > MAX_ARGV or any(
        not isinstance(arg, str) or len(arg) > MAX_ARG_LENGTH or '\0' in arg for arg in argv
    ):
        raise ValueError(f'argv must contain at most {MAX_ARGV} NUL-free strings of at most {MAX_ARG_LENGTH} characters')
    executable = request.get('artifactPath')
    if not isinstance(executable, str):
        raise ValueError('artifactPath must be a file inside the active challenge workspace')
    canonical_executable = posixpath.realpath(executable)
    if (
        not is_within_workspace(workspace, canonical_executable)
        or not os.path.isfile(canonical_executable)
    ):
        raise ValueError('artifactPath must be a file inside the active challenge workspace')
    return mode, workspace, canonical_executable


def _open_workspace_artifact(workspace, executable):
    relative_path = posixpath.relpath(executable, workspace)
    path_segments = relative_path.split('/')
    workspace_segments = workspace.lstrip('/').split('/')
    if (
        not executable.startswith('/')
        or relative_path in ('', '.', '..')
        or relative_path.startswith('../')
        or any(segment in ('', '.', '..') for segment in path_segments)
        or any(segment in ('', '.', '..') for segment in workspace_segments)
    ):
        raise PermissionError('artifact path changed outside the active challenge workspace')

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0)
    directory_descriptors = []
    file_descriptor = None
    keep_file_descriptor = False
    try:
        current_descriptor = os.open('/', directory_flags)
        directory_descriptors.append(current_descriptor)
        for segment in (*workspace_segments, *path_segments[:-1]):
            current_descriptor = os.open(segment, directory_flags, dir_fd=current_descriptor)
            directory_descriptors.append(current_descriptor)

        file_descriptor = os.open(
            path_segments[-1],
            os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0),
            dir_fd=current_descriptor,
        )
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PermissionError('artifactPath must be a regular file')
        keep_file_descriptor = True
        return file_descriptor
    except OSError as error:
        raise PermissionError('artifactPath contains a symlink or cannot be opened safely') from error
    finally:
        if file_descriptor is not None and not keep_file_descriptor:
            os.close(file_descriptor)
        for descriptor in reversed(directory_descriptors):
            os.close(descriptor)


def _stage_workspace_executable(workspace, executable, deadline=None, clock=time.monotonic):
    source_descriptor = _open_workspace_artifact(workspace, executable)
    staging_directory = None
    staged_descriptor = None
    try:
        if deadline is not None and clock() >= deadline:
            raise TimeoutError('Frida executable staging deadline exceeded')
        if os.fstat(source_descriptor).st_size > MAX_STAGED_EXECUTABLE_BYTES:
            raise ValueError(f'workspace executable exceeds the {MAX_STAGED_EXECUTABLE_BYTES}-byte staging size limit')
        staging_directory = tempfile.TemporaryDirectory(prefix='ctf-frida-')
        staged_executable = os.path.join(staging_directory.name, 'target')
        staged_descriptor = os.open(
            staged_executable,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0),
            0o700,
        )
        total_bytes = 0
        while True:
            if deadline is not None and clock() >= deadline:
                raise TimeoutError('Frida executable staging deadline exceeded')
            chunk = os.read(source_descriptor, 1_048_576)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_STAGED_EXECUTABLE_BYTES:
                raise ValueError(f'workspace executable exceeds the {MAX_STAGED_EXECUTABLE_BYTES}-byte staging size limit')
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(staged_descriptor, remaining)
                remaining = remaining[written:]
        os.fchmod(staged_descriptor, 0o700)
        if deadline is not None and clock() >= deadline:
            raise TimeoutError('Frida executable staging deadline exceeded')
        return staging_directory, staged_executable
    except Exception:
        if staging_directory is not None:
            staging_directory.cleanup()
        raise
    finally:
        os.close(source_descriptor)
        if staged_descriptor is not None:
            os.close(staged_descriptor)


def _safe_message(message, data):
    item = {'message': _bounded_value(message, [MAX_MESSAGE_NODES])}
    if data is not None:
        raw = bytes(data[:MAX_BINARY_MESSAGE_BYTES])
        item['dataBase64'] = base64.b64encode(raw).decode('ascii')
        item['dataBytes'] = len(data)
        item['dataTruncated'] = len(raw) < len(data)
    encoded = json.dumps(item, ensure_ascii=True, default=str).encode('utf-8')
    if len(encoded) <= MAX_MESSAGE_BYTES:
        return item, len(encoded)
    fallback = {
        'message': {'truncated': True},
        'dataBytes': len(data) if data is not None else 0,
        'dataTruncated': data is not None,
    }
    return fallback, len(json.dumps(fallback).encode('utf-8'))


def _bounded_value(value, budget, depth=0):
    if budget[0] <= 0:
        return {'truncated': True}
    budget[0] -= 1
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) <= MAX_MESSAGE_STRING_CHARS:
            return value
        return {
            'text': value[:MAX_MESSAGE_STRING_CHARS],
            'originalCharacters': len(value),
            'truncated': True,
        }
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value[:MAX_BINARY_MESSAGE_BYTES])
        return {
            'base64': base64.b64encode(raw).decode('ascii'),
            'bytes': len(value),
            'truncated': len(raw) < len(value),
        }
    if depth >= MAX_MESSAGE_DEPTH:
        return {'truncated': True, 'originalItems': len(value) if hasattr(value, '__len__') else None}
    if isinstance(value, dict):
        bounded = {}
        for key, child in itertools.islice(value.items(), MAX_MESSAGE_ITEMS):
            key_text = key if isinstance(key, str) else type(key).__name__
            bounded[key_text[:MAX_MESSAGE_STRING_CHARS]] = _bounded_value(child, budget, depth + 1)
        if len(value) > MAX_MESSAGE_ITEMS:
            bounded['_truncatedItems'] = len(value) - MAX_MESSAGE_ITEMS
        return bounded
    if isinstance(value, (list, tuple)):
        bounded = [_bounded_value(child, budget, depth + 1) for child in itertools.islice(value, MAX_MESSAGE_ITEMS)]
        if len(value) > MAX_MESSAGE_ITEMS:
            bounded.append({'_truncatedItems': len(value) - MAX_MESSAGE_ITEMS})
        return bounded
    return {'type': type(value).__name__, 'truncated': True}


def _kill_process(pid):
    os.kill(pid, signal.SIGKILL)


def _process_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def execute(
    request,
    frida_module=None,
    wait=time.sleep,
    clock=time.monotonic,
    stop_event=None,
    kill_process=_kill_process,
    process_alive=_process_alive,
    timer_factory=threading.Timer,
):
    mode, workspace, executable = validate_request(request)
    timeout_ms = request.get('timeoutMs', 10_000)
    deadline = clock() + (timeout_ms / 1000)
    if frida_module is None:
        import frida as frida_module

    device = frida_module.get_local_device()
    spawned_pid = None
    session = None
    script = None
    timer = None
    staging_directory = None
    messages = []
    retained_bytes = 0
    omitted_messages = 0
    stopped = stop_event or threading.Event()
    detached_event = threading.Event()
    timeout_event = threading.Event()
    cleanup_errors = []
    watchdog_kill_error = None

    def on_message(message, data):
        nonlocal retained_bytes, omitted_messages
        item, item_bytes = _safe_message(message, data)
        if len(messages) >= MAX_MESSAGES or retained_bytes + item_bytes > MAX_RETAINED_MESSAGE_BYTES:
            omitted_messages += 1
            return
        messages.append(item)
        retained_bytes += item_bytes

    def kill_at_deadline():
        nonlocal watchdog_kill_error
        if timeout_event.is_set() or spawned_pid is None:
            return
        try:
            kill_process(spawned_pid)
        except ProcessLookupError:
            pass
        except Exception as error:
            watchdog_kill_error = error
        timeout_event.set()
        stopped.set()

    def on_detached(*_args):
        detached_event.set()
        stopped.set()

    observation = None
    operation_error = None
    try:
        staging_directory, staged_executable = _stage_workspace_executable(
            workspace, executable, deadline=deadline, clock=clock,
        )
        if clock() >= deadline:
            raise TimeoutError('Frida executable staging deadline exceeded')
        argv = request.get('argv', [])
        spawned_pid = device.spawn(staged_executable, [staged_executable, *argv])
        remaining = max(0, deadline - clock())
        if remaining == 0:
            kill_at_deadline()
        else:
            timer = timer_factory(remaining, kill_at_deadline)
            timer.daemon = True
            timer.start()

        session = device.attach(spawned_pid)
        if hasattr(session, 'on'):
            session.on('detached', on_detached)
        script = session.create_script(request['script'])
        script.on('message', on_message)
        script.load()
        if not timeout_event.is_set() and not stopped.is_set():
            device.resume(spawned_pid)
            while not stopped.is_set() and clock() < deadline:
                wait(min(0.05, max(0, deadline - clock())))
        observation = {
            'pid': spawned_pid,
            'messages': messages,
            'omittedMessages': omitted_messages,
            'observationEnd': 'timeout' if timeout_event.is_set() or clock() >= deadline else 'detached',
        }
    except Exception as error:
        operation_error = error
    finally:
        if timer is not None:
            timer.cancel()
            timer.join(timeout=1)
        if script is not None:
            try:
                script.unload()
            except Exception as error:
                if not detached_event.is_set():
                    cleanup_errors.append(f'script unload failed: {error}')
        if session is not None:
            try:
                session.detach()
            except Exception as error:
                cleanup_errors.append(f'session detach failed: {error}')
        if spawned_pid is not None and (not timeout_event.is_set() or watchdog_kill_error is not None):
            try:
                kill_process(spawned_pid)
            except ProcessLookupError:
                pass
            except Exception as error:
                if process_alive(spawned_pid):
                    if watchdog_kill_error is not None:
                        cleanup_errors.append(
                            f'timed-out child kill failed: {watchdog_kill_error}; final retry failed: {error}'
                        )
                    else:
                        cleanup_errors.append(f'spawned process termination failed: {error}')
        if staging_directory is not None:
            try:
                staging_directory.cleanup()
            except Exception as error:
                cleanup_errors.append(f'executable staging cleanup failed: {error}')

    result = observation or {'pid': spawned_pid}
    if operation_error is not None:
        result['error'] = str(operation_error)
    result['cleanupComplete'] = len(cleanup_errors) == 0
    result['cleanupErrors'] = cleanup_errors
    return result


def main():
    request = json.loads(sys.stdin.read())
    stopped = threading.Event()
    previous_handler = signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    try:
        try:
            result = execute(request, stop_event=stopped)
        except Exception as error:
            result = {'error': str(error), 'cleanupComplete': True, 'cleanupErrors': []}
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
    print(json.dumps(result, ensure_ascii=True, default=str))
    return 0 if result.get('cleanupComplete') and not result.get('error') else 1


if __name__ == '__main__':
    raise SystemExit(main())
