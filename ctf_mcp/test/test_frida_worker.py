import base64
import json
import os
import tempfile
import threading
import unittest
import time
from contextlib import contextmanager
from unittest.mock import patch

from ctf_mcp.tools import frida_worker


class FakeDevice:
    def __init__(self, session=None):
        self.session = session or FakeSession()
        self.attached = []
        self.spawned = []
        self.resumed = []
        self.killed = []
        self.kill_error = None
        self.before_spawn = None
        self.capture_spawned_bytes = False
        self.spawned_contents = []

    def attach(self, pid):
        self.attached.append(pid)
        return self.session

    def spawn(self, executable, argv):
        if self.before_spawn:
            self.before_spawn(executable, argv)
        if self.capture_spawned_bytes:
            with open(executable, 'rb') as stream:
                self.spawned_contents.append(stream.read())
        self.spawned.append((executable, argv))
        return 42

    def resume(self, pid):
        self.resumed.append(pid)

    def kill(self, pid):
        if self.kill_error:
            raise self.kill_error
        self.killed.append(pid)


class FakeScript:
    def __init__(self, session):
        self.session = session
        self.handler = None
        self.unloaded = False
        self.unload_error = None
        self.load_delay = 0

    def on(self, event, handler):
        if event == 'message':
            self.handler = handler

    def load(self):
        if self.load_delay:
            time.sleep(self.load_delay)
        self.handler({'type': 'send', 'payload': {'ready': True}}, None)
        if self.session.detached_on_load and self.session.detached_handler:
            self.session.detached_handler('process-terminated')

    def unload(self):
        if self.unload_error:
            raise self.unload_error
        self.unloaded = True


class FakeSession:
    def __init__(self, detached_on_load=False):
        self.script = FakeScript(self)
        self.detached = False
        self.detached_on_load = detached_on_load
        self.detached_handler = None
        self.detach_error = None

    def on(self, event, handler):
        if event == 'detached':
            self.detached_handler = handler

    def create_script(self, source):
        self.source = source
        return self.script

    def detach(self):
        if self.detach_error:
            raise self.detach_error
        self.detached = True


class FakeFrida:
    def __init__(self, device):
        self.device = device

    def get_local_device(self):
        return self.device


class FridaWorkerTests(unittest.TestCase):
    @contextmanager
    def workspace_executable(self, contents=b'workspace executable'):
        workspace_root = '/home/ctfagent/ctf-workspaces'
        if not os.path.isdir(workspace_root) or not os.access(workspace_root, os.W_OK):
            raise unittest.SkipTest('ctfagent workspace root is not writable in this environment')
        with tempfile.TemporaryDirectory(prefix='test-frida-', dir=workspace_root) as workspace:
            executable = os.path.join(workspace, 'bin', 'game')
            os.makedirs(os.path.dirname(executable))
            with open(executable, 'wb') as stream:
                stream.write(contents)
            os.chmod(executable, 0o600)
            yield workspace, executable

    def test_process_path_must_be_nested_under_workspace(self):
        root = '/home/ctfagent/ctf-workspaces/chal1'

        self.assertTrue(frida_worker.is_within_workspace(root, f'{root}/bin/game'))
        self.assertFalse(frida_worker.is_within_workspace(root, '/home/ctfagent/.ssh/id_rsa'))
        self.assertFalse(frida_worker.is_within_workspace(root, root))

    def test_worker_rejects_a_workspace_redirected_by_a_symlink(self):
        root = '/home/ctfagent/ctf-workspaces/chal1'
        with patch.object(frida_worker.posixpath, 'realpath', return_value='/home/ctfagent/.ssh'):
            with self.assertRaisesRegex(ValueError, 'canonical'):
                frida_worker.validate_request({
                    'mode': 'spawn',
                    'workspace': root,
                    'artifactPath': f'{root}/game',
                    'script': 'send(1);',
                })

    def test_worker_rejects_non_spawn_modes(self):
        with self.assertRaisesRegex(ValueError, 'spawn'):
            frida_worker.validate_request({
                'mode': 'attach',
                'workspace': '/home/ctfagent/ctf-workspaces/chal1',
            })

    def test_worker_rejects_nul_in_script_or_argv(self):
        workspace = '/home/ctfagent/ctf-workspaces/chal1'
        with patch.object(frida_worker.os.path, 'isfile', return_value=True):
            with self.assertRaisesRegex(ValueError, 'NUL'):
                frida_worker.validate_request({
                    'mode': 'spawn', 'artifactPath': f'{workspace}/game', 'script': 'send(1);\0',
                    'workspace': workspace,
                })
            with self.assertRaisesRegex(ValueError, 'NUL'):
                frida_worker.validate_request({
                    'mode': 'spawn', 'artifactPath': f'{workspace}/game', 'argv': ['bad\0arg'],
                    'script': 'send(1);', 'workspace': workspace,
                })

    def test_artifact_open_rejects_a_symlinked_parent_directory(self):
        with self.workspace_executable() as (workspace, executable), \
                tempfile.TemporaryDirectory() as outside_directory:
            binary_directory = os.path.dirname(executable)
            os.unlink(executable)
            os.rmdir(binary_directory)
            os.symlink(outside_directory, binary_directory)

            with self.assertRaisesRegex(PermissionError, 'symlink'):
                frida_worker._open_workspace_artifact(workspace, executable)

    def test_spawn_uses_private_copy_if_workspace_path_changes_before_spawn(self):
        original_bytes = b'approved workspace executable'
        outside_bytes = b'outside workspace executable'
        with self.workspace_executable(original_bytes) as (workspace, executable), \
                tempfile.TemporaryDirectory() as outside_directory:
            outside_file = os.path.join(outside_directory, 'outside')
            with open(outside_file, 'wb') as stream:
                stream.write(outside_bytes)
            device = FakeDevice()
            device.capture_spawned_bytes = True

            def replace_workspace_file(_staged_path, _argv):
                os.unlink(executable)
                os.symlink(outside_file, executable)

            device.before_spawn = replace_workspace_file
            result = frida_worker.execute({
                'mode': 'spawn',
                'artifactPath': executable,
                'script': 'send(Process.id);',
                'timeoutMs': 100,
                'workspace': workspace,
            }, frida_module=FakeFrida(device), kill_process=device.kill)

        self.assertEqual(device.spawned_contents, [original_bytes])
        self.assertNotEqual(device.spawned[0][0], executable)
        self.assertEqual(device.killed, [42])
        self.assertTrue(result['cleanupComplete'])

    def test_safe_message_bounds_large_strings_and_binary_payloads_before_return(self):
        item, encoded_bytes = frida_worker._safe_message(
            {'type': 'send', 'payload': {'text': 'x' * 100_000}},
            b'x' * 100_000,
        )

        self.assertLessEqual(encoded_bytes, frida_worker.MAX_MESSAGE_BYTES)
        self.assertTrue(item['message']['payload']['text']['truncated'])
        self.assertTrue(item['dataTruncated'])
        self.assertEqual(item['dataBytes'], 100_000)
        self.assertLessEqual(len(base64.b64decode(item['dataBase64'])), frida_worker.MAX_BINARY_MESSAGE_BYTES)

    def test_spawn_resumes_then_kills_only_the_spawned_process(self):
        session = FakeSession()
        device = FakeDevice(session=session)
        device.capture_spawned_bytes = True
        with self.workspace_executable() as (workspace, executable):
            result = frida_worker.execute({
                'mode': 'spawn',
                'artifactPath': executable,
                'argv': ['--safe-mode'],
                'script': 'send(Process.id);',
                'timeoutMs': 100,
                'workspace': workspace,
            }, frida_module=FakeFrida(device), kill_process=device.kill)
            self.assertEqual(os.stat(executable).st_mode & 0o111, 0)

        spawned_executable, spawned_argv = device.spawned[0]
        self.assertEqual(spawned_argv, [spawned_executable, '--safe-mode'])
        self.assertNotEqual(spawned_executable, executable)
        self.assertEqual(device.spawned_contents, [b'workspace executable'])
        self.assertFalse(os.path.exists(spawned_executable))
        self.assertEqual(device.resumed, [42])
        self.assertEqual(device.killed, [42])
        self.assertTrue(session.script.unloaded)
        self.assertTrue(session.detached)
        self.assertEqual(result['pid'], 42)

    def test_staging_rejects_executables_over_the_size_limit(self):
        with self.workspace_executable(contents=b'12345') as (workspace, executable):
            staged = None
            try:
                with patch.object(frida_worker, 'MAX_STAGED_EXECUTABLE_BYTES', 4, create=True):
                    with self.assertRaisesRegex(ValueError, 'staging size limit'):
                        staged = frida_worker._stage_workspace_executable(workspace, executable)
            finally:
                if staged is not None:
                    staged[0].cleanup()

    def test_staging_deadline_exhaustion_prevents_frida_spawn(self):
        session = FakeSession()
        device = FakeDevice(session=session)
        elapsed = [0.0]
        original_stage = frida_worker._stage_workspace_executable

        def delayed_stage(workspace, executable, deadline=None, clock=None):
            elapsed[0] += 0.2
            if deadline is None:
                return original_stage(workspace, executable)
            return original_stage(workspace, executable, deadline=deadline, clock=clock)

        with self.workspace_executable() as (workspace, executable):
            with patch.object(frida_worker, '_stage_workspace_executable', side_effect=delayed_stage):
                result = frida_worker.execute({
                    'mode': 'spawn',
                    'artifactPath': executable,
                    'script': 'send(Process.id);',
                    'timeoutMs': 100,
                    'workspace': workspace,
                }, frida_module=FakeFrida(device), clock=lambda: elapsed[0])

        self.assertEqual(device.spawned, [])
        self.assertIn('staging deadline', result['error'])
        self.assertTrue(result['cleanupComplete'])

    def test_deadline_covers_slow_script_load_and_prevents_resume(self):
        session = FakeSession(detached_on_load=False)
        session.script.load_delay = 0.05
        device = FakeDevice(session=session)
        with self.workspace_executable() as (workspace, executable):
            result = frida_worker.execute({
                'mode': 'spawn',
                'artifactPath': executable,
                'script': 'send(Process.id);',
                'timeoutMs': 10,
                'workspace': workspace,
            }, frida_module=FakeFrida(device), kill_process=device.kill)

        self.assertEqual(device.killed, [42])
        self.assertEqual(device.resumed, [])
        self.assertEqual(result['observationEnd'], 'timeout')
        self.assertTrue(result['cleanupComplete'])

    def test_finalizer_retries_a_failed_watchdog_kill(self):
        class ImmediateTimer:
            def __init__(self, _interval, callback):
                self.callback = callback
                self.daemon = False

            def start(self):
                self.callback()

            def cancel(self):
                pass

            def join(self, timeout=None):
                pass

        with self.workspace_executable() as (workspace, executable):
            session = FakeSession()
            device = FakeDevice(session=session)
            attempts = []

            def fail_once_then_kill(pid):
                attempts.append(pid)
                if len(attempts) == 1:
                    raise OSError('temporary kill failure')
                device.killed.append(pid)

            result = frida_worker.execute({
                'mode': 'spawn',
                'artifactPath': executable,
                'script': 'send(Process.id);',
                'timeoutMs': 100,
                'workspace': workspace,
            }, frida_module=FakeFrida(device), kill_process=fail_once_then_kill, timer_factory=ImmediateTimer)

        self.assertEqual(attempts, [42, 42])
        self.assertEqual(device.killed, [42])
        self.assertEqual(device.resumed, [])
        self.assertEqual(result['observationEnd'], 'timeout')
        self.assertTrue(result['cleanupComplete'])

    def test_natural_detach_does_not_report_destroyed_script_as_cleanup_failure(self):
        session = FakeSession(detached_on_load=True)
        session.script.unload_error = RuntimeError('script is destroyed')
        device = FakeDevice(session=session)

        with self.workspace_executable() as (workspace, executable):
            result = frida_worker.execute({
                'mode': 'spawn',
                'artifactPath': executable,
                'script': 'send(Process.id);',
                'timeoutMs': 10_000,
                'workspace': workspace,
            }, frida_module=FakeFrida(device), kill_process=device.kill)

        self.assertEqual(result['observationEnd'], 'detached')
        self.assertEqual(result['cleanupErrors'], [])
        self.assertTrue(result['cleanupComplete'])
        self.assertEqual(device.killed, [42])

    def test_cleanup_failures_are_returned_and_not_hidden(self):
        session = FakeSession()
        session.script.unload_error = RuntimeError('unload failed')
        session.detach_error = RuntimeError('detach failed')
        device = FakeDevice(session=session)
        stopped = threading.Event()
        stopped.set()
        with self.workspace_executable() as (workspace, executable):
            result = frida_worker.execute({
                'mode': 'spawn',
                'artifactPath': executable,
                'script': 'send(Process.id);',
                'timeoutMs': 10_000,
                'workspace': workspace,
            }, frida_module=FakeFrida(device), kill_process=device.kill, stop_event=stopped)

        self.assertFalse(result['cleanupComplete'])
        self.assertEqual(len(result['cleanupErrors']), 2)
        self.assertEqual(device.killed, [42])


if __name__ == '__main__':
    unittest.main()
