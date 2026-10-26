import json
import sys
import unittest
from unittest.mock import patch

from ctf_mcp.tools import doctor_worker


class DoctorWorkerTests(unittest.TestCase):
    def test_runs_argv_without_a_shell_and_preserves_nonzero_exit(self):
        result = doctor_worker.run_probe({
            'id': 'one',
            'argv': [sys.executable, '-c', "import sys; print('out'); print('err', file=sys.stderr); sys.exit(7)"],
        })

        self.assertEqual(result['exitCode'], 7)
        self.assertEqual(result['stdoutBase64'], 'b3V0Cg==')
        self.assertEqual(result['stderrBase64'], 'ZXJyCg==')

    def test_timeout_is_reported(self):
        with patch.object(doctor_worker, 'TIMEOUT_SECONDS', 0.3):
            result = doctor_worker.run_probe({
                'id': 'slow',
                'argv': [sys.executable, '-c', "import time; print('partial', flush=True); time.sleep(2)"],
            })

        self.assertTrue(result['timedOut'])
        self.assertIsNone(result['exitCode'])
        self.assertEqual(result['stdoutBase64'], 'cGFydGlhbAo=')

    def test_probe_output_is_capped(self):
        result = doctor_worker.run_probe({
            'id': 'large',
            'argv': [sys.executable, '-c', f"import sys; sys.stdout.write('x' * {doctor_worker.MAX_PROBE_OUTPUT_BYTES + 1})"],
        })

        self.assertTrue(result['truncated'])
        self.assertEqual(len(result['stdoutBase64']), 4 * ((doctor_worker.MAX_PROBE_OUTPUT_BYTES + 2) // 3))
        self.assertEqual(result['stderrBase64'], '')

    def test_request_rejects_malformed_and_oversized_input(self):
        with self.assertRaises(json.JSONDecodeError):
            doctor_worker.run_request(b'{')
        with self.assertRaisesRegex(ValueError, 'input exceeds'):
            doctor_worker.run_request(b' ' * (doctor_worker.MAX_INPUT_BYTES + 1))

    def test_request_rejects_invalid_probe_argv(self):
        with self.assertRaisesRegex(ValueError, 'argv'):
            doctor_worker.run_request(b'{"probes":[{"id":"bad","argv":[]}]}')

    def test_conditional_group_probe_is_skipped_when_account_is_missing(self):
        probes = [
            {'id': 'uid', 'argv': ['id', '-u', 'ctfagent']},
            {'id': 'groups', 'argv': ['id', '-nG', 'ctfagent'], 'ifPreviousExitCode': 0},
        ]
        completed = {
            'id': 'uid', 'exitCode': 1, 'stdoutBase64': '', 'stderrBase64': '',
            'timedOut': False, 'truncated': False,
        }
        with patch.object(doctor_worker, 'run_probe', return_value=completed) as run:
            results = doctor_worker.run_request(json.dumps({'probes': probes}).encode())['results']

        self.assertEqual(run.call_count, 1)
        self.assertTrue(results[1]['skipped'])


if __name__ == '__main__':
    unittest.main()
