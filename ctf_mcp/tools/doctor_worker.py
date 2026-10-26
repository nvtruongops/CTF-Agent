import base64
import json
import os
import selectors
import signal
import subprocess
import sys
import time


MAX_INPUT_BYTES = 65_536
MAX_PROBES = 128
MAX_OUTPUT_BYTES = 900_000
MAX_PROBE_OUTPUT_BYTES = 65_536
TIMEOUT_SECONDS = 30
MAX_ARGS = 64
MAX_ARG_LENGTH = 8_192


def run_probe(probe):
    args = probe.get('argv')
    if (not isinstance(args, list) or not args or len(args) > MAX_ARGS
            or any(not isinstance(arg, str) or len(arg) > MAX_ARG_LENGTH for arg in args)):
        raise ValueError('each probe requires a non-empty argv of strings')

    try:
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
        selector = selectors.DefaultSelector()
        output = {'stdout': bytearray(), 'stderr': bytearray()}
        total_bytes = 0
        timed_out = False
        truncated = False
        for name, stream in (('stdout', process.stdout), ('stderr', process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        deadline = time.monotonic() + TIMEOUT_SECONDS
        while selector.get_map():
            events = selector.select(max(0, deadline - time.monotonic()))
            if not events and time.monotonic() >= deadline:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for key, _ in events:
                chunk = os.read(key.fd, 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                remaining = max(0, MAX_PROBE_OUTPUT_BYTES - total_bytes)
                retained = chunk[:remaining]
                output[key.data].extend(retained)
                total_bytes += len(retained)
                if len(retained) < len(chunk) and not truncated:
                    truncated = True
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        selector.close()
        exit_code = process.wait()
        if timed_out:
            exit_code = None
        stdout = bytes(output['stdout'])
        stderr = bytes(output['stderr'])
    except OSError as error:
        stdout = b''
        stderr = str(error).encode('utf-8', errors='replace')
        exit_code = None
        timed_out = False
        truncated = False
    return {
        'id': probe['id'],
        'exitCode': exit_code,
        'stdoutBase64': base64.b64encode(stdout).decode('ascii'),
        'stderrBase64': base64.b64encode(stderr).decode('ascii'),
        'timedOut': timed_out,
        'truncated': truncated,
    }


def run_request(raw):
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError('doctor worker input exceeds the limit')
    request = json.loads(raw)
    if not isinstance(request, dict):
        raise ValueError('doctor worker request must be an object')
    probes = request.get('probes')
    if not isinstance(probes, list) or len(probes) > MAX_PROBES:
        raise ValueError('doctor worker probe list exceeds the limit')
    ids = [probe.get('id') for probe in probes if isinstance(probe, dict)]
    if (len(ids) != len(probes) or any(not isinstance(item, str) or len(item) > 128 for item in ids)
            or len(set(ids)) != len(ids)):
        raise ValueError('doctor worker probe IDs must be unique strings')

    results = []
    total_bytes = 0
    previous_exit_code = None
    for probe in probes:
        if 'ifPreviousExitCode' in probe and probe['ifPreviousExitCode'] != previous_exit_code:
            result = {
                'id': probe['id'], 'exitCode': None, 'stdoutBase64': '',
                'stderrBase64': '', 'timedOut': False, 'truncated': False,
                'skipped': True,
            }
        else:
            result = run_probe(probe)
        previous_exit_code = result['exitCode']
        total_bytes += len(result['stdoutBase64']) + len(result['stderrBase64'])
        if total_bytes > MAX_OUTPUT_BYTES:
            raise ValueError('doctor worker output exceeds the limit')
        results.append(result)

    return {'results': results}


def main():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    sys.stdout.write(json.dumps(run_request(raw), ensure_ascii=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        sys.stdout.write(json.dumps({'error': str(error)}, ensure_ascii=True))
        raise SystemExit(1)
