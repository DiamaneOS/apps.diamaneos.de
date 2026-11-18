#!/usr/bin/env python3
"""grapheneos-mirror.py fetch() against a local server that sends fuzzed HTTP responses.

Property checks:
- bytes are returned only for status 200 without redirect
- never more than the limit, in memory or written out
- a body shorter than its Content-Length is refused
- returned bytes are exactly what the server sent as the body.
Any other exception than Refused is recorded by type: it would stop a mirror run with a traceback.
"""
import http.client
import os
from pathlib import Path
import socket
import sys
import threading

import atheris

with atheris.instrument_imports():
    import fuzzlib
mirror = fuzzlib.load('grapheneos_mirror', 'grapheneos-mirror.py')
for name in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY'):
    os.environ.pop(name, None)

RESPONSE = [b'']
server = socket.socket()
server.bind(('127.0.0.1', 0))
server.listen(8)
PORT = server.getsockname()[1]


def serve():
    while True:
        conn, _ = server.accept()
        with conn:
            conn.settimeout(2)
            try:
                request = b''
                while b'\r\n\r\n' not in request:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    request += chunk
                conn.sendall(RESPONSE[0])
            except OSError:
                pass


threading.Thread(target=serve, daemon=True).start()
mirror.UPSTREAM = f'http://127.0.0.1:{PORT}'
STATUS = [b'200 OK', b'200 OK', b'301 Moved', b'302 Found', b'404 Not Found', b'206 Partial', b'500 Oops', b'204 No']


class Out:
    def __init__(self):
        self.data = bytearray()

    def write(self, block):
        self.data += block


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    status = STATUS[fdp.ConsumeIntInRange(0, len(STATUS) - 1)]
    limit = fdp.ConsumeIntInRange(0, 4096)
    body = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 6000))
    length_mode = fdp.ConsumeIntInRange(0, 4)
    chunked = fdp.ConsumeBool()
    to_out = fdp.ConsumeBool()
    extra = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 64)).replace(b'\r', b'').replace(b'\n', b'')
    headers = [b'HTTP/1.1 ' + status, b'Connection: close']
    declared = None
    if length_mode == 1:
        declared = len(body)
    elif length_mode == 2:
        declared = len(body) + fdp.ConsumeIntInRange(1, 100)
    elif length_mode == 3:
        declared = max(0, len(body) - fdp.ConsumeIntInRange(1, 100))
    if declared is not None:
        headers.append(b'Content-Length: ' + str(declared).encode())
    if status.startswith(b'30'):
        headers.append(b'Location: /elsewhere')
    if extra:
        headers.append(b'X-Fuzz: ' + extra)
    payload = body
    if chunked and declared is None:
        headers.append(b'Transfer-Encoding: chunked')
        payload = b''.join(b'%x\r\n%s\r\n' % (len(body[i:i + 700]), body[i:i + 700]) for i in range(0, len(body), 700))
        if fdp.ConsumeBool():
            payload += b'0\r\n\r\n'
    RESPONSE[0] = b'\r\n'.join(headers) + b'\r\n\r\n' + payload
    out = Out() if to_out else None
    try:
        result = mirror.fetch('file', limit, out)
    except mirror.Refused:
        return
    except (http.client.HTTPException, OSError, ValueError) as error:
        fuzzlib.record('fetch raised ' + type(error).__name__, data, repr(error))
        return
    except Exception as error:
        fuzzlib.record('fetch raised unexpected ' + fuzzlib.where(error), data, repr(error))
        return
    got = bytes(out.data) if to_out else result
    if not status.startswith(b'200'):
        fuzzlib.record('fetch returned a non-200 response', data, status.decode())
    if len(got) > limit:
        fuzzlib.record('fetch returned more than the limit', data)
    if declared is not None and len(got) != declared:
        fuzzlib.record('fetch returned a body other than Content-Length', data)
    sent = body if declared is None or declared >= len(body) else body[:declared]
    if got != sent and not (declared is None and not chunked and sent.startswith(got)):
        fuzzlib.record('fetch returned other bytes than the body', data)
    if declared is None and not chunked and got != body:
        fuzzlib.record('fetch returned a cut body without Content-Length', data)


def write_seeds(directory):
    os.makedirs(directory, exist_ok=True)
    (Path(directory) / 'seed-0').write_bytes(b'\x00\x10\x00\x20' + b'catalog bytes' * 10 + b'\x01\x00\x00\x00')


if __name__ == '__main__':
    if sys.argv[1:2] == ['seeds']:
        write_seeds(sys.argv[2])
    else:
        atheris.instrument_all()
        atheris.Setup(sys.argv, TestOneInput)
        atheris.Fuzz()
