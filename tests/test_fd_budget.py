"""Loopback-only resource regression. Run after cargo build.

The child's hard limit is 256, so startup cannot raise away the condition.
The real daemon, user config and system proxy are never touched.
"""
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FdBudgetTest(unittest.TestCase):
    def test_overload_preserves_tunnels_and_recovers(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            with socket.socket() as origin:
                origin.bind(('127.0.0.1', 0))
                origin.listen(128)
                origin.settimeout(0.2)
                stop = threading.Event()

                def echo(conn):
                    with conn:
                        conn.settimeout(0.2)
                        while not stop.is_set():
                            try:
                                data = conn.recv(4096)
                                if not data:
                                    return
                                conn.sendall(data)
                            except socket.timeout:
                                continue
                            except OSError:
                                return

                def serve():
                    while not stop.is_set():
                        try:
                            conn, _ = origin.accept()
                        except socket.timeout:
                            continue
                        except OSError:
                            return
                        threading.Thread(target=echo, args=(conn,), daemon=True).start()

                # Choose a separate loopback proxy port before starting the child.
                with socket.socket() as port_socket:
                    port_socket.bind(('127.0.0.1', 0))
                    port = port_socket.getsockname()[1]
                config = home / 'config.yaml'
                config.write_text(f'mixed-port: {port}\nmode: direct\ndns:\n  enable: false\n')

                def low_limit():
                    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))

                with (home / 'daemon.log').open('w+') as log:
                    proc = subprocess.Popen(
                        [str(ROOT / 'target/debug/clashx-rs'), '-c', str(config), 'run'],
                        env={**os.environ, 'HOME': tmp}, preexec_fn=low_limit,
                        stdout=log, stderr=log)
                    tunnels = []
                    worker = threading.Thread(target=serve, daemon=True)
                    worker.start()
                    try:
                        control = home / f'.config/clashx-rs/clashx-rs-{port}.sock'

                        def request(command='status'):
                            with socket.socket(socket.AF_UNIX) as s:
                                s.settimeout(2)
                                s.connect(str(control))
                                s.sendall(json.dumps({'command': command}).encode() + b'\n')
                                with s.makefile('rb') as reader:
                                    result = json.loads(reader.readline())
                                self.assertTrue(result['ok'], result)
                                return result.get('data')

                        for _ in range(100):
                            if control.exists():
                                break
                            self.assertIsNone(proc.poll(), 'daemon exited before readiness')
                            time.sleep(0.05)
                        budget = request()['resources']
                        self.assertEqual(budget['fd_soft_limit'], 256)
                        limit = budget['connection_limit']
                        self.assertGreater(limit, 0)
                        self.assertLess(limit * 2, 256)

                        def tunnel():
                            s = socket.create_connection(('127.0.0.1', port), timeout=2)
                            tunnels.append(s)
                            target = f'127.0.0.1:{origin.getsockname()[1]}'
                            s.sendall(f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n'.encode())
                            response = b''
                            while b'\r\n\r\n' not in response:
                                chunk = s.recv(4096)
                                self.assertTrue(chunk)
                                response += chunk
                            self.assertIn(b'200', response)
                            s.sendall(b'alive')
                            self.assertEqual(s.recv(5), b'alive')
                            return s

                        for _ in range(limit):
                            tunnel()
                        for _ in range(12):
                            with socket.create_connection(('127.0.0.1', port), timeout=2) as extra:
                                try:
                                    self.assertEqual(extra.recv(1), b'')
                                except ConnectionResetError:
                                    pass
                        full = request()['resources']
                        self.assertEqual(full['active_connections'], limit)
                        self.assertGreaterEqual(full['overload_count'], 12)
                        # Reload must not replace the process-wide semaphore.
                        request('reload')
                        self.assertEqual(request()['resources']['active_connections'], limit)
                        tunnels[0].sendall(b'still alive')
                        self.assertEqual(tunnels[0].recv(11), b'still alive')
                        for s in tunnels:
                            s.close()
                        tunnels.clear()
                        for _ in range(100):
                            if request()['resources']['active_connections'] == 0:
                                break
                            time.sleep(0.05)
                        self.assertEqual(request()['resources']['active_connections'], 0)
                        tunnel()
                        self.assertIsNone(proc.poll())
                    finally:
                        for s in tunnels:
                            s.close()
                        proc.terminate()
                        proc.wait(timeout=10)
                        stop.set()
                        worker.join(timeout=2)
                    log.seek(0)
                    output = log.read()
                    self.assertNotIn('Too many open files', output)
                    self.assertLessEqual(output.count('proxy resource pressure'), 2)
