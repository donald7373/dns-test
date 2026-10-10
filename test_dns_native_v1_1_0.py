"""Native behavior suite. Requires real PySide6; QT_QPA_PLATFORM=offscreen.
Run with Python 3.10+ / PySide6-Essentials: -m unittest -v test_dns_native_v1_1_0
"""
import importlib.util
import pathlib
import tempfile
import unittest
import os
import socket
import struct
import threading
import time

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
SOURCE = pathlib.Path(__file__).with_name('dns_test_v1.1.0.py')

class NativeTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SOURCE.exists(), 'Native single-file application is missing')
        spec = importlib.util.spec_from_file_location('dns_native', SOURCE)
        self.app = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.app)
        self.qt = self.app.QApplication.instance() or self.app.QApplication([])
        self.temp = tempfile.TemporaryDirectory()
        self.window = self.app.MainWindow(settings_path=str(pathlib.Path(self.temp.name) / 'settings.ini'))

    def tearDown(self):
        if hasattr(self, 'window'):
            self.window.close()
            self.qt.processEvents()
            self.temp.cleanup()

    def test_real_udp_benchmark_updates_native_charts_exports_and_cancels(self):
        import socket, struct, threading, time
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.settimeout(.1)
        stop = threading.Event()
        def answer():
            while not stop.is_set():
                try:
                    query, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                packet = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + query[12:]
                packet += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('1.2.3.4')
                sock.sendto(packet, addr)
        thread = threading.Thread(target=answer)
        thread.start()
        def pump_until(predicate):
            deadline = time.monotonic() + 6
            while not predicate() and time.monotonic() < deadline:
                self.qt.processEvents()
                time.sleep(.01)
            self.assertTrue(predicate(), 'GUI benchmark did not settle')
        try:
            w = self.window
            w.probe = lambda ip, domain, **kw: self.app.query_dns(ip, domain, port=port, **kw)
            w.replace_servers([{'ip': '127.0.0.1', 'name': 'LAN'}])
            w.rounds.setValue(10)
            w.domains.setPlainText('example.com')
            w.start_benchmark()
            self.assertFalse(w.start_button.isEnabled())
            self.assertTrue(w.stop_button.isEnabled())
            self.assertFalse(w.server_list.isEnabled())
            with self.assertRaises(ValueError):
                w.start_benchmark()
            pump_until(lambda: w.state['status'] == 'done')
            self.assertEqual(w.state['completed'], 10)
            self.assertEqual(w.state['servers'][0]['success'], 10)
            self.assertEqual(w.state['recommended'], ['127.0.0.1'])
            self.assertEqual(w.ranking.rowCount(), 1)
            self.assertIn('127.0.0.1', w.legend.text())
            self.assertEqual(w.line_chart.state['completed'], 10)
            self.assertTrue(w.start_button.isEnabled())
            self.assertFalse(w.stop_button.isEnabled())
            report = pathlib.Path(self.temp.name) / 'result.csv'
            w.export_csv(report)
            self.assertTrue(report.read_bytes().startswith(b'\xef\xbb\xbf'))
            self.assertIn('1.2.3.4', report.read_text(encoding='utf-8-sig'))
            w.start_benchmark()
            w.stop_benchmark()
            pump_until(lambda: w.state['status'] == 'cancelled')
            self.assertEqual(w.state['recommended'], [])
            w.start_benchmark()
            w.close()
            pump_until(lambda: not w.job.thread.is_alive())
            self.assertFalse(w.isVisible())
        finally:
            stop.set()
            thread.join(2)
            sock.close()

    def test_selection_validation_and_atomic_config_roundtrip(self):
        import json
        w = self.window
        w.replace_servers([{'name': 'LAN', 'ip': '127.0.0.1', 'enabled': True}])
        w.add_server('2001:db8::1', 'IPv6')
        self.assertEqual(len(w.configuration()['servers']), 2)
        w.server_list.item(1).setCheckState(self.app.Qt.CheckState.Unchecked)
        self.assertEqual(len(w.configuration()['servers']), 1)
        for ip in ('hostname.invalid', '224.0.0.1', '0.0.0.0', '127.0.0.1'):
            with self.assertRaises(ValueError):
                w.add_server(ip, 'invalid')
        target = pathlib.Path(self.temp.name) / 'config.json'
        w.qtype.setCurrentIndex(1)
        w.warmup.setChecked(False)
        w.save_config(target)
        w.remove_server(1)
        w.import_config(target)
        self.assertEqual(w.server_list.count(), 2)
        self.assertEqual(w.qtype.currentData(), 'AAAA')
        self.assertFalse(w.warmup.isChecked())
        self.assertFalse(w.server_list.item(1).checkState() == self.app.Qt.CheckState.Checked)
        before = w.config_document()
        target.write_text(json.dumps({'servers': [{'ip': 'not-an-ip'}]}), encoding='utf-8')
        with self.assertRaises(ValueError):
            w.import_config(target)
        self.assertEqual(w.config_document(), before)
        w.persist_settings()
        w.close()
        restored = self.app.MainWindow(settings_path=str(pathlib.Path(self.temp.name) / 'settings.ini'))
        self.assertEqual(restored.config_document(), before)
        restored.close()

    def test_smoke_cli_runs_real_gui_and_udp_writes_artifacts(self):
        import socket, struct, threading, subprocess, sys, json
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.settimeout(.1)
        stop = threading.Event()
        def reply():
            while not stop.is_set():
                try:
                    query, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                packet = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + query[12:]
                sock.sendto(packet + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('1.2.3.4'), addr)
        thread = threading.Thread(target=reply)
        thread.start()
        try:
            output = pathlib.Path(self.temp.name) / 'smoke'
            result = subprocess.run([sys.executable, str(SOURCE), '--smoke-test', str(output), '--server', '127.0.0.1', '--dns-port', str(port)], capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8', errors='replace'))
            self.assertTrue((output / 'outcome.json').exists(), 'Smoke developer entrypoint did not produce real output')
            state = json.loads((output / 'outcome.json').read_text(encoding='utf-8'))
            self.assertEqual(state['status'], 'done')
            self.assertEqual(state['completed'], 10)
            self.assertEqual(state['servers'][0]['success'], 10)
            self.assertEqual(state['servers'][0]['samples'][0]['answers'], ['1.2.3.4'])
            self.assertTrue(state['native_window_visible'])
            self.assertEqual(state['qt_platform'], self.qt.platformName())
            self.assertTrue((output / 'screenshot.png').read_bytes().startswith(b'\x89PNG'))
            self.assertTrue((output / 'results.csv').read_bytes().startswith(b'\xef\xbb\xbf'))
        finally:
            stop.set()
            thread.join(2)
            sock.close()

    def test_32_server_limit_and_ip_legend_colors_match_first_render(self):
        servers = [{'ip': f'10.0.0.{i}', 'name': 'Ten sam DNS'} for i in range(1, 33)]
        self.window.replace_servers(servers)
        with self.assertRaises(ValueError):
            self.window.add_server('10.0.0.33')
        self.assertEqual(self.window.server_list.count(), 32)
        self.window.replace_servers(servers[:2])
        config = self.window.configuration()
        job = self.app.Benchmark(config)
        self.window.job = job
        self.window.state = job.snapshot()
        self.window.render_state()
        self.assertEqual(self.window.ranking.item(1, 0).foreground().color(), self.window.line_chart.color('10.0.0.2'))
        self.assertIn('10.0.0.1', self.window.legend.text())
        self.assertIn('10.0.0.2', self.window.legend.text())

    def test_timeout_only_results_remain_failures_and_close_is_nonblocking(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        w = self.window
        w.probe = lambda ip, domain, **kw: self.app.query_dns(ip, domain, port=port, **kw)
        w.replace_servers([{'ip': '127.0.0.1'}])
        w.timeout.setValue(200)
        w.rounds.setValue(10)
        w.warmup.setChecked(False)
        w.domains.setPlainText('example.com')
        try:
            w.show()
            w.start_button.click()
            deadline = time.monotonic() + 6
            while w.state['status'] == 'running' and time.monotonic() < deadline:
                self.qt.processEvents()
                time.sleep(.01)
            self.assertEqual(w.state['status'], 'done')
            self.assertEqual(w.state['servers'][0]['success'], 0)
            self.assertEqual(w.state['servers'][0]['errors'], 10)
            self.assertIsNone(w.state['servers'][0]['median'])
            self.assertEqual(w.state['recommended'], [])
            self.assertEqual(w.ranking.item(0, 1).text(), '—')
            self.assertEqual(w.cards[2].value.text(), '0.0%')
            w.start_benchmark()
            time.sleep(.03)
            started = time.monotonic()
            w.close()
            self.assertLess(time.monotonic() - started, .15, 'Close blocked the UI')
            deadline = time.monotonic() + 2
            while (w.job.thread.is_alive() or w.isVisible()) and time.monotonic() < deadline:
                self.qt.processEvents()
                time.sleep(.01)
            self.qt.processEvents()
            self.assertFalse(w.job.thread.is_alive())
            self.assertFalse(w.isVisible())
            self.assertEqual(w.job.snapshot()['status'], 'cancelled')
        finally:
            sock.close()

    def test_native_layout_has_thin_meters_legends_and_diagnostic_limits(self):
        w = self.window
        w.resize(1152, 720)
        w.show()
        self.qt.processEvents()
        self.assertEqual(w.report_scroll.horizontalScrollBar().maximum(), 0)
        self.assertLessEqual(w.progress.height(), 6)
        self.assertTrue(hasattr(w, 'color_legend'))
        self.assertIn('DNSSEC', w.interpretation.text())
        self.assertIn('DoH', w.interpretation.text())
        self.assertIn('cache', w.interpretation.text())
        self.assertGreater(w.sidebar_scroll.verticalScrollBar().maximum(), 0)

    def test_system_dns_detection_runs_off_ui_thread_and_unlocks_start(self):
        w = self.window
        w.begin_detection()
        self.assertFalse(w.start_button.isEnabled())
        deadline = time.monotonic() + 12
        while (w._dns_thread.is_alive() or w._dns_result is not None or not w.start_button.isEnabled()) and time.monotonic() < deadline:
            self.qt.processEvents()
            time.sleep(.01)
        self.assertFalse(w._dns_thread.is_alive())
        self.assertTrue(w.start_button.isEnabled())
        self.assertTrue(w.detect_button.isEnabled())
        self.assertLessEqual(w.server_list.count(), 32)
        self.assertTrue('systemowych' in w.status_label.text() or 'Nie wykryto' in w.status_label.text())

    def test_real_native_window_constructs_with_empty_results(self):
        self.window.show()
        self.qt.processEvents()
        self.assertTrue(self.window.isVisible())
        self.assertEqual(self.window.state['status'], 'idle')
        self.assertEqual(self.window.ranking.rowCount(), 0)
        self.assertTrue(self.window.start_button.isEnabled())
        self.assertFalse(self.window.stop_button.isEnabled())
        self.assertEqual(self.window.rounds.minimum(), 10)
        self.assertEqual(self.window.rounds.maximum(), 200)
        self.assertEqual(self.window.timeout.minimum(), 200)
        self.assertEqual(self.window.timeout.maximum(), 5000)
        self.assertFalse(hasattr(self.app, 'make_server'))
        self.assertFalse(hasattr(self.app, 'HTML'))



class EngineTests(unittest.TestCase):
    def setUp(self):
            self.assertTrue(SOURCE.exists(), 'Single-file DNS program has not been implemented')
            spec = importlib.util.spec_from_file_location('dns_test', SOURCE)
            self.app = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.app)

    def test_actual_dns_response_on_udp(self):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            sock.settimeout(3)
            def answer():
                try:
                    query, addr = sock.recvfrom(4096)
                    header = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)
                    reply = header + query[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('93.184.216.34')
                    sock.sendto(reply, addr)
                finally:
                    sock.close()
            thread = threading.Thread(target=answer)
            thread.start()
            result = self.app.query_dns('127.0.0.1', 'example.com', timeout=1, port=sock.getsockname()[1])
            thread.join(3)
            self.assertTrue(result['ok'])
            self.assertEqual(result['answers'], ['93.184.216.34'])
            self.assertGreater(result['ms'], 0)
            self.assertEqual(result['transport'], 'UDP')

    def test_statistics_count_errors_and_do_not_recommend_incomplete_runs(self):
            samples = [{'ok': True, 'ms': value} for value in (10, 20, 30)]
            samples.append({'ok': False, 'ms': 1500})
            summary = self.app.summarize(samples)
            self.assertEqual(summary['attempts'], 4)
            self.assertEqual(summary['success'], 3)
            self.assertEqual(summary['loss'], 25)
            self.assertEqual(summary['median'], 20)
            self.assertEqual(summary['p95'], 30)
            self.assertFalse(summary['eligible'])

    def test_config_rejects_hostnames_bad_domains_and_excessive_work(self):
            config = {'servers': [{'name': 'LAN', 'ip': '127.0.0.1'}], 'domains': ['example.com'], 'rounds': 10, 'timeout': 500, 'qtype': 'A'}
            valid = self.app.validate_config(config)
            self.assertEqual(valid['servers'][0]['ip'], '127.0.0.1')
            for key, value in [('servers', [{'ip': 'localhost'}]), ('rounds', 9999), ('domains', ['bad..example'])]:
                with self.subTest(key=key):
                    with self.assertRaises(ValueError):
                        self.app.validate_config(dict(config, **{key: value}))

    def test_completed_benchmark_uses_real_dns_and_recommends_server(self):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
            sock.settimeout(.1)
            stop = threading.Event()
            def answer():
                while not stop.is_set():
                    try:
                        query, addr = sock.recvfrom(4096)
                    except socket.timeout:
                        continue
                    header = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)
                    sock.sendto(header + query[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 1, 4) + socket.inet_aton('1.2.3.4'), addr)
            thread = threading.Thread(target=answer)
            thread.start()
            try:
                config = self.app.validate_config({'servers': [{'ip': '127.0.0.1'}], 'domains': ['example.com'], 'rounds': 10, 'timeout': 500})
                job = self.app.Benchmark(config, probe=lambda ip, domain, **kw: self.app.query_dns(ip, domain, port=port, **kw))
                job.start()
                job.thread.join(5)
                result = job.snapshot()
                self.assertEqual(result['status'], 'done')
                self.assertEqual(result['completed'], 10)
                self.assertEqual(result['servers'][0]['success'], 10)
                self.assertEqual(result['recommended'][0], '127.0.0.1')
            finally:
                stop.set()
                thread.join(2)
                sock.close()

    def test_tcp_fallback_after_truncated_udp(self):
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.bind(('127.0.0.1', 0))
            port = tcp.getsockname()[1]
            tcp.listen(1)
            tcp.settimeout(3)
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(('127.0.0.1', port))
            udp.settimeout(3)
            def reply():
                try:
                    query, address = udp.recvfrom(4096)
                    udp.sendto(query[:2] + struct.pack('!HHHHH', 0x8380, 1, 0, 0, 0) + query[12:], address)
                    conn, _ = tcp.accept()
                    with conn:
                        size = struct.unpack('!H', self.app.receive_exact(conn, 2))[0]
                        query = self.app.receive_exact(conn, size)
                        packet = query[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0) + query[12:]
                        packet += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 1, 4) + socket.inet_aton('1.2.3.4')
                        conn.sendall(struct.pack('!H', len(packet)) + packet[:3])
                        conn.sendall(packet[3:])
                finally:
                    tcp.close()
                    udp.close()
            thread = threading.Thread(target=reply)
            thread.start()
            try:
                result = self.app.query_dns('127.0.0.1', 'example.com', timeout=2, port=port)
                self.assertTrue(result['ok'])
                self.assertEqual(result['transport'], 'TCP')
                self.assertEqual(result['answers'], ['1.2.3.4'])
            finally:
                thread.join(4)

    def test_malformed_and_unrelated_responses_are_rejected(self):
            question = self.app.encode_domain('example.com') + struct.pack('!HH', 1, 1)
            header = struct.pack('!6H', 42, 0x8180, 1, 1, 0, 0)
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 1, 4) + socket.inet_aton('1.2.3.4')
            for packet, ident, domain in [(b'bad', 42, 'example.com'), (header + question + answer, 41, 'example.com'), (header + question + answer, 42, 'other.com'), (header + question + answer[:-1], 42, 'example.com'), (header + b'\xc0\x0c', 42, 'example.com')]:
                with self.subTest(packet=packet):
                    with self.assertRaises(ValueError):
                        self.app.parse_response(packet, ident, domain, 1)

    def test_aaaa_and_error_codes(self):
            question = self.app.encode_domain('example.com') + struct.pack('!HH', 28, 1)
            header = struct.pack('!6H', 42, 0x8180, 1, 1, 0, 0)
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, '2001:db8::1')
            result = self.app.parse_response(header + question + answer, 42, 'example.com', 28)
            self.assertEqual(result['answers'], ['2001:db8::1'])
            for rcode in (2, 3, 5):
                packet = struct.pack('!6H', 42, 0x8180 | rcode, 1, 0, 0, 0) + question
                result = self.app.parse_response(packet, 42, 'example.com', 28)
                self.assertEqual(result['rcode'], rcode)
                self.assertFalse(result['answers'])

    def test_cancelled_benchmark_has_no_recommendation(self):
            config = self.app.validate_config({'servers': [{'ip': '127.0.0.1'}], 'domains': ['example.com']})
            job = self.app.Benchmark(config)
            job.cancel.set()
            job.start()
            job.thread.join(2)
            state = job.snapshot()
            self.assertEqual(state['status'], 'cancelled')
            self.assertEqual(state['recommended'], [])
            self.assertEqual(state['completed'], 0)

    def test_timeout_is_failure_not_fast_success(self):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            try:
                result = self.app.query_dns('127.0.0.1', 'example.com', timeout=.05, port=sock.getsockname()[1])
                self.assertFalse(result['ok'])
                self.assertEqual(result['error'], 'Timeout')
                self.assertGreaterEqual(result['ms'], 45)
            finally:
                sock.close()

    def test_tcp_header_cannot_extend_total_timeout(self):
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.bind(('127.0.0.1', 0))
            port = tcp.getsockname()[1]
            tcp.listen(1)
            tcp.settimeout(2)
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(('127.0.0.1', port))
            udp.settimeout(2)
            def reply():
                try:
                    query, address = udp.recvfrom(4096)
                    udp.sendto(query[:2] + struct.pack('!HHHHH', 0x8380, 1, 0, 0, 0) + query[12:], address)
                    conn, _ = tcp.accept()
                    with conn:
                        conn.recv(4096)
                        time.sleep(.2)
                        conn.sendall(b'\x00')
                        time.sleep(.2)
                        conn.sendall(b'\x20')
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    tcp.close()
                    udp.close()
            thread = threading.Thread(target=reply)
            thread.start()
            try:
                result = self.app.query_dns('127.0.0.1', 'example.com', timeout=.3, port=port)
                self.assertFalse(result['ok'])
                self.assertLess(result['ms'], 370, 'TCP framing extended the timeout budget')
            finally:
                thread.join(3)

    def test_csv_export_escapes_spreadsheet_formulas(self):
            config = self.app.validate_config({'servers': [{'name': '=1+1', 'ip': '127.0.0.1'}], 'domains': ['example.com']})
            job = self.app.Benchmark(config)
            report = self.app.csv_report(job.snapshot())
            self.assertTrue(report.startswith('\ufeff'))
            self.assertIn("'=1+1", report)

if __name__ == '__main__':
    unittest.main()
