#!/usr/bin/env python3
"""DNS Test 1.1.0 — natywny pulpit Qt, bez przeglądarki.
Python 3.10+ i PySide6-Essentials (QtCore, QtGui, QtWidgets).
Uruchomienie: python dns_test_v1.1.0.py
Nie zmienia ustawień DNS systemu. Brak telemetrii.
"""
import argparse
import concurrent.futures
import csv
import io
import ipaddress
import json
import math
import os
import random
import secrets
import socket
import statistics
import struct
import sys
import threading
import time
from pathlib import Path
from PySide6.QtCore import Qt, QTimer, QSettings, QPointF, QRectF
from PySide6.QtGui import QColor, QPainter, QPen, QPainterPath, QFont, QIcon, QPixmap
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout, QScrollArea, QListWidget,
    QListWidgetItem, QLineEdit, QPlainTextEdit, QSpinBox, QComboBox, QCheckBox,
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog)
VERSION = '1.1.0'
COLORS = ['#77e3c1', '#a59cff', '#73baff', '#ffc979', '#ff8295', '#88d7fa', '#d2aaef', '#b7db83']
STYLE = """
QWidget { background: #0a0d14; color: #edf3ff; font: 10pt 'Segoe UI'; }
QLabel { background: transparent; }
QLabel#title { font-size: 23pt; font-weight: 700; }
QLabel#muted { color: #91a0b9; }
QWidget#panel { background: #111621; border: 1px solid #263044; border-radius: 9px; }
QPushButton { background: #18202e; border: 1px solid #263044; border-radius: 6px; padding: 8px 11px; }
QPushButton:hover { border-color: #77e3c1; }
QPushButton:disabled { color: #59657a; }
QPushButton#primary { background: #77e3c1; color: #10291f; font-weight: 700; }
QLineEdit, QPlainTextEdit, QSpinBox, QComboBox, QListWidget, QTableWidget { background: #0c111b; border: 1px solid #263044; border-radius: 5px; padding: 5px; }
QHeaderView::section { background: #18202e; padding: 7px; border: 0; }
QProgressBar { background: #263044; border: 0; border-radius: 2px; height: 4px; }
QProgressBar::chunk { background: #77e3c1; border-radius: 2px; }
QScrollArea { border: 0; }
QScrollBar:vertical { background: #111621; width: 10px; }
QScrollBar::handle:vertical { background: #263044; min-height: 25px; }
"""

def encode_domain(domain):
    domain = domain.strip().rstrip('.')
    if not domain:
        raise ValueError('Pusta nazwa domeny')
    labels = domain.encode('idna').split(b'.')
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError('Nieprawidłowa etykieta domeny')
    wire = b''.join(bytes([len(label)]) + label for label in labels) + b'\0'
    if len(wire) > 255:
        raise ValueError('Nazwa domeny jest za długa')
    return wire

def read_name(packet, offset):
    labels, next_offset, visited = [], None, set()
    while True:
        if offset >= len(packet) or offset in visited:
            raise ValueError('Uszkodzona nazwa DNS')
        visited.add(offset)
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError('Niepełny wskaźnik DNS')
            if next_offset is None:
                next_offset = offset + 2
            offset = ((length & 0x3F) << 8) | packet[offset + 1]
            continue
        if length & 0xC0:
            raise ValueError('Nieprawidłowa kompresja DNS')
        offset += 1
        if length == 0:
            return b'.'.join(labels).lower(), next_offset if next_offset is not None else offset
        if offset + length > len(packet):
            raise ValueError('Niepełna etykieta DNS')
        labels.append(packet[offset:offset + length])
        offset += length

def parse_response(packet, query_id, domain, qtype):
    if len(packet) < 12:
        raise ValueError('Zbyt krótka odpowiedź DNS')
    ident, flags, qd, an, ns, ar = struct.unpack('!6H', packet[:12])
    if ident != query_id or not flags & 0x8000 or flags & 0x7800:
        raise ValueError('Odpowiedź nie pasuje do zapytania')
    if qd != 1:
        raise ValueError('Nieprawidłowa liczba pytań')
    name, offset = read_name(packet, 12)
    expected = domain.strip().rstrip('.').encode('idna').lower()
    if offset + 4 > len(packet):
        raise ValueError('Niepełne pytanie DNS')
    response_type, klass = struct.unpack('!HH', packet[offset:offset + 4])
    offset += 4
    if name != expected or response_type != qtype or klass != 1:
        raise ValueError('Inna domena lub typ odpowiedzi')
    if flags & 0x200:
        return {'truncated': True, 'rcode': flags & 15, 'answers': []}
    answers = []
    records = []
    for _ in range(an):
        owner, offset = read_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError('Niepełny rekord DNS')
        typ, cls, ttl, size = struct.unpack('!HHIH', packet[offset:offset + 10])
        offset += 10
        if offset + size > len(packet):
            raise ValueError('Niepełne dane rekordu DNS')
        data = packet[offset:offset + size]
        alias = None
        if typ == 5 and cls == 1:
            alias, alias_end = read_name(packet, offset)
            if alias_end != offset + size:
                raise ValueError('Nieprawidłowy rekord CNAME')
        records.append((owner, typ, cls, data, alias))
        offset += size
    allowed = {expected}
    for _ in range(len(records) + 1):
        before = len(allowed)
        for owner, typ, cls, data, alias in records:
            if owner in allowed and alias is not None:
                allowed.add(alias)
        if len(allowed) == before:
            break
    for owner, typ, cls, data, alias in records:
        if owner in allowed and cls == 1 and typ == qtype:
            if typ == 1 and len(data) == 4:
                answers.append(socket.inet_ntop(socket.AF_INET, data))
            elif typ == 28 and len(data) == 16:
                answers.append(socket.inet_ntop(socket.AF_INET6, data))
    return {'truncated': False, 'rcode': flags & 15, 'answers': list(dict.fromkeys(answers))}

def receive_exact(sock, size, deadline=None):
    data = bytearray()
    while len(data) < size:
        if deadline is not None:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise TimeoutError('Timeout TCP')
            sock.settimeout(remaining)
        part = sock.recv(size - len(data))
        if not part:
            raise ValueError('Przerwane połączenie TCP')
        data.extend(part)
    return bytes(data)

def query_dns(server, domain, qtype=1, timeout=1.5, port=53):
    started = time.perf_counter()
    transport = 'UDP'
    try:
        address = ipaddress.ip_address(server)
        if qtype not in (1, 28):
            raise ValueError('Obsługiwane typy: A i AAAA')
        query_id = secrets.randbelow(65536)
        packet = struct.pack('!6H', query_id, 0x0100, 1, 0, 0, 0) + encode_domain(domain) + struct.pack('!HH', qtype, 1)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        endpoint = (str(address), port)
        deadline = time.perf_counter() + timeout
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect(endpoint)
            sock.send(packet)
            while True:
                sock.settimeout(max(0.001, deadline - time.perf_counter()))
                reply = sock.recv(65535)
                if len(reply) >= 2 and struct.unpack('!H', reply[:2])[0] == query_id:
                    break
                if time.perf_counter() >= deadline:
                    raise TimeoutError('Timeout DNS')
        result = parse_response(reply, query_id, domain, qtype)
        if result['truncated']:
            transport = 'TCP'
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(max(0.001, deadline - time.perf_counter()))
                sock.connect(endpoint)
                sock.settimeout(max(0.001, deadline - time.perf_counter()))
                sock.sendall(struct.pack('!H', len(packet)) + packet)
                size = struct.unpack('!H', receive_exact(sock, 2, deadline))[0]
                # Keep the total UDP + TCP attempt within one timeout budget.
                result = parse_response(receive_exact(sock, size, deadline), query_id, domain, qtype)
        error_names = {1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}
        ok = result['rcode'] == 0 and bool(result['answers']) and not result['truncated']
        error = '' if ok else error_names.get(result['rcode'], 'Brak adresu w odpowiedzi' if result['rcode'] == 0 else 'RCODE ' + str(result['rcode']))
        return {'ok': ok, 'ms': round((time.perf_counter() - started) * 1000, 3), 'answers': result['answers'], 'error': error, 'transport': transport}
    except (OSError, ValueError, TimeoutError) as exc:
        error = 'Timeout' if isinstance(exc, (socket.timeout, TimeoutError)) else str(exc)
        return {'ok': False, 'ms': round((time.perf_counter() - started) * 1000, 3), 'answers': [], 'error': error, 'transport': transport}

def summarize(samples):
    values = sorted(sample['ms'] for sample in samples if sample['ok'])
    count, good = len(samples), len(values)
    loss = 100 * (count - good) / count if count else 0
    return {
        'attempts': count, 'success': good, 'errors': count - good,
        'loss': round(loss, 2), 'eligible': count >= 10 and loss <= 5 and good > 0,
        'median': round(statistics.median(values), 2) if values else None,
        'mean': round(statistics.mean(values), 2) if values else None,
        'p95': round(values[max(0, math.ceil(good * .95) - 1)], 2) if values else None,
        'min': round(values[0], 2) if values else None,
        'max': round(values[-1], 2) if values else None,
        'jitter': round(statistics.pstdev(values), 2) if values else None,
    }

def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError('Nieprawidłowa konfiguracja')
    servers = config.get('servers', [])
    domains = config.get('domains', [])
    if not isinstance(servers, list) or not 1 <= len(servers) <= 32:
        raise ValueError('Wybierz od 1 do 32 serwerów DNS')
    clean, seen = [], set()
    for server in servers:
        if not isinstance(server, dict):
            raise ValueError('Nieprawidłowy serwer')
        try:
            ip = str(ipaddress.ip_address(str(server.get('ip', '')).strip()))
        except ValueError:
            raise ValueError('Podaj adres IPv4 lub IPv6, nie nazwę hosta') from None
        address = ipaddress.ip_address(ip)
        if address.is_multicast or address.is_unspecified or ip == '255.255.255.255':
            raise ValueError('Adres grupowy lub nieokreślony nie jest serwerem DNS')
        if ip in seen:
            raise ValueError('Powtórzony adres DNS: ' + ip)
        seen.add(ip)
        clean.append({'ip': ip, 'name': str(server.get('name', ip)).strip()[:60] or ip})
    if not isinstance(domains, list) or not 1 <= len(domains) <= 50:
        raise ValueError('Podaj od 1 do 50 domen')
    normalized = []
    for domain in domains:
        if not isinstance(domain, str):
            raise ValueError('Nieprawidłowa domena')
        domain = domain.strip().rstrip('.')
        if any(ch.isspace() for ch in domain) or any(ch in domain for ch in '/:@\\'):
            raise ValueError('Podaj domenę bez protokołu, portu i ścieżki')
        encode_domain(domain)
        normalized.append(domain)
    try:
        rounds, timeout = int(config.get('rounds', 30)), int(config.get('timeout', 1500))
    except (ValueError, TypeError):
        raise ValueError('Liczba prób i timeout muszą być liczbami') from None
    if not 10 <= rounds <= 200 or not 200 <= timeout <= 5000:
        raise ValueError('Liczba prób: 10–200; timeout: 200–5000 ms')
    qtype = config.get('qtype', 'A')
    if qtype not in ('A', 'AAAA'):
        raise ValueError('Wybierz A albo AAAA')
    return {'servers': clean, 'domains': normalized, 'rounds': rounds,
            'timeout': timeout, 'qtype': qtype, 'warmup': bool(config.get('warmup', True))}

class Benchmark:
    def __init__(self, config, probe=query_dns):
        self.config = config
        self.probe = probe
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.status = 'running'
        self.phase = 'Rozgrzewka' if config['warmup'] else 'Pomiar'
        self.started = time.time()
        self.ended = None
        self.error = ''
        self.samples = {server['ip']: [] for server in config['servers']}
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()

    def run(self):
        try:
            config = self.config
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(config['servers']))) as pool:
                if config['warmup'] and not self.cancel.is_set():
                    futures = [pool.submit(self.measure, server, config['domains'][0], 0, False) for server in config['servers']]
                    for future in futures:
                        future.result()
                with self.lock:
                    self.phase = 'Pomiar'
                domain_order = list(config['domains'])
                random.SystemRandom().shuffle(domain_order)
                for index in range(config['rounds']):
                    if self.cancel.is_set():
                        break
                    domain = domain_order[index % len(domain_order)]
                    order = list(config['servers'])
                    random.SystemRandom().shuffle(order)
                    futures = [pool.submit(self.measure, server, domain, index + 1, True) for server in order]
                    for future in futures:
                        future.result()
                    if self.cancel.wait(.10):
                        break
            with self.lock:
                self.status = 'cancelled' if self.cancel.is_set() else 'done'
                self.ended = time.time()
        except Exception as exc:
            with self.lock:
                self.status = 'error'
                self.error = str(exc)
                self.ended = time.time()

    def measure(self, server, domain, index, record):
        if self.cancel.is_set():
            return
        sample = self.probe(server['ip'], domain, qtype=1 if self.config['qtype'] == 'A' else 28,
                            timeout=self.config['timeout'] / 1000)
        sample.update({'domain': domain, 'round': index, 'time': time.time()})
        if record:
            with self.lock:
                self.samples[server['ip']].append(sample)

    def snapshot(self):
        with self.lock:
            rows = []
            for server in self.config['servers']:
                samples = list(self.samples[server['ip']])
                rows.append(dict(server, **summarize(samples), samples=samples))
            rows.sort(key=lambda row: (not row['eligible'], row['median'] is None,
                                       row['median'] if row['median'] is not None else float('inf'), row['loss']))
            recommended = [row['ip'] for row in rows if row['eligible']][:2] if self.status == 'done' else []
            return {'status': self.status, 'phase': self.phase, 'servers': rows,
                    'completed': sum(len(s) for s in self.samples.values()),
                    'total': self.config['rounds'] * len(rows), 'config': self.config,
                    'elapsed': round((self.ended or time.time()) - self.started, 1),
                    'recommended': recommended, 'error': self.error}

def detect_system_dns():
    addresses = []
    if os.name == 'nt':
        import subprocess
        command = 'Get-DnsClientServerAddress | ForEach-Object { $_.ServerAddresses }'
        try:
            result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                                    capture_output=True, text=True, timeout=8,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            addresses = result.stdout.splitlines()
        except (OSError, subprocess.TimeoutExpired):
            return []
    else:
        try:
            with open('/etc/resolv.conf', encoding='utf-8') as stream:
                addresses = [line.split()[1] for line in stream if line.startswith('nameserver ') and len(line.split()) >= 2]
        except OSError:
            return []
    valid = []
    for value in addresses:
        try:
            ip = str(ipaddress.ip_address(value.strip()))
            if ip not in valid:
                valid.append(ip)
        except ValueError:
            continue
    return valid

def csv_report(state):
    stream = io.StringIO(newline='')
    stream.write('\ufeff')
    writer = csv.writer(stream, delimiter=';')
    writer.writerow(['DNS Test', VERSION, 'Stan', state['status'], 'Typ', state['config']['qtype']])
    writer.writerow(['Nazwa', 'IP', 'Próba', 'Domena', 'OK', 'Czas ms', 'Transport', 'Adresy odpowiedzi', 'Błąd'])
    for server in state['servers']:
        for sample in server['samples']:
            row = [server['name'], server['ip'], sample['round'], sample['domain'], sample['ok'],
                   str(sample['ms']).replace('.', ','), sample['transport'], ', '.join(sample['answers']), sample['error']]
            # Prevent CSV spreadsheet formulas in user-supplied names and domains.
            writer.writerow(["'" + value if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')) else value for value in row])
    writer.writerow([])
    writer.writerow(['Nazwa', 'IP', 'Próby', 'OK', 'Błędy %', 'Mediana ms', 'Średnia ms', 'P95 ms', 'Min ms', 'Max ms', 'Zmienność ms'])
    for server in state['servers']:
        row = [server[key] for key in ('name', 'ip', 'attempts', 'success', 'loss', 'median', 'mean', 'p95', 'min', 'max', 'jitter')]
        writer.writerow(["'" + value if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')) else str(value).replace('.', ',') if isinstance(value, float) else value for value in row])
    return stream.getvalue()

class StatCard(QWidget):
    def __init__(self, title):
        super().__init__()
        self.setObjectName('panel')
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        layout = QVBoxLayout(self)
        label = QLabel(title)
        label.setWordWrap(True)
        label.setObjectName('muted')
        layout.addWidget(label)
        self.value = QLabel('—')
        self.value.setStyleSheet('font-size: 19pt; font-weight: 700; color: #77e3c1;')
        layout.addWidget(self.value)
        self.note = QLabel('Czeka na pomiar')
        self.note.setWordWrap(True)
        self.note.setObjectName('muted')
        layout.addWidget(self.note)
        self.meter = QProgressBar()
        self.meter.setTextVisible(False)
        self.meter.setFixedHeight(3)
        layout.addWidget(self.meter)

    def display(self, value, note, percent):
        self.value.setText(str(value))
        self.note.setText(str(note))
        self.meter.setValue(round(percent))


class DnsChart(QWidget):
    """Charts are native QPainter drawings; failed samples never become latency points."""
    def __init__(self, mode):
        super().__init__()
        self.mode = mode
        self.state = {'status': 'idle'}
        self.setMinimumHeight(205)
        self.setMinimumWidth(260)
        self.setToolTip('Przerwy i czerwone krzyżyki oznaczają błędy. Słupki: mediana / P95.')

    def set_state(self, state):
        self.state = state
        if self.mode == 'bars':
            self.setMinimumHeight(max(205, len(state.get('servers', [])) * 45 + 24))
        self.update()

    def color(self, ip):
        order = [s['ip'] for s in self.state.get('config', {}).get('servers', [])]
        return QColor(COLORS[(order.index(ip) if ip in order else 0) % len(COLORS)])

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor('#111621'))
        p.setFont(QFont('Segoe UI', 8))
        rows = self.state.get('servers', [])
        if not self.state.get('completed'):
            p.setPen(QColor('#91a0b9'))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, 'Tu pojawią się rzeczywiste pomiary\nBez przykładowych wyników')
            return
        if self.mode == 'bars':
            width = self.width()
            left = max(135, min(190, width * .43))
            available = max(30, width - left - 12)
            maximum = max([1] + [r['p95'] or 0 for r in rows]) * 1.12
            for index, row in enumerate(rows):
                y = 8 + index * 45
                p.setPen(QColor('#edf3ff'))
                name = p.fontMetrics().elidedText(row['name'], Qt.TextElideMode.ElideRight, int(left - 8))
                p.drawText(QPointF(4, y + 12), name)
                p.setPen(QColor('#91a0b9'))
                ip = p.fontMetrics().elidedText(row['ip'], Qt.TextElideMode.ElideRight, int(left - 8))
                p.drawText(QPointF(4, y + 28), ip)
                if row['median'] is None:
                    p.setPen(QColor('#ff8295'))
                    p.drawText(QPointF(left, y + 18), 'Brak odpowiedzi')
                    continue
                color = self.color(row['ip'])
                light = QColor(color)
                light.setAlpha(60)
                p.fillRect(QRectF(left, y, row['p95'] / maximum * available, 13), light)
                p.fillRect(QRectF(left, y, max(1, row['median'] / maximum * available), 13), color)
                p.setPen(QColor('#91a0b9'))
                p.drawText(QPointF(left, y + 29), f"{row['median']:g} ms / P95 {row['p95']:g}")
            return
        left, top = 45, 14
        w, h = max(1, self.width() - left - 15), max(1, self.height() - top - 30)
        maximum = max([1] + [s['ms'] for row in rows for s in row['samples'] if s['ok']]) * 1.15
        for i in range(5):
            y = top + h * i / 4
            p.setPen(QPen(QColor('#263044'), 1))
            p.drawLine(QPointF(left, y), QPointF(left + w, y))
            p.setPen(QColor('#91a0b9'))
            p.drawText(QPointF(2, y + 4), f'{maximum * (1 - i / 4):.1f}')
        rounds = self.state['config']['rounds']
        for n in sorted({1, math.ceil(rounds / 2), rounds}):
            x = left + (n - 1) / max(1, rounds - 1) * w
            p.drawText(QPointF(x - 4, top + h + 20), str(n))
        for row in rows:
            previous = None
            for s in row['samples']:
                x = left + (s['round'] - 1) / max(1, rounds - 1) * w
                if not s['ok']:
                    p.setPen(QPen(QColor('#ff8295'), 1.5))
                    y = top + h - 4
                    p.drawLine(QPointF(x - 3, y - 3), QPointF(x + 3, y + 3))
                    p.drawLine(QPointF(x - 3, y + 3), QPointF(x + 3, y - 3))
                    previous = None
                    continue
                point = QPointF(x, top + h - s['ms'] / maximum * h)
                p.setPen(QPen(self.color(row['ip']), 1.6))
                if previous is not None:
                    p.drawLine(previous, point)
                p.setBrush(self.color(row['ip']))
                p.drawEllipse(point, 2.2, 2.2)
                previous = point


class DnsLegend(QWidget):
    def __init__(self):
        super().__init__()
        self.state = {'servers': []}
        self.setFixedHeight(0)

    def set_state(self, state):
        self.state = state
        self.setAccessibleName('Legenda: ' + ', '.join(r['name'] + ' ' + r['ip'] for r in state['servers']))
        self.setFixedHeight(math.ceil(len(state['servers']) / 2) * 24)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setFont(QFont('Segoe UI', 8))
        order = [r['ip'] for r in self.state.get('config', {}).get('servers', [])]
        column_width = self.width() / 2
        for index, row in enumerate(self.state['servers']):
            x, y = (index % 2) * column_width, (index // 2) * 24
            color = QColor(COLORS[order.index(row['ip']) % len(COLORS)])
            p.fillRect(QRectF(x + 2, y + 7, 8, 8), color)
            p.setPen(color)
            ip_width = p.fontMetrics().horizontalAdvance(row['ip'])
            name_width = max(0, int(column_width - ip_width - 33))
            name = p.fontMetrics().elidedText(row['name'], Qt.TextElideMode.ElideRight, name_width)
            p.drawText(QPointF(x + 17, y + 16), name + ' · ' + row['ip'])


class MainWindow(QMainWindow):
    def __init__(self, settings_path=None, probe=None):
        super().__init__()
        self.setWindowTitle('DNS Test · v' + VERSION)
        self.resize(1280, 800)
        self.setMinimumSize(1000, 650)
        self.setStyleSheet(STYLE)
        self.settings = QSettings(settings_path, QSettings.Format.IniFormat) if settings_path else QSettings('DNS Test', 'DNS Test 1.1')
        self.probe = probe or query_dns
        self.job = None
        self.state = {'status': 'idle'}
        self._closing = False
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(20, 16, 20, 16)
        heading = QLabel('dns test   /   v' + VERSION)
        heading.setObjectName('title')
        layout.addWidget(heading)
        subtitle = QLabel('Znajdź szybszą drogę do internetu.  •  Pomiar lokalny, bez chmury')
        subtitle.setObjectName('muted')
        layout.addWidget(subtitle)
        body = QHBoxLayout()
        layout.addLayout(body, 1)
        sidebar = QWidget()
        side = QVBoxLayout(sidebar)
        side.addWidget(QLabel('01 / SERWERY — Twoi kandydaci'))
        self.server_list = QListWidget()
        self.server_list.setMinimumHeight(190)
        side.addWidget(self.server_list)
        self.new_name = QLineEdit()
        self.new_name.setPlaceholderText('Nazwa, np. Router / Pi-hole')
        self.new_ip = QLineEdit()
        self.new_ip.setPlaceholderText('Adres IPv4 lub IPv6')
        side.addWidget(self.new_name)
        side.addWidget(self.new_ip)
        self.add_button = QPushButton('Dodaj serwer')
        self.remove_button = QPushButton('Usuń zaznaczony')
        for button in (self.add_button, self.remove_button):
            side.addWidget(button)
        self.detect_button = QPushButton('+ DNS z ustawień systemu')
        side.addWidget(self.detect_button)
        config_actions = QHBoxLayout()
        self.save_button = QPushButton('Zapisz listę')
        self.load_button = QPushButton('Wczytaj listę')
        config_actions.addWidget(self.save_button)
        config_actions.addWidget(self.load_button)
        side.addLayout(config_actions)
        side.addWidget(QLabel('02 / PARAMETRY — Warunki pomiaru'))
        form = QFormLayout()
        self.rounds = QSpinBox()
        self.rounds.setRange(10, 200)
        self.rounds.setValue(30)
        self.timeout = QSpinBox()
        self.timeout.setRange(200, 5000)
        self.timeout.setSingleStep(100)
        self.timeout.setValue(1500)
        self.qtype = QComboBox()
        self.qtype.addItem('A · adres IPv4', 'A')
        self.qtype.addItem('AAAA · adres IPv6', 'AAAA')
        self.warmup = QCheckBox('Rozgrzewka (poza wynikami)')
        self.warmup.setChecked(True)
        form.addRow('Próby / serwer', self.rounds)
        form.addRow('Timeout (ms)', self.timeout)
        form.addRow('Typ rekordu', self.qtype)
        side.addLayout(form)
        side.addWidget(self.warmup)
        side.addWidget(QLabel('03 / DOMENY — jedna na linię'))
        self.domains = QPlainTextEdit('example.com\nwikipedia.org\ngithub.com\nmicrosoft.com\ncloudflare.com\ngoogle.com')
        self.domains.setMinimumHeight(130)
        side.addWidget(self.domains)
        notice = QLabel('Program nie zmienia DNS systemu.\nPrywatne domeny wyślesz do wybranych serwerów.')
        notice.setWordWrap(True)
        notice.setObjectName('muted')
        side.addWidget(notice)
        side.addStretch()
        self.sidebar_scroll = QScrollArea()
        self.sidebar_scroll.setWidgetResizable(True)
        self.sidebar_scroll.setWidget(sidebar)
        self.sidebar_scroll.setFixedWidth(310)
        body.addWidget(self.sidebar_scroll)
        report = QWidget()
        self.report_layout = QVBoxLayout(report)
        title = QLabel('Nie zgaduj. Zmierz.')
        title.setObjectName('title')
        self.report_layout.addWidget(title)
        actions = QHBoxLayout()
        self.export_button = QPushButton('↓ Eksport CSV')
        self.export_button.setEnabled(False)
        self.stop_button = QPushButton('Zatrzymaj')
        self.stop_button.setEnabled(False)
        self.start_button = QPushButton('▶ Rozpocznij test')
        self.start_button.setObjectName('primary')
        for button in (self.export_button, self.stop_button, self.start_button):
            actions.addWidget(button)
        self.report_layout.addLayout(actions)
        self.status_label = QLabel('Gotowy. Wybierz serwery i rozpocznij pomiar.')
        self.status_label.setWordWrap(True)
        self.report_layout.addWidget(self.status_label)
        self.progress = QProgressBar()
        self.progress.setFixedHeight(5)
        self.progress.setTextVisible(False)
        self.report_layout.addWidget(self.progress)
        cards = QHBoxLayout()
        self.cards = [StatCard(t) for t in ('NAJNIŻSZA MEDIANA', 'BADANE SERWERY', 'POPRAWNE ODPOWIEDZI', 'CZAS TESTU')]
        for card in self.cards:
            cards.addWidget(card, 1)
        self.report_layout.addLayout(cards)
        self.recommendation = QLabel('Rekomendacja dopiero po pełnym teście: ≥10 prób i ≥95% skuteczności.')
        self.recommendation.setWordWrap(True)
        self.recommendation.setTextFormat(Qt.TextFormat.PlainText)
        self.recommendation.setStyleSheet('color: #a59cff; padding: 6px;')
        self.report_layout.addWidget(self.recommendation)
        charts = QHBoxLayout()
        self.line_chart = DnsChart('line')
        self.bar_chart = DnsChart('bars')
        for title, chart in [('Odpowiedzi w czasie · ms / próba', self.line_chart), ('Porównanie · mediana / P95', self.bar_chart)]:
            panel = QWidget()
            panel.setObjectName('panel')
            box = QVBoxLayout(panel)
            chart_title = QLabel(title)
            chart_title.setWordWrap(True)
            box.addWidget(chart_title)
            box.addWidget(chart)
            charts.addWidget(panel, 1)
        self.report_layout.addLayout(charts)
        self.legend = QLabel('Każdy serwer otrzyma własną linię. Czerwone × = błędy.')
        self.legend.setTextFormat(Qt.TextFormat.PlainText)
        self.legend.setWordWrap(True)
        self.legend.setObjectName('muted')
        self.report_layout.addWidget(self.legend)
        self.color_legend = DnsLegend()
        self.report_layout.addWidget(self.color_legend)
        self.legend_note = QLabel('Czerwone × = błędy; przerwy nie są zerowym opóźnieniem.')
        self.legend_note.setObjectName('muted')
        self.legend_note.setWordWrap(True)
        self.report_layout.addWidget(self.legend_note)
        ranking_title = QLabel('Ranking serwerów · stabilne najpierw, następnie mediana ↑')
        ranking_title.setWordWrap(True)
        self.report_layout.addWidget(ranking_title)
        self.ranking = QTableWidget(0, 9)
        self.ranking.setHorizontalHeaderLabels(['Serwer / IP', 'Mediana', 'Średnia', 'P95', 'Min', 'Max', 'Zmienność σ', 'Błędy', 'Status'])
        self.ranking.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ranking.verticalHeader().setVisible(False)
        self.ranking.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.ranking.setMinimumHeight(210)
        self.report_layout.addWidget(self.ranking)
        details_button = QPushButton('Jak interpretować wyniki?')
        self.report_layout.addWidget(details_button)
        self.interpretation = QLabel(
            'Mediana opisuje typową odpowiedź; P95 obejmuje co najmniej 95% poprawnych prób '
            '(nearest rank). Zmienność σ to odchylenie standardowe. Błędy i timeouty nie są '
            'udanymi odpowiedziami. Rekomendacja: pełny test, ≥10 prób, ≥95% skuteczności.\n\n'
            'To klasyczny DNS, nie DoH/DoT. Powtórzone domeny mogą pochodzić z cache — '
            'program nie opróżnia pamięci serwerów. Sprawdza zgodność odpowiedzi i obecność '
            'adresu, ale nie waliduje kryptograficznie DNSSEC. Szybszy DNS nie gwarantuje '
            'większej prędkości pobierania. Powtórz test o różnych porach, bez dużego ruchu.')
        self.interpretation.setWordWrap(True)
        self.interpretation.setTextFormat(Qt.TextFormat.PlainText)
        self.interpretation.setObjectName('muted')
        self.interpretation.hide()
        details_button.clicked.connect(lambda: self.interpretation.setVisible(not self.interpretation.isVisible()))
        self.report_layout.addWidget(self.interpretation)
        self.report_layout.addStretch()
        self.report_scroll = QScrollArea()
        self.report_scroll.setWidgetResizable(True)
        self.report_scroll.setWidget(report)
        body.addWidget(self.report_scroll, 1)

        self.replace_servers([
            {'name': 'Cloudflare', 'ip': '1.1.1.1'},
            {'name': 'Cloudflare · zapasowy', 'ip': '1.0.0.1'},
            {'name': 'Google', 'ip': '8.8.8.8'},
            {'name': 'Google · zapasowy', 'ip': '8.8.4.4'},
            {'name': 'Quad9', 'ip': '9.9.9.9'},
            {'name': 'OpenDNS', 'ip': '208.67.222.222'}])
        saved = self.settings.value('configuration', '')
        if saved:
            try:
                self.apply_document(json.loads(saved))
            except (ValueError, TypeError, KeyError):
                self.status_label.setText('Nieprawidłowe zapisane ustawienia — używam domyślnych.')
        self.add_button.clicked.connect(lambda: self.guard(lambda: self.add_server(self.new_ip.text(), self.new_name.text())))
        self.remove_button.clicked.connect(lambda: self.guard(lambda: self.remove_server(self.server_list.currentRow())))
        self.save_button.clicked.connect(lambda: self.file_action('save'))
        self.load_button.clicked.connect(lambda: self.file_action('load'))
        self.start_button.clicked.connect(lambda: self.guard(self.start_benchmark))
        self.stop_button.clicked.connect(self.stop_benchmark)
        self.export_button.clicked.connect(self.export_dialog)
        self.detect_button.clicked.connect(self.begin_detection)
        self._dns_thread = None
        self._dns_result = None
        self._dns_pending = False
        self.timer = QTimer(self)
        self.timer.setInterval(100)
        self.timer.timeout.connect(self.poll)
        self.timer.start()
        pixmap = QPixmap(40, 40)
        pixmap.fill(QColor('#77e3c1'))
        painter = QPainter(pixmap)
        painter.setPen(QPen(QColor('#10291f'), 3))
        painter.drawLine(10, 30, 30, 10)
        painter.drawLine(17, 10, 30, 10)
        painter.drawLine(30, 10, 30, 23)
        painter.end()
        self.setWindowIcon(QIcon(pixmap))

    def raw_settings(self):
        return {'domains': [s.strip() for s in self.domains.toPlainText().splitlines() if s.strip()],
                'rounds': self.rounds.value(), 'timeout': self.timeout.value(),
                'qtype': self.qtype.currentData(), 'warmup': self.warmup.isChecked()}

    def server_records(self):
        return [dict(self.server_list.item(i).data(Qt.ItemDataRole.UserRole),
                     enabled=self.server_list.item(i).checkState() == Qt.CheckState.Checked)
                for i in range(self.server_list.count())]

    def configuration(self):
        return validate_config(dict(self.raw_settings(), servers=[s for s in self.server_records() if s['enabled']]))

    def config_document(self):
        return {'version': 1, 'servers': self.server_records(), 'settings': self.raw_settings()}

    def replace_servers(self, servers):
        checked = validate_config(dict(self.raw_settings(), servers=servers))['servers']
        self.server_list.clear()
        for clean, original in zip(checked, servers):
            item = QListWidgetItem(clean['name'] + '\n' + clean['ip'])
            item.setData(Qt.ItemDataRole.UserRole, clean)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked if original.get('enabled') is False else Qt.CheckState.Checked)
            self.server_list.addItem(item)

    def add_server(self, ip, name=''):
        servers = self.server_records()
        servers.append({'ip': ip, 'name': name or ip, 'enabled': True})
        self.replace_servers(servers)
        self.new_ip.clear()
        self.new_name.clear()
        self.persist_settings()

    def remove_server(self, index):
        if index < 0:
            raise ValueError('Zaznacz serwer do usunięcia')
        self.server_list.takeItem(index)
        self.persist_settings()

    def apply_document(self, document):
        if not isinstance(document, dict):
            raise ValueError('Nieprawidłowy plik konfiguracji')
        servers = document.get('servers', [])
        checked = validate_config(dict(self.raw_settings(), **document.get('settings', {}), servers=servers))
        # Validation completes before any widget is mutated.
        self.rounds.setValue(checked['rounds'])
        self.timeout.setValue(checked['timeout'])
        self.qtype.setCurrentIndex(self.qtype.findData(checked['qtype']))
        self.warmup.setChecked(checked['warmup'])
        self.domains.setPlainText('\n'.join(checked['domains']))
        self.replace_servers([dict(s, enabled=o.get('enabled') is not False) for s, o in zip(checked['servers'], servers)])

    def save_config(self, path):
        Path(path).write_text(json.dumps(self.config_document(), ensure_ascii=False, indent=2), encoding='utf-8')

    def import_config(self, path):
        if Path(path).stat().st_size > 65536:
            raise ValueError('Plik konfiguracji jest za duży (maks. 64 KB)')
        self.apply_document(json.loads(Path(path).read_text(encoding='utf-8-sig')))
        self.persist_settings()

    def persist_settings(self):
        self.settings.setValue('configuration', json.dumps(self.config_document(), ensure_ascii=False))
        self.settings.sync()

    def guard(self, operation):
        try:
            operation()
        except (ValueError, TypeError, OSError, KeyError) as exc:
            self.status_label.setText('Błąd: ' + str(exc))

    def file_action(self, action):
        if action == 'load':
            path, _ = QFileDialog.getOpenFileName(self, 'Wczytaj listę DNS', '', 'Konfiguracja (*.json)')
            if path:
                self.guard(lambda: self.import_config(path))
        else:
            path, _ = QFileDialog.getSaveFileName(self, 'Zapisz listę DNS', 'dns_test_lista_v1.1.0.json', 'Konfiguracja (*.json)')
            if path:
                self.guard(lambda: self.save_config(path))


    def set_busy(self, busy):
        self.start_button.setEnabled(not busy and not self._dns_pending and not self._closing)
        self.stop_button.setEnabled(busy and not self._closing)
        for widget in (self.server_list, self.new_name, self.new_ip, self.add_button,
                       self.remove_button, self.load_button, self.rounds, self.timeout,
                       self.qtype, self.warmup, self.domains):
            widget.setEnabled(not busy)
        self.detect_button.setEnabled(not busy and not (self._dns_thread and self._dns_thread.is_alive()))
        self.export_button.setEnabled(bool(self.state.get('completed')))

    def start_benchmark(self):
        if self.job and self.job.thread.is_alive():
            raise ValueError('Test już trwa')
        config = self.configuration()
        self.persist_settings()
        self.job = Benchmark(config, probe=self.probe)
        self.job.start()
        self.poll()

    def stop_benchmark(self):
        if self.job and self.job.thread.is_alive():
            self.job.cancel.set()
            self.stop_button.setEnabled(False)
            self.status_label.setText('Zatrzymywanie — oczekiwanie na rozpoczęte zapytania…')

    def poll(self):
        if self._dns_result is not None:
            self._dns_pending = False
            detected, self._dns_result = self._dns_result, None
            added = 0
            for ip in detected:
                if len(self.server_records()) >= 32:
                    break
                if ip not in [s['ip'] for s in self.server_records()]:
                    try:
                        self.add_server(ip, 'DNS systemowy')
                        added += 1
                    except ValueError:
                        continue
            self.status_label.setText(f'Dodano {added} serwerów systemowych.' if detected else 'Nie wykryto DNS. Dodaj adres routera ręcznie.')
            self.set_busy(bool(self.job and self.job.thread.is_alive()))
        if self.job:
            self.state = self.job.snapshot()
            self.render_state()
        if self._closing and not (self.job and self.job.thread.is_alive()) and not (self._dns_thread and self._dns_thread.is_alive()):
            self.close()

    def render_state(self):
        state = self.state
        rows = state['servers']
        busy = state['status'] == 'running'
        self.set_busy(busy)
        if self.job.cancel.is_set() and busy:
            self.stop_button.setEnabled(False)
        good = sum(r['success'] for r in rows)
        done, total = state['completed'], state['total']
        progress = done / total * 100 if total else 0
        success = good / done * 100 if done else 0
        best = min((r for r in rows if r['median'] is not None), key=lambda r: r['median'], default=None)
        self.cards[0].display(f"{best['median']:g} ms" if best else '—', best['ip'] if best else 'Brak poprawnej odpowiedzi', 100 if best else 0)
        self.cards[1].display(len(rows), f"{sum(r['success'] > 0 for r in rows)} zwróciło adres", sum(r['success'] > 0 for r in rows) / len(rows) * 100)
        self.cards[2].display(f'{success:.1f}%', f'{good} poprawnych / {done}', success)
        self.cards[3].display(f"{state['elapsed']:g} s", 'Pomiar trwa…' if busy else 'Pomiar zakończony', progress)
        self.progress.setValue(round(progress))
        description = {'done': 'Test zakończony. Wyniki gotowe.', 'cancelled': 'Test przerwany — wyniki częściowe, bez rekomendacji.',
                       'error': 'Błąd testu: ' + state['error'], 'running': state['phase'] + ' — pomiar trwa…'}[state['status']]
        if self._closing or (busy and self.job.cancel.is_set()):
            description = 'Zatrzymywanie — oczekiwanie na rozpoczęte zapytania…'
        self.status_label.setText(f"{description}   {done} / {total} prób\n{state['config']['qtype']} · {len(state['config']['domains'])} domen · UDP/53 + fallback TCP · timeout {state['config']['timeout']} ms")
        if state['recommended']:
            self.recommendation.setText('Najlepsi kandydaci w tym pomiarze: ' + ' / '.join(state['recommended']) + '\n≥95% skuteczności · ustawienia systemu bez zmian')
        else:
            self.recommendation.setText('Rekomendacja po pełnym, stabilnym teście.' if busy else 'Brak wiarygodnej rekomendacji — przerwany test lub zbyt wiele błędów.')
        self.legend.setText('   •   '.join(f"{r['name']} · {r['ip']}" for r in rows) + '\nCzerwone × = błędy; przerwy nie są zerowym opóźnieniem.')
        self.line_chart.set_state(state)
        self.bar_chart.set_state(state)
        self.color_legend.set_state(state)
        self.legend.hide()
        self.ranking.setRowCount(len(rows))
        for i, row in enumerate(rows):
            badge = 'Stabilny' if row['eligible'] else 'Za mało prób' if row['attempts'] < 10 else 'Niestabilny'
            values = [row['name'] + '\n' + row['ip']] + [('—' if row[k] is None else f"{row[k]:g} ms") for k in ('median', 'mean', 'p95', 'min', 'max', 'jitter')] + [f"{row['errors']} / {row['attempts']} ({row['loss']:g}%)", badge]
            errors = '\n'.join(s['domain'] + ': ' + s['error'] for s in row['samples'] if not s['ok'])
            for j, value in enumerate(values):
                item = QTableWidgetItem(value)
                if j == 0:
                    item.setForeground(self.line_chart.color(row['ip']))
                item.setToolTip(errors if j == 7 else value)
                self.ranking.setItem(i, j, item)
        self.ranking.resizeRowsToContents()

    def export_csv(self, path):
        if not self.state.get('completed'):
            raise ValueError('Brak wyników do eksportu')
        Path(path).write_text(csv_report(self.state), encoding='utf-8', newline='')

    def export_dialog(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Eksportuj wyniki', 'dns_test_wyniki_v1.1.0.csv', 'Wyniki (*.csv)')
        if path:
            self.guard(lambda: self.export_csv(path))

    def begin_detection(self):
        if self._dns_thread and self._dns_thread.is_alive():
            return
        self._dns_pending = True
        self.detect_button.setEnabled(False)
        self.start_button.setEnabled(False)
        self.status_label.setText('Odczyt ustawień DNS systemu…')
        def detect():
            self._dns_result = detect_system_dns()
        self._dns_thread = threading.Thread(target=detect, daemon=True)
        self._dns_thread.start()

    def closeEvent(self, event):
        self.persist_settings()
        if (self.job and self.job.thread.is_alive()) or (self._dns_thread and self._dns_thread.is_alive()):
            self._closing = True
            self.stop_benchmark()
            self.set_busy(True)
            event.ignore()
        else:
            self.timer.stop()
            event.accept()


def argument_parser():
    parser = argparse.ArgumentParser(description='DNS Test 1.1.0 — natywna aplikacja Qt. Bez argumentów: pulpit.')
    parser.add_argument('--smoke-test', metavar='KATALOG', help='Tryb deweloperski: prawdziwy pomiar, outcome.json, screenshot.png, results.csv; zakończ program')
    parser.add_argument('--server', action='append', metavar='IP', help='Serwer testu smoke; można powtarzać (maks. 32)')
    parser.add_argument('--domain', action='append', metavar='DOMENA', help='Domena smoke; domyślnie example.com')
    parser.add_argument('--rounds', type=int, default=10, help='Próby smoke: 10–200 (domyślnie 10)')
    parser.add_argument('--timeout', type=int, default=500, help='Timeout smoke: 200–5000 ms')
    parser.add_argument('--qtype', choices=('A', 'AAAA'), default='A', help='Typ rekordu smoke')
    parser.add_argument('--no-warmup', action='store_true', help='Wyłącz rozgrzewkę smoke')
    parser.add_argument('--dns-port', type=int, default=53, help='Port fixture smoke: 1–65535; zwykły pomiar zawsze 53')
    parser.add_argument('--settings-path', metavar='PLIK', help='Izolowany plik QSettings; smoke używa KATALOG/settings.ini')
    return parser


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    parser = argument_parser()
    args = parser.parse_args(argv)
    if not args.smoke_test and (args.server or args.domain or args.dns_port != 53 or args.no_warmup or args.rounds != 10 or args.timeout != 500 or args.qtype != 'A'):
        parser.error('Parametry pomiaru deweloperskiego wymagają --smoke-test KATALOG')
    if not 1 <= args.dns_port <= 65535:
        parser.error('Port DNS musi należeć do zakresu 1–65535')
    config = None
    output = Path(args.smoke_test) if args.smoke_test else None
    if output:
        try:
            config = validate_config({'servers': [{'ip': ip, 'name': 'DNS ' + ip} for ip in (args.server or ['1.1.1.1', '8.8.8.8'])],
                                      'domains': args.domain or ['example.com'], 'rounds': args.rounds,
                                      'timeout': args.timeout, 'qtype': args.qtype, 'warmup': not args.no_warmup})
            output.mkdir(parents=True, exist_ok=True)
        except (ValueError, OSError) as exc:
            parser.error(str(exc))
    app = QApplication.instance() or QApplication([sys.argv[0]])
    app.setApplicationName('DNS Test')
    app.setApplicationVersion(VERSION)
    app.setOrganizationName('DNS Test')
    settings_path = args.settings_path or (str(output / 'settings.ini') if output else None)
    probe = query_dns if args.dns_port == 53 else lambda ip, domain, **kw: query_dns(ip, domain, port=args.dns_port, **kw)
    window = MainWindow(settings_path=settings_path, probe=probe)
    window.show()
    if output:
        window.apply_document({'servers': config['servers'], 'settings': {k: v for k, v in config.items() if k != 'servers'}})
        window.start_benchmark()
        deadline = time.monotonic() + (args.rounds + 1) * math.ceil(len(config['servers']) / 4) * args.timeout / 1000 + args.rounds * .1 + 15
        checker = QTimer(window)
        checker.setInterval(100)
        capturing = [False]
        def finish():
            window.poll()
            state = dict(window.state)
            state.update({'app_version': VERSION, 'native_window_visible': window.isVisible(),
                          'qt_platform': app.platformName(),
                          'window_size': [window.width(), window.height()],
                          'chart_mode': 'QPainter / QtWidgets'})
            if not window.grab().save(str(output / 'screenshot.png')):
                state['artifact_error'] = 'Nie udało się zapisać zrzutu ekranu'
            (output / 'outcome.json').write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding='utf-8')
            if state.get('completed'):
                window.export_csv(output / 'results.csv')
            window.save_config(output / 'configuration.json')
            success = state['status'] == 'done' and state['completed'] == state['total'] and any(r['success'] for r in state['servers']) and not state.get('artifact_error')
            window.close()
            app.exit(0 if success else 2)
        def check():
            if time.monotonic() > deadline and window.job.thread.is_alive():
                window.stop_benchmark()
            if not window.job.thread.is_alive() and not capturing[0]:
                capturing[0] = True
                checker.stop()
                QTimer.singleShot(200, finish)
        checker.timeout.connect(check)
        checker.start()
    result = app.exec()
    if window.job:
        window.job.cancel.set()
        window.job.thread.join()
    if window._dns_thread:
        window._dns_thread.join()
    return result


if __name__ == '__main__':
    sys.exit(main())
