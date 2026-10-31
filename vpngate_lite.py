#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vpngate_lite.py — 抓取 VPN Gate 节点，本地完成 SSTP 检测 + 测速，输出 edgetunnel 链式格式。

零第三方依赖（纯 Python 标准库）。两种跑法：
  本机:   python vpngate_lite.py --proxy http://127.0.0.1:7897
          （国内直连 opengw.net 不通，必须走本机代理，检测视角 = 代理出口）
  GitHub Actions: python vpngate_lite.py --out out
          （runner 在海外，直连即可，检测视角 = 海外）

流程: 抓官方 CSV -> 解 base64 OpenVPN 配置 -> 筛 TCP 节点 -> 对每台:
  TCP 连接 -> TLS -> SSTP HTTP 握手 -> PPP(LCP/PAP/IPCP) 建链
  -> 隧道内查出口 IP(ip-api, 顺带判住宅/机房) -> 隧道内下载 1MB 测速
输出: out/nodes.txt(链式) + out/report.csv + out/summary.json
"""

import argparse
import base64
import csv
import json
import os
import random
import re
import socket
import ssl
import struct
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from urllib.request import Request, build_opener, ProxyHandler, urlopen

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

API_URLS = ['https://www.vpngate.net/api/iphone/', 'http://www.vpngate.net/api/iphone/']
SSTP_PATH = '/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/'
INFO_URL = 'http://ip-api.com/json/?fields=status,query,country,countryCode,city,isp,org,as,hosting,proxy'
SPEED_URLS = ['https://speed.cloudflare.com/__down?bytes=1000000',
              'http://ipv4.download.thinkbroadband.com/1MB.zip']
SPEED_BYTES = 1_000_000
UP_URL = 'https://speed.cloudflare.com/__up'
UP_BYTES = 1_000_000

DEFAULT_EDGE_POOL = ['saas.sin.fan:443', 'cdn.204910.best:443', 'www.mfyx.cn:443',
                     'p.etime.vip:443', 'cdn.ctn32.us.kg:443', 'spring.io:443']

COUNTRY_ZH = {
    'JP': '日本', 'KR': '韩国', 'RU': '俄罗斯', 'US': '美国', 'TH': '泰国', 'VN': '越南',
    'TW': '台湾', 'HK': '香港', 'SG': '新加坡', 'DE': '德国', 'FR': '法国', 'GB': '英国',
    'CA': '加拿大', 'BR': '巴西', 'IN': '印度', 'ID': '印尼', 'MY': '马来西亚', 'PH': '菲律宾',
    'TR': '土耳其', 'UA': '乌克兰', 'PL': '波兰', 'NL': '荷兰', 'SE': '瑞典', 'CH': '瑞士',
    'IT': '意大利', 'ES': '西班牙', 'RO': '罗马尼亚', 'CZ': '捷克', 'GR': '希腊', 'PT': '葡萄牙',
    'FI': '芬兰', 'NO': '挪威', 'DK': '丹麦', 'IE': '爱尔兰', 'BE': '比利时', 'AT': '奥地利',
    'HU': '匈牙利', 'AR': '阿根廷', 'CL': '智利', 'CO': '哥伦比亚', 'NZ': '新西兰', 'ZA': '南非',
    'IL': '以色列', 'AE': '阿联酋', 'SA': '沙特', 'EG': '埃及', 'MD': '摩尔多瓦', 'LA': '老挝',
    'MN': '蒙古', 'NP': '尼泊尔', 'LK': '斯里兰卡', 'MM': '缅甸', 'GD': '格林纳达', 'PA': '巴拿马',
    'GE': '格鲁吉亚', 'KZ': '哈萨克斯坦', 'AM': '亚美尼亚', 'BY': '白俄罗斯', 'CN': '中国',
}

_print_lock = threading.Lock()

UP_BODY = os.urandom(UP_BYTES)  # 上传测速用随机负载，进程内只生成一次


def log(msg):
    with _print_lock:
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
        print(msg, flush=True)


def short_err(e):
    s = str(e)
    return s[:100]


# ---------------------------------------------------------------------------
# 抓取与解析
# ---------------------------------------------------------------------------

def fetch_api(proxy, timeout=60):
    last_err = None
    for url in API_URLS:
        try:
            req = Request(url, headers={'User-Agent': 'Mozilla/5.0 (vpngate-lite)'})
            if proxy:
                opener = build_opener(ProxyHandler({'http': proxy, 'https': proxy}))
                body = opener.open(req, timeout=timeout).read()
            else:
                body = urlopen(req, timeout=timeout).read()
            text = body.decode('utf-8', 'replace')
            log('[fetch] %s -> %d bytes' % (url, len(text)))
            return text
        except Exception as e:
            last_err = e
            log('[fetch] %s 失败: %s' % (url, short_err(e)))
    raise SystemExit('所有 API 源都拉取失败: %s' % short_err(last_err))


def parse_rows(text, include_official=False):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    start = -1
    for i, ln in enumerate(lines):
        if ln.lstrip('*#').startswith('HostName'):
            start = i
            break
    if start < 0:
        raise SystemExit('CSV 表头找不到 (HostName)')
    header = lines[start].lstrip('*#').split(',')
    rows = []
    for ln in lines[start + 1:]:
        fields = next(csv.reader([ln]), None)
        if not fields or len(fields) < len(header):
            continue
        d = dict(zip(header, fields))
        host = (d.get('HostName') or '').strip()
        if not host:
            continue
        official = bool(re.match(r'^public-vpn', host)) or ('Academic Use Only' in (d.get('Operator') or ''))
        if official and not include_official:
            continue
        cfg_b64 = (d.get('OpenVPN_ConfigData_Base64') or '').strip()
        if not cfg_b64:
            continue
        try:
            cfg = base64.b64decode(cfg_b64).decode('utf-8', 'replace')
        except Exception:
            continue
        if not re.search(r'^proto\s+tcp', cfg, re.M):
            continue
        m = re.search(r'^remote\s+\S+\s+(\d+)', cfg, re.M)
        if not m:
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            continue
        entry = host if host.endswith('.opengw.net') else host + '.opengw.net'
        try:
            ping = int(d.get('Ping') or 9999)
        except ValueError:
            ping = 9999
        rows.append({
            'host': entry, 'port': port, 'code': (d.get('CountryShort') or '?').upper(),
            'country': d.get('CountryLong') or '?', 'ping': ping,
        })
    # 去重
    seen, out = set(), []
    for r in rows:
        key = (r['host'].lower(), r['port'])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


# ---------------------------------------------------------------------------
# 代理 socket / TLS
# ---------------------------------------------------------------------------

def open_tcp(host, port, proxy, timeout):
    if not proxy:
        return socket.create_connection((host, port), timeout=timeout)
    u = urlparse(proxy if '://' in proxy else 'http://' + proxy)
    s = socket.create_connection((u.hostname, u.port or 80), timeout=timeout)
    s.sendall(('CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n' % (host, port, host, port)).encode())
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = s.recv(4096)
        if not chunk:
            s.close()
            raise OSError('代理在 CONNECT 阶段断开')
        buf += chunk
        if len(buf) > 16384:
            break
    status = buf.split(b'\r\n', 1)[0].decode('latin1')
    if ' 200' not in status:
        s.close()
        raise OSError('代理 CONNECT 失败: ' + status)
    return s


def wrap_tls(sock, host, timeout):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(sock, server_hostname=host)
    s.settimeout(timeout)
    return s


# ---------------------------------------------------------------------------
# SSTP 帧 / PPP 协议
# ---------------------------------------------------------------------------

def sstp_ctrl_frame(payload):
    n = 4 + len(payload)
    return bytes([0x10, 0x01, 0x80 | ((n >> 8) & 0x0F), n & 0xFF]) + payload


def sstp_data_frame(ppp):
    n = 6 + len(ppp)
    return bytes([0x10, 0x00, 0x80 | ((n >> 8) & 0x0F), n & 0xFF, 0xFF, 0x03]) + ppp


def ppp_frame(proto, code, ident, options=b''):
    n = 4 + len(options)
    return bytes([proto >> 8, proto & 0xFF, code, ident & 0xFF, n >> 8, n & 0xFF]) + options


def parse_ppp(body):
    off = 2 if body[:2] == b'\xff\x03' else 0
    if len(body) - off < 2:
        return None
    proto = (body[off] << 8) | body[off + 1]
    payload = body[off + 2:]
    if proto == 0x0021:
        return ('ip', payload)
    if len(payload) < 4:
        return None
    return ('ctrl', proto, payload[0], payload[1], payload[4:])


def parse_opts(data):
    opts, i = [], 0
    while i + 2 <= len(data):
        t, l = data[i], data[i + 1]
        if l < 2 or i + l > len(data):
            break
        opts.append((t, data[i + 2:i + l]))
        i += l
    return opts


def cksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip_tcp_packet(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b''):
    tcp_len = 20 + len(payload)
    # 注意格式: 偏移(0x50)与 flags 各占 1 字节, 否则 TCP 头非法会被节点静默丢弃
    tcp = struct.pack('>HHIIBBHHH', sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + b'\x00\x06' + struct.pack('>H', tcp_len)
    c = cksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack('>H', c) + tcp[18:]
    total = 20 + tcp_len
    ip = struct.pack('>BBHHHBBH', 0x45, 0, total, random.getrandbits(16), 0x4000, 64, 6, 0)
    ip += socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
    c = cksum(ip)
    ip = ip[:10] + struct.pack('>H', c) + ip[12:]
    return ip + tcp


class SstpFail(Exception):
    pass


class Sstp(object):
    """最小 SSTP 客户端: HTTP 握手 + PPP(LCP/PAP/IPCP)，随后用隧道跑 IP 包。"""

    def __init__(self, tls, host, port, user, password, timeout=12):
        self.tls = tls
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.timeout = timeout
        self.buf = b''
        self.pid = 1
        self.src_ip = None
        self.auth_required = False

    def next_pid(self):
        self.pid = (self.pid + 1) & 0xFF
        return self.pid

    def _recv_until(self, deadline, n):
        while len(self.buf) < n:
            if time.time() > deadline:
                raise SstpFail('timeout waiting for SSTP data')
            self.tls.settimeout(max(0.5, deadline - time.time()))
            try:
                chunk = self.tls.recv(65536)
            except socket.timeout:
                raise SstpFail('timeout waiting for SSTP data')
            if not chunk:
                raise SstpFail('node closed connection')
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv_packet(self, deadline):
        hdr = self._recv_until(deadline, 4)
        if hdr[0] != 0x10:
            raise SstpFail('bad SSTP magic 0x%02x' % hdr[0])
        length = ((hdr[2] & 0x0F) << 8) | hdr[3]
        if length < 4:
            raise SstpFail('bad SSTP length %d' % length)
        body = self._recv_until(deadline, length - 4) if length > 4 else b''
        return (hdr[1] & 1) == 1, body

    def http_handshake(self, deadline):
        head_req = ('SSTP_DUPLEX_POST %s HTTP/1.1\r\n'
                    'Host: %s:%d\r\n'
                    'Content-Length: 18446744073709551615\r\n'
                    'SSTPCORRELATIONID: {%s}\r\n\r\n'
                    % (SSTP_PATH, self.host, self.port, uuid.uuid4()))
        # CONNECT_REQUEST: msgType=1, attrCount=1, attr(id=1, len=6, encapsulatedProto=PPP)
        ctrl = sstp_ctrl_frame(b'\x00\x01\x00\x01\x00\x01\x00\x06\x00\x01')
        lcp = sstp_data_frame(ppp_frame(0xC021, 1, self.next_pid(), bytes([1, 4]) + struct.pack('>H', 1500)))
        self.tls.sendall(head_req.encode() + ctrl + lcp)

        while b'\r\n\r\n' not in self.buf:
            if time.time() > deadline:
                raise SstpFail('timeout on SSTP HTTP handshake')
            self.tls.settimeout(max(0.5, deadline - time.time()))
            try:
                chunk = self.tls.recv(65536)
            except socket.timeout:
                raise SstpFail('timeout on SSTP HTTP handshake')
            if not chunk:
                raise SstpFail('closed during SSTP HTTP handshake')
            self.buf += chunk
        head, _, self.buf = self.buf.partition(b'\r\n\r\n')
        status = head.split(b'\r\n', 1)[0].decode('latin1', 'replace')
        if not re.match(r'HTTP/\d(?:\.\d)?\s+2\d\d', status):
            raise SstpFail('SSTP handshake rejected: ' + status[:60])

    def negotiate(self, deadline):
        peer_lcp = local_lcp = False
        pap_required = pap_sent = pap_done = False
        ipcp_started = ipcp_done = False
        rounds = 0
        while not ipcp_done and rounds < 60:
            rounds += 1
            is_ctrl, body = self.recv_packet(deadline)
            if is_ctrl:
                continue
            p = parse_ppp(body)
            if not p or p[0] != 'ctrl':
                continue
            _, proto, code, ident, payload = p
            if proto == 0xC021:  # LCP
                if code == 1:
                    for t, d in parse_opts(payload):
                        if t == 3:
                            ap = ((d[0] << 8) | d[1]) if len(d) >= 2 else 0
                            if ap != 0xC023:
                                raise SstpFail('unsupported PPP auth 0x%x (only PAP/vpn:vpn)' % ap)
                            self.auth_required = True
                    self.tls.sendall(sstp_data_frame(ppp_frame(0xC021, 2, ident, payload)))
                    peer_lcp = True
                elif code == 2:
                    local_lcp = True
                elif code == 9:  # Echo-Request -> Echo-Reply (保活)
                    self.tls.sendall(sstp_data_frame(ppp_frame(0xC021, 10, ident, payload)))
            elif proto == 0xC023:  # PAP
                if code == 2:
                    pap_done = True
                elif code == 3:
                    raise SstpFail('PAP authentication failed')
            elif proto == 0x8021:  # IPCP
                if code == 1:
                    self.tls.sendall(sstp_data_frame(ppp_frame(0x8021, 2, ident, payload)))
                elif code == 3:  # Nak: 给出应使用的 IP
                    for t, d in parse_opts(payload):
                        if t == 3 and len(d) == 4:
                            self.src_ip = '.'.join(str(b) for b in d[0:4])
                    opt = bytes([3, 6]) + (socket.inet_aton(self.src_ip) if self.src_ip else b'\x00\x00\x00\x00')
                    self.tls.sendall(sstp_data_frame(ppp_frame(0x8021, 1, self.next_pid(), opt)))
                    ipcp_started = True
                elif code == 2:  # Ack
                    for t, d in parse_opts(payload):
                        if t == 3 and len(d) == 4:
                            self.src_ip = '.'.join(str(b) for b in d[0:4])
                    ipcp_done = True
            if peer_lcp and local_lcp and self.auth_required and not pap_sent:
                u = self.user.encode()
                pw = self.password.encode()
                pap = b'\xc0\x23' + bytes([1, self.next_pid()]) + struct.pack('>H', 6 + len(u) + len(pw))
                pap += bytes([len(u)]) + u + bytes([len(pw)]) + pw
                self.tls.sendall(sstp_data_frame(pap))
                pap_sent = True
            if peer_lcp and local_lcp and (pap_done or not self.auth_required) and not ipcp_started:
                self.tls.sendall(sstp_data_frame(ppp_frame(0x8021, 1, self.next_pid(), bytes([3, 6, 0, 0, 0, 0]))))
                ipcp_started = True
        if not self.src_ip:
            raise SstpFail('SSTP negotiation did not assign an IP')
        # IPCP 完成后短暂排水: 服务器常在此时追加 DNS 等 Configure-Request / Echo, 必须确认
        drain_end = time.time() + 0.8
        while time.time() < drain_end:
            try:
                is_ctrl, body = self.recv_packet(drain_end)
            except Exception:
                break
            if is_ctrl:
                continue
            p = parse_ppp(body)
            if not p or p[0] != 'ctrl':
                continue
            _, proto, code, ident, payload = p
            if code == 1:
                self.tls.sendall(sstp_data_frame(ppp_frame(proto, 2, ident, payload)))
            elif proto == 0xC021 and code == 9:
                self.tls.sendall(sstp_data_frame(ppp_frame(0xC021, 10, ident, payload)))
        return self.src_ip


# ---------------------------------------------------------------------------
# PPP 内最小 TCP（不重传、不校验序号 —— 与 edgetunnel 的实现同级，测速够用）
# ---------------------------------------------------------------------------

class MiniTcp(object):
    MSS = 1400  # PPP MRU 1500 内：IP20 + TCP20 + 载荷 1400

    def __init__(self, cli, src_ip, dst_ip, dport, timeout):
        self.cli = cli
        self.src = src_ip
        self.dst = dst_ip
        self.dport = dport
        self.sport = 10000 + random.getrandbits(14)
        self.seq = random.getrandbits(32)
        self.ack = 0
        self.deadline = time.time() + timeout
        self.server_ack = 0
        self.peer_window = 65535

    def unacked(self):
        return (self.seq - self.server_ack) & 0xFFFFFFFF

    def _send(self, flags, payload=b''):
        pkt = ip_tcp_packet(self.src, self.dst, self.sport, self.dport, self.seq, self.ack, flags, payload)
        self.cli.tls.sendall(sstp_data_frame(b'\x00\x21' + pkt))

    def collect(self):
        """返回 (flags, peer_seq, payload)；只挑本连接的 TCP 数据包，顺带跟踪对端 ACK/窗口。"""
        while True:
            is_ctrl, body = self.cli.recv_packet(self.deadline)
            if is_ctrl:
                continue
            p = parse_ppp(body)
            if not p:
                continue
            if p[0] == 'ctrl':
                _, proto, code, ident, payload = p
                if proto == 0xC021 and code == 9:  # 隧道内的 LCP 保活
                    self.cli.tls.sendall(sstp_data_frame(ppp_frame(0xC021, 10, ident, payload)))
                continue
            ipb = p[1]
            if len(ipb) < 20 or ipb[9] != 6:
                continue
            if socket.inet_ntoa(ipb[16:20]) != self.src:
                continue
            ihl = (ipb[0] & 0x0F) * 4
            tcp = ipb[ihl:]
            if len(tcp) < 20:
                continue
            sport, dport = struct.unpack('>HH', tcp[:4])
            if sport != self.dport or dport != self.sport:
                continue
            seq = struct.unpack('>I', tcp[4:8])[0]
            self.server_ack = struct.unpack('>I', tcp[8:12])[0]
            self.peer_window = max(struct.unpack('>H', tcp[14:16])[0], self.peer_window)
            flags = tcp[13]
            payload = tcp[(tcp[12] >> 4) * 4:]
            return flags, seq, payload

    def connect(self):
        self._send(0x02)  # SYN
        self.seq = (self.seq + 1) & 0xFFFFFFFF
        end = time.time() + 10
        while time.time() < end:
            flags, pseq, _ = self.collect()
            if flags & 0x02:  # SYN|ACK
                self.ack = (pseq + 1) & 0xFFFFFFFF
                self._send(0x10)
                return
        raise SstpFail('PPP TCP connect timeout')

    def send_all(self, data):
        """大负载分片成 MSS 的 IP 包发送，尊重对端窗口（简单流控）。"""
        view = memoryview(data)
        while view:
            while self.unacked() >= max(self.peer_window, 1):
                if time.time() > self.deadline:
                    raise SstpFail('send stalled (flow control)')
                flags, pseq, payload = self.collect()
                if payload:
                    self.ack = (pseq + len(payload)) & 0xFFFFFFFF
                    self._send(0x10)
                if flags & 0x01:
                    raise SstpFail('connection closed during send')
            n = min(self.MSS, len(view))
            self._send(0x18, bytes(view[:n]))
            self.seq = (self.seq + n) & 0xFFFFFFFF
            view = view[n:]

    def send_request(self, data):
        self.send_all(data)

    def read_until_close(self, max_bytes=4_000_000):
        raw = b''
        while time.time() < self.deadline and len(raw) < max_bytes:
            flags, pseq, payload = self.collect()
            if payload:
                self.ack = (pseq + len(payload)) & 0xFFFFFFFF
                self._send(0x10)
                raw += payload
            if flags & 0x01:  # FIN
                self.ack = (pseq + len(payload) + 1) & 0xFFFFFFFF
                self._send(0x10)
                break
        return raw

    def recv_raw(self):
        """取下一个数据段并 ACK；对端 FIN 返回 b''。供隧道内 TLS 使用。"""
        while True:
            flags, pseq, payload = self.collect()
            if payload:
                self.ack = (pseq + len(payload)) & 0xFFFFFFFF
                self._send(0x10)
                return payload
            if flags & 0x01:
                self.ack = (pseq + len(payload) + 1) & 0xFFFFFFFF
                self._send(0x10)
                return b''
            # 纯 ACK / 保活，继续等


class TunnelTLS(object):
    """PPP 隧道内 TLS (内存 BIO 实现, 无需真实 socket)。"""

    def __init__(self, mt, host):
        self.mt = mt
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.in_bio = ssl.MemoryBIO()
        self.out_bio = ssl.MemoryBIO()
        self.obj = ctx.wrap_bio(self.in_bio, self.out_bio, server_hostname=host)

    def _pump_out(self):
        data = self.out_bio.read()
        if data:
            self.mt.send_all(data)

    def handshake(self, deadline):
        while True:
            if time.time() > deadline:
                raise SstpFail('TLS handshake timeout in tunnel')
            try:
                self.obj.do_handshake()
                self._pump_out()
                return
            except ssl.SSLWantReadError:
                self._pump_out()
                data = self.mt.recv_raw()
                if not data:
                    raise SstpFail('EOF during TLS handshake')
                self.in_bio.write(data)
            except ssl.SSLWantWriteError:
                self._pump_out()

    def sendall(self, data):
        self.obj.write(data)
        while self.out_bio.pending:
            chunk = self.out_bio.read(16384)
            if not chunk:
                break
            self.mt.send_all(chunk)

    def read(self, n=65536, deadline=None):
        while True:
            try:
                return self.obj.read(n)
            except ssl.SSLWantReadError:
                if deadline and time.time() > deadline:
                    raise SstpFail('TLS read timeout')
                self._pump_out()
                data = self.mt.recv_raw()
                if not data:
                    return b''
                self.in_bio.write(data)
            except ssl.SSLWantWriteError:
                self._pump_out()
            except ssl.SSLEOFError:
                return b''


def https_get_over_ppp(cli, src_ip, url, timeout, max_bytes):
    u = urlparse(url)
    ip = socket.gethostbyname(u.hostname)
    mt = MiniTcp(cli, src_ip, ip, 443, timeout)
    mt.connect()
    tt = TunnelTLS(mt, u.hostname)
    tt.handshake(time.time() + timeout)
    path = u.path + (('?' + u.query) if u.query else '')
    t0 = time.perf_counter()
    tt.sendall(('GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vpngate-lite\r\n\r\n'
                % (path, u.hostname)).encode())
    raw = b''
    while len(raw) < max_bytes and time.perf_counter() - t0 < timeout:
        chunk = tt.read(65536, deadline=mt.deadline)
        if not chunk:
            break
        raw += chunk
    elapsed = time.perf_counter() - t0
    head, sep, body = raw.partition(b'\r\n\r\n')
    if not sep:
        raise SstpFail('no HTTPS response over PPP tunnel')
    return head, body, elapsed


def upload_over_ppp(cli, src_ip, body, timeout=20):
    """隧道内 POST 大负载到 Cloudflare __up，测节点上行带宽。"""
    u = urlparse(UP_URL)
    ip = socket.gethostbyname(u.hostname)
    mt = MiniTcp(cli, src_ip, ip, 443, timeout)
    mt.connect()
    tt = TunnelTLS(mt, u.hostname)
    tt.handshake(time.time() + timeout)
    req = ('POST /__up HTTP/1.1\r\nHost: %s\r\nUser-Agent: vpngate-lite\r\n'
           'Content-Type: application/octet-stream\r\nContent-Length: %d\r\n'
           'Connection: close\r\n\r\n' % (u.hostname, len(body)))
    t0 = time.perf_counter()
    tt.sendall(req.encode() + body)
    t_sent = time.perf_counter()
    raw = b''
    while time.perf_counter() - t0 < timeout:
        try:
            chunk = tt.read(65536, deadline=min(time.time() + 5, mt.deadline))
        except SstpFail:
            break
        if not chunk:
            break
        if not raw:
            raw = chunk
        if b'\r\n\r\n' in raw:
            head, _, rest = raw.partition(b'\r\n\r\n')
            m = re.search(rb'Content-Length:\s*(\d+)', head, re.I)
            need = int(m.group(1)) if m else 0
            if len(rest) >= need:
                break
    head, _, _ = raw.partition(b'\r\n\r\n')
    if not raw.startswith(b'HTTP/1.1 2'):
        raise SstpFail('upload rejected: ' + raw[:40].decode('latin1', 'replace'))
    return round(len(body) * 8 / max(t_sent - t0, 1e-6) / 1e6, 2)


def http_over_ppp(cli, src_ip, url, timeout, max_bytes):
    u = urlparse(url)
    ip = socket.gethostbyname(u.hostname)
    mt = MiniTcp(cli, src_ip, ip, u.port or 80, timeout)
    mt.connect()
    path = u.path + (('?' + u.query) if u.query else '')
    req = ('GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: vpngate-lite\r\n\r\n' % (path, u.hostname)).encode()
    t0 = time.perf_counter()
    mt.send_request(req)
    raw = mt.read_until_close(max_bytes=max_bytes)
    elapsed = time.perf_counter() - t0
    head, sep, body = raw.partition(b'\r\n\r\n')
    if not sep:
        raise SstpFail('no HTTP response over PPP tunnel')
    m = re.search(rb'Content-Length:\s*(\d+)', head, re.I)
    clen = int(m.group(1)) if m else len(body)
    return head, body, clen, elapsed


# ---------------------------------------------------------------------------
# 单节点探测
# ---------------------------------------------------------------------------

def probe_node(cand, args):
    r = {'host': cand['host'], 'port': cand['port'], 'code': cand['code'], 'country': cand['country'],
         'ok': False, 'stage': '', 'error': '', 'latency_ms': None, 'mbps': None, 'up_mbps': None,
         'speed_src': '', 'exit_ip': '', 'isp': '', 'city': '', 'tag': '', 'streak': 0}
    t0 = time.time()
    sock = None
    tls = None
    cli = None
    try:
        sock = open_tcp(cand['host'], cand['port'], args.proxy, 12)
    except Exception as e:
        r['stage'] = 'tcp'
        r['error'] = short_err(e)
        return r
    try:
        tls = wrap_tls(sock, cand['host'], 12)
    except Exception as e:
        r['stage'] = 'tls'
        r['error'] = short_err(e)
        return r
    try:
        cli = Sstp(tls, cand['host'], cand['port'], 'vpn', 'vpn', 12)
        cli.http_handshake(time.time() + 15)
        src_ip = cli.negotiate(time.time() + 30)
        r['latency_ms'] = int((time.time() - t0) * 1000)
    except Exception as e:
        r['stage'] = 'sstp'
        r['error'] = short_err(e)
        return r

    if not args.no_info:
        try:
            head, body, _, _ = http_over_ppp(cli, src_ip, INFO_URL, 15, 100_000)
            j = json.loads(body.decode('utf-8', 'replace').strip() or '{}')
            if j.get('status') == 'success':
                r['exit_ip'] = j.get('query', '')
                r['isp'] = j.get('isp', '')
                r['city'] = j.get('city', '')
                r['tag'] = 'dc' if (j.get('hosting') or j.get('proxy')) else 'home'
        except Exception as e:
            r['stage'] = r['stage'] or 'info'
            r['error'] = r['error'] or short_err(e)

    if not args.no_speed:
        for url in SPEED_URLS:
            try:
                if url.startswith('https://'):
                    head, body, el = https_get_over_ppp(cli, src_ip, url, 15, SPEED_BYTES + 100_000)
                    got = len(body)
                else:
                    head, body, clen, el = http_over_ppp(cli, src_ip, url, 12, SPEED_BYTES + 200_000)
                    got = min(len(body), clen) if clen else len(body)
                if got < 50_000:  # 太少不算有效测速
                    raise SstpFail('only %d bytes' % got)
                r['mbps'] = round(got * 8 / el / 1e6, 2) if el > 0 else 0.0
                r['speed_src'] = urlparse(url).hostname
                break
            except Exception as e:
                r['stage'] = r['stage'] or 'speed'
                r['error'] = r['error'] or short_err(e)

    if not args.no_up:
        try:
            r['up_mbps'] = upload_over_ppp(cli, src_ip, UP_BODY, 20)
        except Exception as e:
            r['stage'] = r['stage'] or 'up'
            r['error'] = r['error'] or short_err(e)

    r['ok'] = True
    try:
        tls.close()
    except Exception:
        pass
    return r


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

def build_outputs(results, edge_pool, out_dir, include_dc=False):
    os.makedirs(out_dir, exist_ok=True)
    ok_all = [r for r in results if r['ok']]
    dc_found = [r for r in ok_all if r['tag'] == 'dc']
    # 默认排除机房节点; report.csv 仍保留全量供审计
    ok = ok_all if include_dc else [r for r in ok_all if r['tag'] != 'dc']
    # 排序: 稳定优先 -> 住宅优先 -> mbps 降序 -> 延迟升序
    def sort_key(r):
        return (0 if r['tag'] != 'dc' else 1, -r.get('streak', 0), -(r['mbps'] or 0), r['latency_ms'] or 99999)
    ok.sort(key=sort_key)

    # 按国家分组（数量多的国家靠前），组内按 tag+速度
    by_country = {}
    for r in ok:
        by_country.setdefault(r['code'], []).append(r)
    ordered = []
    for code, group in sorted(by_country.items(), key=lambda kv: -len(kv[1])):
        group.sort(key=sort_key)
        ordered.extend(group)

    counter = {}
    lines = []
    for i, r in enumerate(ordered):
        code = r['code'] or '??'
        zh = COUNTRY_ZH.get(code, code)
        tag = {'home': '住宅', 'dc': '机房'}.get(r['tag'], '节点')
        stable = '-稳' if r.get('streak', 0) >= 2 else ''
        counter[(code, tag, stable)] = counter.get((code, tag, stable), 0) + 1
        name = '%s-%s%s-%02d' % (zh, tag, stable, counter[(code, tag, stable)])
        entry = edge_pool[i % len(edge_pool)]
        lines.append('%s#%s$sstp://vpn:vpn@%s:%d' % (entry, name, r['host'], r['port']))

    with open(os.path.join(out_dir, 'nodes.txt'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + ('\n' if lines else ''))

    fields = ['host', 'port', 'code', 'country', 'ok', 'tag', 'streak', 'mbps', 'up_mbps', 'speed_src',
              'latency_ms', 'exit_ip', 'isp', 'city', 'stage', 'error']
    with open(os.path.join(out_dir, 'report.csv'), 'w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in sorted(results, key=lambda x: (not x['ok'], x['code'], x['host'])):
            w.writerow(r)

    up_vals = sorted([r['up_mbps'] for r in ok if r['up_mbps'] is not None])
    stats = {
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'checked': len(results), 'ok': len(ok),
        'residential': sum(1 for r in ok if r['tag'] == 'home'),
        'datacenter': sum(1 for r in ok if r['tag'] == 'dc'),
        'dc_excluded': (len(dc_found) if not include_dc else 0),
        'stable': sum(1 for r in ok if r.get('streak', 0) >= 2),
        'countries': sorted({r['code'] for r in ok}),
        'median_mbps': (sorted([r['mbps'] for r in ok if r['mbps'] is not None])[len([r for r in ok if r['mbps'] is not None]) // 2]
                        if any(r['mbps'] is not None for r in ok) else None),
        'median_up': (up_vals[len(up_vals) // 2] if up_vals else None),
    }
    with open(os.path.join(out_dir, 'summary.json'), 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=1)
    return stats, lines


def load_state(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(path, st):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(st, f, ensure_ascii=False)


def load_edge_pool(explicit):
    """入口池优先级: --edge 参数 > edge_hosts.txt(脚本同目录) > 内置默认池。
    文件每行一个入口, 支持 # 注释; 缺端口默认 443。"""
    if explicit:
        return [e.strip() for e in explicit.split(',') if e.strip()], '--edge 参数'
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, 'edge_hosts.txt')
    if os.path.exists(path):
        pool = []
        for ln in open(path, encoding='utf-8'):
            ln = ln.split('#', 1)[0].strip()
            if not ln:
                continue
            if ':' not in ln:
                ln += ':443'
            pool.append(ln)
        if pool:
            return pool, 'edge_hosts.txt'
    return list(DEFAULT_EDGE_POOL), '内置默认池'


def main():
    ap = argparse.ArgumentParser(description='VPN Gate SSTP probe -> edgetunnel chain format')
    ap.add_argument('--proxy', default='', help='HTTP 代理 (本机跑必填, 如 http://127.0.0.1:7897)')
    ap.add_argument('--edge', default='', help='入口域名池, 逗号分隔 (默认内置 6 个)')
    ap.add_argument('--country', default='', help='只要这些国家, 逗号分隔 如 JP,KR')
    ap.add_argument('--max', type=int, default=120, help='最多探测多少个节点 (按 ping 排序取前 N)')
    ap.add_argument('--concurrency', type=int, default=6)
    ap.add_argument('--out', default='out')
    ap.add_argument('--include-dc', action='store_true', help='保留机房节点 (默认排除, nodes.txt 只出住宅/未判定)')
    ap.add_argument('--include-official', action='store_true', help='包含官方机房 (默认排除)')
    ap.add_argument('--no-info', action='store_true', help='跳过出口 IP 查询 (更快)')
    ap.add_argument('--no-speed', action='store_true', help='跳过测速 (更快)')
    ap.add_argument('--no-up', action='store_true', help='跳过上传测速 (更快)')
    args = ap.parse_args()

    state_path = os.path.join(args.out, 'state.json')
    state = load_state(state_path)
    log('[state] 记忆节点 %d 个' % len(state))

    text = fetch_api(args.proxy)
    rows = parse_rows(text, include_official=args.include_official)
    log('[parse] TCP 节点 %d 个' % len(rows))

    if args.country:
        keep = {c.strip().upper() for c in args.country.split(',') if c.strip()}
        rows = [r for r in rows if r['code'] in keep]
        log('[parse] 国家过滤后 %d 个' % len(rows))
    rows.sort(key=lambda r: r['ping'])
    rows = rows[:args.max]

    # 存活记忆: 上轮活着的、不在本轮 API 名单里的节点，补进候选（按存活轮数降序）
    rows_keys = {'%s:%d' % (r['host'].lower(), r['port']) for r in rows}
    extras = []
    for k, v in sorted(state.items(), key=lambda kv: -kv[1].get('streak', 0)):
        if v.get('streak', 0) < 1 or k in rows_keys:
            continue
        h, _, p = k.rpartition(':')
        extras.append({'host': h, 'port': int(p), 'code': v.get('code', '?'),
                       'country': v.get('country', '?'), 'ping': 0})
    rows = rows + extras
    log('[plan] 将探测 %d 个 (API %d + 记忆 %d), 并发 %d' % (len(rows), len(rows) - len(extras), len(extras), args.concurrency))

    edge_pool, edge_src = load_edge_pool(args.edge)
    log('[edge] 入口池: %d 个 (来源: %s)' % (len(edge_pool), edge_src))

    results = []
    done = [0]
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futs = {pool.submit(probe_node, c, args): c for c in rows}
        for fut in as_completed(futs):
            try:
                r = fut.result()
            except Exception as e:
                c = futs[fut]
                r = {'host': c['host'], 'port': c['port'], 'code': c['code'], 'country': c['country'],
                     'ok': False, 'stage': 'internal', 'error': short_err(e), 'latency_ms': None,
                     'mbps': None, 'up_mbps': None, 'exit_ip': '', 'isp': '', 'city': '', 'tag': '',
                     'streak': 0}
            results.append(r)
            done[0] += 1
            okn = sum(1 for x in results if x['ok'])
            log('[%3d/%3d] %-4s %-30s:%-5d %s %s' % (
                done[0], len(rows), r['code'], r['host'], r['port'],
                'OK ' + ('%sms' % r['latency_ms'] if r['latency_ms'] else '')
                + (' ↓%.1f' % r['mbps'] if r['mbps'] else '')
                + (' ↑%.1f' % r['up_mbps'] if r['up_mbps'] else '')
                + (' 稳x%d' % r['streak'] if r.get('streak', 0) >= 2 else ''),
                ('fail@' + r['stage'] + ' ' + r['error']) if not r['ok'] else ''))

    # 更新存活记忆: 本轮探测过的节点, 活着 streak+1, 挂了清零; 没探测到的保持原状
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    for r in results:
        k = '%s:%d' % (r['host'].lower(), r['port'])
        if r['ok']:
            v = state.get(k, {})
            state[k] = {'streak': v.get('streak', 0) + 1,
                        'mbps': r['mbps'] if r['mbps'] is not None else v.get('mbps'),
                        'up': r['up_mbps'] if r['up_mbps'] is not None else v.get('up'),
                        'code': r['code'], 'country': r['country'], 'last': now}
        elif k in state:
            state[k]['streak'] = 0
            state[k]['last'] = now
    stale_cut = (datetime.now(timezone.utc) - timedelta(days=7)).strftime('%Y-%m-%d')
    stale = [k for k, v in state.items() if v.get('last', '9999') < stale_cut]
    for k in stale:
        del state[k]
    for k in stale:
        del state[k]
    save_state(state_path, state)
    log('[state] 记忆已保存: %d 个节点 (存活 streak>=1: %d)' % (
        len(state), sum(1 for v in state.values() if v.get('streak', 0) >= 1)))

    # 把更新后的 streak 回填到结果（供排序与「稳」命名）
    for r in results:
        k = '%s:%d' % (r['host'].lower(), r['port'])
        r['streak'] = state.get(k, {}).get('streak', 0) if r['ok'] else 0

    stats, lines = build_outputs(results, edge_pool, args.out, include_dc=args.include_dc)
    log('')
    log('===== 结果 =====')
    log('可用: %d / %d (住宅 %d, 机房 %d%s)' % (stats['ok'], stats['checked'],
                                              stats['residential'], stats['datacenter'],
                                              ('', ', 机房已排除 %d 个' % stats['dc_excluded'])[stats['dc_excluded'] > 0]))
    for code in stats['countries']:
        zh = COUNTRY_ZH.get(code, code)
        n = sum(1 for r in results if r['ok'] and r['code'] == code)
        log('  %s(%s): %d' % (zh, code, n))
    if stats['median_mbps'] is not None:
        log('中位速度: %.2f Mbps (节点侧下载 1MB)' % stats['median_mbps'])
    log('输出: %s' % ', '.join('out/%s' % f for f in ('nodes.txt', 'report.csv', 'summary.json')))
    if stats['ok'] == 0:
        sys.exit(2)


if __name__ == '__main__':
    main()
