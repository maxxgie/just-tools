"""Power features: parallel hosts, progress, daemon, PDF, NVD, plugins, etc."""
import socket, ssl, json, threading, time, os, importlib, urllib.request

def parallel_hosts(hosts, fn, workers=10):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(fn, hosts))

def progress(done, total):
    pct = int(done / total * 100) if total else 100
    return f"[{'#' * (pct//2)}{'.' * (50 - pct//2)}] {pct}%"

def plugin_load(path):
    try:
        spec = importlib.util.spec_from_file_location("plugin", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None

def tls_ciphers(host, port=443):
    ciphers = []
    for proto in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = proto
            ctx.maximum_version = proto
            with socket.create_connection((host, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    ciphers.append((ss.version(), ss.cipher()[0]))
        except Exception as e:
            ciphers.append((str(proto), f"error: {e}"))
    return ciphers

def smb_full(host):
    out = []
    for port in (139, 445):
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.sendall(b"\x00\x00\x00\x00\xffSMB")
            data = s.recv(1024)
            s.close()
            if b"SMB" in data:
                out.append(f"SMB on {port}")
        except Exception:
            pass
    return out or ["no SMB"]

def web_brute(host, port=80, wordlist=None):
    if not wordlist or not os.path.exists(wordlist):
        return []
    found = []
    with open(wordlist) as f:
        for path in f:
            path = path.strip()
            if not path: continue
            try:
                s = socket.create_connection((host, port), timeout=2)
                s.sendall(f"GET /{path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                data = s.recv(1024)
                s.close()
                if b"200" in data.split(b"\r\n")[0]:
                    found.append(path)
            except Exception:
                pass
    return found

def dns_zone_transfer(domain, ns=None):
    # basic AXFR attempt over TCP 53
    try:
        s = socket.create_connection((ns or domain, 53), timeout=3)
        # minimal AXFR query not implemented fully
        s.close()
        return "AXFR requires full DNS packet"
    except Exception:
        return "failed"

def nvd_lookup(cve):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.read().decode()[:500]
    except Exception as e:
        return f"error: {e}"

def pdf_export(results, path):
    # minimal PDF writer (text only)
    lines = []
    for r in results:
        lines.append(f"Host {r['host']}")
        for p in r["ports"]:
            lines.append(f"  {p['port']} {p.get('svc','')} {p.get('ver','')}")
    content = "\n".join(lines)
    # very simple PDF
    objs = []
    objs.append("<< /Type /Catalog /Pages 2 0 R >>")
    objs.append("<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objs.append("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>")
    stream = f"BT /F1 12 Tf 50 750 Td ({content}) Tj ET"
    objs.append(f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream")
    objs.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    out = "%PDF-1.4\n"
    offsets = [0]
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{o}\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n"
    out += f"trailer << /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
    with open(path, "w") as f:
        f.write(out)

def daemon(host="0.0.0.0", port=8080):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"nmap-js daemon running")
    HTTPServer((host, port), H).serve_forever()
EOF
echo done