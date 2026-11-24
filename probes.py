"""Service/version detection probes."""
import socket

PROBES = {
    "http": b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    "https": b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    "ssh": b"",
    "ftp": b"",
    "smtp": b"EHLO probe\r\n",
    "generic": b"\r\n",
}

PATTERNS = [
    (b"SSH-", "ssh"),
    (b"HTTP/", "http"),
    (b"220 ", "smtp/ftp"),
    (b"MySQL", "mysql"),
    (b"Redis", "redis"),
    (b"MongoDB", "mongodb"),
]

def probe(host, port, timeout=3):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        # send HTTP probe
        try:
            s.sendall(PROBES["http"])
        except Exception:
            pass
        s.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
                if len(data) > 4096:
                    break
        except socket.timeout:
            pass
        s.close()
        text = data.decode(errors="replace")
        for pat, name in PATTERNS:
            if pat in data:
                return name, text.splitlines()[0][:120] if text else ""
        # fallback banner
        if text.strip():
            return "unknown", text.splitlines()[0][:120]
        return "unknown", ""
    except Exception:
        return None, ""
EOF
echo done