"""Advanced/pro scanning helpers."""
import socket, ssl, re, json

OUI = {"00:00:0C":"Cisco","00:1A:2B":"Ayecom","00:50:56":"VMware","08:00:27":"VirtualBox","00:0C:29":"VMware","00:1C:42":"Parallels"}

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def mac_vendor(mac):
    if not mac:
        return None
    prefix = mac.upper()[:8]
    return OUI.get(prefix, "Unknown")

def tls_info(host, port=443, timeout=3):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                    "subject": dict(x[0] for x in cert.get("subject", [])) if cert else {},
                }
    except Exception as e:
        return {"error": str(e)}

def udp_scan(host, port, timeout=1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"\x00", (host, port))
        try:
            s.recvfrom(1024)
            return "open"
        except socket.timeout:
            return "open|filtered"
        except ConnectionRefusedError:
            return "closed"
    except Exception:
        return "filtered"
    finally:
        try: s.close()
        except: pass

def crawl(host, port=80, timeout=3):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        s.close()
        text = data.decode(errors="replace")
        links = re.findall(r'href=["\']([^"\']+)["\']', text, re.I)
        return sorted(set(links))[:50]
    except Exception:
        return []

def ftp_bounce_scan(proxy_host, proxy_port, target, port, timeout=3):
    try:
        s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
        s.recv(1024)  # banner
        s.sendall(b"USER anonymous\r\n"); s.recv(1024)
        s.sendall(b"PASS probe\r\n"); s.recv(1024)
        cmd = f"PORT {target.replace('.', ',')},{port//256},{port%256}\r\n"
        s.sendall(cmd.encode()); s.recv(1024)
        s.sendall(b"LIST\r\n")
        data = b""
        s.settimeout(timeout)
        try:
            while True:
                chunk = s.recv(1024)
                if not chunk: break
                data += chunk
        except socket.timeout:
            pass
        s.close()
        if b"150" in data or b"226" in data:
            return "open"
        return "closed"
    except Exception:
        return "error"

def idle_scan(zombie, target, port, timeout=3):
    """Placeholder idle scan; requires raw spoofing (root)."""
    # real implementation needs IP spoofing and zombie IPID tracking
    return "requires raw spoofing support"
EOF
echo done