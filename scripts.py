"""Simple NSE-like script runner (Python functions instead of Lua)."""
import socket, re

def banner(host, port, banner):
    return (banner or "no banner")[:200]

def http_title(host, port, banner):
    if not banner:
        return "n/a"
    m = re.search(r"<title>([^<]*)</title>", banner, re.I)
    return m.group(1) if m else "no title"

def ssh_hostkey(host, port, banner):
    return (banner or "")[:120]

SCRIPTS = {
    "banner": banner,
    "http-title": http_title,
    "ssh-hostkey": ssh_hostkey,
}

def run(name, host, port, banner):
    fn = SCRIPTS.get(name)
    if not fn:
        return "script not found"
    try:
        return fn(host, port, banner)
    except Exception as e:
        return f"error: {e}"
EOF
echo done