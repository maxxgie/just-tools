"""Extra features: rate limiting, traceroute, config, logging, resume."""
import json, socket, time, logging, os

class RateLimiter:
    def __init__(self, rate):
        self.interval = 1.0 / rate if rate > 0 else 0
        self.last = 0
    def wait(self):
        if self.interval:
            now = time.time()
            delta = now - self.last
            if delta < self.interval:
                time.sleep(self.interval - delta)
            self.last = time.time()

def load_config(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)

def setup_logging(path):
    logging.basicConfig(filename=path, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

def traceroute(dst, max_hops=30, timeout=1):
    out = []
    for ttl in range(1, max_hops + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            s.settimeout(timeout)
            s.sendto(b"", (dst, 33434))
            _, addr = s.recvfrom(512)
            out.append((ttl, addr[0]))
            s.close()
            if addr[0] == dst:
                break
        except socket.timeout:
            out.append((ttl, "*"))
        except Exception:
            out.append((ttl, "!"))
    return out

def save_resume(path, data):
    with open(path, "w") as f:
        json.dump(data, f)

def load_resume(path):
    if path and os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []
EOF
echo done
PROFILES = {
    "quick": {"ports": "1-1000", "timing": 4, "svc": True, "osdet": False},
    "full": {"ports": "1-65535", "timing": 4, "svc": True, "osdet": True},
    "stealth": {"ports": "1-1000", "timing": 2, "svc": True, "osdet": True, "fragment": True, "scan": "syn"},
}

def apply_profile(args):
    prof = PROFILES.get(args.profile)
    if not prof:
        return args
    for k, v in prof.items():
        if hasattr(args, k):
            setattr(args, k, v)
    return args
