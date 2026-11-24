"""Basic tests (no external deps)."""
import socket, threading, sys, os
sys.path.insert(0, os.path.dirname(__file__))

def test_port_parser():
    from nmap import parse_ports
    assert parse_ports("22,80,443", 0) == [22, 80, 443]
    assert parse_ports("1-5", 0) == [1, 2, 3, 4, 5]

def test_target_parser():
    from nmap import parse_targets
    hosts = parse_targets(["127.0.0.1"], [])
    assert "127.0.0.1" in hosts

def test_tcp_connect():
    from nmap import tcp_connect
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.listen(1)
    def accept():
        c, _ = s.accept(); c.close()
    t = threading.Thread(target=accept, daemon=True); t.start()
    ok, _ = tcp_connect("127.0.0.1", port, 1)
    assert ok

if __name__ == "__main__":
    test_port_parser()
    test_target_parser()
    test_tcp_connect()
    print("all tests passed")
EOF
echo done