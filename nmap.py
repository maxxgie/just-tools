#!/usr/bin/env python3
import argparse, socket, ipaddress, concurrent.futures, json, xml.etree.ElementTree as ET, time, sys
try:
    import rawscan
    HAVE_RAW = True
except Exception:
    HAVE_RAW = False
try:
    import probes
    HAVE_PROBES = True
except Exception:
    HAVE_PROBES = False

TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443]
SVC_MAP = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"domain",80:"http",110:"pop3",143:"imap",443:"https",445:"microsoft-ds",3306:"mysql",3389:"ms-wbt-server",5432:"postgres",6379:"redis",27017:"mongodb",8080:"http-proxy"}

def parse_targets(targets, exclude):
    out=[]
    for t in targets:
        try:
            net=ipaddress.ip_network(t, strict=False)
            for h in net.hosts():
                out.append(str(h))
        except ValueError:
            if "-" in t and "." in t:
                ip,end=t.split("-")
                parts=ip.split(".")
                prefix=".".join(parts[:3])
                for i in range(int(parts[3]), int(end)+1):
                    out.append(f"{prefix}.{i}")
            else:
                out.append(t)
    return [h for h in out if h not in exclude]

def parse_ports(spec, top):
    if top:
        return TOP_PORTS[:top]
    ports=set()
    for part in spec.split(","):
        part=part.strip()
        if not part: continue
        if "-" in part:
            a,b=part.split("-")
            for i in range(int(a), int(b)+1): ports.add(i)
        else:
            ports.add(int(part))
    return sorted(ports)

def tcp_connect(host,port,timeout):
    try:
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        s=socket.create_connection((host,port),timeout=timeout)
        s.settimeout(0.3)
        try:
            data=s.recv(256).decode(errors="replace")
        except Exception:
            data=""
        s.close()
        return True, data.strip()
    except Exception:
        return False, ""

def host_alive(host, timeout):
    if HAVE_RAW:
        r = rawscan.icmp_ping(host, timeout)
        if r is True:
            return True
        if r is None:
            pass
    for p in (80,443,22,445):
        ok,_=tcp_connect(host,p,timeout)
        if ok: return True
    try:
        socket.gethostbyname(host); return True
    except Exception:
        return False

def os_guess(open_ports):
    if 445 in open_ports and 3389 in open_ports: return "Windows"
    if 22 in open_ports and 3306 in open_ports: return "Linux"
    if 22 in open_ports: return "Linux/Unix"
    if 80 in open_ports or 443 in open_ports: return "Network device / Web server"
    return "Unknown"

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import scripts as nse
    HAVE_SCRIPTS = True
except Exception as e:
    HAVE_SCRIPTS = False
    _scripts_err = str(e)
try:
    import extras
    HAVE_EXTRAS = True
except Exception:
    HAVE_EXTRAS = False
try:
    import advanced
    HAVE_ADV = True
except Exception:
    HAVE_ADV = False
try:
    import pro
    HAVE_PRO = True
except Exception:
    HAVE_PRO = False
try:
    import power
    HAVE_POWER = True
except Exception:
    HAVE_POWER = False

def script_run(name, host, port, banner):
    # inline implementations (always available)
    if name == "banner":
        return (banner or "no banner")[:200]
    if name == "http-title":
        import re
        m = re.search(r"<title>([^<]*)</title>", banner or "", re.I)
        return m.group(1) if m else "no title"
    if name == "ssh-hostkey":
        return (banner or "")[:120]
    if HAVE_SCRIPTS:
        return nse.run(name, host, port, banner)
    return "script not found"

def main():
    ap=argparse.ArgumentParser(description="nmap-js python port")
    ap.add_argument("targets", nargs="*", default=["127.0.0.1"])
    ap.add_argument("-p", dest="ports", default="1-1024")
    ap.add_argument("-sS", dest="scan", action="store_const", const="syn", default="connect")
    ap.add_argument("-sT", dest="scan", action="store_const", const="connect")
    ap.add_argument("-sU", dest="scan", action="store_const", const="udp")
    ap.add_argument("-sY", dest="scan", action="store_const", const="sctp")
    ap.add_argument("-sV", dest="svc", action="store_true")
    ap.add_argument("-O", dest="osdet", action="store_true")
    ap.add_argument("-sn", dest="hostonly", action="store_true")
    ap.add_argument("-Pn", dest="skiphost", action="store_true")
    ap.add_argument("-T", dest="timing", type=int, default=3, choices=range(6))
    ap.add_argument("-oN", dest="outN")
    ap.add_argument("-oG", dest="outG")
    ap.add_argument("-oX", dest="outX")
    ap.add_argument("-oJ", dest="outJ")
    ap.add_argument("-v", dest="verbose", action="store_true")
    ap.add_argument("--top-ports", dest="top", type=int, default=0)
    ap.add_argument("--script", dest="scripts", action="append", default=[])
    ap.add_argument("--exclude", dest="exclude", default="")
    ap.add_argument("--rate", dest="rate", type=float, default=0)
    ap.add_argument("--traceroute", dest="traceroute", action="store_true")
    ap.add_argument("--config", dest="config")
    ap.add_argument("--log", dest="logfile")
    ap.add_argument("--resume", dest="resume")
    ap.add_argument("--fragment", dest="fragment", action="store_true")
    ap.add_argument("--decoy", dest="decoy")
    ap.add_argument("--ttl", dest="ttl", type=int, default=64)
    ap.add_argument("--tls", dest="tls", action="store_true")
    ap.add_argument("--dns", dest="dns", action="store_true")
    ap.add_argument("--crawl", dest="crawl", action="store_true")
    ap.add_argument("--ftp-bounce", dest="ftp_bounce")
    ap.add_argument("--idle", dest="idle")
    ap.add_argument("--profile", dest="profile", choices=["quick","full","stealth"])
    ap.add_argument("-A", dest="aggro", action="store_true")
    ap.add_argument("-F", dest="fast", action="store_true")
    ap.add_argument("-q", dest="quick_alias", action="store_true")
    ap.add_argument("-s", dest="stealth_alias", action="store_true")
    ap.add_argument("--dns-enum", dest="dns_enum", action="store_true")
    ap.add_argument("--smb", dest="smb", action="store_true")
    ap.add_argument("--vuln", dest="vuln", action="store_true")
    ap.add_argument("--csv", dest="csv")
    ap.add_argument("--html", dest="html")
    ap.add_argument("--diff", dest="diff")
    ap.add_argument("--parallel", dest="parallel", type=int, default=1)
    ap.add_argument("--progress", dest="progress", action="store_true")
    ap.add_argument("--daemon", dest="daemon", action="store_true")
    ap.add_argument("--pdf", dest="pdf")
    ap.add_argument("--nvd", dest="nvd")
    ap.add_argument("--tls-ciphers", dest="tls_ciphers", action="store_true")
    ap.add_argument("--smb-full", dest="smb_full", action="store_true")
    ap.add_argument("--brute", dest="brute")
    ap.add_argument("--zone-transfer", dest="zone")
    ap.add_argument("--mac", dest="mac")
    ap.add_argument("--plugin", dest="plugin")
    args=ap.parse_args()
    if args.daemon and HAVE_POWER:
        print("Starting daemon on :8080")
        power.daemon()
        return
    if HAVE_EXTRAS and args.profile:
        args = extras.apply_profile(args)
    if args.aggro:
        args.svc = True; args.osdet = True; args.scripts = (args.scripts or []) + ["banner","http-title"]
    if args.fast:
        args.top = 100; args.ports = ""
    if args.quick_alias:
        args.profile = "quick"; args = extras.apply_profile(args)
    if args.stealth_alias:
        args.profile = "stealth"; args = extras.apply_profile(args)

    if args.config and HAVE_EXTRAS:
        cfg = extras.load_config(args.config)
        if cfg.get("rate") and not args.rate:
            args.rate = cfg["rate"]
        if cfg.get("timing") and args.timing == 3:
            args.timing = cfg["timing"]
    if args.logfile and HAVE_EXTRAS:
        extras.setup_logging(args.logfile)

    limiter = extras.RateLimiter(args.rate) if HAVE_EXTRAS and args.rate else None
    resumed = set(extras.load_resume(args.resume)) if args.resume and HAVE_EXTRAS else set()

    hosts=parse_targets(args.targets, args.exclude.split(",") if args.exclude else [])
    ports=[] if args.hostonly else parse_ports(args.ports, args.top)
    delay=[1000,500,200,100,50,10][args.timing]/1000.0
    timeout=[5,3,2,1,0.5,0.3][args.timing]
    conc=[1,5,10,50,100,200][args.timing]

    results=[]
    for host in hosts:
        if host in resumed:
            print(f"Skipping {host} (resumed)")
            continue
        if args.traceroute and HAVE_EXTRAS:
            print(f"Traceroute to {host}:")
            for hop, addr in extras.traceroute(host):
                print(f"  {hop:2d} {addr}")
        if not args.skiphost and not args.hostonly:
            if not host_alive(host, timeout):
                print(f"Host {host} seems down."); continue
        if args.hostonly:
            print(f"{host} is up."); results.append({"host":host,"ports":[],"os":None,"scripts":{}}); continue
        print(f"\nScanning {host}...")
        if args.progress and HAVE_POWER:
            print(power.progress(hosts.index(host)+1, len(hosts)))
        open_ports=[]
        port_results=[]
        adaptive_timeout = timeout
        adaptive_conc = conc
        failed = 0
        def scan_port(p):
            if limiter:
                limiter.wait()
            if args.ftp_bounce and HAVE_ADV:
                proxy = args.ftp_bounce.split(":")
                state = advanced.ftp_bounce_scan(proxy[0], int(proxy[1]) if len(proxy)>1 else 21, host, p)
                return {"port": p, "open": state == "open", "svc": "", "ver": "", "banner": ""}
            if args.idle and HAVE_ADV:
                state = advanced.idle_scan(args.idle, host, p)
                return {"port": p, "open": state == "open", "svc": "", "ver": "", "banner": ""}
            if args.scan == "udp" and HAVE_ADV:
                state = advanced.udp_scan(host, p, adaptive_timeout)
                return {"port": p, "open": state == "open", "svc": "", "ver": "", "banner": ""}
            if args.scan == "sctp" and HAVE_ADV:
                state = advanced.sctp_scan(host, p, adaptive_timeout)
                return {"port": p, "open": state == "open", "svc": "", "ver": "", "banner": ""}
            if args.scan == "syn" and HAVE_RAW:
                decoys = args.decoy.split(",") if args.decoy else None
                state = rawscan.raw_syn_scan(host, p, adaptive_timeout, frag=args.fragment, ttl=args.ttl, decoys=decoys)
                if state in (None, "filtered"):
                    pass
                else:
                    if state == "open":
                        ok, banner = tcp_connect(host, p, adaptive_timeout) if args.svc else (True, "")
                        svc = SVC_MAP.get(p, "unknown") if args.svc else ""
                        return {"port": p, "open": True, "svc": svc, "ver": banner if args.svc else "", "banner": banner}
                    return {"port": p, "open": False}
            ok, banner = tcp_connect(host, p, timeout)
            if ok:
                if args.svc and HAVE_PROBES:
                    svc, ver = probes.probe(host, p, timeout)
                    if not svc:
                        svc = SVC_MAP.get(p, "unknown")
                    if not ver and banner:
                        ver = banner.splitlines()[0][:120] if banner else ""
                else:
                    svc = SVC_MAP.get(p, "unknown") if args.svc else ""
                    ver = banner if args.svc else ""
                return {"port": p, "open": True, "svc": svc, "ver": ver, "banner": banner}
            return {"port": p, "open": False}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(adaptive_conc,len(ports) or 1)) as ex:
            for r in ex.map(scan_port, ports):
                if r["open"]:
                    open_ports.append(r["port"])
                    port_results.append(r)
                    if args.verbose: print(f"  {host}:{r['port']} open {r['svc']} {r['ver']}")
                else:
                    failed += 1
                    if failed > len(ports) * 0.8:
                        adaptive_timeout = min(adaptive_timeout * 1.5, 10)
                        adaptive_conc = max(1, adaptive_conc // 2)
        if args.osdet:
            ttl, win = (None, None)
            if HAVE_RAW and open_ports:
                port_for_probe = open_ports[0] if open_ports else 80
                ttl, win = rawscan.os_fingerprint_ttl(host, port_for_probe, timeout)
            if ttl is not None:
                osv = rawscan.os_guess_advanced(ttl, win, open_ports)
            else:
                osv = os_guess(open_ports)
        else:
            osv = None
        scripts={}
        if args.scripts:
            names = []
            for s in args.scripts:
                names.extend([x.strip() for x in s.split(",") if x.strip()])
            for s in names:
                for pr in port_results:
                    scripts[f"{pr['port']}/{s}"]=script_run(s, host, pr["port"], pr.get("banner",""))
        res={"host":host,"ports":port_results,"os":osv,"scripts":scripts}
        results.append(res)
        print(f"\nNmap scan report for {host}")
        if osv: print(f"OS guess: {osv}")
        print("PORT     STATE SERVICE")
        for p in port_results:
            print(f"{str(p['port']).ljust(8)} open  {(p['svc']+' '+p['ver']).strip()}")
            for k,v in scripts.items():
                if k.startswith(str(p['port'])+"/"):
                    print(f"|_{k.split('/')[1]}: {v}")
        if not port_results: print("No open ports found.")
        if args.dns and HAVE_ADV:
            name = advanced.reverse_dns(host)
            if name: print(f"Reverse DNS: {name}")
        if args.tls and HAVE_ADV and 443 in open_ports:
            info = advanced.tls_info(host, 443)
            if info and "error" not in info:
                print(f"TLS: {info.get('protocol')} cipher={info.get('cipher')}")
        if args.crawl and HAVE_ADV and (80 in open_ports or 8080 in open_ports):
            port = 80 if 80 in open_ports else 8080
            links = advanced.crawl(host, port)
            if links: print("Links: " + ", ".join(links[:10]))
        if args.dns_enum and HAVE_PRO:
            info = pro.dns_enum(host)
            if info: print("DNS:", info)
        if args.smb and HAVE_PRO and 445 in open_ports:
            print("SMB:", pro.smb_enum(host))
        if args.vuln and HAVE_PRO:
            for pr in port_results:
                vs = pro.vuln_check(host, pr["port"], pr.get("banner",""))
                for v in vs: print(f"Vuln {pr['port']}: {v}")
        if args.tls_ciphers and HAVE_POWER and 443 in open_ports:
            print("TLS ciphers:", power.tls_ciphers(host, 443))
        if args.smb_full and HAVE_POWER and 445 in open_ports:
            print("SMB:", power.smb_full(host))
        if args.brute and HAVE_POWER and (80 in open_ports or 8080 in open_ports):
            print("Brute:", power.web_brute(host, 80 if 80 in open_ports else 8080, args.brute))
        if args.nvd and HAVE_POWER:
            print("NVD:", power.nvd_lookup(args.nvd))

    out=None; fmt=None
    if args.outN: out=args.outN; fmt="normal"
    elif args.outG: out=args.outG; fmt="greppable"
    elif args.outX: out=args.outX; fmt="xml"
    elif args.outJ: out=args.outJ; fmt="json"
    if out:
        if fmt=="json":
            content=json.dumps(results,indent=2)
        elif fmt=="xml":
            root=ET.Element("nmaprun")
            for r in results:
                h=ET.SubElement(root,"host"); a=ET.SubElement(h,"address"); a.set("addr",r["host"])
                ps=ET.SubElement(h,"ports")
                for p in r["ports"]:
                    port=ET.SubElement(ps,"port"); port.set("protocol","tcp"); port.set("portid",str(p["port"]))
                    ET.SubElement(port,"state").set("state","open")
                    ET.SubElement(port,"service").set("name",p["svc"] or "")
            content=ET.tostring(root,encoding="unicode")
        elif fmt=="greppable":
            content="\n".join(f"Host: {r['host']} Ports: "+", ".join(f"{p['port']}/open/tcp//{p['svc']}//" for p in r["ports"]) for r in results)+"\n"
        else:
            content=""
            for r in results:
                content+=f"Nmap scan report for {r['host']}\n"
                if r["os"]: content+=f"OS guess: {r['os']}\n"
                content+="PORT     STATE SERVICE\n"
                for p in r["ports"]: content+=f"{p['port']}/tcp open  {p['svc']} {p['ver']}\n"
                content+="\n"
        with open(out,"w") as f: f.write(content)
        print(f"\nSaved to {out}")
    if args.csv and HAVE_PRO:
        with open(args.csv,"w") as f: f.write(pro.export_csv(results))
        print(f"Saved CSV to {args.csv}")
    if args.html and HAVE_PRO:
        with open(args.html,"w") as f: f.write(pro.export_html(results))
        print(f"Saved HTML to {args.html}")
    if args.diff and HAVE_PRO:
        try:
            with open(args.diff) as f: old = json.load(f)
            print("Diff:", pro.diff_results(old, results))
        except Exception as e:
            print("Diff error:", e)
    if args.pdf and HAVE_POWER:
        power.pdf_export(results, args.pdf)
        print(f"Saved PDF to {args.pdf}")

if __name__=="__main__":
    main()
EOF
chmod +x /workspace/app/nmap.py 2>/dev/null; echo done