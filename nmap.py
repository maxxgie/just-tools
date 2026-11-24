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

def script_run(name, banner):
    if name=="banner": return (banner or "no banner")[:200]
    if name=="http-title":
        import re
        m=re.search(r"<title>([^<]*)</title>", banner or "", re.I)
        return m.group(1) if m else "no title"
    return "script not found"

def main():
    ap=argparse.ArgumentParser(description="nmap-js python port")
    ap.add_argument("targets", nargs="*", default=["127.0.0.1"])
    ap.add_argument("-p", dest="ports", default="1-1024")
    ap.add_argument("-sS", dest="scan", action="store_const", const="syn", default="connect")
    ap.add_argument("-sT", dest="scan", action="store_const", const="connect")
    ap.add_argument("-sU", dest="scan", action="store_const", const="udp")
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
    args=ap.parse_args()

    hosts=parse_targets(args.targets, args.exclude.split(",") if args.exclude else [])
    ports=[] if args.hostonly else parse_ports(args.ports, args.top)
    delay=[1000,500,200,100,50,10][args.timing]/1000.0
    timeout=[5,3,2,1,0.5,0.3][args.timing]
    conc=[1,5,10,50,100,200][args.timing]

    results=[]
    for host in hosts:
        if not args.skiphost and not args.hostonly:
            if not host_alive(host, timeout):
                print(f"Host {host} seems down."); continue
        if args.hostonly:
            print(f"{host} is up."); results.append({"host":host,"ports":[],"os":None,"scripts":{}}); continue
        print(f"\nScanning {host}...")
        open_ports=[]
        port_results=[]
        def scan_port(p):
            if args.scan == "syn" and HAVE_RAW:
                state = rawscan.raw_syn_scan(host, p, timeout)
                if state == "open":
                    ok, banner = tcp_connect(host, p, timeout) if args.svc else (True, "")
                    svc = SVC_MAP.get(p, "unknown") if args.svc else ""
                    return {"port": p, "open": True, "svc": svc, "ver": banner if args.svc else "", "banner": banner}
                return {"port": p, "open": False}
            ok, banner = tcp_connect(host, p, timeout)
            if ok:
                if args.svc and HAVE_PROBES:
                    svc, ver = probes.probe(host, p, timeout)
                    if not svc:
                        svc = SVC_MAP.get(p, "unknown")
                else:
                    svc = SVC_MAP.get(p, "unknown") if args.svc else ""
                    ver = banner if args.svc else ""
                return {"port": p, "open": True, "svc": svc, "ver": ver, "banner": banner}
            return {"port": p, "open": False}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(conc,len(ports) or 1)) as ex:
            for r in ex.map(scan_port, ports):
                if r["open"]:
                    open_ports.append(r["port"])
                    port_results.append(r)
                    if args.verbose: print(f"  {host}:{r['port']} open {r['svc']} {r['ver']}")
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
            for s in args.scripts:
                for pr in port_results:
                    scripts[f"{pr['port']}/{s}"]=script_run(s, pr.get("banner",""))
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

if __name__=="__main__":
    main()
EOF
chmod +x /workspace/app/nmap.py 2>/dev/null; echo done