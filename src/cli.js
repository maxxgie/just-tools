import { runScan } from "./scanner.js";

const args = process.argv.slice(2);
const opts = parseArgs(args);

if (opts.help) {
  printHelp();
  process.exit(0);
}

runScan(opts).catch((e) => {
  console.error("Error:", e.message || e);
  process.exit(1);
});

function parseArgs(a) {
  const o = {
    targets: [],
    ports: "1-1024",
    scanType: "connect",
    timing: 3,
    output: null,
    format: "normal",
    serviceDetect: false,
    osDetect: false,
    hostDiscovery: true,
    scripts: [],
    verbose: false,
    topPorts: 0,
    exclude: [],
  };
  for (let i = 0; i < a.length; i++) {
    const x = a[i];
    switch (x) {
      case "-h":
      case "--help":
        o.help = true;
        break;
      case "-p":
        o.ports = a[++i];
        break;
      case "-sS":
        o.scanType = "syn";
        break;
      case "-sT":
        o.scanType = "connect";
        break;
      case "-sU":
        o.scanType = "udp";
        break;
      case "-sV":
        o.serviceDetect = true;
        break;
      case "-O":
        o.osDetect = true;
        break;
      case "-sn":
        o.hostDiscovery = true;
        o.ports = "";
        break;
      case "-Pn":
        o.hostDiscovery = false;
        break;
      case "-T0":
      case "-T1":
      case "-T2":
      case "-T3":
      case "-T4":
      case "-T5":
        o.timing = parseInt(x.slice(2));
        break;
      case "-oN":
        o.output = a[++i];
        o.format = "normal";
        break;
      case "-oG":
        o.output = a[++i];
        o.format = "greppable";
        break;
      case "-oX":
        o.output = a[++i];
        o.format = "xml";
        break;
      case "-oJ":
        o.output = a[++i];
        o.format = "json";
        break;
      case "-v":
      case "--verbose":
        o.verbose = true;
        break;
      case "--top-ports":
        o.topPorts = parseInt(a[++i]);
        break;
      case "--script":
        o.scripts.push(a[++i]);
        break;
      case "--exclude":
        o.exclude.push(...a[++i].split(","));
        break;
      default:
        if (!x.startsWith("-")) o.targets.push(x);
    }
  }
  if (o.targets.length === 0) o.targets = ["127.0.0.1"];
  return o;
}

function printHelp() {
  console.log(`nmap-js - terminal network scanner

Usage: nmap [options] <target>...

Targets: IP, hostname, CIDR (192.168.1.0/24), ranges (192.168.1.1-50)

Options:
  -p <ports>        Port spec (22,80,443 or 1-1024 or top)
  -sS/-sT/-sU      Scan type (syn/connect/udp)
  -sV               Service/version detection
  -O                OS detection (heuristic)
  -sn               Host discovery only
  -Pn               Skip host discovery
  -T0..-T5          Timing template
  -oN/-oG/-oX/-oJ  Output file (normal/greppable/xml/json)
  -v                Verbose
  --top-ports N     Scan top N ports
  --script <name>   Run script (banner, http-title)
  --exclude <list>  Exclude hosts
  -h, --help        Show help`);
}
