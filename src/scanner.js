import net from "node:net";
import dns from "node:dns/promises";
import { writeFileSync } from "node:fs";

const TOP_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443];

function parseTargets(targets, exclude) {
  const out = [];
  for (const t of targets) {
    if (t.includes("/")) {
      const [ip, bits] = t.split("/");
      const base = ip.split(".").map(Number);
      const n = 1 << (32 - parseInt(bits));
      const start = (base[0]<<24|base[1]<<16|base[2]<<8|base[3]) - ((base[0]<<24|base[1]<<16|base[2]<<8|base[3]) % n);
      for (let i = 1; i < n - 1; i++) {
        const v = start + i;
        out.push(`${(v>>>24)&255}.${(v>>>16)&255}.${(v>>>8)&255}.${v&255}`);
      }
    } else if (t.includes("-") && /^\d+\.\d+\.\d+\.\d+-\d+$/.test(t)) {
      const [ip, end] = t.split("-");
      const parts = ip.split(".");
      const prefix = parts.slice(0,3).join(".");
      const s = parseInt(parts[3]);
      for (let i = s; i <= parseInt(end); i++) out.push(`${prefix}.${i}`);
    } else {
      out.push(t);
    }
  }
  return out.filter((h) => !exclude.includes(h));
}

function parsePorts(spec, topPorts) {
  if (!spec && !topPorts) return [];
  if (topPorts) return TOP_PORTS.slice(0, topPorts);
  const ports = new Set();
  for (const part of spec.split(",")) {
    if (part.includes("-")) {
      const [a, b] = part.split("-").map(Number);
      for (let i = a; i <= b; i++) ports.add(i);
    } else if (part.trim()) {
      ports.add(parseInt(part));
    }
  }
  return [...ports].sort((a,b)=>a-b);
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

async function tcpConnect(host, port, timeout) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let done = false;
    const finish = (open, banner) => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve({ open, banner });
    };
    sock.setTimeout(timeout);
    sock.on("connect", () => {
      // try banner grab
      let data = "";
      sock.on("data", (d) => { data += d.toString(); if (data.length > 200) finish(true, data); });
      setTimeout(() => finish(true, data || null), 300);
    });
    sock.on("timeout", () => finish(false, null));
    sock.on("error", () => finish(false, null));
    sock.connect(port, host);
  });
}

async function hostAlive(host, timeout) {
  // TCP probe on common ports
  for (const p of [80, 443, 22, 445]) {
    const r = await tcpConnect(host, p, timeout);
    if (r.open) return true;
  }
  // DNS resolve check
  try {
    await dns.lookup(host);
    return true;
  } catch {
    return false;
  }
}

function serviceGuess(port, banner) {
  const map = { 21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"domain",80:"http",110:"pop3",143:"imap",443:"https",445:"microsoft-ds",3306:"mysql",3389:"ms-wbt-server",5432:"postgres",6379:"redis",27017:"mongodb",8080:"http-proxy" };
  let svc = map[port] || "unknown";
  let ver = "";
  if (banner) {
    const b = banner.replace(/\r/g,"").split("\n")[0].slice(0,80);
    ver = b;
  }
  return { svc, ver };
}

function osGuess(ttlOrPorts) {
  // heuristic based on open ports
  const ports = ttlOrPorts;
  if (ports.includes(445) && ports.includes(3389)) return "Windows";
  if (ports.includes(22) && ports.includes(3306)) return "Linux";
  if (ports.includes(22)) return "Linux/Unix";
  if (ports.includes(80) || ports.includes(443)) return "Network device / Web server";
  return "Unknown";
}

function scriptRun(name, host, port, banner) {
  if (name === "banner") return banner ? banner.slice(0,200) : "no banner";
  if (name === "http-title") {
    if (!banner) return "n/a";
    const m = banner.match(/<title>([^<]*)<\/title>/i);
    return m ? m[1] : "no title";
  }
  return "script not found";
}

export async function runScan(opts) {
  const hosts = parseTargets(opts.targets, opts.exclude);
  const ports = parsePorts(opts.ports, opts.topPorts);
  const timingDelays = [1000, 500, 200, 100, 50, 10][opts.timing] || 100;
  const timeout = [5000, 3000, 2000, 1000, 500, 300][opts.timing] || 1000;
  const concurrency = [1, 5, 10, 50, 100, 200][opts.timing] || 50;

  const results = [];

  for (const host of hosts) {
    if (opts.hostDiscovery && opts.ports) {
      const alive = await hostAlive(host, timeout);
      if (!alive) {
        console.log(`Host ${host} seems down.`);
        continue;
      }
    }
    console.log(`\nScanning ${host}...`);
    const openPorts = [];
    const portResults = [];

    // scan with concurrency
    let idx = 0;
    const queue = [...ports];
    async function worker() {
      while (queue.length) {
        const port = queue.shift();
        const r = await tcpConnect(host, port, timeout);
        if (r.open) {
          openPorts.push(port);
          const svc = opts.serviceDetect ? serviceGuess(port, r.banner) : { svc: "", ver: "" };
          portResults.push({ port, open: true, ...svc, banner: r.banner });
          if (opts.verbose) console.log(`  ${host}:${port} open ${svc.svc} ${svc.ver || ""}`);
        } else {
          portResults.push({ port, open: false });
        }
        if (timingDelays > 0) await delay(timingDelays / ports.length > 1 ? 0 : 0);
      }
    }
    const workers = Array.from({ length: Math.min(concurrency, ports.length) }, () => worker());
    await Promise.all(workers);

    const os = opts.osDetect ? osGuess(openPorts) : null;

    // scripts
    const scriptOut = {};
    if (opts.scripts.length) {
      for (const s of opts.scripts) {
        for (const pr of portResults.filter((p) => p.open)) {
          scriptOut[`${pr.port}/${s}`] = scriptRun(s, host, pr.port, pr.banner);
        }
      }
    }

    const res = { host, ports: portResults.filter((p) => p.open), os, scripts: scriptOut };
    results.push(res);

    // print
    printResult(res, opts);
  }

  // output file
  if (opts.output) {
    writeFileSync(opts.output, formatOutput(results, opts.format));
    console.log(`\nSaved to ${opts.output}`);
  }
}

function printResult(res, opts) {
  console.log(`\nNmap scan report for ${res.host}`);
  if (res.os) console.log(`OS guess: ${res.os}`);
  console.log("PORT     STATE SERVICE");
  for (const p of res.ports) {
    const svc = p.svc ? `${p.svc} ${p.ver || ""}`.trim() : "";
    console.log(`${String(p.port).padEnd(8)} open  ${svc}`);
    if (opts.scripts.length) {
      for (const [k, v] of Object.entries(res.scripts)) {
        if (k.startsWith(p.port + "/")) console.log(`|_${k.split("/")[1]}: ${v}`);
      }
    }
  }
  if (res.ports.length === 0) console.log("No open ports found.");
}

function formatOutput(results, format) {
  if (format === "json") return JSON.stringify(results, null, 2);
  if (format === "xml") {
    let x = '<?xml version="1.0"?>\n<nmaprun>\n';
    for (const r of results) {
      x += `  <host><address addr="${r.host}"/><ports>`;
      for (const p of r.ports) x += `<port protocol="tcp" portid="${p.port}"><state state="open"/><service name="${p.svc||""}"/></port>`;
      x += `</ports></host>\n`;
    }
    x += "</nmaprun>\n";
    return x;
  }
  if (format === "greppable") {
    return results.map((r) => `Host: ${r.host} Ports: ${r.ports.map((p) => `${p.port}/open/tcp//${p.svc||""}//`).join(", ")}`).join("\n") + "\n";
  }
  // normal
  let out = "";
  for (const r of results) {
    out += `Nmap scan report for ${r.host}\n`;
    if (r.os) out += `OS guess: ${r.os}\n`;
    out += "PORT     STATE SERVICE\n";
    for (const p of r.ports) out += `${p.port}/tcp open  ${p.svc||""} ${p.ver||""}\n`;
    out += "\n";
  }
  return out;
}
