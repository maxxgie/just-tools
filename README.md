nmap-js (Python)

Usage:
  python3 nmap.py <target> [options]

Options:
  -p <ports>        Port spec (22,80,443 or 1-1024)
  -sS/-sT/-sU       Scan type (syn/connect/udp)
  -sV               Service/version detection
  -O                OS detection
  -sn               Host discovery only
  -Pn               Skip host discovery
  -T0..-T5          Timing template
  -oN/-oG/-oX/-oJ   Output file (normal/greppable/xml/json)
  -v                Verbose
  --top-ports N     Scan top N ports
  --script <name>   Run script (banner, http-title, ssh-hostkey)
  --exclude <list>  Exclude hosts
  --rate N          Rate limit packets/sec
  --traceroute      Traceroute
  --config file     Config JSON
  --log file        Log file
  --resume file     Resume from saved hosts
  -h, --help        Show help

Examples:
  python3 nmap.py scanme.nmap.org -p 22,80 -sT -sV -v
  python3 nmap.py 192.168.1.0/24 -p 1-1000 -T4 -oJ out.json
EOF
echo done