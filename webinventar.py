#!/usr/bin/env python3
"""
webinventar.py – Inventar öffentlich erreichbarer Webdienste für eigene
Netzbereiche und Domains.

Grundsatz: Externe Dienste erfahren nichts Neues über euer Netz.
  - DNS: Das Skript löst Namen selbst auf, beginnend bei den Root-Servern und
    mit QNAME-Minimierung (RFC 9156). Vollständige Namen und Rückwärts-Abfragen
    sehen nur die autoritativen Nameserver eurer Zonen, also ihr selbst bzw.
    euer DNS-Provider. Öffentliche Resolver (Google, Cloudflare, …) werden nicht
    benutzt; so landen auch geratene Namen in keiner Passive-DNS-Datenbank.
  - Passive Quellen (CT-Logs, Subdomain-Datenbanken): Diese Dienste
    bekommen nur den Domainnamen, keine IP-Adressen oder Netze.
  - IP-Adressen eurer Netze werden an keinen externen Dienst geschickt.

Ablauf:
  1. Hostnamen sammeln: 7 passive Quellen, DNS-Records, Zonentransfer-Versuch,
     Wortliste, PTR-Records eurer Netze; später Zertifikats-SANs, Redirects und
     Namen aus Seiteninhalt und Headern der abgerufenen Antworten.
  2. Auflösen, Wildcards erkennen, verwaiste CNAMEs melden.
  3. Portscan: eigene Netze mit voller Portliste, fremde IPs, auf die eure
     Namen zeigen (Hoster, SaaS), nur auf 80/443.
  4. HTTP/HTTPS-Abruf je IP:Port und je Hostname (Host-Header + SNI), Redirects
     folgen, Technologien erkennen (Wappalyzer-Fingerprints wie bei httpx).
  5. Wiederholung, bis keine neuen Hostnamen mehr auftauchen (max. 5 Runden).

Keine Abhängigkeiten außer der Python-Standardbibliothek (ab Python 3.9).
Nur gegen Netze und Domains einsetzen, für die ihr berechtigt seid.
"""
import argparse
import asyncio
import concurrent.futures
import csv
import hashlib
import ipaddress
import json
import struct
import os
import random
import re
import ssl
import string
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "3.6"

# ============================================================== Einstellungen

# Web-typische Ports (Standard für -p web)
WEB_PORTS = [
    80, 81, 300, 443, 591, 593, 832, 981, 1010, 1311, 2082, 2083, 2086, 2087,
    2095, 2096, 2480, 3000, 3001, 3128, 3333, 4000, 4243, 4443, 4567, 4711,
    4712, 4993, 5000, 5001, 5104, 5108, 5601, 5800, 6080, 6443, 6543, 7000,
    7001, 7080, 7396, 7443, 7474, 8000, 8001, 8008, 8009, 8010, 8014, 8042,
    8069, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
    8091, 8095, 8118, 8123, 8172, 8180, 8181, 8222, 8243, 8280, 8281, 8333,
    8443, 8444, 8500, 8834, 8880, 8888, 8983, 9000, 9001, 9043, 9060, 9080,
    9090, 9091, 9200, 9443, 9800, 9981, 10000, 10443, 12443, 16080, 18080,
    18091, 18092, 20720, 28017,
]
# Nmap-Top-Ports, übernommen aus naabu (pkg/runner/ports.go)
NMAP_TOP100 = (
    "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-"
    "445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,"
    "1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,"
    "5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,"
    "9100,9999-10000,32768,49152-49157")
NMAP_TOP1000 = (
    "1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,"
    "125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,36"
    "6,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,"
    "554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,72"
    "2,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-"
    "993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,112"
    "6,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,118"
    "5-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,127"
    "7,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,150"
    "0-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-172"
    "1,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,197"
    "1-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,206"
    "8,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,219"
    "6,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,252"
    "5,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,286"
    "9,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3006,3011,3017,3030-3031,3052,307"
    "1,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,336"
    "7,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,376"
    "6,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,394"
    "5,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-444"
    "6,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-506"
    "1,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,541"
    "4,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,580"
    "0-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,592"
    "2,5925,5950,5952,5959-5963,5985-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,612"
    "9,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,678"
    "8-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-720"
    "1,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,799"
    "9-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,820"
    "0,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,880"
    "0,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,911"
    "0-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,987"
    "6-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,1"
    "0180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,1"
    "2174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,1"
    "5742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,1"
    "9101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,2"
    "3502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,3"
    "0951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,4"
    "4176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-5"
    "0003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,5"
    "5055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,6"
    "4623,64680,65000,65129,65389")
# Fremde IPs (eure Namen zeigen auf Hoster/SaaS/CDN) nur hier prüfen
EXTERNAL_PORTS = [80, 443]

# Lastprofile: neue Verbindungen/s gesamt, gleichzeitige Verbindungen je Ziel-IP
# und gesamt, Verbindungs-Timeout in Sekunden
PROFILES = {
    "schonend": {"rate": 20, "per_host": 1, "concurrency": 50, "timeout": 4.0},
    "normal":   {"rate": 100, "per_host": 4, "concurrency": 300, "timeout": 3.0},
    "schnell":  {"rate": 0, "per_host": 50, "concurrency": 500, "timeout": 2.0},
}

MAX_ROUNDS = 5            # Entdeckungsrunden (neue Namen aus Zertifikaten/Redirects)
DNS_TIMEOUT = 3.0         # Sekunden je DNS-Anfrage
DNS_RATE_PER_SERVER = 20  # Anfragen/s je Nameserver – bleibt unter üblichen Rate-Limits (RRL)
DNS_ROUNDS = 3            # Versuche je Frage (mit Pause), falls Antworten verloren gehen
CERT_WARN_DAYS = 30       # Warnung, wenn ein Zertifikat in weniger Tagen abläuft
SOURCE_TIMEOUT = 60       # Sekunden je passiver Quelle und Domain (danach zählt, was bis dahin da ist)
MAX_ADDRESSES = 65536     # größere Netze bitte aufteilen oder masscan/naabu vorschalten
CACHE_DIR = os.path.expanduser("~/.cache/webinventar")
FINGERPRINT_URL = "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/main/fingerprints_data.json"

# Root-Server (IPv4) als Startpunkt der eigenen DNS-Auflösung
ROOT_SERVERS = [
    "198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
    "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
    "193.0.14.129", "199.7.83.42", "202.12.27.33",
]

# SRV-Einträge, die oft auf weitere Hosts zeigen
SRV_NAMES = [
    "_autodiscover._tcp", "_sip._tls", "_sipfederationtls._tcp", "_sip._tcp",
    "_xmpp-server._tcp", "_xmpp-client._tcp", "_caldavs._tcp", "_carddavs._tcp",
    "_imaps._tcp", "_submission._tcp", "_submissions._tcp", "_ldap._tcp",
    "_ldaps._tcp", "_kerberos._tcp", "_http._tcp", "_https._tcp",
    "_matrix._tcp", "_matrix-fed._tcp",
]

# Typische technische Subdomains. Die Abfragen gehen nur an eure eigenen Nameserver.
WORDLIST = """
www www1 www2 web mail mail1 mail2 webmail smtp imap pop pop3 mx mx1 mx2
autodiscover autoconfig mta-sts owa exchange outlook vpn vpn1 vpn2 sslvpn remote
gateway gw fw firewall portal intranet extranet login sso auth idp adfs
ns ns1 ns2 ns3 dns dns1 dns2 ftp sftp api cloud files git gitlab wiki status
monitoring proxy citrix rdweb meet dev test staging
""".split()

# Titel/Technologien, bei denen ein Blick lohnt (Admin-Oberflächen, VPN-Portale, …)
SENSITIVE = re.compile(
    r"index of /|phpinfo|phpmyadmin|adminer|jenkins|grafana|kibana|elasticsearch|tomcat|"
    r"swagger|actuator|portainer|webmin|router|login|admin|fortinet|fortigate|globalprotect|"
    r"pulse secure|ivanti|citrix|sonicwall|outlook web|exchange|vmware|esxi|vcenter|idrac|"
    r"\bilo\b|ipmi|synology|qnap|plesk|cpanel", re.I)


# Typische Fehlerseiten, die technische Details preisgeben (Pfade, Versionen, Code)
ERROR_DETAILS = re.compile(
    r"TYPO3 Exception|Traceback \(most recent call last\)|Stack trace:|Fatal error:|"
    r"Uncaught [\w\\]*Exception|PHP (?:Warning|Notice|Fatal error)|on line <b>\d+</b>|"
    r"Whoops, looks like something went wrong|Server Error in '/' Application|"
    r"Exception Details:|Django Version:|java\.lang\.\w+(?:Exception|Error)|"
    r"SQLSTATE\[|You have an error in your SQL syntax|ORA-\d{5}|"
    r"Werkzeug Debugger|Symfony\\Component\\|NullPointerException")


# ============================================================== Hilfsfunktionen

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def norm_name(name):
    """Hostnamen vereinheitlichen; None, wenn es kein gültiger Hostname ist."""
    name = (name or "").strip().lower().rstrip(".")
    while name.startswith(("*.", ".")):
        name = name[2:] if name.startswith("*.") else name[1:]
    if not re.fullmatch(r"[a-z0-9_]([a-z0-9_\-]{0,62}\.)*[a-z0-9_\-]{1,63}", name):
        return None
    if re.fullmatch(r"[\d.]+", name):
        return None  # IP-Adresse
    return name


def parse_ports(spec):
    """'web', 'top100', 'top1000', 'all' und Listen/Bereiche, kommagetrennt kombinierbar."""
    named = {"web": ",".join(map(str, WEB_PORTS)), "top100": NMAP_TOP100,
             "top1000": NMAP_TOP1000, "all": "1-65535"}
    ports = set()
    for part in spec.lower().split(","):
        for item in named.get(part.strip(), part).split(","):
            item = item.strip()
            if "-" in item:
                a, b = item.split("-")
                ports |= set(range(int(a), int(b) + 1))
            elif item:
                ports.add(int(item))
    return sorted(p for p in ports if 0 < p < 65536)


def read_args(values):
    """Werte direkt oder – wenn es eine Datei ist – zeilenweise aus der Datei."""
    out = []
    for v in values:
        if os.path.isfile(v):
            with open(v, encoding="utf-8") as f:
                out += [ln.split("#")[0].strip() for ln in f if ln.split("#")[0].strip()]
        else:
            out.append(v)
    return out


def decode_der_cert(der):
    """Zertifikat ohne Zusatzbibliothek dekodieren (Format wie ssl.getpeercert())."""
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
            path = f.name
        return ssl._ssl._test_decode_cert(path)  # pylint: disable=protected-access
    except Exception:  # noqa: BLE001
        return {}
    finally:
        if path:
            os.unlink(path)


def cert_field(rdns, key):
    for rdn in rdns or ():
        for k, v in rdn:
            if k == key:
                return v
    return ""


def host_header(host, ip, port, tls):
    h = host or (f"[{ip}]" if ":" in ip else ip)
    if port != (443 if tls else 80):
        h = f"{h}:{port}"
    return h


def url_for(host, ip, port, tls):
    return f"{'https' if tls else 'http'}://{host_header(host, ip, port, tls)}/"


def ip_sort_key(ip):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, 0)


# ============================================================== Technologie-Erkennung

def load_fingerprints():
    """Wappalyzer-Fingerprints von GitHub laden (wöchentlich aktualisiert, lokal zwischengespeichert).
    GitHub erfährt dabei nur, dass die Datei geladen wird – nichts über euer Netz."""
    path = os.path.join(CACHE_DIR, "fingerprints_data.json")
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < 7 * 86400:
        return path
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with urllib.request.urlopen(FINGERPRINT_URL, timeout=60) as r:
            data = r.read()
        json.loads(data)  # nur gültige Dateien übernehmen
        with open(path + ".tmp", "wb") as f:
            f.write(data)
        os.replace(path + ".tmp", path)
    except Exception as e:  # noqa: BLE001
        log(f"Fingerprints nicht ladbar ({e.__class__.__name__})"
            + (" – nutze vorhandene Kopie" if os.path.exists(path) else " – keine Technologie-Erkennung"))
    return path if os.path.exists(path) else None


class TechDetector:
    """Technologien anhand von Headern, Cookies, HTML, Script-URLs und Meta-Tags erkennen.
    Muster aus projectdiscovery/wappalyzergo; js/dom-Regeln bräuchten einen Browser."""

    KINDS = ("headers", "cookies", "meta", "scriptSrc", "html")

    def __init__(self, path=None):
        self.rules = {k: [] for k in self.KINDS}   # kind -> [(app, key, regex, versionsvorlage)]
        self.implies = {}                          # app -> [apps, die daraus folgen]
        if not path:
            return
        with open(path, encoding="utf-8") as f:
            apps = json.load(f).get("apps", {})
        for app, spec in apps.items():
            for kind in ("scriptSrc", "html"):
                for pat in self._as_list(spec.get(kind)):
                    self._add(kind, app, None, pat)
            for kind in ("headers", "cookies", "meta"):
                for key, pats in (spec.get(kind) or {}).items():
                    for pat in self._as_list(pats) or [""]:
                        self._add(kind, app, key.lower(), pat)
            if spec.get("implies"):
                self.implies[app] = [i.split("\\;")[0] for i in self._as_list(spec["implies"])]

    def __len__(self):
        return sum(len(v) for v in self.rules.values())

    @staticmethod
    def _as_list(v):
        return [] if v is None else (v if isinstance(v, list) else [v])

    def _add(self, kind, app, key, pattern):
        # Format: "regex\;version:\1\;confidence:50"
        parts = str(pattern).split("\\;")
        version = next((p[8:] for p in parts[1:] if p.startswith("version:")), "")
        try:
            rx = re.compile(parts[0], re.I) if parts[0] else None   # leer = "vorhanden"
        except re.error:
            return  # einzelne Muster nutzen in Python unbekannte Regex-Syntax
        self.rules[kind].append((app, key, rx, version))

    @staticmethod
    def _version(match, template):
        if not match or match is True or not template:
            return ""
        try:
            v = re.sub(r"\\(\d)", lambda g: match.group(int(g.group(1))) or "", template)
            return re.sub(r"\?([^:]*):.*", r"\1", v).strip()[:20]
        except (IndexError, re.error):
            return ""

    def detect(self, headers, cookies, body):
        if not len(self):
            return []
        html = body[:150000]
        meta = {}
        for tag in re.findall(r"<meta\s[^>]*>", html, re.I):
            k = re.search(r"(?:name|property|http-equiv)=[\"']?([^\"'\s>]+)", tag, re.I)
            c = re.search(r"content=[\"']([^\"']*)", tag, re.I)
            if k and c:
                meta[k.group(1).lower()] = c.group(1)
        targets = {"headers": headers, "cookies": cookies, "meta": meta,
                   "scriptSrc": re.findall(r"<script[^>]+src=[\"']?([^\"'\s>]+)", html, re.I),
                   "html": [html]}
        found = {}
        for kind in self.KINDS:
            data = targets[kind]
            for app, key, rx, tpl in self.rules[kind]:
                if key is not None:          # headers/cookies/meta: Wert zu einem Schlüssel
                    if key not in data:
                        continue
                    m = rx.search(data[key]) if rx else True
                else:                        # scriptSrc/html: Liste von Texten
                    m = next((x for x in (rx.search(t) for t in data) if x), None) if rx else None
                if m:
                    v = self._version(m, tpl)
                    if not found.get(app):
                        found[app] = v
        todo = list(found)                   # abgeleitete Technologien (z. B. WordPress -> PHP)
        while todo:
            for imp in self.implies.get(todo.pop(), []):
                if imp not in found:
                    found[imp] = ""
                    todo.append(imp)
        return sorted(f"{a}:{v}" if v else a for a, v in found.items())


# ============================================================== Passive Quellen
# Öffentliche Quellen ohne Anmeldung; gesendet wird ausschließlich der Domainname.
# Endpunkte wie in projectdiscovery/subfinder. Jede Funktion liefert Rohtext, aus dem
# die Hostnamen per Regex gezogen werden. Alle Quellen laufen parallel, jede höchstens
# SOURCE_TIMEOUT Sekunden; was bis dahin geladen ist, wird ausgewertet.

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")
_source_state = threading.local()   # Frist der gerade laufenden Quelle (je Thread)


class SourceTimeout(Exception):
    pass


def http_get(url, headers=None, data=None):
    """Abruf mit harter Frist: Auch ein langsamer Download endet spätestens zur Frist der
    Quelle; was bis dahin geladen ist, wird zurückgegeben. Wiederholt bei Überlastung."""
    deadline = getattr(_source_state, "deadline", time.monotonic() + SOURCE_TIMEOUT)
    hdr = {"User-Agent": BROWSER_UA, "Accept": "*/*"}
    hdr.update(headers or {})
    last_error = None
    for attempt in range(3):
        remaining = deadline - time.monotonic()
        if remaining < 1:
            raise last_error or SourceTimeout()   # Frist vorbei: Fehler melden, falls es einen gab
        req = urllib.request.Request(url, headers=hdr, data=data, method="POST" if data else "GET")
        try:
            with urllib.request.urlopen(req, timeout=min(15, remaining)) as r:
                chunks, size = [], 0
                while size < 50_000_000:
                    if time.monotonic() > deadline:
                        _source_state.truncated = True
                        break
                    chunk = r.read1(65536)        # liefert, was gerade da ist (Frist prüfbar)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                return b"".join(chunks).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == 2:
                raise
            last_error = e
        except OSError as e:                      # Verbindungsfehler, Zeitüberschreitung
            if attempt == 2 or time.monotonic() > deadline:
                raise
            last_error = e
        time.sleep(max(0, min(5 * (attempt + 1), deadline - time.monotonic() - 1)))
    return ""


# --- Certificate Transparency
def src_crtsh(d):
    yield http_get(f"https://crt.sh/?q=%25.{d}&output=json")


def src_certspotter(d):
    url = f"https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names"
    after = None
    for _ in range(50):                           # seitenweise
        text = http_get(url + (f"&after={after}" if after else ""))
        yield text
        data = json.loads(text or "[]")
        if not data:
            return
        after = data[-1]["id"]


def src_shodanct(d):
    yield http_get(f"https://ctl.shodan.io/api/v1/domain/{d}/hostnames")


def src_crtname(d):
    yield http_get(f"https://crt.name/v1/search?apex={d}")


# --- Subdomain- und DNS-Datenbanken
def src_hackertarget(d):
    yield http_get(f"https://api.hackertarget.com/hostsearch/?q={d}")


def src_thc(d):
    state = ""
    for _ in range(50):                           # seitenweise per POST
        body = json.dumps({"domain": d, "page_state": state, "limit": 1000}).encode()
        text = http_get("https://ip.thc.org/api/v1/lookup/subdomains", {"Content-Type": "application/json"}, body)
        yield text
        state = (json.loads(text or "{}") or {}).get("next_page_state") or ""
        if not state:
            return


def src_rapiddns(d):
    page, last = 1, 1
    while page <= min(last, 10):                  # seitenweise, höchstens 10 Seiten
        text = http_get(f"https://rapiddns.io/subdomain/{d}?page={page}&full=1")
        yield text
        pages = [int(x) for x in re.findall(r'class="page-link" href="/subdomain/[^"]+\?page=(\d+)"', text)]
        last = max(pages + [last])
        page += 1


SOURCES = {
    "crt.sh": src_crtsh, "certspotter": src_certspotter, "shodanct": src_shodanct, "crtname": src_crtname,
    "hackertarget": src_hackertarget, "thc": src_thc, "rapiddns": src_rapiddns,
}


def run_source(src, domain):
    """Eine Quelle abarbeiten (läuft in einem eigenen Thread). Liefert die gefundenen Namen
    und ob die Frist erreicht wurde; Teilergebnisse bleiben erhalten."""
    _source_state.deadline = time.monotonic() + SOURCE_TIMEOUT
    _source_state.truncated = False
    names = set()
    try:
        for text in SOURCES[src](domain):
            if text:
                names |= extract_names(text, domain)
    except SourceTimeout:
        return names, True
    except ValueError:                            # abgeschnittenes JSON nach Fristende
        if not _source_state.truncated:
            raise
    return names, _source_state.truncated


def extract_names(text, domain):
    """Alle Hostnamen unterhalb von domain aus beliebigem Text ziehen (JSON, HTML, URLs)."""
    # JSON-Escapes (crt.sh trennt mehrere Namen mit "\n") und URL-Kodierung auflösen
    text = urllib.parse.unquote(text.replace("\\n", "\n").replace("\\u002e", "."))
    # (?!\.?[a-z0-9-]) verhindert Treffer wie "www.firma.de" in "www.firma.de.fremd.com"
    rx = r"(?i)[a-z0-9*_.\-]+\." + re.escape(domain) + r"(?!\.?[a-z0-9\-])"
    return {m.lower() for m in re.findall(rx, text)}


# ============================================================== DNS ohne fremde Resolver

# ============================================================== Drosselung

class RateLimiter:
    """Begrenzt Anfragen pro Sekunde. Für Nameserver passt sich die Rate an: Jede ausbleibende
    Antwort senkt sie (bis 5/s), jede Antwort hebt sie wieder bis zum Ausgangswert. Das hält
    sich bei rund 20 % Verlust die Waage: Erst bei mehr Verlust wird es dauerhaft langsamer –
    typisch für Rate Limiting, das genau dann aufhört."""

    def __init__(self, rate):
        self.interval = self.base = 1.0 / rate if rate else 0.0
        self.next = 0.0
        self.lock = asyncio.Lock()

    @property
    def rate(self):
        return 1 / self.interval if self.interval else 0

    def slow_down(self):
        if self.interval:
            self.interval = min(self.interval * 1.5, 0.2)

    def speed_up(self):
        if self.interval:
            self.interval = max(self.base, self.interval * 0.9)

    async def wait(self):
        if not self.interval:
            return
        async with self.lock:
            now = time.monotonic()
            self.next = max(self.next, now)
            delay = self.next - now
            self.next += self.interval
        if delay > 0:
            await asyncio.sleep(delay)


# DNS-Protokoll nach RFC 1035, nur mit der Standardbibliothek. Unterstützt werden die
# Record-Typen, die das Skript braucht; alles andere wird beim Lesen übersprungen.

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
         "AAAA": 28, "SRV": 33, "OPT": 41, "AXFR": 252}
NOERROR, FORMERR, NXDOMAIN = 0, 1, 3
FLAG_AA, FLAG_TC = 0x0400, 0x0200
EDNS_SIZE = 1232          # empfohlene UDP-Größe (DNS Flag Day 2020)


class DNSFail(Exception):
    pass


class RR:
    """Ein Record: Name (klein, ohne Punkt am Ende), Typ als Zahl und Wert als Text.
    Wert je Typ: A/AAAA Adresse, NS/CNAME/PTR Zielname, MX Mailserver, SRV Zielhost,
    SOA primärer Nameserver, TXT Text."""
    __slots__ = ("name", "type", "value")

    def __init__(self, name, rtype, value):
        self.name, self.type, self.value = name, rtype, value


class Message:
    __slots__ = ("id", "flags", "rcode", "question", "answer", "authority", "additional")


def encode_name(name):
    out = b""
    for label in filter(None, name.rstrip(".").split(".")):
        raw = label.encode("idna") if not label.isascii() else label.encode()
        if len(raw) > 63:
            raise ValueError("Label zu lang")
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def build_query(qname, qtype, edns=True):
    """Anfrage ohne Rekursionswunsch (RD=0), mit zufälliger ID und optional EDNS."""
    qid = random.getrandbits(16)
    msg = struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 1 if edns else 0)
    msg += encode_name(qname) + struct.pack("!HH", TYPES[qtype], 1)
    if edns:
        msg += b"\0" + struct.pack("!HHIH", TYPES["OPT"], EDNS_SIZE, 0, 0)
    return qid, msg


def read_name(buf, off):
    """Namen lesen, inkl. Komprimierung. Zeiger dürfen nur rückwärts zeigen; damit sind
    Endlosschleifen durch manipulierte Antworten ausgeschlossen."""
    labels, end, start = [], None, off
    while True:
        if off >= len(buf):
            raise ValueError("Name abgeschnitten")
        n = buf[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("Zeiger abgeschnitten")
            ptr = ((n & 0x3F) << 8) | buf[off + 1]
            if ptr >= start:
                raise ValueError("ungültiger Zeiger")
            end = off + 2 if end is None else end
            off = start = ptr
            continue
        if n & 0xC0:
            raise ValueError("unbekannter Label-Typ")
        off += 1
        if n == 0:
            break
        labels.append(buf[off:off + n].decode("ascii", "replace").lower())
        off += n
        if sum(len(x) + 1 for x in labels) > 255:
            raise ValueError("Name zu lang")
    return ".".join(labels), (end if end is not None else off)


def parse_message(buf):
    """Antwort lesen. Wirft ValueError bei kaputten Daten."""
    if len(buf) < 12:
        raise ValueError("zu kurz")
    m = Message()
    m.id, m.flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
    m.rcode = m.flags & 0x0F
    off, m.question = 12, None
    for _ in range(qd):
        name, off = read_name(buf, off)
        if off + 4 > len(buf):
            raise ValueError("Frage abgeschnitten")
        m.question = (name, struct.unpack("!H", buf[off:off + 2])[0])
        off += 4
    sections = []
    for count in (an, ns, ar):
        records = []
        for _ in range(count):
            name, off = read_name(buf, off)
            if off + 10 > len(buf):
                raise ValueError("Record abgeschnitten")
            rtype, _, _, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
            off += 10
            if off + rdlen > len(buf):
                raise ValueError("Daten abgeschnitten")
            rd, value = buf[off:off + rdlen], None
            if rtype == 1 and rdlen == 4:
                value = str(ipaddress.IPv4Address(rd))
            elif rtype == 28 and rdlen == 16:
                value = str(ipaddress.IPv6Address(rd))
            elif rtype in (2, 5, 12, 6):          # NS, CNAME, PTR, SOA (primärer Nameserver)
                value = read_name(buf, off)[0]
            elif rtype == 15 and rdlen > 2:       # MX: Priorität, Name
                value = read_name(buf, off + 2)[0]
            elif rtype == 33 and rdlen > 6:       # SRV: Priorität, Gewicht, Port, Name
                value = read_name(buf, off + 6)[0]
            elif rtype == 16:                     # TXT: Folge von Längen-Strings
                parts, i = [], 0
                while i < rdlen:
                    parts.append(rd[i + 1:i + 1 + rd[i]])
                    i += 1 + rd[i]
                value = b"".join(parts).decode("utf-8", "replace")
            if value is not None:
                records.append(RR(name, rtype, value))
            off += rdlen
        sections.append(records)
    m.answer, m.authority, m.additional = sections
    return m


def matches(m, qid, qname, qtype):
    """Gehört die Antwort zur Anfrage? (Schutz vor verirrten oder gefälschten Paketen)"""
    return m.id == qid and m.question == (qname.rstrip(".").lower(), TYPES[qtype])


async def udp_query(ip, qname, qtype, edns=True):
    qid, data = build_query(qname, qtype, edns)
    loop = asyncio.get_running_loop()
    fut = loop.create_future()

    class Proto(asyncio.DatagramProtocol):
        def datagram_received(self, packet, addr):
            try:
                m = parse_message(packet)
            except ValueError:
                return
            if matches(m, qid, qname, qtype) and not fut.done():
                fut.set_result(m)

    # "verbundener" UDP-Socket: das Betriebssystem nimmt nur Pakete dieser IP an;
    # der Quellport ist zufällig
    transport, _ = await loop.create_datagram_endpoint(Proto, remote_addr=(ip, 53))
    try:
        transport.sendto(data)
        return await asyncio.wait_for(fut, DNS_TIMEOUT)
    finally:
        transport.close()


async def tcp_read(reader):
    size = struct.unpack("!H", await reader.readexactly(2))[0]
    return await reader.readexactly(size)


async def tcp_query(ip, qname, qtype, edns=True):
    qid, data = build_query(qname, qtype, edns)
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 53), DNS_TIMEOUT)
    try:
        writer.write(struct.pack("!H", len(data)) + data)
        await writer.drain()
        m = parse_message(await asyncio.wait_for(tcp_read(reader), DNS_TIMEOUT))
        if not matches(m, qid, qname, qtype):
            raise ValueError("fremde Antwort")
        return m
    finally:
        writer.close()


async def axfr(ip, zone):
    """Zonentransfer versuchen. Liefert die Namen der Zone oder None, wenn abgelehnt."""
    qid, data = build_query(zone, "AXFR", edns=False)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 53), 8)
    except (OSError, asyncio.TimeoutError):
        return None
    names, soa_seen = set(), 0
    try:
        writer.write(struct.pack("!H", len(data)) + data)
        await writer.drain()
        deadline = time.monotonic() + 30
        while soa_seen < 2 and time.monotonic() < deadline:
            m = parse_message(await asyncio.wait_for(tcp_read(reader), 8))
            if m.id != qid or m.rcode != NOERROR or (not names and not m.answer):
                return None
            for rr in m.answer:
                names.add(rr.name)
                soa_seen += rr.type == TYPES["SOA"]
            if soa_seen == 0:
                return None                         # erste Antwort muss mit SOA beginnen
    except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        return sorted(names) if soa_seen >= 2 else None
    finally:
        writer.close()
    return sorted(names) if soa_seen >= 2 else None


class IterativeResolver:
    """Löst Namen selbst auf: Root -> TLD -> … -> autoritativer Server.

    Mit QNAME-Minimierung fragt das Skript jeden übergeordneten Server nur nach dem
    nächsten Label (z. B. die .de-Server nur nach "firma.de", nie nach
    "intern.firma.de"). Vollständige Namen erreichen nur die zuständigen Server.
    Delegationen werden zwischengespeichert, damit jede Zone nur einmal gesucht wird.
    Namen werden intern klein und ohne abschließenden Punkt geführt; "" ist die Wurzel.
    """

    def __init__(self, roots=None, own_domains=()):
        self.zones = {"": list(roots or ROOT_SERVERS)}   # Zone -> Nameserver-IPs
        self.own = tuple(own_domains)  # eigene Domains: nur dort sind Ausweichanfragen erlaubt
        self.no_edns = set()       # Server, die EDNS ablehnen
        self.no_cut = set()        # Namen ohne eigene Zone (keine Delegation)
        self.cache = {}            # (name, typ) -> Ergebnis
        self.sem = asyncio.Semaphore(100)
        self.per_server = {}       # Nameserver-IP -> (Semaphore, RateLimiter)
        self.nx = set()            # Namen, die nachweislich nicht existieren (samt Unternamen)
        self.throttled = set()     # Nameserver, deren Rate deutlich gesenkt wurde
        self.queries = 0
        self.retries = 0

    async def _query(self, ip, qname, qtype):
        """Eine Anfrage an einen Server, gedrosselt je Server. Gekürzte Antworten werden
        per TCP wiederholt, Server ohne EDNS-Unterstützung ohne EDNS gefragt."""
        if ip not in self.per_server:
            self.per_server[ip] = (asyncio.Semaphore(10), RateLimiter(DNS_RATE_PER_SERVER))
        slot, rate = self.per_server[ip]
        async with self.sem, slot:
            await rate.wait()
            self.queries += 1
            edns = ip not in self.no_edns
            m = await udp_query(ip, qname, qtype, edns)
            if m.rcode == FORMERR and edns:
                self.no_edns.add(ip)
                m = await udp_query(ip, qname, qtype, edns=False)
            if m.flags & FLAG_TC:
                m = await tcp_query(ip, qname, qtype, ip not in self.no_edns)
            return m

    async def ask(self, servers, qname, qtype):
        """Eine Frage an bis zu drei Server der Zone; erste brauchbare Antwort zählt.
        Bleibt alles ohne Antwort (Paketverlust, Rate Limiting), wird es nach einer
        kurzen Pause wiederholt."""
        for attempt in range(DNS_ROUNDS):
            if attempt:
                self.retries += 1
                await asyncio.sleep(2 * attempt + random.random())
            for ip in random.sample(servers, min(3, len(servers))):
                try:
                    m = await self._query(ip, qname, qtype)
                except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                    self._throttle(ip)
                    continue
                self.per_server[ip][1].speed_up()
                if m.rcode in (NOERROR, NXDOMAIN):
                    return m
        return None

    def _throttle(self, ip):
        """Antwort blieb aus: Rate für diesen Nameserver senken (vermutlich Rate Limiting)."""
        limiter = self.per_server[ip][1]
        limiter.slow_down()
        if limiter.rate < DNS_RATE_PER_SERVER / 3 and ip not in self.throttled:
            self.throttled.add(ip)
            log(f"Nameserver {ip} antwortet nicht auf alle Anfragen – Abfragerate gesenkt "
                f"(jetzt {limiter.rate:.0f}/s)")

    def known_nx(self, name):
        """Existiert der Name (oder ein übergeordneter Name) nachweislich nicht?"""
        labels = name.split(".")
        return any(".".join(labels[i:]) in self.nx for i in range(len(labels)))

    @staticmethod
    def _records(section, owner, qtype):
        t = TYPES[qtype]
        return [rr for rr in section if rr.type == t and rr.name == owner]

    async def _ns_addresses(self, m, ns_names, depth):
        """IPv4-Adressen der Nameserver: Glue-Records oder eigene Auflösung."""
        ips = [rr.value for rr in m.additional if rr.type == TYPES["A"] and rr.name in ns_names]
        if not ips and depth < 4:
            for n in ns_names[:4]:
                st, recs, _ = await self.resolve(n, "A", depth + 1)
                ips += [r.value for r in recs] if st == "ok" else []
                if len(ips) >= 2:
                    break
        return ips

    async def _learn_delegation(self, m, depth):
        """Verweis (Referral) auf zuständige Nameserver einer tieferen Zone merken."""
        for zone in {rr.name for rr in m.authority if rr.type == TYPES["NS"]} - set(self.zones):
            ns = [rr.value for rr in self._records(m.authority, zone, "NS")]
            ips = await self._ns_addresses(m, ns, depth)
            if ips:
                self.zones[zone] = ips
                return True
        return False

    async def servers_for(self, name, depth=0, include_last=True):
        """Zuständige Nameserver für name suchen (von der Wurzel abwärts, je Label eine Frage).
        Mit include_last=False endet die Suche beim übergeordneten Namen: Die eigentliche
        Frage geht dann direkt an dessen Server (RFC 9156 erlaubt das; es erfährt dabei
        niemand mehr als ohnehin). Liefert None, wenn ein übergeordneter Name nicht existiert."""
        if self.known_nx(name):
            return None
        if name in self.zones:                   # der Name ist selbst eine bekannte Zone
            return self.zones[name]
        labels = name.split(".")
        zone, servers = "", self.zones[""]
        for i in range(len(labels) - 1, 0 if not include_last else -1, -1):
            child = ".".join(labels[i:])
            if child in self.zones:
                zone, servers = child, self.zones[child]
                continue
            if child in self.no_cut:
                continue
            m = await self.ask(servers, child, "NS")          # nur nach dem nächsten Label fragen
            if m is None:
                raise DNSFail(child)
            if m.rcode == NXDOMAIN:
                # Manche Server melden NXDOMAIN für leere Zwischenebenen (RFC 8020 nicht
                # umgesetzt). Nur bei den Servern der eigenen Domains wird dann der
                # vollständige Name gestellt; Root, TLDs und fremde Server erfahren ihn nie.
                own = any(zone == d or zone.endswith("." + d) for d in self.own)
                if i > 0 and own:
                    return servers
                self.nx.add(child)
                return None
            ns = [rr.value for rr in self._records(m.answer + m.authority, child, "NS")]
            ips = await self._ns_addresses(m, ns, depth) if ns else []
            if ips:
                self.zones[child] = servers = ips
                zone = child
            else:
                self.no_cut.add(child)                       # keine eigene Zone
        return servers

    async def resolve(self, name, qtype, depth=0):
        """Ergebnis: (status, records, cname_kette); status ist ok | nxdomain | nodata | fail."""
        key = (name.lower().rstrip("."), qtype)
        if key in self.cache:
            return self.cache[key]
        if self.known_nx(key[0]):                # spart z. B. die AAAA-Frage nach NXDOMAIN
            return ("nxdomain", [], [])
        chain, cur, result = [], key[0], ("fail", [], [])
        for _ in range(10):                     # CNAME-Ziele und Verweise in andere Zonen
            try:
                servers = await self.servers_for(cur, depth, include_last=False)
            except DNSFail:
                break
            if servers is None:
                result = ("nxdomain", [], chain)
                break
            m = await self.ask(servers, cur, qtype)
            if m is None:
                break
            owner, recs = cur, []               # CNAME-Kette innerhalb der Antwort verfolgen
            while len(chain) < 10:
                recs = self._records(m.answer, owner, qtype)
                cname = [] if qtype == "CNAME" else self._records(m.answer, owner, "CNAME")
                if recs or not cname:
                    break
                owner = cname[0].value
                chain.append(owner)
            if recs:
                result = ("ok", recs, chain)
                break
            if owner != cur:                     # CNAME-Ziel liegt woanders: dort weiterfragen
                cur = owner
                continue
            if m.rcode == NXDOMAIN:
                self.nx.add(cur)
                result = ("nxdomain", [], chain)
                break
            if not m.answer and not (m.flags & FLAG_AA) and await self._learn_delegation(m, depth):
                continue                         # Verweis auf tiefere Zone: dort erneut fragen
            result = ("nodata", [], chain)
            break
        if result[0] != "fail":                  # Fehler nicht merken: später neu versuchen
            self.cache[key] = result
        return result


# ============================================================== Inventar

class Inventory:
    def __init__(self, domains, nets, ports, profile, wordlist=None, tech=True,
                 roots=None, overrides=None):
        self.domains = sorted({n for n in map(norm_name, domains) if n})
        self.nets = [ipaddress.ip_network(n, strict=False) for n in nets]
        self.ports = ports
        self.cfg = PROFILES[profile]
        self.wordlist = wordlist
        self.use_tech = tech
        self.overrides = overrides or {}       # Name -> [IP]  (nur für Tests/Sonderfälle)
        self.dns = IterativeResolver(roots, self.domains)
        self.tech = TechDetector()

        self.hosts = {}          # Name -> {status, a, aaaa, cname, sources, net_only}
        self.ips = {}            # IP -> {in_net, ptr, hostnames}
        self.wildcards = {}      # Elternname -> IPs eines Zufallsnamens (leer = keine Wildcard)
        self.wildcard_lock = asyncio.Lock()
        self.scanned = {}        # IP -> geprüfte Ports
        self.open_ports = {}     # IP -> offene Ports
        self.scheme = {}         # (IP, Port) -> https | http | tls-non-http | non-http
        self.probed = set()      # (IP, Port, Hostname) bereits abgerufen
        self.services = []       # Ergebniszeilen
        self.findings = {}       # (Art, Gruppe) -> {type, detail, targets}
        self.source_stats = {}   # Quelle -> {names, exclusive, error, timeout}
        self.source_names = {}   # Quelle -> gefundene Namen

        # Last und Sperr-Erkennung
        self.rate = RateLimiter(self.cfg["rate"])
        self.port_sem = asyncio.Semaphore(self.cfg["concurrency"])
        self.http_sem = asyncio.Semaphore(max(10, self.cfg["concurrency"] // 4))
        self.host_sems = {}
        self.stats = {"tcp": 0, "http": 0}
        self.conn_per_ip = {}
        self.canary = {}         # IP -> Port, der nachweislich offen war
        self.blocked = {}        # IP -> Phase, nach der er nicht mehr antwortete
        self.foreign_count = 0
        self.ptr_done = set()    # IPs mit erledigter Rückwärtsauflösung

    # ---------------------------------------------------------- Scope
    def in_domains(self, name):
        return any(name == d or name.endswith("." + d) for d in self.domains)

    def in_net(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self.nets)

    def add_host(self, name, source, foreign_ok=False):
        """Namen aufnehmen. Fremde Namen (nicht unter euren Domains) nur, wenn foreign_ok –
        sie werden später nur behalten, wenn sie in eure Netze auflösen."""
        name = norm_name(name)
        if not name:
            return False
        ours = self.in_domains(name)
        if not ours and not (foreign_ok and self.nets):
            return False
        if name in self.hosts:
            self.hosts[name]["sources"].add(source)
            return False
        if not ours:
            if self.foreign_count >= 2000:
                return False
            self.foreign_count += 1
        self.hosts[name] = {"name": name, "status": "pending", "a": [], "aaaa": [], "cname": [],
                            "sources": {source}, "net_only": not ours}
        return True

    def ipinfo(self, ip):
        if ip not in self.ips:
            self.ips[ip] = {"ip": ip, "in_net": self.in_net(ip), "ptr": "", "hostnames": set()}
        return self.ips[ip]

    def finding(self, kind, target, detail, group=None):
        """Auffälligkeit merken. Gleiche Art und Gruppe (standardmäßig die Beschreibung, bei
        Zertifikaten das Zertifikat) werden zu einem Eintrag mit mehreren Zielen zusammengefasst."""
        fd = self.findings.setdefault((kind, group or detail), {"type": kind, "detail": detail, "targets": []})
        if target not in fd["targets"]:
            fd["targets"].append(target)

    def live_hosts(self):
        return [h for h in self.hosts.values() if h["status"].startswith("resolved")]

    # ---------------------------------------------------------- DNS-Helfer
    async def q(self, name, rtype):
        """Records eines Typs oder [] (Fehler zählen als 'nicht vorhanden')."""
        st, recs, _ = await self.dns.resolve(name, rtype)
        return recs if st == "ok" else []

    # ---------------------------------------------------------- Phase 1: Namen sammeln
    async def collect_passive(self):
        """Alle passiven Quellen parallel abfragen, je Quelle höchstens SOURCE_TIMEOUT Sekunden.
        Übertragen wird nur der Domainname."""
        loop = asyncio.get_running_loop()
        jobs = [(s, d) for d in self.domains for s in SOURCES]
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=min(64, len(jobs)))

        async def one(src, d):
            st = self.source_stats.setdefault(src, {"names": 0, "exclusive": 0, "error": "", "timeout": False})
            t0 = time.time()
            try:
                names, timed_out = await loop.run_in_executor(pool, run_source, src, d)
            except Exception as e:  # noqa: BLE001
                st["error"] = e.__class__.__name__
                log(f"  {src:<16} {d}: nicht erreichbar ({st['error']}, {time.time() - t0:.0f}s)")
                return
            for n in names:
                self.add_host(n, src)
            self.source_names.setdefault(src, set()).update(names)
            st["names"] += len(names)
            st["timeout"] |= timed_out
            note = f" – nach {SOURCE_TIMEOUT}s abgebrochen, Teilergebnis" if timed_out else ""
            log(f"  {src:<16} {d}: {len(names):>5} Namen ({time.time() - t0:.0f}s){note}")
        log(f"Passive Quellen ({len(SOURCES)}, parallel, je max. {SOURCE_TIMEOUT}s): {', '.join(SOURCES)}")
        try:
            await asyncio.gather(*[one(s, d) for s, d in jobs])
        finally:
            pool.shutdown(wait=False)
        # Wie viele Namen kennt nur diese eine Quelle? (unabhängig davon, wer zuerst fertig war)
        for src, names in self.source_names.items():
            others = set().union(*[n for s, n in self.source_names.items() if s != src])
            self.source_stats[src]["exclusive"] = len({norm_name(n) for n in names} - {norm_name(n) for n in others})

    async def collect_dns(self):
        """NS, MX, SOA, TXT (SPF), SRV und Zonentransfer-Versuch je Domain."""
        for d in self.domains:
            for qtype in ("NS", "MX", "SOA"):
                for rr in await self.q(d, qtype):
                    self.add_host(rr.value, "dns")
            for rr in await self.q(d, "TXT"):
                for m in re.findall(r"(?:a|mx|include|ptr|exists)[:=]([a-z0-9.\-_]+)", rr.value, re.I):
                    self.add_host(m, "dns")
            for recs in await asyncio.gather(*[self.q(f"{s}.{d}", "SRV") for s in SRV_NAMES]):
                for rr in recs:
                    self.add_host(rr.value, "dns")
            await self.try_axfr(d)

    async def try_axfr(self, domain):
        """Zonentransfer bei den eigenen Nameservern versuchen (sollte abgelehnt werden)."""
        try:
            servers = await self.dns.servers_for(domain)
        except DNSFail:
            return
        for ip in servers or []:
            names = await axfr(ip, domain)
            if names is None:
                continue                                 # abgelehnt = gut
            for n in names:
                self.add_host(n, "axfr")
            self.finding("Zonentransfer offen", f"{domain} @ {ip}", f"{len(names)} Einträge abrufbar")
            log(f"Zonentransfer {domain} @ {ip}: OFFEN ({len(names)} Einträge)")
            return

    async def bruteforce(self):
        """Häufige Subdomain-Namen ausprobieren."""
        words = list(WORDLIST)
        if self.wordlist:
            with open(self.wordlist, encoding="utf-8", errors="ignore") as f:
                words += [w.strip().lower() for w in f if w.strip() and not w.startswith("#")]
        words = sorted(set(words))
        sem = asyncio.Semaphore(100)

        async def check(name):
            async with sem:
                st, _, chain = await self.dns.resolve(name, "A")
                if st == "nodata":
                    st, _, chain = await self.dns.resolve(name, "AAAA")
            if st == "ok" or chain:      # auch CNAMEs ins Leere (verwaiste Einträge) aufnehmen
                self.add_host(name, "wortliste")
        for d in self.domains:
            await asyncio.gather(*[check(f"{w}.{d}") for w in words])
            log(f"Wortliste {d}: {len(words)} Namen geprüft")

    async def ptr_lookup(self, ips):
        """Rückwärtsauflösung (fragt nur die für eure Reverse-Zonen zuständigen Server)."""
        self.ptr_done.update(ips)
        sem = asyncio.Semaphore(100)

        async def one(ip):
            async with sem:
                recs = await self.q(ipaddress.ip_address(ip).reverse_pointer, "PTR")
            if recs:
                ptr = recs[0].value
                self.ipinfo(ip)["ptr"] = ptr
                self.add_host(ptr, "ptr", foreign_ok=True)
        await asyncio.gather(*[one(ip) for ip in ips])

    # ---------------------------------------------------------- Phase 2: auflösen
    async def is_wildcard(self, h):
        """Liefert ein Zufallsname auf derselben Ebene dieselben IPs? Dann Wildcard-Treffer."""
        parent = h["name"].split(".", 1)[1] if "." in h["name"] else ""
        if not self.in_domains(parent):
            return False
        async with self.wildcard_lock:          # je Ebene nur einmal testen
            if parent not in self.wildcards:
                rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=20)) + "." + parent
                ips = {r.value for t in ("A", "AAAA") for r in await self.q(rnd, t)}
                self.wildcards[parent] = ips
                if ips:
                    log(f"Wildcard-DNS bei *.{parent}")
        wild = self.wildcards[parent]
        return bool(wild) and set(h["a"] + h["aaaa"]) <= wild

    async def resolve_host(self, h):
        name = h["name"]
        if name in self.overrides:
            h["a"] = [i for i in self.overrides[name] if ":" not in i]
            h["aaaa"] = [i for i in self.overrides[name] if ":" in i]
            h["status"] = "resolved"
            return
        st4, a, chain4 = await self.dns.resolve(name, "A")
        st6, aaaa, chain6 = await self.dns.resolve(name, "AAAA")
        h["a"] = sorted({r.value for r in a})
        h["aaaa"] = sorted({r.value for r in aaaa})
        h["cname"] = chain4 or chain6
        if h["a"] or h["aaaa"]:
            h["status"] = "resolved"
        elif h["cname"] and "nxdomain" in (st4, st6):
            h["status"] = "dangling-cname"
            if not h["net_only"]:
                self.finding("Verwaister CNAME", name, f"zeigt auf {h['cname'][-1]}, das nicht existiert – "
                             "Subdomain-Übernahme möglich, Eintrag löschen")
        else:
            h["status"] = {"nxdomain": "nxdomain", "fail": "dns-fehler"}.get(st4, "keine-adresse")

    async def resolve_pending(self):
        pending = [h for h in self.hosts.values() if h["status"] == "pending"]
        sem = asyncio.Semaphore(100)

        async def one(h):
            async with sem:
                await self.resolve_host(h)
            if h["status"] != "resolved":
                return
            if h["net_only"] and not any(self.in_net(i) for i in h["a"] + h["aaaa"]):
                h["status"] = "out-of-scope"       # fremder Name, zeigt nicht in eure Netze
            elif not h["net_only"] and await self.is_wildcard(h):
                # Nur geratene Namen verwerfen; Namen aus CT/Archiven bleiben, markiert
                h["status"] = "wildcard" if h["sources"] == {"wortliste"} else "resolved (wildcard)"
        await asyncio.gather(*[one(h) for h in pending])
        failed = [h for h in pending if h["status"] == "dns-fehler"]
        if failed:                                   # zweiter Anlauf nach kurzer Pause
            log(f"{len(failed)} Namen ohne DNS-Antwort – neuer Versuch in 10 s …")
            await asyncio.sleep(10)
            await asyncio.gather(*[one(h) for h in failed])
            still = sum(h["status"] == "dns-fehler" for h in failed)
            if still:
                log(f"{still} Namen weiterhin ohne DNS-Antwort (Nameserver überlastet oder nicht erreichbar)")
        return len(pending)

    # ---------------------------------------------------------- Phase 3: Ports
    def host_slot(self, ip):
        """Begrenzt gleichzeitige Verbindungen je Ziel-IP."""
        if ip not in self.host_sems:
            self.host_sems[ip] = asyncio.Semaphore(self.cfg["per_host"])
        return self.host_sems[ip]

    async def tcp_open(self, ip, port):
        async with self.host_slot(ip), self.port_sem:
            await self.rate.wait()
            self.stats["tcp"] += 1
            self.conn_per_ip[ip] = self.conn_per_ip.get(ip, 0) + 1
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), self.cfg["timeout"])
            except Exception:  # noqa: BLE001  (geschlossen oder gefiltert)
                return False
            w.close()
            try:
                await asyncio.wait_for(w.wait_closed(), 2)
            except Exception:  # noqa: BLE001
                pass
            return True

    async def port_scan(self, targets):
        """Erst 80/443 überall (liefert Referenzports für die Sperr-Erkennung), dann der Rest.
        Die Reihenfolge wird gemischt, damit kein Ziel viele Anfragen am Stück bekommt."""
        jobs = [(ip, p) for ip, ports in targets.items() for p in ports
                if p not in self.scanned.setdefault(ip, set())]
        if not jobs:
            return
        first = [j for j in jobs if j[1] in (80, 443)]
        rest = [j for j in jobs if j[1] not in (80, 443)]
        random.shuffle(first)
        random.shuffle(rest)
        log(f"Portscan: {len(jobs)} Verbindungsversuche auf {len(targets)} IPs")
        for batch in (first, rest):
            results = await asyncio.gather(*[self.tcp_open(ip, p) for ip, p in batch])
            for (ip, p), is_open in zip(batch, results):
                self.scanned[ip].add(p)
                if is_open:
                    self.open_ports.setdefault(ip, set()).add(p)
                    self.canary.setdefault(ip, p)
        await self.check_blocked("Portscan")
        log(f"Portscan fertig: {sum(map(len, self.open_ports.values()))} offene Ports insgesamt")

    async def check_blocked(self, phase):
        """Antwortet ein vorher offener Port nicht mehr, hat uns vermutlich fail2ban/IPS gesperrt."""
        async def one(ip):
            for _ in range(2):
                if await self.tcp_open(ip, self.canary[ip]):
                    return
                await asyncio.sleep(3)
            self.blocked[ip] = phase
            self.finding("Scanner vermutlich gesperrt", ip, f"Port {self.canary[ip]} antwortet nach "
                         f"'{phase}' nicht mehr – Ergebnisse für diese IP unvollständig")
            log(f"WARNUNG: {ip} antwortet nach '{phase}' nicht mehr – vermutlich gesperrt")
        await asyncio.gather(*[one(ip) for ip in self.canary if ip not in self.blocked])

    # ---------------------------------------------------------- Phase 4: HTTP
    async def http(self, ip, port, host, tls, path="/", verify=False):
        """Ein HTTP(S)-Abruf mit Drosselung. verify=True prüft nur das Zertifikat."""
        async with self.host_slot(ip):
            await self.rate.wait()
            self.stats["tcp" if verify else "http"] += 1
            self.conn_per_ip[ip] = self.conn_per_ip.get(ip, 0) + 1
            return await self._http(ip, port, host, tls, path, verify)

    async def _http(self, ip, port, host, tls, path, verify):
        timeout = self.cfg["timeout"] + 2
        ctx = None
        if tls and verify:
            ctx = ssl.create_default_context()
        elif tls:
            ctx = ssl._create_unverified_context()  # noqa: S323  (Inventar, keine Datenübertragung)
            try:  # auch alte/schwache Server erfassen
                ctx.set_ciphers("ALL:@SECLEVEL=0")
                ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            except (ssl.SSLError, ValueError):
                pass
        t0 = time.monotonic()
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(
                ip, port, ssl=ctx, server_hostname=(host or "") if tls else None), timeout)
        except ssl.SSLCertVerificationError as e:
            return {"verify_error": e.verify_message or str(e)}
        except Exception:  # noqa: BLE001
            return None
        if verify:
            w.close()
            return {"verified": True}

        out = {}
        if tls:
            sslobj = w.get_extra_info("ssl_object")
            cert = decode_der_cert(sslobj.getpeercert(binary_form=True) or b"") if sslobj else {}
            out.update({
                "tls_version": sslobj.version() if sslobj else "",
                "tls_cipher": (sslobj.cipher() or [""])[0] if sslobj else "",
                "cert_cn": cert_field(cert.get("subject"), "commonName"),
                "cert_issuer": cert_field(cert.get("issuer"), "organizationName")
                or cert_field(cert.get("issuer"), "commonName"),
                "cert_not_after": cert.get("notAfter", ""),
                "cert_sans": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
            })
        request = (f"GET {path} HTTP/1.1\r\nHost: {host_header(host, ip, port, tls)}\r\n"
                   f"User-Agent: Mozilla/5.0 (compatible; webinventar/{VERSION})\r\n"
                   "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
        data, first_byte = b"", None
        try:
            w.write(request.encode())
            await w.drain()
            while len(data) < 262144:
                chunk = await asyncio.wait_for(r.read(16384), timeout)
                first_byte = first_byte or time.monotonic()
                if not chunk:
                    break
                data += chunk
        except Exception:  # noqa: BLE001  (Timeout: mit dem arbeiten, was da ist)
            pass
        finally:
            w.close()
        if not data.startswith(b"HTTP/"):
            out["http"] = False
            return out

        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        status = lines[0].split(" ", 2)
        headers, cookies = {}, {}
        for ln in lines[1:]:
            if ":" not in ln:
                continue
            k, v = (x.strip() for x in ln.split(":", 1))
            k = k.lower()
            if k == "set-cookie" and "=" in v:
                ck, cv = v.split(";", 1)[0].split("=", 1)
                cookies[ck.strip()] = cv.strip()
            headers[k] = f"{headers[k]}, {v}" if k in headers else v
        if "chunked" in headers.get("transfer-encoding", "").lower():
            body = dechunk(body)
        text = body.decode("utf-8", "replace")
        title = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        out.update({
            "http": True,
            "status": int(status[1]) if len(status) > 1 and status[1].isdigit() else 0,
            "title": re.sub(r"\s+", " ", title.group(1)).strip()[:200] if title else "",
            "server": headers.get("server", ""),
            "location": headers.get("location", ""),
            "content_type": headers.get("content-type", "").split(";")[0],
            "length": len(body),
            "hsts": "strict-transport-security" in headers,
            "response_ms": int(((first_byte or time.monotonic()) - t0) * 1000),
            "body_hash": hashlib.sha256(body).hexdigest()[:16],
            "headers": headers, "cookies": cookies, "body": text,
        })
        return out

    async def detect_scheme(self, ip, port):
        """Spricht der Port HTTPS, HTTP oder etwas anderes?"""
        if (ip, port) in self.scheme:
            return
        async with self.http_sem:
            res = await self.http(ip, port, None, True)
            if res and res.get("http"):
                self.scheme[(ip, port)] = "https"
                return
            plain = await self.http(ip, port, None, False)
            if plain and plain.get("http"):
                self.scheme[(ip, port)] = "http"
            else:
                self.scheme[(ip, port)] = "tls-non-http" if res else "non-http"

    async def follow_redirects(self, res, url):
        """Weiterleitungen folgen (max. 5), solange sie zu euren Domains oder Netzen führen.
        Fremde Ziele werden nur notiert, nicht aufgelöst und nicht abgerufen."""
        chain, cur = [], res
        for _ in range(5):
            if not (300 <= cur.get("status", 0) < 400 and cur.get("location")):
                break
            url = urllib.parse.urljoin(url, cur["location"])
            p = urllib.parse.urlsplit(url)
            if p.scheme not in ("http", "https") or not p.hostname:
                break
            chain.append(url)
            host = p.hostname.lower().rstrip(".")
            known = self.hosts.get(host)
            ip = None
            if known and (known["a"] or known["aaaa"]):          # schon aufgelöst
                ip = (known["a"] + known["aaaa"])[0]
            elif self.in_domains(host):                           # eure Domain: selbst auflösen
                self.add_host(host, "redirect")
                ip = next((r.value for r in await self.q(host, "A")), None)
            elif self.in_net(host):                               # IP-Adresse in eurem Netz
                ip, host = host, None
            if not ip or not (self.in_net(ip) or (host and self.in_domains(host))):
                return chain, None
            path = (p.path or "/") + (f"?{p.query}" if p.query else "")
            nxt = await self.http(ip, p.port or (443 if p.scheme == "https" else 80), host,
                                  p.scheme == "https", path)
            if not nxt or not nxt.get("http"):
                return chain, None
            cur = nxt
        return chain, (cur if chain else None)

    async def probe(self, ip, port, host):
        """Einen Dienst abrufen (mit Hostname = vHost, ohne = IP-Default) und Zeile anlegen."""
        if (ip, port, host or "") in self.probed:
            return
        self.probed.add((ip, port, host or ""))
        sch = self.scheme.get((ip, port))
        h = self.hosts.get(host, {}) if host else {}
        row = {"ip": ip, "port": port, "hostname": host or "", "in_own_net": self.in_net(ip),
               "ptr": self.ipinfo(ip)["ptr"], "cname": " -> ".join(h.get("cname", [])),
               "foreign_name": "ja" if h.get("net_only") else "", "notes": ""}
        if sch in ("non-http", "tls-non-http"):
            if not host:
                self.services.append({**row, "scheme": sch, "url": f"{ip}:{port}",
                                      "notes": "Port offen, kein HTTP"})
            return
        tls = sch == "https"
        url = url_for(host, ip, port, tls)
        async with self.http_sem:
            res = await self.http(ip, port, host, tls)
            if not res or not res.get("http"):
                if not host:
                    self.services.append({**row, "scheme": sch, "url": url, "notes": "keine HTTP-Antwort"})
                return
            ver = await self.http(ip, port, host, True, verify=True) if tls and host else None
            chain, final = await self.follow_redirects(res, url)
        tech = set(self.tech.detect(res["headers"], res["cookies"], res["body"]))
        if final:
            tech |= set(self.tech.detect(final["headers"], final["cookies"], final["body"]))
        row.update({k: res.get(k, "") for k in (
            "status", "title", "server", "location", "content_type", "length", "response_ms",
            "body_hash", "tls_version", "tls_cipher", "cert_cn", "cert_issuer", "cert_not_after")})
        row.update({
            "scheme": "https" if tls else "http", "url": url, "tech": ", ".join(sorted(tech)),
            "hsts": res["hsts"] if tls else "", "cert_sans": " ".join(res.get("cert_sans", [])),
            "final_url": chain[-1] if chain else "",
            "final_status": final["status"] if final else "", "final_title": final["title"] if final else "",
            "cert_valid": "" if ver is None else
            ("ja" if ver.get("verified") else f"nein: {ver.get('verify_error', 'Fehler')}"),
        })
        # Neue Namen aus dem Zertifikat. Fremde Namen nur von Diensten in euren Netzen,
        # sonst würden z. B. die hunderten SANs eines Hoster-Zertifikats aufgelöst.
        for san in res.get("cert_sans", []) + [res.get("cert_cn", "")]:
            self.add_host(san, "zertifikat", foreign_ok=self.in_net(ip))
        for r in (res, final):
            self.harvest_names(r)
            m = ERROR_DETAILS.search(r["body"][:150000]) if r and r.get("http") else None
            if m and not row.get("error_details"):
                row["error_details"] = m.group(0)
        self.services.append(row)

    def harvest_names(self, res):
        """Hostnamen eurer Domains aus einer bereits abgerufenen Antwort ziehen: Seiteninhalt
        (Links, Skripte, eingebettetes JSON) und alle Header (z. B. Content-Security-Policy,
        Link, Access-Control-Allow-Origin). Keine zusätzlichen Anfragen.
        Nur Namen unter euren Domains – fremde Namen (Google Fonts, Analytics, …) werden
        ignoriert und auch nicht aufgelöst."""
        if not res or not res.get("http"):
            return
        text = res["body"] + "\n" + "\n".join(res["headers"].values())
        text = text.replace("\\/", "/")      # in JSON/JavaScript maskierte Schrägstriche
        for d in self.domains:
            if d in text.lower():
                for name in extract_names(text, d):
                    self.add_host(name, "http-inhalt")

    # ---------------------------------------------------------- Ablauf
    def net_addresses(self):
        ips = []
        for n in self.nets:
            if n.version == 6 and n.prefixlen < 112:
                log(f"{n}: IPv6-Netz zu groß zum Durchsuchen – nur aufgelöste Adressen daraus werden geprüft")
                continue
            ips += [str(i) for i in (n.hosts() if n.num_addresses > 2 else n)]
        return ips

    async def run(self):
        # Eigene DNS-Auflösung braucht direkten Zugang zu UDP/TCP-Port 53 im Internet
        if not await self.dns.ask(self.dns.zones[""], "", "NS"):
            sys.exit("Fehler: Die DNS-Root-Server sind nicht erreichbar. Das Skript löst Namen selbst auf "
                     "(ohne fremde Resolver) und braucht dafür ausgehend UDP/TCP-Port 53. Bitte von einem "
                     "Rechner mit freiem DNS-Zugang ausführen, idealerweise außerhalb eures Netzes.")
        if self.use_tech:
            path = await asyncio.to_thread(load_fingerprints)
            if path:
                self.tech = await asyncio.to_thread(TechDetector, path)
                log(f"Technologie-Fingerprints: {len(self.tech)} Muster")
        for d in self.domains:
            self.add_host(d, "eingabe")
        for n in self.overrides:
            self.add_host(n, "eingabe", foreign_ok=True)
        net_ips = self.net_addresses()
        for ip in net_ips:
            self.ipinfo(ip)

        # Phase 1: Namen sammeln (parallel)
        tasks = [self.ptr_lookup(net_ips)]
        if self.domains:
            tasks += [self.collect_passive(), self.collect_dns(), self.bruteforce()]
        await asyncio.gather(*tasks)

        for rnd in range(1, MAX_ROUNDS + 1):
            # Phase 2: neue Namen auflösen
            n = await self.resolve_pending()
            log(f"Runde {rnd}: {n} Hostnamen aufgelöst")
            by_ip = {}
            for h in self.live_hosts():
                for ip in h["a"] + h["aaaa"]:
                    by_ip.setdefault(ip, set()).add(h["name"])
                    self.ipinfo(ip)["hostnames"].add(h["name"])

            # Phase 3: Ports – eigene Netze voll, fremde IPs nur 80/443
            # PTR auch für eigene Adressen, die erst jetzt bekannt wurden (z. B. IPv6)
            await self.ptr_lookup([ip for ip in by_ip if self.in_net(ip) and ip not in self.ptr_done])
            targets = {ip: self.ports if self.in_net(ip) else EXTERNAL_PORTS for ip in set(net_ips) | set(by_ip)}
            await self.port_scan(targets)

            # Phase 4: HTTP – jeder offene Port als IP-Default (nur eigene Netze) und je Hostname
            pairs = [(ip, p) for ip, ps in self.open_ports.items() for p in ps]
            await asyncio.gather(*[self.detect_scheme(ip, p) for ip, p in pairs])
            jobs = [(ip, p, None) for ip, p in pairs if self.in_net(ip)]
            jobs += [(ip, p, name) for ip, p in pairs for name in by_ip.get(ip, ())]
            jobs = [j for j in jobs if (j[0], j[1], j[2] or "") not in self.probed]
            random.shuffle(jobs)
            before = len(self.hosts)
            log(f"Runde {rnd}: {len(jobs)} HTTP-Abrufe …")
            await asyncio.gather(*[self.probe(*j) for j in jobs])
            await self.check_blocked(f"HTTP-Abrufe Runde {rnd}")
            if len(self.hosts) == before:
                break      # keine neuen Namen aus Zertifikaten/Redirects
        self.analyse()

    def analyse(self):
        """Auffälligkeiten aus den Ergebnissen ableiten. Gleiche Befunde (gleiche Art und
        Beschreibung, bzw. dasselbe Zertifikat) werden zu einem Eintrag zusammengefasst."""
        defaults = {(r["ip"], r["port"]): (r.get("status"), r.get("body_hash"))
                    for r in self.services if not r["hostname"]}
        now = time.time()
        for r in self.services:
            host = r["hostname"] or r["ip"]      # für Zertifikats-Befunde
            url, status, tls = r["url"], r.get("status"), r.get("scheme") == "https"
            if r["hostname"] and r.get("body_hash") and defaults.get((r["ip"], r["port"])) == \
                    (status, r.get("body_hash")):
                r["notes"] = "gleiche Antwort wie ohne Hostname"
            if r.get("scheme") == "http" and status == 200:
                self.finding("HTTP ohne Umleitung", url, "unverschlüsselt, keine Weiterleitung auf HTTPS")
            # Umleitung von HTTPS auf HTTP (erster Schritt oder Ziel der Kette)
            if tls:
                first = urllib.parse.urljoin(url, r.get("location") or "")
                if (r.get("location") and first.startswith("http://")) or \
                        str(r.get("final_url", "")).startswith("http://"):
                    target = first if first.startswith("http://") else r["final_url"]
                    self.finding("Umleitung von HTTPS auf HTTP", url, f"leitet auf {target} um")
            # Zertifikate: gruppiert je Zertifikat, damit ein gemeinsames Zertifikat nur einmal erscheint
            if r.get("cert_not_after"):
                cert = f"{r.get('cert_cn', '')} (gültig bis {r['cert_not_after']})"
                try:
                    days = (ssl.cert_time_to_seconds(r["cert_not_after"]) - now) / 86400
                except ValueError:
                    days = None
                if days is not None and days < 0:
                    self.finding("Zertifikat abgelaufen", host, cert, cert)
                elif days is not None and days < CERT_WARN_DAYS:
                    self.finding("Zertifikat läuft bald ab", host, f"{cert}, noch {int(days)} Tage", cert)
            if str(r.get("cert_valid", "")).startswith("nein"):
                self.finding("Zertifikat ungültig", url, r["cert_valid"][6:])
            if tls and r["hostname"] and r.get("cert_valid") == "ja" and isinstance(status, int) \
                    and 200 <= status < 400 and not r.get("hsts"):
                self.finding("HTTPS ohne HSTS", url, "kein Strict-Transport-Security-Header")
            if r.get("tls_version") in ("SSLv3", "TLSv1", "TLSv1.1"):
                self.finding("Veraltetes TLS", url, r["tls_version"])
            if r.get("error_details"):
                self.finding("Fehlerseite mit technischen Details", url,
                             f"enthält „{r['error_details']}“ – kann Pfade, Versionen oder Code verraten")
            text = f"{r.get('title', '')} {r.get('final_title', '')} {r.get('tech', '')}".strip()
            if (status in (200, 401, 403) or r.get("final_status") == 200) and SENSITIVE.search(text):
                self.finding("Sensible Oberfläche?", url, text[:120])

    # ---------------------------------------------------------- Ausgabe
    def write(self, prefix):
        cols = ["url", "scheme", "hostname", "ip", "port", "in_own_net", "status", "title", "tech",
                "server", "final_url", "final_status", "final_title", "location", "content_type",
                "length", "response_ms", "body_hash", "hsts", "tls_version", "tls_cipher", "cert_cn",
                "cert_issuer", "cert_not_after", "cert_valid", "cert_sans", "error_details", "cname", "ptr",
                "foreign_name", "notes"]
        rows = sorted(self.services, key=lambda r: (ip_sort_key(r["ip"]), r["port"], r["hostname"]))
        with open(f"{prefix}_services.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore", delimiter=";")
            w.writeheader()
            w.writerows(rows)

        hosts = sorted((h for h in self.hosts.values() if h["status"] not in ("out-of-scope", "wildcard")),
                       key=lambda h: h["name"].split(".")[::-1])
        csv_hosts = [h for h in hosts if h["status"] != "nxdomain"]   # vollständig nur im JSON
        with open(f"{prefix}_hosts.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["hostname", "status", "a", "aaaa", "cname", "in_own_net", "foreign_name", "sources"])
            for h in csv_hosts:
                addrs = h["a"] + h["aaaa"]
                w.writerow([h["name"], h["status"], " ".join(h["a"]), " ".join(h["aaaa"]),
                            " -> ".join(h["cname"]),
                            ("ja" if any(map(self.in_net, addrs)) else "nein") if addrs else "",
                            "ja" if h["net_only"] else "", " ".join(sorted(h["sources"]))])

        ips = sorted((i for i in self.ips.values() if self.open_ports.get(i["ip"]) or i["hostnames"]),
                     key=lambda i: ip_sort_key(i["ip"]))
        with open(f"{prefix}_ips.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["ip", "in_own_net", "ptr", "open_ports", "hostnames", "blocked"])
            for i in ips:
                w.writerow([i["ip"], "ja" if i["in_net"] else "nein", i["ptr"],
                            " ".join(map(str, sorted(self.open_ports.get(i["ip"], [])))),
                            " ".join(sorted(i["hostnames"])), self.blocked.get(i["ip"], "")])

        with open(f"{prefix}.json", "w", encoding="utf-8") as f:
            json.dump({"generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "version": VERSION,
                       "scope": {"domains": self.domains, "nets": [str(n) for n in self.nets]},
                       "load": {**self.stats, "dns_queries": self.dns.queries,
                                "dns_retries": self.dns.retries,
                                "dns_throttled_servers": sorted(self.dns.throttled)},
                       "sources": self.source_stats, "findings": list(self.findings.values()),
                       "services": rows,
                       "hosts": [{**h, "sources": sorted(h["sources"])} for h in hosts],
                       "ips": [{**i, "hostnames": sorted(i["hostnames"]),
                                "open_ports": sorted(self.open_ports.get(i["ip"], []))} for i in ips]},
                      f, indent=2, ensure_ascii=False)

    def summary(self):
        web = {}
        for r in self.services:
            if r.get("status"):
                web.setdefault(r["url"], r)
        print("\n=== Ergebnis ===")
        print(f"Hostnamen:          {len(self.live_hosts())} aufgelöst "
              f"(davon fremde Namen in euren Netzen: {sum(h['net_only'] for h in self.live_hosts())})")
        failed = [s for s, v in self.source_stats.items() if v["error"] and not v["names"]]
        if failed:
            print(f"  nicht erreichbar:  {', '.join(failed)}")
        cut = [s for s, v in self.source_stats.items() if v.get("timeout")]
        if cut:
            print(f"  nach {SOURCE_TIMEOUT}s abgebrochen (Teilergebnis): {', '.join(cut)}")
        ranked = sorted(((v["names"], v["exclusive"], s) for s, v in self.source_stats.items() if v["names"]),
                        reverse=True)
        if ranked:
            print("  Namen je Quelle (davon nur dort): "
                  + ", ".join(f"{s} {n} ({x})" for n, x, s in ranked))
        print(f"Offene Ports:       {sum(map(len, self.open_ports.values()))} auf {len(self.open_ports)} IPs")
        print(f"Webdienste (URLs):  {len(web)}")
        for url in sorted(web)[:60]:
            r = web[url]
            info = r.get("title") or (f"-> {r['final_url']}" if r.get("final_url") else "")
            print(f"  {r['status']:>3}  {url:<50} {info[:40]:<40} {r.get('tech', '')[:45]}")
        if len(web) > 60:
            print(f"  … {len(web) - 60} weitere, siehe CSV")
        busiest = max(self.conn_per_ip.items(), key=lambda x: x[1], default=("-", 0))
        print(f"\nLast auf euren Systemen: {self.stats['tcp']} TCP-Verbindungen, {self.stats['http']} "
              f"HTTP-Anfragen, max. {busiest[1]} Verbindungen auf eine IP ({busiest[0]})")
        if self.blocked:
            print(f"\n!!! {len(self.blocked)} IP(s) haben den Scanner offenbar gesperrt, Ergebnisse "
                  f"unvollständig: {', '.join(sorted(self.blocked))}\n    -> Scanner-IP freischalten "
                  "(fail2ban ignoreip, IPS-/WAF-Ausnahme) oder mit --profil schonend nur diese IPs "
                  "erneut prüfen (-n IP).")
        if self.findings:
            print(f"\nAuffälligkeiten ({len(self.findings)}):")
            for fd in self.findings.values():
                t = fd["targets"]
                more = f" … und {len(t) - 5} weitere (siehe JSON)" if len(t) > 5 else ""
                print(f"  [{fd['type']}] {fd['detail']}\n      {', '.join(t[:5])}{more}")


def dechunk(body):
    """HTTP 'Transfer-Encoding: chunked' zusammensetzen (so weit gelesen)."""
    out, i = b"", 0
    try:
        while i < len(body):
            j = body.index(b"\r\n", i)
            size = int(body[i:j].split(b";")[0], 16)
            if size == 0:
                break
            out += body[j + 2:j + 2 + size]
            i = j + 4 + size
        return out
    except (ValueError, IndexError):
        return out or body


# ============================================================== Kommandozeile

def main():
    p = argparse.ArgumentParser(
        description="Inventar öffentlich erreichbarer Webdienste für eigene Netze und Domains.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Beispiele:\n"
               "  python3 webinventar.py -d firma.de firma.com -n 203.0.113.0/24\n"
               "  python3 webinventar.py -d domains.txt -n netze.txt -p web,top1000 --profil schonend")
    p.add_argument("-d", "--domains", nargs="+", default=[], metavar="DOMAIN",
                   help="Domains inkl. aller Subdomains, oder Datei mit einer Domain pro Zeile")
    p.add_argument("-n", "--nets", nargs="+", default=[], metavar="NETZ",
                   help="Netzbereiche/IPs (z. B. 203.0.113.0/24), oder Datei mit einem Netz pro Zeile")
    p.add_argument("-p", "--ports", default="web",
                   help="Ports für eure Netze: web (Standard), top100, top1000, all oder Liste, "
                        "kombinierbar, z. B. web,top1000,9999")
    p.add_argument("--profil", choices=PROFILES, default="normal",
                   help="Last: schonend (20 Verb./s, 1 je Host), normal (100/s, 4 je Host), schnell")
    p.add_argument("-w", "--wordlist", help="zusätzliche Subdomain-Wortliste")
    p.add_argument("-o", "--out", default="webinventar", help="Präfix der Ausgabedateien")
    p.add_argument("--no-tech", action="store_true",
                   help="ohne Technologie-Erkennung (lädt dann nichts von GitHub)")
    # Für Tests: eigene Root-Server und feste Zuordnungen, in der Hilfe ausgeblendet
    p.add_argument("--root-servers", help=argparse.SUPPRESS)
    p.add_argument("--resolve", action="append", default=[], help=argparse.SUPPRESS)
    a = p.parse_args()

    domains, nets = read_args(a.domains), read_args(a.nets)
    if not domains and not nets:
        p.error("mindestens eine Domain (-d) oder ein Netz (-n) angeben")
    try:
        parsed = [ipaddress.ip_network(n, strict=False) for n in nets]
    except ValueError as e:
        p.error(f"ungültiges Netz: {e}")
    total = sum(n.num_addresses for n in parsed if n.version == 4 or n.prefixlen >= 112)
    if total > MAX_ADDRESSES:
        p.error(f"{total} Adressen sind zu viele für einen Lauf – bitte in Teilbereiche aufteilen "
                "oder die Ports vorher mit masscan/naabu ermitteln.")
    ports = parse_ports(a.ports)
    overrides = {}
    for spec in a.resolve:
        name, ip = spec.split(":", 1)
        overrides.setdefault(norm_name(name), []).append(ip)
    roots = a.root_servers.split(",") if a.root_servers else None

    cfg = PROFILES[a.profil]
    attempts = total * len(ports)
    if cfg["rate"] and attempts / cfg["rate"] > 600:
        log(f"Hinweis: {attempts:,} Verbindungsversuche – bei Profil '{a.profil}' mindestens "
            f"{attempts / cfg['rate'] / 60:.0f} Minuten.")

    inv = Inventory(domains, nets, ports, a.profil, a.wordlist, not a.no_tech, roots, overrides)
    t0 = time.time()
    try:
        asyncio.run(inv.run())
    except KeyboardInterrupt:
        log("Abgebrochen – schreibe bisherige Ergebnisse.")
        inv.analyse()
    inv.write(a.out)
    inv.summary()
    print(f"\nDateien: {a.out}_services.csv, {a.out}_hosts.csv, {a.out}_ips.csv, {a.out}.json "
          f"(Laufzeit {time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()
