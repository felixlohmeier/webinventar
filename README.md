# webinventar

Ermittelt alle öffentlich erreichbaren Webdienste der eigenen Netzbereiche und Domains. Das Ergebnis sind CSV-Dateien, in denen jede gefundene URL mit Titel, Technologie, Zertifikat und Auffälligkeiten steht.

Das Tool ist ein einzelnes Python-Skript ohne Abhängigkeiten außer der Standardbibliothek. Externe Dienste erfahren bei einem Scan nichts Neues über das untersuchte Netz.

> **Hinweis:** Das Tool nur gegen Netze und Domains einsetzen, für die eine Berechtigung vorliegt. Den Scan vorab beim zuständigen Firewall- oder Sicherheitsteam ankündigen.

## Datenschutz: Wer erfährt was?

| Gegenstelle | Was sie erhält | Warum das unkritisch ist |
|---|---|---|
| DNS-Root- und TLD-Server (z. B. `.de`) | nur den Zonennamen, z. B. `example.de` | Durch QNAME-Minimierung (RFC 9156) bekommen sie nie den vollständigen Hostnamen zu sehen, auch nicht bei nicht existierenden Namen. |
| Die autoritativen Nameserver der eigenen Domains (bzw. der DNS-Provider) | alle Namensabfragen, auch die geratenen | Sie verwalten die Zone ohnehin. |
| Die Nameserver der eigenen Reverse-Zonen (meist der Netzbetreiber selbst oder dessen Provider) | Rückwärtsabfragen der IP-Adressen | Sie verwalten diese Zonen ohnehin. |
| Nameserver von Hostern, auf die CNAME-Einträge zeigen | nur deren eigene Namen, auf die die CNAMEs zeigen | Das ist die normale Abfrage, die jeder Besucher der Seite auch auslöst. |
| 19 öffentliche Quellen (siehe unten) | nur den Domainnamen | Die Domain ist ohnehin öffentlich bekannt. IP-Adressen und Netze werden nicht übertragen. |
| GitHub | Abruf der Technologie-Muster (wöchentlich) | Enthält keinen Bezug zum untersuchten Netz. Mit `--no-tech` abschaltbar. |
| Die untersuchten Server | die eigentlichen Port- und HTTP-Prüfungen | Das ist der Zweck des Tools. |

Bewusst **nicht** verwendet:

- **Öffentliche DNS-Resolver** wie Google, Cloudflare oder Quad9. Sie würden jeden geratenen Namen sehen, und solche Namen landen oft in Passive-DNS-Datenbanken.
- **Dienste, die IP-Adressen entgegennehmen**, etwa Shodan InternetDB oder ASN-Abfragen.
- **Quellen, die eine Anmeldung oder einen API-Schlüssel erfordern.**

Ob einzelne Quellen die angefragten Domainnamen speichern, anzeigen oder daraufhin selbst untersuchen, ist nicht bekannt. Übertragen wird in jedem Fall nur der Domainname.

### Passive Quellen

Alle Quellen werden parallel abgefragt, jede höchstens 60 Sekunden lang. Was eine Quelle bis dahin geliefert hat, wird ausgewertet. In der Zusammenfassung steht, welche Quellen nicht erreichbar waren, welche abgebrochen wurden und wie viele neue Namen jede beigetragen hat.

| Art | Quellen |
|---|---|
| Certificate Transparency | crt.sh, Certspotter, Shodan CT (ctl.shodan.io), crt.name, certificatedetails.com |
| Web-Archive | Internet Archive (Wayback Machine), Common Crawl |
| Subdomain- und DNS-Datenbanken | HackerTarget, Anubis, ThreatMiner, Riddler, recon.cloud, Reconeer, subdomain.center, sub.md, ScanMalware, THC (ip.thc.org), RapidDNS, Sitedossier |

Die Endpunkte entsprechen denen von [subfinder](https://github.com/projectdiscovery/subfinder). Kleinere Dienste sind gelegentlich nicht erreichbar oder begrenzen die Zahl der kostenlosen Abfragen pro Tag. Das schadet dem Lauf nicht, es fehlen dann nur deren Beiträge.

## Voraussetzungen

- Python 3.9 oder neuer, keine weiteren Pakete
- **Ausgehender Zugriff auf Port 53 (UDP und TCP) ins Internet.** Das Skript löst Namen selbst auf, angefangen bei den Root-Servern. Ist das gesperrt, bricht es mit einer Meldung ab.
- Für ein realistisches Ergebnis das Skript von **außerhalb** des untersuchten Netzes ausführen, etwa von einem kleinen Cloud-Server. Ein Scan von innen zeigt auch Dienste, die die Firewall nach außen gar nicht freigibt.

## Installation

```bash
git clone https://github.com/felixlohmeier/webinventar.git
cd webinventar
```

Alternativ genügt es, die einzelne Datei `webinventar.py` herunterzuladen.

## Nutzung

```bash
python3 webinventar.py -d example.de example.com -n 203.0.113.0/24 198.51.100.0/26
python3 webinventar.py -d domains.txt -n netze.txt -p web,top1000 --profil schonend -o inventar
```

| Parameter | Bedeutung | Standard |
|---|---|---|
| `-d` | Domains, jeweils mit allen Subdomains. Alternativ eine Datei mit einer Domain pro Zeile. | – |
| `-n` | Netzbereiche oder einzelne IP-Adressen. Alternativ eine Datei mit einem Netz pro Zeile. | – |
| `-p` | Ports, die in den angegebenen Netzen geprüft werden: `web` (~100 Web-Ports), `top100`, `top1000`, `all` oder eine Liste wie `8000-8100,9443`. Kombinierbar, z. B. `web,top1000`. | `web` |
| `--profil` | Wie stark das Tool die untersuchten Systeme belastet: `schonend`, `normal` oder `schnell` (siehe unten) | `normal` |
| `-w` | zusätzliche Subdomain-Wortliste | – |
| `-o` | Präfix der Ausgabedateien | `webinventar` |
| `--no-tech` | ohne Technologie-Erkennung | – |

Mindestens `-d` oder `-n` muss angegeben sein. In Dateien werden Leerzeilen und alles nach `#` ignoriert. Ein Lauf ist auf 65.536 Adressen begrenzt, also ein /16. Größere Bereiche bitte aufteilen.

## Ablauf

1. **Hostnamen sammeln**
   - 19 passive Quellen: Certificate-Transparency-Logs, Web-Archive und Subdomain-Datenbanken (siehe oben)
   - DNS-Einträge: NS, MX, SOA, SPF und gängige SRV-Einträge
   - Versuch eines Zonentransfers (AXFR)
   - eingebaute Wortliste mit rund 260 Namen
   - Rückwärtsauflösung (PTR) aller IP-Adressen der angegebenen Netze
2. **Auflösen**
   - Namen in IP-Adressen auflösen, Wildcard-DNS auf jeder Ebene erkennen.
   - Verwaiste CNAMEs melden, also Einträge, deren Ziel nicht mehr existiert.
   - Fremde Namen, etwa aus der Rückwärtsauflösung oder aus Zertifikaten, nur behalten, wenn sie in die angegebenen Netze zeigen. Typisch sind Kundenseiten auf einem eigenen Webserver.
3. **Portscan**
   - Angegebene Netze: die mit `-p` gewählte Portliste.
   - Fremde IP-Adressen, auf die die Hostnamen zeigen (Hoster, SaaS, CDN): nur 80 und 443.
4. **HTTP-Abruf**
   - Jeder offene Port wird ohne Hostnamen und zusätzlich mit jedem passenden Hostnamen abgerufen (Host-Header und SNI). So werden auch Webseiten gefunden, die nur über ihren Namen erreichbar sind.
   - Weiterleitungen werden verfolgt, solange sie zu den angegebenen Domains oder Netzen führen.
   - Technologie-Erkennung mit den Wappalyzer-Mustern von ProjectDiscovery.
   - Hostnamen der angegebenen Domains, die in Seiteninhalt oder Headern der abgerufenen Antworten vorkommen, werden gesammelt. Das sind z. B. Links, Skript-Adressen, eingebettetes JSON oder die Content-Security-Policy. Dafür sind keine zusätzlichen Anfragen nötig. Fremde Namen wie Google Fonts oder Analytics werden ignoriert und auch nicht aufgelöst.
5. **Wiederholen**: Neue Namen aus Zertifikaten, Weiterleitungen und Seiteninhalten starten eine weitere Runde, höchstens 5.

## Ausgaben

| Datei | Inhalt |
|---|---|
| `*_services.csv` | eine Zeile je Webdienst (URL) bzw. offenem Port ohne HTTP |
| `*_hosts.csv` | alle gefundenen Hostnamen mit Status, IP-Adressen, CNAME-Kette und Fundquelle (z. B. `crt.sh`, `wortliste`, `zertifikat`, `http-inhalt`) |
| `*_ips.csv` | je IP-Adresse: PTR-Eintrag, offene Ports, Hostnamen und Sperrhinweis |
| `*.json` | alles zusammen, dazu Statistik und Auffälligkeiten |

Die CSV-Dateien nutzen `;` als Trennzeichen und lassen sich direkt in Excel öffnen.

Wichtige Spalten in `*_services.csv`:

- `url`, `status`, `title`, `server`
- `tech`: erkannte Technologien mit Version, soweit ermittelbar
- `final_url`, `final_status`, `final_title`: wohin eine Weiterleitung führt
- `cert_*`: Aussteller, Ablaufdatum, enthaltene Namen (SANs); `cert_valid` gibt an, ob das Zertifikat für diesen Hostnamen gültig ist
- `foreign_name = ja`: fremder Hostname, der in eines der angegebenen Netze zeigt
- `notes`:
  - „gleiche Antwort wie ohne Hostname“: Der Server liefert für diesen Namen keine eigene Seite, sondern seine Standardseite.
  - „Port offen, kein HTTP“

### Auffälligkeiten (am Ende der Ausgabe und in der JSON-Datei)

- Zonentransfer möglich
- verwaister CNAME, also Gefahr einer Subdomain-Übernahme
- HTTP ohne Weiterleitung auf HTTPS
- Umleitung von HTTPS auf HTTP
- HTTPS ohne HSTS (nur bei gültigem Zertifikat)
- Zertifikat abgelaufen, ungültig oder läuft in weniger als 30 Tagen ab
- veraltetes TLS (1.0 oder 1.1)
- mögliche sensible Oberflächen, z. B. Login- und Admin-Seiten, VPN-Portale, Jenkins, phpMyAdmin, Swagger UI
- Scanner vermutlich gesperrt (siehe unten)

Gleiche Befunde werden zu einem Eintrag mit allen betroffenen Adressen zusammengefasst. Ein Zertifikat, das für viele Hostnamen gilt, erscheint also nur einmal. In der JSON-Datei steht die vollständige Liste unter `targets`.

## Last und Sperren

| Profil | Verbindungen/s | gleichzeitig je IP | Dauer pro /24 mit `-p web` (ca.) |
|---|---|---|---|
| `schonend` | 20 | 1 | 20–35 min |
| `normal` | 100 | 4 | 5 min |
| `schnell` | unbegrenzt | 50 | 2 min |

Dazu kommen pro Lauf etwa 2–4 Minuten für passive Quellen (höchstens 60 Sekunden, parallel zur DNS-Phase), DNS und HTTP-Abrufe. DNS-Anfragen werden auf 20 pro Sekunde je Nameserver begrenzt, damit dessen Rate Limiting nicht greift. Bleibt eine Antwort trotzdem aus, wiederholt das Tool die Anfrage nach einer kurzen Pause. Namen, die danach noch ohne Antwort sind, versucht es nach 10 Sekunden ein weiteres Mal. In der JSON-Datei stehen unter `load` die Zahl der DNS-Anfragen und der Wiederholungen. Je Hostname sendet das Tool nur `GET /`, ohne Pfade durchzuprobieren oder Logins zu versuchen. Am Ende zeigt es, wie viele Verbindungen es auf den untersuchten Systemen erzeugt hat.

**Sperr-Erkennung:** Das Tool merkt sich pro IP-Adresse einen Port, der nachweislich offen war. Nach dem Portscan und nach jeder Runde HTTP-Abrufe prüft es diesen Port erneut. Antwortet er nicht mehr, hat vermutlich fail2ban, ein IPS oder eine WAF den Scanner gesperrt. Dann warnt das Tool und markiert die Ergebnisse dieser IP-Adresse als unvollständig.

Empfehlung: Die IP-Adresse des Scan-Rechners in fail2ban (`ignoreip`), im IPS und in der WAF als Ausnahme eintragen. Alternativ betroffene IP-Adressen einzeln mit `--profil schonend -n <IP>` erneut prüfen.

## Grenzen

- **Ports:** Es wird nur die gewählte Portliste geprüft. Mit `-p all` sind alle Ports abgedeckt, das dauert aber sehr lange. Für große Netze besser vorher masscan oder naabu laufen lassen und die offenen Ports mit `-p` übergeben.
- **Archive:** Hostnamen, die in keinem Zertifikat, keinem Archiv, keiner Wortliste und keinem DNS-Eintrag vorkommen, findet das Tool nur, wenn sie in die angegebenen Netze zeigen oder auf einer gefundenen Seite verlinkt sind. Verlinkte JavaScript-Dateien werden dabei nicht zusätzlich abgerufen. Gegenüber Tools wie subfinder fehlen die Quellen, die einen API-Schlüssel erfordern.
- **IPv6:** Netze größer als /112 werden nicht vollständig durchsucht. Geprüft werden nur IPv6-Adressen, auf die ein DNS-Name zeigt.
- **Technologie-Erkennung:** Erkannt wird, was sich aus Headern und HTML ablesen lässt. Was erst durch JavaScript im Browser sichtbar wird, fehlt.
- **Gesperrte Abfragen:** Antworten einzelne Archive nicht, etwa weil crt.sh ausgelastet ist, steht das in der Zusammenfassung unter „nicht erreichbar“. Dann den Lauf später wiederholen.

## Regelmäßig ausführen

Wird der Lauf z. B. wöchentlich gestartet und die `*_services.csv` jeweils mit dem Vorlauf verglichen, fallen neue oder vergessene Dienste schnell auf:

```bash
python3 webinventar.py -d domains.txt -n netze.txt -o inventar_$(date +%F)
```
