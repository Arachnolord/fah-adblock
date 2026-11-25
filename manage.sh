#!/bin/sh
# ============================================================================
# Erdacht und programmiert von Fabian Hammer.
# (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
# Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
# schriftliche Genehmigung des Urhebers ist untersagt.
# ============================================================================
#
# manage.sh – FAH-Adblock Verwaltung (kein 'unzip' noetig, python3 genuegt)
#
#   ./manage.sh install           – Installation aus dem Git-Repo (git clone): legt .env + docker-compose.yml an,
#                                   traegt beim ersten Mal IP, Gateway und eigenes Netz selbst ein, baut und startet.
#                                   Spaeter nach 'git pull' erneut aufrufen = Update (data/ und .env bleiben).
#                                   Vorgaben moeglich: DNS_BIND=… GATEWAY=… ERLAUBTE_NETZE=… ./manage.sh install
#   ./manage.sh update            – Update aus fah-adblock_release.zip (hoechste (N) gewinnt)
#   ./manage.sh update <zip>      – Update aus bestimmter ZIP
#   ./manage.sh update --no-cache – Update mit vollstaendigem Neubau
#   ./manage.sh start|stop|restart|status|logs|url
#   ./manage.sh port [<PORT>]     – WebGUI-Port anzeigen/aendern
#   ./manage.sh test              – DNS-Probe gegen den laufenden Dienst
#
# Prinzip:
#   Code (src/, public/, tools/, Dockerfile) -> bei jedem Update ersetzt.
#   .env, docker-compose.yml                 -> nie aus der ZIP, nur einmal aus *.example.
#   ./data                                   -> Nutzerdaten (Einstellungen, Listen, Protokoll), nie angefasst.
#   WebGUI-Port                              -> Erstinstallation: freier Port per Bind-Test (Host-Netz),
#                                               danach fix (.adblock_ports.lock).
#   DNS-Port 53                              -> kann nicht ausweichen: belegt ein fremder Dienst
#                                               DNS_BIND:53, bricht der Start mit Hinweis ab.

set -e
export DOCKER_BUILDKIT=1
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZIP_NAME="fah-adblock_release.zip"
ENV_FILE="$SCRIPT_DIR/.env"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
LOCK_FILE="$SCRIPT_DIR/.adblock_ports.lock"
CONTAINER="fah-adblock"
NO_CACHE="${NO_CACHE:-0}"

detect_compose() {
    if docker compose version >/dev/null 2>&1; then DC="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
    else echo "Fehler: weder 'docker compose' noch 'docker-compose' gefunden."; exit 1; fi
}

env_wert() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d ' \r'; }
laeuft() { docker ps --filter "name=^${CONTAINER}\$" --filter status=running -q 2>/dev/null | grep -q .; }

# Neueste Release-ZIP: "fah-adblock_release (3).zip" schlaegt "(2)" und die ohne Nummer, dann juengste Zeit
find_latest_zip() {
    python3 - "$SCRIPT_DIR" "$ZIP_NAME" <<'PYEOF'
import os, re, sys
d, name = sys.argv[1], sys.argv[2]
stamm, endung = os.path.splitext(name)
muster = re.compile(r'^' + re.escape(stamm) + r'(?: \((\d+)\))?' + re.escape(endung) + r'$')
kandidaten = []
for f in os.listdir(d):
    m = muster.match(f)
    if m: kandidaten.append((int(m.group(1) or 0), os.path.getmtime(os.path.join(d, f)), f))
if kandidaten: print(os.path.join(d, sorted(kandidaten)[-1][2]))
PYEOF
}

# Freier WebGUI-Port (Host-Netz: echter Bind-Test auf 0.0.0.0); nur Erstinstallation oder wenn der Dienst steht
ensure_web_port() {
    [ -f "$ENV_FILE" ] || return 0
    if [ -f "$LOCK_FILE" ] && laeuft; then return 0; fi
    python3 - "$ENV_FILE" <<'PYEOF'
import re, socket, sys
env = sys.argv[1]
text = open(env, encoding='utf-8').read()
m = re.search(r'^WEB_PORT=(\d+)', text, re.M)
start = int(m.group(1)) if m else 8053
def frei(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: s.bind(('0.0.0.0', p)); return True
    except OSError: return False
    finally: s.close()
port = start
while not frei(port): port += 1
if port != start: print(f"  [PORTS] WEB_PORT {start} belegt -> {port}")
else: print(f"  [PORTS] WEB_PORT {port} frei")
if m: text = re.sub(r'^WEB_PORT=\d+', f'WEB_PORT={port}', text, flags=re.M)
else: text += f"\nWEB_PORT={port}\n"
open(env, 'w', encoding='utf-8').write(text)
PYEOF
    touch "$LOCK_FILE"
}

# DNS-Port muss frei sein (oder uns selbst gehoeren)
check_dns_port() {
    BIND="$(env_wert DNS_BIND)"; PORT="$(env_wert DNS_PORT)"; [ -n "$PORT" ] || PORT=53
    if [ -z "$BIND" ]; then echo "Fehler: DNS_BIND fehlt in .env (IP des NAS, z. B. 192.168.1.23)."; exit 1; fi
    if laeuft; then return 0; fi
    BELEGT="$( (ss -lun 2>/dev/null; ss -ltn 2>/dev/null) | awk '{print $4}' | grep -E "^(${BIND}|0\.0\.0\.0|\*|\[::\]):${PORT}\$" | head -1 || true)"
    if [ -n "$BELEGT" ]; then
        echo "Fehler: ${BIND}:${PORT} ist bereits belegt ($BELEGT) – ein anderer DNS-Dienst laeuft dort."
        (ss -lunp 2>/dev/null; ss -ltnp 2>/dev/null) | grep -E ":${PORT}\b" || true
        exit 1
    fi
}

compose_up() {
    cd "$SCRIPT_DIR"
    ensure_web_port
    check_dns_port
    if [ "${FORCE_RECREATE:-0}" = "1" ]; then $DC up -d --force-recreate; else $DC up -d; fi
}

# Frisch angelegte .env: eigene Adresse, Gateway und Netz eintragen (Vorgaben aus der Umgebung haben Vorrang).
# Eine vorhandene .env wird NIE angefasst.
env_einrichten() {
    WEG="$(ip -4 route get 1.1.1.1 2>/dev/null | head -1 || true)"
    IP="${DNS_BIND:-$(echo "$WEG" | sed -n 's/.* src \([0-9.]*\).*/\1/p')}"
    GW="${GATEWAY:-$(echo "$WEG" | sed -n 's/.* via \([0-9.]*\).*/\1/p')}"
    DEV="$(echo "$WEG" | sed -n 's/.* dev \([^ ]*\).*/\1/p')"
    CIDR=""
    if [ -n "$DEV" ] && [ -n "$IP" ]; then
        CIDR="$(ip -4 -o addr show dev "$DEV" 2>/dev/null | awk -v ip="$IP" '{ split($4, a, "/"); if (a[1] == ip) print $4 }' | head -1 || true)"
    fi
    python3 - "$ENV_FILE" "$IP" "$GW" "$CIDR" "${ERLAUBTE_NETZE:-}" <<'PYEOF'
import ipaddress, re, sys
env, ip, gw, cidr, netze = sys.argv[1:6]
try:
    ipaddress.IPv4Address(ip)
except ValueError:
    print("  [ENV] Eigene IP-Adresse nicht ermittelbar."); sys.exit(2)
if not netze:
    try: netz = ipaddress.ip_interface(cidr).network if cidr else ipaddress.ip_network(ip + '/24', strict=False)
    except ValueError: netz = ipaddress.ip_network(ip + '/24', strict=False)
    netze = f"{netz},127.0.0.1/32"
werte = {'DNS_BIND': ip, 'ERLAUBTE_NETZE': netze}
if gw:
    try: ipaddress.IPv4Address(gw); werte['GATEWAY'] = gw
    except ValueError: pass
text = open(env, encoding='utf-8').read()
for k, v in werte.items():
    if re.search(rf'^{k}=', text, re.M): text = re.sub(rf'^{k}=.*$', f'{k}={v}', text, flags=re.M)
    else: text += f"\n{k}={v}\n"
open(env, 'w', encoding='utf-8').write(text)
for k in ('DNS_BIND', 'GATEWAY', 'ERLAUBTE_NETZE'):
    if k in werte: print(f"  [ENV] {k}={werte[k]}")
if 'GATEWAY' not in werte: print("  [ENV] GATEWAY nicht ermittelbar – Wert aus der Vorlage bleibt, bitte in .env pruefen.")
PYEOF
}

# .env + docker-compose.yml einmalig aus den Vorlagen, data/ anlegen
einrichten() {
    if [ ! -f "$ENV_FILE" ]; then
        cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"; echo "  [ENV] .env aus .env.example erzeugt."
        if ! env_einrichten; then
            echo "  Bitte DNS_BIND (IP dieses Rechners), GATEWAY (Router) und ERLAUBTE_NETZE in $ENV_FILE eintragen,"
            echo "  dann erneut aufrufen – oder vorgeben: DNS_BIND=<IP> ./manage.sh $CMD"
            exit 1
        fi
    fi
    [ -f "$COMPOSE_FILE" ] || { cp "$SCRIPT_DIR/docker-compose.yml.example" "$COMPOSE_FILE"; echo "  [COMPOSE] docker-compose.yml erzeugt."; }
    mkdir -p "$SCRIPT_DIR/data"
}

bauen_und_starten() {
    echo "=== Baue & starte Container ==="
    if [ "$NO_CACHE" = "1" ]; then $DC build --no-cache; else $DC build; fi
    FORCE_RECREATE=1 compose_up
}

# Installation/Update direkt aus dem Git-Repo (ohne Release-ZIP)
do_install() {
    detect_compose
    cd "$SCRIPT_DIR"
    if [ ! -f "$SCRIPT_DIR/Dockerfile" ] || [ ! -d "$SCRIPT_DIR/src" ]; then echo "Fehler: kein FAH-Adblock-Code in $SCRIPT_DIR (Dockerfile/src fehlen)."; exit 1; fi
    einrichten
    bauen_und_starten
    echo ""; warte_gesund; print_url
    echo "=== Installation abgeschlossen ==="
}

do_update() {
    ZIP="$1"; [ -n "$ZIP" ] || ZIP="$(find_latest_zip)"
    if [ -z "$ZIP" ] || [ ! -f "$ZIP" ]; then echo "Fehler: keine $ZIP_NAME gefunden (Ordner: $SCRIPT_DIR)."; exit 1; fi
    echo "=== Update aus: $ZIP ==="
    cd "$SCRIPT_DIR"; detect_compose

    # 1. manage.sh selbst aktualisieren und neu starten
    if [ -z "${ADBLOCK_SELFUPDATED:-}" ]; then
        python3 - "$ZIP" "$SCRIPT_DIR/manage.sh.new" <<'PYEOF'
import sys, zipfile
z, aus = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(z) as f:
    for n in f.namelist():
        if n.lstrip('/') == 'manage.sh':
            open(aus, 'wb').write(f.read(n)); break
PYEOF
        if [ -f "$SCRIPT_DIR/manage.sh.new" ] && ! cmp -s "$SCRIPT_DIR/manage.sh.new" "$SCRIPT_DIR/manage.sh"; then
            chmod +x "$SCRIPT_DIR/manage.sh.new"; mv "$SCRIPT_DIR/manage.sh.new" "$SCRIPT_DIR/manage.sh"
            echo "  [SELF-UPDATE] manage.sh aktualisiert – starte neu ..."
            export ADBLOCK_SELFUPDATED=1
            [ "$NO_CACHE" = "1" ] && exec "$SCRIPT_DIR/manage.sh" update --no-cache "$ZIP"
            exec "$SCRIPT_DIR/manage.sh" update "$ZIP"
        fi
        rm -f "$SCRIPT_DIR/manage.sh.new"
    fi

    # 2. Code entpacken (Konfiguration und data/ geschuetzt)
    python3 - "$ZIP" <<'PYEOF'
import os, sys, zipfile
geschuetzt = {'.env', 'docker-compose.yml', 'manage.sh'}
with zipfile.ZipFile(sys.argv[1]) as z:
    geschrieben = uebersprungen = 0
    for m in z.namelist():
        n = m.lstrip('/')
        if n.endswith('/') or '..' in n.split('/'): continue
        if n in geschuetzt or n.startswith('data/'): uebersprungen += 1; continue
        os.makedirs(os.path.dirname(n) or '.', exist_ok=True)
        with z.open(m) as q, open(n, 'wb') as a: a.write(q.read())
        geschrieben += 1
print(f"  [CODE] {geschrieben} Datei(en) aktualisiert, {uebersprungen} geschuetzt.")
PYEOF

    # 3. Konfiguration beim ersten Mal anlegen (IP/Gateway/Netz werden selbst ermittelt)
    einrichten

    # 4. Bauen und Container ersetzen
    bauen_und_starten

    # 5. aeltere Release-ZIPs wegraeumen (die eingespielte bleibt als Archiv)
    for alt in "$SCRIPT_DIR"/fah-adblock_release\ \(*\).zip; do if [ -f "$alt" ] && [ "$alt" != "$ZIP" ]; then rm -f "$alt"; fi; done
    echo ""; warte_gesund; print_url
    echo "=== Update abgeschlossen ==="
}

warte_gesund() {
    i=0
    while [ $i -lt 40 ]; do
        S="$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo unbekannt)"
        [ "$S" = "healthy" ] && { echo "  [GESUND] DNS und Weboberflaeche antworten."; return 0; }
        i=$((i + 1)); sleep 2
    done
    echo "  [WARNUNG] Container meldet noch nicht 'healthy' – ./manage.sh logs"
}

print_url() {
    P="$(env_wert WEB_PORT)"; [ -n "$P" ] || P=8053
    B="$(env_wert DNS_BIND)"
    echo "  Weboberflaeche: http://${B:-<NAS-IP>}:$P   (Erstanmeldung admin / admin)"
    echo "  DNS-Server:     ${B:-<NAS-IP>}:$(env_wert DNS_PORT | sed 's/^$/53/')"
}

CMD="${1:-}"
case "$CMD" in
    install) shift; for a in "$@"; do case "$a" in --no-cache) NO_CACHE=1 ;; esac; done; do_install ;;
    update) shift; ZIP=""; for a in "$@"; do case "$a" in --no-cache) NO_CACHE=1 ;; *) ZIP="$a" ;; esac; done; do_update "$ZIP" ;;
    start)   [ -f "$ENV_FILE" ] && [ -f "$COMPOSE_FILE" ] || { echo "Noch nicht eingerichtet – zuerst ./manage.sh install"; exit 1; }
             detect_compose; compose_up; warte_gesund; print_url ;;
    stop)    detect_compose; cd "$SCRIPT_DIR"; $DC down ;;
    restart) detect_compose; cd "$SCRIPT_DIR"; $DC down; compose_up; warte_gesund; print_url ;;
    status)  detect_compose; cd "$SCRIPT_DIR"; $DC ps ;;
    logs)    detect_compose; cd "$SCRIPT_DIR"; shift; $DC logs -f "$@" ;;
    url)     print_url ;;
    test)    docker exec "$CONTAINER" sh -c 'node tools/dnsprobe.mjs --server="$DNS_BIND" --port="$DNS_PORT"' ;;
    port)
        if [ -z "${2:-}" ]; then echo "WebGUI-Port: $(env_wert WEB_PORT)"; else
            sed -i "s/^WEB_PORT=.*/WEB_PORT=$2/" "$ENV_FILE"; detect_compose; cd "$SCRIPT_DIR"; FORCE_RECREATE=1 compose_up; print_url; fi ;;
    *) echo "FAH-Adblock – manage.sh"; echo "Kommandos: install [--no-cache] | update [<zip>] [--no-cache] | start | stop | restart | status | logs | url | port [<PORT>] | test" ;;
esac
