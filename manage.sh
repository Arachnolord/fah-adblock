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

    # 3. Konfiguration beim ersten Mal anlegen
    [ -f "$ENV_FILE" ] || { cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"; echo "  [ENV] .env aus .env.example erzeugt – DNS_BIND pruefen!"; }
    [ -f "$COMPOSE_FILE" ] || { cp "$SCRIPT_DIR/docker-compose.yml.example" "$COMPOSE_FILE"; echo "  [COMPOSE] docker-compose.yml erzeugt."; }
    mkdir -p "$SCRIPT_DIR/data"

    # 4. Bauen und Container ersetzen
    echo "=== Baue & starte Container ==="
    if [ "$NO_CACHE" = "1" ]; then $DC build --no-cache; else $DC build; fi
    FORCE_RECREATE=1 compose_up

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
    update) shift; ZIP=""; for a in "$@"; do case "$a" in --no-cache) NO_CACHE=1 ;; *) ZIP="$a" ;; esac; done; do_update "$ZIP" ;;
    start)   detect_compose; compose_up; warte_gesund; print_url ;;
    stop)    detect_compose; cd "$SCRIPT_DIR"; $DC down ;;
    restart) detect_compose; cd "$SCRIPT_DIR"; $DC down; compose_up; warte_gesund; print_url ;;
    status)  detect_compose; cd "$SCRIPT_DIR"; $DC ps ;;
    logs)    detect_compose; cd "$SCRIPT_DIR"; shift; $DC logs -f "$@" ;;
    url)     print_url ;;
    test)    docker exec "$CONTAINER" sh -c 'node tools/dnsprobe.mjs --server="$DNS_BIND" --port="$DNS_PORT"' ;;
    port)
        if [ -z "${2:-}" ]; then echo "WebGUI-Port: $(env_wert WEB_PORT)"; else
            sed -i "s/^WEB_PORT=.*/WEB_PORT=$2/" "$ENV_FILE"; detect_compose; cd "$SCRIPT_DIR"; FORCE_RECREATE=1 compose_up; print_url; fi ;;
    *) echo "FAH-Adblock – manage.sh"; echo "Kommandos: update [<zip>] [--no-cache] | start | stop | restart | status | logs | url | port [<PORT>] | test" ;;
esac
