#!/bin/sh
# Handbuch als PDF: sh docs/handbuch/pdf.sh  (Chrome headless; Chrome beendet sich nach --print-to-pdf nicht immer → wird nach fertigem PDF beendet)
cd "$(dirname "$0")" || exit 1
PROFIL="$(mktemp -d)"; rm -f FAH-Adblock_Handbuch.pdf
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu --no-pdf-header-footer --user-data-dir="$PROFIL" \
  --allow-file-access-from-files --run-all-compositor-stages-before-draw --print-to-pdf="$PWD/FAH-Adblock_Handbuch.pdf" "file://$PWD/handbuch.html" >/dev/null 2>&1 &
PID=$!
python3 - "$PID" <<'PY'
import os, sys, time
pid, datei, alt, gleich = int(sys.argv[1]), 'FAH-Adblock_Handbuch.pdf', -1, 0
for _ in range(240):
    time.sleep(0.5)
    try: os.kill(pid, 0)
    except OSError: break
    g = os.path.getsize(datei) if os.path.exists(datei) else -1
    gleich = gleich + 1 if g > 0 and g == alt else 0; alt = g
    if gleich >= 4: break
PY
kill "$PID" 2>/dev/null; pkill -f "$PROFIL" 2>/dev/null; rm -rf "$PROFIL"
ls -la FAH-Adblock_Handbuch.pdf
