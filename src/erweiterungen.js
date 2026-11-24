// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Optionale Erweiterungen: jeder Unterordner von src/erweiterungen/ mit index.js, der eine Fabrik exportiert
// (deps) → { name, oberflaeche?, routen?(route, hilfen), kachel?(), stoppen?() }. Fehlt der Ordner, gibt es keine.
// Eine Erweiterung, die beim Laden scheitert, wird übergangen – der DNS-Filter läuft immer weiter.
'use strict';
const fs = require('fs');
const path = require('path');

const NAME = /^[a-z0-9-]{1,40}$/;

function ladeErweiterungen(ordner, deps = {}) {
  const log = deps.protokoll || ((t) => console.log(t));
  let namen;
  try {
    namen = fs.readdirSync(ordner, { withFileTypes: true })
      .filter((d) => d.isDirectory() && NAME.test(d.name) && fs.existsSync(path.join(ordner, d.name, 'index.js')))
      .map((d) => d.name).sort();
  } catch (e) { return []; }
  const aus = [];
  for (const name of namen) {
    try {
      const fabrik = require(path.join(ordner, name, 'index.js'));
      const e = typeof fabrik === 'function' ? fabrik(deps) : null;
      if (!e || typeof e !== 'object') throw new Error('liefert keine Erweiterung');
      e.name = name;
      aus.push(e);
    } catch (err) { log(`[erweiterungen] ${name}: ${err.message}`); }
  }
  return aus;
}

module.exports = { ladeErweiterungen };
