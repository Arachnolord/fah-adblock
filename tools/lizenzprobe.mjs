#!/usr/bin/env node
// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// ============================================================================
// Lizenzprobe: jede Abhängigkeit (auch transitiv, aus package-lock.json) muss MIT oder
// Apache-2.0 sein – Vorgabe des Betreibers für eine mögliche Weitergabe an Dritte.
// Aufruf: node tools/lizenzprobe.mjs   (Rückgabewert ≠ 0 bei Verstoß)
import fs from 'node:fs';
import path from 'node:path';
const ERLAUBT = new Set(['MIT', 'Apache-2.0']);
const wurzel = path.join(path.dirname(new URL(import.meta.url).pathname), '..');
const lock = JSON.parse(fs.readFileSync(path.join(wurzel, 'package-lock.json'), 'utf8'));
let fehler = 0, n = 0;
for (const [pfad, info] of Object.entries(lock.packages || {})) {
  if (!pfad) continue;
  n++;
  let lizenz = info.license;
  if (!lizenz) { try { lizenz = JSON.parse(fs.readFileSync(path.join(wurzel, pfad, 'package.json'), 'utf8')).license; } catch (e) {} }
  const ok = ERLAUBT.has(String(lizenz));
  console.log(`${ok ? 'OK  ' : 'FEHL'} ${pfad.replace(/^node_modules\//, '')}@${info.version} – ${lizenz || 'keine Angabe'}`);
  if (!ok) fehler++;
}
console.log(`\n${n - fehler}/${n} Abhängigkeiten MIT/Apache-2.0.`);
process.exit(fehler ? 1 : 0);
