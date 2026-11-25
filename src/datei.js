// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Zustandsdateien sicher schreiben und robust lesen (25.11.2026, Prüfung K7).
// Vorher galt eine kaputte Datei (Tippfehler beim Bearbeiten von Hand, Stromausfall ohne fsync) wie „nicht vorhanden“ und wurde sofort mit
// der Werkseinstellung überschrieben: alle Profile, Geräte und Regeln weg – bei der Nutzerdatei galt wieder admin/admin.
// Jetzt: Schreiben = temporäre Datei + fsync + Umbenennen + fsync des Ordners, danach eine Kopie als <datei>.bak (letzter guter Stand).
// Lesen: kaputte Datei wird als <datei>.kaputt-<Zeit> weggesichert (nie überschrieben), dann wird die .bak versucht.
'use strict';
const fs = require('fs');
const path = require('path');

function ordnerSync(ordner) { try { const d = fs.openSync(ordner, 'r'); try { fs.fsyncSync(d); } finally { fs.closeSync(d); } } catch (e) { /* nicht überall möglich – kein Fehler */ } }

/** Text atomar und dauerhaft schreiben; danach Sicherungskopie <datei>.bak. Fehler (volle Platte …) werfen – die alte Datei bleibt dann unberührt. */
function schreibenSicher(datei, text, { modus = 0o644, sicherung = true } = {}) {
  fs.mkdirSync(path.dirname(datei), { recursive: true });
  const tmp = `${datei}.tmp`;
  const fd = fs.openSync(tmp, 'w', modus);
  try { fs.writeSync(fd, text); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  try { fs.chmodSync(tmp, modus); } catch (e) {}
  fs.renameSync(tmp, datei);
  ordnerSync(path.dirname(datei));
  if (sicherung) { try { fs.copyFileSync(datei, `${datei}.bak`); fs.chmodSync(`${datei}.bak`, modus); } catch (e) {} }
}

/**
 * JSON robust lesen. `pruefen(daten)` darf ein unbrauchbares Ergebnis ablehnen (false).
 * → { daten, quelle: 'datei' | 'sicherung' | 'neu', kaputt: Pfad der weggesicherten Datei oder null }
 */
function lesenRobust(datei, { pruefen = () => true, jetzt = Date.now(), umwandeln = (t) => t } = {}) {
  const versuch = (pfad) => { const d = JSON.parse(umwandeln(fs.readFileSync(pfad, 'utf8'))); if (d === null || typeof d !== 'object' || !pruefen(d)) throw new Error('Inhalt unbrauchbar'); return d; };
  if (!fs.existsSync(datei)) return { daten: null, quelle: 'neu', kaputt: null };
  try { return { daten: versuch(datei), quelle: 'datei', kaputt: null }; } catch (e) { /* weiter unten */ }
  const kaputt = `${datei}.kaputt-${new Date(jetzt).toISOString().replace(/[:.]/g, '-')}`;
  try { fs.renameSync(datei, kaputt); } catch (e) {}
  try { return { daten: versuch(`${datei}.bak`), quelle: 'sicherung', kaputt }; } catch (e) {}
  return { daten: null, quelle: 'neu', kaputt };
}

module.exports = { schreibenSicher, lesenRobust };
