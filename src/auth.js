// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Anmeldung: Nutzer in data/nutzer.json (scrypt), Sitzung als signiertes Cookie
// (HMAC-SHA256, 30 Tage). Erster Start: admin / admin.
// Bremsen: je Adresse (10 Fehlversuche → 15 min) und je Nutzername (ab dem 3. Fehlversuch steigende
// Wartezeit 2 s, 4 s, 8 s … bis 15 min – wirkt auch, wenn ein Angreifer die Adresse wechselt).
// Bekanntes Gerät (25.11.2026, Prüfung K14): Ein Browser, der sich schon einmal erfolgreich angemeldet hat, trägt ein signiertes
// Geräte-Cookie (1 Jahr, ungültig nach Passwortwechsel). Nur er darf während einer Namenssperre weiter prüfen (5× je 15 min) –
// so kann ein Fremder den Betreiber nicht aussperren, bekommt selbst aber keinen einzigen zusätzlichen Rateversuch.
// Jeder Nutzer trägt einen Sitzungszähler; Passwortwechsel und Abmelden erhöhen ihn, ältere Cookies
// (auch noch gültig signierte) sind damit ungültig.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { schreibenSicher, lesenRobust } = require('./datei');

const COOKIE = 'fah_adblock';
const GERAET_COOKIE = 'fah_adblock_geraet', GERAET_LAUFZEIT = 365 * 86400000;
const LAUFZEIT = 30 * 86400000;

function hash(passwort, salz = crypto.randomBytes(16)) {
  const h = crypto.scryptSync(String(passwort), salz, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt:${salz.toString('base64')}:${h.toString('base64')}`;
}
function pruefen(passwort, gespeichert) {
  const [art, salz, h] = String(gespeichert || '').split(':');
  if (art !== 'scrypt') return false;
  const soll = Buffer.from(h, 'base64'), ist = crypto.scryptSync(String(passwort), Buffer.from(salz, 'base64'), 64, { N: 16384, r: 8, p: 1 });
  return soll.length === ist.length && crypto.timingSafeEqual(soll, ist);
}

class Auth {
  constructor({ verzeichnis, geheimnis, jetzt = () => Date.now() }) {
    Object.assign(this, { geheimnis, jetzt });
    this.datei = path.join(verzeichnis, 'nutzer.json');
    this.versuche = new Map();        // Adresse → {n, ab}
    this.nutzerVersuche = new Map();  // Nutzername → {n, bis, zuletzt}
    this.geraetVersuche = new Map();  // Geräte-ID → {n, ab} – Prüfungen während einer Namenssperre
    this.nutzer = this.laden();
  }
  laden() {
    // Kaputte Nutzerdatei (K7): nie wieder still admin/admin – wegsichern, letzten guten Stand (.bak) nehmen, sonst ein Einmal-Passwort
    // Jeder Nutzer braucht Namen und einen vollständigen scrypt-Hash, Namen eindeutig – sonst gilt die Datei als beschädigt (Codex-Nachprüfung R5)
    // Name in genau der Form, die die Anmeldung sucht (getrimmt, 1–64 Zeichen, keine Steuerzeichen) – sonst wäre er nie anmeldbar (Codex R-P23-008)
    const nutzerOk = (n) => n && typeof n.name === 'string' && n.name === n.name.trim() && n.name.length >= 1 && n.name.length <= 64 && !/\p{Cc}/u.test(n.name) && /^scrypt:[A-Za-z0-9+/]{22}==:[A-Za-z0-9+/]{86}==$/.test(String(n.hash || ''));
    const r = lesenRobust(this.datei, { pruefen: (d) => Array.isArray(d.nutzer) && d.nutzer.length > 0 && d.nutzer.every(nutzerOk) && new Set(d.nutzer.map((n) => n.name)).size === d.nutzer.length });
    const weg = r.kaputt ? path.basename(r.kaputt) : '';
    if (r.daten) {
      if (r.kaputt) { this.warnung = `Die Nutzerdatei war beschädigt (weggesichert als ${weg}) – der letzte gesicherte Stand gilt.`; console.error(`[auth] ${this.warnung}`); this.nutzer = r.daten; this.speichern(); }
      return r.daten;
    }
    let erst;
    if (r.kaputt) {
      const einmal = crypto.randomBytes(9).toString('base64url');
      erst = { nutzer: [{ name: 'admin', hash: hash(einmal), standardPasswort: true, angelegt: this.jetzt() }] };
      this.warnung = this.anmeldeHinweis = `Die Nutzerdatei war beschädigt (weggesichert als ${weg}) und keine Sicherung lesbar. Anmeldung mit „admin“ und dem Einmal-Passwort aus dem Container-Protokoll (docker logs fah-adblock), danach Passwort ändern.`;
      console.error(`[auth] ${this.warnung} Einmal-Passwort: ${einmal}`);
    } else erst = { nutzer: [{ name: 'admin', hash: hash('admin'), standardPasswort: true, angelegt: this.jetzt() }] };   // Erstinstallation (Betreiber-Vorgabe)
    schreibenSicher(this.datei, JSON.stringify(erst, null, 1), { modus: 0o600 });
    return erst;
  }
  speichern() { schreibenSicher(this.datei, JSON.stringify(this.nutzer, null, 1), { modus: 0o600 }); }
  signatur(text) { return crypto.createHmac('sha256', this.geheimnis).update(text).digest('base64url'); }
  sitzungFuer(name) {
    const n = this.nutzer.nutzer.find((x) => x.name === name);
    const inhalt = Buffer.from(JSON.stringify({ n: name, s: n?.sitzung || 0, b: this.jetzt() + LAUFZEIT, c: crypto.randomBytes(9).toString('base64url') })).toString('base64url');
    return `${inhalt}.${this.signatur(inhalt)}`;
  }
  /** Stempel des aktuellen Passworts (ändert sich mit jedem Passwortwechsel) – bindet das Geräte-Cookie */
  pwStempel(n) { return this.signatur(`pw|${n.name}|${n.hash}`).slice(0, 22); }
  geraetFuer(name) {
    const n = this.nutzer.nutzer.find((x) => x.name === name); if (!n) return null;
    const inhalt = Buffer.from(JSON.stringify({ n: name, g: crypto.randomBytes(9).toString('base64url'), p: this.pwStempel(n), b: this.jetzt() + GERAET_LAUFZEIT })).toString('base64url');
    return `${inhalt}.${this.signatur(`geraet|${inhalt}`)}`;
  }
  /** Geräte-Cookie prüfen → Geräte-ID, wenn es zu diesem Nutzer und seinem aktuellen Passwort passt, sonst null */
  geraetLesen(cookieKopf, name) {
    const wert = String(cookieKopf || '').split(/;\s*/).map((c) => c.split('=')).find(([k]) => k === GERAET_COOKIE)?.[1];
    if (!wert) return null;
    const [inhalt, sig] = wert.split('.');
    if (!inhalt || !sig) return null;
    const soll = Buffer.from(this.signatur(`geraet|${inhalt}`)), ist = Buffer.from(sig);
    if (soll.length !== ist.length || !crypto.timingSafeEqual(soll, ist)) return null;
    try {
      const d = JSON.parse(Buffer.from(inhalt, 'base64url').toString('utf8'));
      const n = this.nutzer.nutzer.find((x) => x.name === d.n);
      if (!n || d.n !== name || d.b < this.jetzt() || d.p !== this.pwStempel(n) || typeof d.g !== 'string') return null;
      return d.g;
    } catch (e) { return null; }
  }
  sitzungLesen(cookieKopf) {
    const wert = String(cookieKopf || '').split(/;\s*/).map((c) => c.split('=')).find(([k]) => k === COOKIE)?.[1];
    if (!wert) return null;
    const [inhalt, sig] = wert.split('.');
    if (!inhalt || !sig) return null;
    const soll = Buffer.from(this.signatur(inhalt)), ist = Buffer.from(sig);
    if (soll.length !== ist.length || !crypto.timingSafeEqual(soll, ist)) return null;
    try {
      const d = JSON.parse(Buffer.from(inhalt, 'base64url').toString('utf8'));
      if (d.b < this.jetzt()) return null;
      const n = this.nutzer.nutzer.find((x) => x.name === d.n);
      if (!n || (d.s || 0) !== (n.sitzung || 0)) return null;   // Sitzungszähler: nach Abmelden/Passwortwechsel ungültig
      return { name: n.name, standardPasswort: !!n.standardPasswort, csrf: this.signatur(`csrf|${inhalt}`).slice(0, 32) };
    } catch (e) { return null; }
  }
  // Wartezeit je Nutzername nach n Fehlversuchen: ab dem 3. 2 s, dann verdoppelt bis 15 min
  static wartezeit(n) { return n < 3 ? 0 : Math.min(15 * 60000, 1000 * 2 ** (n - 2)); }
  anmelden(name, passwort, ip, cookieKopf = '') {
    const jetzt = this.jetzt(), nameText = String(name || '').trim();
    // Speicher deckeln: abgelaufene Adressen weg, notfalls die ältesten (viele IPv6-Adressen hinter einem vertrauten Proxy)
    if (this.versuche.size > 1000) for (const [a, x] of this.versuche) if (jetzt - x.ab > 15 * 60000) this.versuche.delete(a);
    while (this.versuche.size > 5000) this.versuche.delete(this.versuche.keys().next().value);
    const v = this.versuche.get(ip) || { n: 0, ab: jetzt };
    if (jetzt - v.ab > 15 * 60000) { v.n = 0; v.ab = jetzt; }
    if (v.n >= 10) return { fehler: 'Zu viele Versuche – bitte 15 Minuten warten' };
    const b = this.nutzerVersuche.get(nameText) || { n: 0, bis: 0, zuletzt: jetzt };
    if (jetzt - b.zuletzt > 60 * 60000) { b.n = 0; b.bis = 0; }
    const sperrText = () => { const s = Math.max(1, Math.ceil((b.bis - jetzt) / 1000)); return `Zu viele Fehlversuche für diesen Namen – bitte ${s >= 120 ? Math.ceil(s / 60) + ' Minuten' : s + ' Sekunden'} warten`; };
    // Namenssperre: Fremde werden während der Sperre gar nicht geprüft (kein zusätzlicher Rateversuch). Ein bekanntes Gerät (Geräte-Cookie
    // zu diesem Namen und dem aktuellen Passwort) darf weiter prüfen – 5× je 15 min –, damit ein Fremder den Betreiber nicht aussperren kann.
    const gesperrt = b.bis > jetzt;
    if (gesperrt) {
      const g = this.geraetLesen(cookieKopf, nameText);
      if (!g) return { fehler: sperrText() };
      const gv = this.geraetVersuche.get(g) || { n: 0, ab: jetzt };
      if (jetzt - gv.ab > 15 * 60000) { gv.n = 0; gv.ab = jetzt; }
      if (gv.n >= 5) return { fehler: sperrText() };
      gv.n++; this.geraetVersuche.set(g, gv);
      while (this.geraetVersuche.size > 1000) this.geraetVersuche.delete(this.geraetVersuche.keys().next().value);
    }
    const n = this.nutzer.nutzer.find((x) => x.name === nameText);
    if (!n || !pruefen(passwort, n.hash)) {
      v.n++; this.versuche.set(ip, v);
      b.n++; b.zuletzt = jetzt; b.bis = Math.max(b.bis, jetzt + Auth.wartezeit(b.n));
      if (this.nutzerVersuche.size >= 1000) this.nutzerVersuche.delete(this.nutzerVersuche.keys().next().value);   // Speicher deckeln (erfundene Namen)
      this.nutzerVersuche.set(nameText, b);
      return { fehler: gesperrt ? sperrText() : this.anmeldeHinweis || 'Name oder Passwort falsch' };
    }
    this.versuche.delete(ip); this.nutzerVersuche.delete(nameText);
    return { cookie: this.sitzungFuer(n.name), geraet: this.geraetFuer(n.name), standardPasswort: !!n.standardPasswort };
  }
  // Alle Sitzungen des Nutzers ungültig machen (Abmelden, Passwortwechsel)
  sitzungenBeenden(name) {
    const n = this.nutzer.nutzer.find((x) => x.name === name);
    if (!n) return false;
    n.sitzung = (n.sitzung || 0) + 1; this.speichern();
    return true;
  }
  passwortAendern(name, alt, neu) {
    const n = this.nutzer.nutzer.find((x) => x.name === name);
    if (!n || !pruefen(alt, n.hash)) return { fehler: 'Bisheriges Passwort stimmt nicht' };
    if (String(neu || '').length < 8) return { fehler: 'Neues Passwort: mindestens 8 Zeichen' };
    n.hash = hash(neu); n.standardPasswort = false; n.sitzung = (n.sitzung || 0) + 1; this.speichern();
    return { ok: true, cookie: this.sitzungFuer(n.name), geraet: this.geraetFuer(n.name) };   // neues Cookie für die aktuelle Sitzung, alle anderen (und alte Geräte-Cookies) sind ab jetzt ungültig
  }
}

module.exports = { Auth, COOKIE, LAUFZEIT, GERAET_COOKIE, GERAET_LAUFZEIT, hash, pruefen };
