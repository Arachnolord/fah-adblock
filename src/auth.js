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
// Jeder Nutzer trägt einen Sitzungszähler; Passwortwechsel und Abmelden erhöhen ihn, ältere Cookies
// (auch noch gültig signierte) sind damit ungültig.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const COOKIE = 'fah_adblock';
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
    this.nutzer = this.laden();
  }
  laden() {
    try { return JSON.parse(fs.readFileSync(this.datei, 'utf8')); } catch (e) {}
    const erst = { nutzer: [{ name: 'admin', hash: hash('admin'), standardPasswort: true, angelegt: this.jetzt() }] };
    fs.mkdirSync(path.dirname(this.datei), { recursive: true });
    fs.writeFileSync(this.datei, JSON.stringify(erst, null, 1));
    return erst;
  }
  speichern() { fs.writeFileSync(this.datei + '.tmp', JSON.stringify(this.nutzer, null, 1)); fs.renameSync(this.datei + '.tmp', this.datei); }
  signatur(text) { return crypto.createHmac('sha256', this.geheimnis).update(text).digest('base64url'); }
  sitzungFuer(name) {
    const n = this.nutzer.nutzer.find((x) => x.name === name);
    const inhalt = Buffer.from(JSON.stringify({ n: name, s: n?.sitzung || 0, b: this.jetzt() + LAUFZEIT, c: crypto.randomBytes(9).toString('base64url') })).toString('base64url');
    return `${inhalt}.${this.signatur(inhalt)}`;
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
  anmelden(name, passwort, ip) {
    const jetzt = this.jetzt(), nameText = String(name || '').trim();
    const v = this.versuche.get(ip) || { n: 0, ab: jetzt };
    if (jetzt - v.ab > 15 * 60000) { v.n = 0; v.ab = jetzt; }
    if (v.n >= 10) return { fehler: 'Zu viele Versuche – bitte 15 Minuten warten' };
    const b = this.nutzerVersuche.get(nameText) || { n: 0, bis: 0, zuletzt: jetzt };
    if (jetzt - b.zuletzt > 60 * 60000) { b.n = 0; b.bis = 0; }
    if (b.bis > jetzt) { const s = Math.ceil((b.bis - jetzt) / 1000); return { fehler: `Zu viele Fehlversuche für diesen Namen – bitte ${s >= 120 ? Math.ceil(s / 60) + ' Minuten' : s + ' Sekunden'} warten` }; }
    const n = this.nutzer.nutzer.find((x) => x.name === nameText);
    if (!n || !pruefen(passwort, n.hash)) {
      v.n++; this.versuche.set(ip, v);
      b.n++; b.zuletzt = jetzt; b.bis = jetzt + Auth.wartezeit(b.n);
      if (this.nutzerVersuche.size >= 1000) this.nutzerVersuche.delete(this.nutzerVersuche.keys().next().value);   // Speicher deckeln (erfundene Namen)
      this.nutzerVersuche.set(nameText, b);
      return { fehler: 'Name oder Passwort falsch' };
    }
    this.versuche.delete(ip); this.nutzerVersuche.delete(nameText);
    return { cookie: this.sitzungFuer(n.name), standardPasswort: !!n.standardPasswort };
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
    return { ok: true, cookie: this.sitzungFuer(n.name) };   // neues Cookie für die aktuelle Sitzung, alle anderen sind ab jetzt ungültig
  }
}

module.exports = { Auth, COOKIE, LAUFZEIT, hash, pruefen };
