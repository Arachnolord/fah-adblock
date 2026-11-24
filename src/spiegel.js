// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Haupt- und Ersatz-Instanz (09.10.2026, wie FAH-Proxy): Geräte bekommen per DHCP zwei DNS-Server (Haupt + Ersatz) und
// weichen bei einem Ausfall selbst aus – beide müssen also gleich filtern. Der Ersatz holt deshalb alle 2 Minuten die
// Einstellungen des Haupts (Listen, Profile, Geräte, Regeln, Dienste, Pausen, DNS) und übernimmt sie geprüft wie eine
// Sicherung; ändern lässt sich nur am Haupt. Je Instanz bleiben: UniFi-Schlüssel (mit eigenem Geheimnis verschlüsselt),
// vertraute Proxys, Protokoll und Statistik. Zugang: Kopplungscode – der Haupt speichert nur seinen Hash, der Ersatz
// den Code verschlüsselt. Zustand in data/spiegel.json (gehört der Instanz, wird nie gespiegelt).
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { verschluesseln, entschluesseln } = require('./einstellungen');

const ABGLEICH_MS = 2 * 60 * 1000;
// Nichts eingerichtet (frisch installiert): keine Geräte-Zuordnungen, Regeln oder Dienst-Einstellungen. Ein solcher Stand
// überschreibt nie eine eingerichtete Instanz (09.10.2026) – sonst wären nach einer Neuinstallation des Haupts alle Regeln weg.
const istLeer = (s) => !s || (!Object.keys(s.geraete || {}).length && !(s.regeln || []).length && !Object.keys(s.dienste || {}).length);
const LEER_TEXT = 'Der Haupt ist noch leer (keine Geräte, Regeln oder Dienste) – nicht übernommen, damit hier nichts verloren geht. Neu einrichten: Einstellungen → Haupt & Ersatz → Mit Partner koppeln.';
/** Adresse einer FAH-Adblock-Oberfläche → Origin (http/https), sonst Fehler mit Status 400. */
function adresse(roh, feld = 'url') {
  const u = String(roh || '').trim().replace(/\/+$/, '');
  try { const x = new URL(u); if (!['http:', 'https:'].includes(x.protocol) || (x.pathname !== '/' && x.pathname !== '')) throw new Error(); return x.origin; } catch (e) { throw Object.assign(new Error('Adresse als http://IP:Port angeben, z. B. http://192.168.1.29:8053'), { status: 400, feld }); }
}
const hash = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');
const gleich = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

/** Einstellungen, die der Haupt ausliefert: alles außer UniFi-Zugang und vertrauten Proxys (gehören der Instanz). */
function standVon(einst, version) {
  const s = einst.oeffentlich();
  delete s.unifi; delete s.web;
  return { art: 'fah-adblock-sicherung', version, erstellt: Date.now(), einstellungen: s };
}

/** GET mit Zeitlimit (http oder https, selbstsigniert erlaubt) → JSON. `eigene` = Adresse dieses Ersatzes (der Haupt merkt sie sich). */
function holen(url, code, zeitlimit_ms = 10000, eigene = '') {
  return new Promise((ok, nein) => {
    let u; try { u = new URL('/api/spiegel/stand', url); } catch (e) { return nein(new Error('Adresse des Haupts ungültig')); }
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.get(u, { headers: { Authorization: `Bearer ${code}`, 'User-Agent': 'FAH-Adblock-Ersatz', ...(eigene ? { 'X-FAH-Adblock-Url': eigene } : {}) }, timeout: zeitlimit_ms, rejectUnauthorized: false }, (res) => {
      const nein0 = nein; nein = (e) => nein0(Object.assign(e, { antwort: true }));   // der Haupt läuft – er hat geantwortet
      let t = ''; res.setEncoding('utf8');
      res.on('data', (d) => { t += d; if (t.length > 5e6) req.destroy(new Error('Antwort zu groß')); });
      res.on('end', () => {
        if (res.statusCode === 401 || res.statusCode === 403) return nein(new Error('Der Haupt lehnt den Kopplungscode ab'));
        if (res.statusCode === 409) { let m = ''; try { m = JSON.parse(t).fehler; } catch (e) {} return nein(new Error(m || 'Die Gegenstelle ist kein Haupt')); }
        if (res.statusCode !== 200) return nein(new Error(`Haupt antwortet mit HTTP ${res.statusCode}`));
        try { ok(JSON.parse(t)); } catch (e) { nein(new Error('Antwort des Haupts ist kein JSON')); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('Haupt antwortet nicht (Zeitüberschreitung)')));
    req.on('error', (e) => nein(e.code === 'ECONNREFUSED' ? new Error('Haupt nicht erreichbar (Verbindung abgewiesen)') : e));
  });
}

/** POST mit Kopplungscode → JSON (Ersatz → Haupt: Meldungen, Zeitkonto, „zuletzt gesehen“) */
function senden(url, code, daten, zeitlimit_ms = 10000) {
  return new Promise((ok, nein) => {
    let u; try { u = new URL('/api/spiegel/meldung', url); } catch (e) { return nein(new Error('Adresse des Haupts ungültig')); }
    const mod = u.protocol === 'https:' ? https : http, text = JSON.stringify(daten || {});
    const req = mod.request(u, { method: 'POST', headers: { Authorization: `Bearer ${code}`, 'User-Agent': 'FAH-Adblock-Ersatz', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) }, timeout: zeitlimit_ms, rejectUnauthorized: false }, (res) => {
      let t = ''; res.setEncoding('utf8');
      res.on('data', (d) => { t += d; if (t.length > 1e6) req.destroy(new Error('Antwort zu groß')); });
      res.on('end', () => { if (res.statusCode !== 200) return nein(new Error(`Haupt nimmt Meldungen nicht an (HTTP ${res.statusCode})`)); try { ok(JSON.parse(t)); } catch (e) { nein(new Error('Antwort des Haupts ist kein JSON')); } });
    });
    req.on('timeout', () => req.destroy(new Error('Haupt antwortet nicht (Zeitüberschreitung)')));
    req.on('error', nein);
    req.end(text);
  });
}

/** Bei der Oberfläche des Partners anmelden → {anfrage(methode, pfad, daten)} mit Sitzungscookie und CSRF. */
async function partnerAnmelden(basis, name, passwort, zeitlimit_ms = 30000) {
  let cookie = '', csrf = '';
  const anfrage = (methode, pfad, daten) => new Promise((ok, nein) => {
    const u = new URL(pfad, basis); const mod = u.protocol === 'https:' ? https : http;
    const text = daten === undefined ? undefined : JSON.stringify(daten);
    const req = mod.request(u, { method: methode, timeout: zeitlimit_ms, rejectUnauthorized: false, headers: { 'User-Agent': 'FAH-Adblock-Partner', Accept: 'application/json',
      ...(cookie ? { Cookie: cookie } : {}), ...(csrf && methode !== 'GET' ? { 'X-CSRF': csrf } : {}), ...(text !== undefined ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) } : {}) } }, (res) => {
      let t = ''; res.setEncoding('utf8');
      res.on('data', (d) => { t += d; if (t.length > 5e6) req.destroy(new Error('Antwort zu groß')); });
      res.on('end', () => {
        for (const c of [].concat(res.headers['set-cookie'] || [])) { const nv = String(c).split(';')[0]; if (nv.startsWith('fah_adblock=') && nv.length > 13) cookie = nv; }
        let j = null; try { j = JSON.parse(t); } catch (e) {}
        if (!j || typeof j !== 'object') return nein(Object.assign(new Error(`Unter ${basis} antwortet kein FAH-Adblock (HTTP ${res.statusCode})`), { status: 502 }));
        if (res.statusCode !== 200) return nein(Object.assign(new Error(`Partner: ${j.fehler || `HTTP ${res.statusCode}`}`), { status: res.statusCode === 401 ? 400 : 502, partnerStatus: res.statusCode }));
        ok(j);
      });
    });
    req.on('timeout', () => req.destroy(new Error('Partner antwortet nicht (Zeitüberschreitung)')));
    req.on('error', (e) => nein(Object.assign(e.code === 'ECONNREFUSED' ? new Error(`Partner ${basis} nicht erreichbar (Verbindung abgewiesen)`) : e, { status: 502 })));
    req.end(text);
  });
  try { await anfrage('POST', '/api/anmelden', { name: String(name || '').trim(), passwort: String(passwort || '') }); } catch (e) {
    if (e.partnerStatus === 401) throw Object.assign(new Error(`Anmeldung beim Partner: ${e.message.replace(/^Partner: /, '')}`), { status: 400, feld: 'passwort' });
    throw e;
  }
  csrf = (await anfrage('GET', '/api/ich')).csrf || '';
  return { anfrage };
}

class Spiegel {
  /** @param {{verzeichnis:string, einst, geheimnis:string, version:string, anwenden:(s:object)=>void, holen?:Function, jetzt?:()=>number}} o */
  constructor({ verzeichnis, einst, geheimnis, version, anwenden, holen: holenFn = holen, senden: sendenFn = senden, jetzt = () => Date.now(), eigeneUrl = '', anmelden = partnerAnmelden, austausch = null }) {
    Object.assign(this, { einst, geheimnis, version, anwenden, holenFn, sendenFn, jetzt, eigeneUrl, anmelden, austausch });
    this.datei = path.join(verzeichnis, 'spiegel.json');
    this.z = { rolle: 'allein' };
    try { this.z = { rolle: 'allein', ...JSON.parse(fs.readFileSync(this.datei, 'utf8')) }; } catch (e) {}
    if (this.z.eigene_url) this.eigeneUrl = this.z.eigene_url;   // beim Koppeln angegeben – gilt vor der Vorgabe aus DNS_BIND/WEB_PORT
    this.timer = null; this.laeuft = null;
  }
  speichern() { fs.writeFileSync(this.datei + '.tmp', JSON.stringify(this.z, null, 1), { mode: 0o600 }); fs.renameSync(this.datei + '.tmp', this.datei); }
  get rolle() { return this.z.rolle || 'allein'; }
  /** Wann der Haupt zuletzt geantwortet hat (Abgleich erfolgreich ODER eine HTTP-Antwort, z. B. Code abgelehnt) – für die Übernahme */
  hauptZuletzt() { return Math.max(this.z.letzter_abgleich || 0, this.z.haupt_gesehen || 0); }
  istErsatz() { return this.rolle === 'ersatz'; }
  status() {
    const z = this.z;
    return { rolle: this.rolle, haupt_url: z.haupt_url || null, letzter_abgleich: z.letzter_abgleich || null, letzte_aenderung: z.letzte_aenderung || null,
      fehler: z.fehler || null, ersatz: z.ersatz || null, code_gesetzt: !!z.code_hash, leer: istLeer(this.einst.werte), eigene_url: this.eigeneUrl || null,
      partner_url: this.rolle === 'ersatz' ? z.haupt_url || null : this.rolle === 'haupt' ? (z.ersatz && z.ersatz.url) || null : null };
  }

  /** Diese Instanz wird Haupt: neuer Kopplungscode (nur jetzt sichtbar, gespeichert wird der Hash). */
  hauptWerden() {
    const code = crypto.randomBytes(18).toString('base64url');
    this.z = { rolle: 'haupt', code_hash: hash(code), ersatz: this.z.rolle === 'haupt' ? this.z.ersatz || null : null };
    this.speichern(); this.stoppen();
    return { code };
  }
  /** Haupt: Abruf des Ersatzes mit Code prüfen und merken (für die Anzeige „zuletzt abgeholt“). */
  standFuer(code, ip, url = '') {
    if (this.rolle !== 'haupt') { const f = new Error('Diese Instanz ist kein Haupt'); f.status = 409; throw f; }
    if (!code || !gleich(hash(code), this.z.code_hash)) { const f = new Error('Kopplungscode falsch'); f.status = 401; throw f; }
    let u = null; try { u = url ? adresse(url) : null; } catch (e) {}
    this.z.ersatz = { ip: ip || null, zeit: this.jetzt(), url: u || (this.z.ersatz && this.z.ersatz.url) || null }; this.speichern();
    return standVon(this.einst, this.version);
  }
  /** Haupt: Meldungen/Zeitkonto des Ersatzes annehmen (Kinderschutz) → Antwort für den Ersatz (z. B. aufgebrauchte Zeitlimits) */
  meldungFuer(code, daten) {
    if (this.rolle !== 'haupt') { const f = new Error('Diese Instanz ist kein Haupt'); f.status = 409; throw f; }
    if (!code || !gleich(hash(code), this.z.code_hash)) { const f = new Error('Kopplungscode falsch'); f.status = 401; throw f; }
    return this.austausch ? this.austausch.empfangen(daten || {}, code) : {};
  }
  /** Diese Instanz wird Ersatz des Haupts unter `url` – erst nach erfolgreichem Probe-Abgleich. */
  async ersatzWerden(url, code) {
    const u = String(url || '').trim().replace(/\/+$/, '');
    try { const x = new URL(u); if (!['http:', 'https:'].includes(x.protocol)) throw new Error(); } catch (e) { throw Object.assign(new Error('Adresse des Haupts als http(s)://IP:Port angeben, z. B. http://192.168.1.29:8053'), { status: 400 }); }
    if (!code) throw Object.assign(new Error('Kopplungscode fehlt'), { status: 400 });
    const stand = await this.holenFn(u, String(code).trim(), undefined, this.eigeneUrl);
    if (istLeer(stand.einstellungen) && !istLeer(this.einst.werte)) throw Object.assign(new Error(LEER_TEXT), { status: 409 });
    this.anwenden(stand.einstellungen, { pausen: true });
    this.z = { rolle: 'ersatz', haupt_url: u, code: verschluesseln(String(code).trim(), this.geheimnis), letzter_abgleich: this.jetzt(), letzte_aenderung: this.jetzt(), stand_hash: hash(JSON.stringify(stand.einstellungen)), fehler: null };
    this.speichern(); this.starten();
    return this.status();
  }
  loesen() { this.z = { rolle: 'allein' }; this.speichern(); this.stoppen(); return this.status(); }

  /**
   * Koppeln von EINER Oberfläche aus (09.10.2026): diese Instanz wird `rolle` ('haupt' | 'ersatz'), der Partner die andere.
   * Mit Name und Passwort eines Kontos des Partners meldet sich diese Instanz dort an und richtet beide Seiten ein (das
   * Passwort wird nicht gespeichert). Eine leere Instanz holt sich dabei zuerst den Stand der eingerichteten – auch als Haupt.
   */
  async partnerKoppeln({ rolle, url, name, passwort, eigene_url }) {
    if (!['haupt', 'ersatz'].includes(rolle)) throw Object.assign(new Error('Bitte wählen, ob diese Instanz Haupt oder Ersatz wird'), { status: 400, feld: 'rolle' });
    const ziel = adresse(url);
    const eigen = adresse(eigene_url || this.eigeneUrl, 'eigene_url');
    if (eigen === ziel) throw Object.assign(new Error('Das ist die Adresse dieser Instanz – bitte die des Partners eingeben'), { status: 400, feld: 'url' });
    if (!String(name || '').trim() || !passwort) throw Object.assign(new Error('Name und Passwort eines Kontos beim Partner eingeben'), { status: 400, feld: name ? 'passwort' : 'name' });
    const p = await this.anmelden(ziel, name, passwort);
    const pz = await p.anfrage('GET', '/api/spiegel');
    if (!pz || !pz.rolle) throw Object.assign(new Error('Der Partner kennt Haupt & Ersatz nicht – bitte dort zuerst FAH-Adblock aktualisieren'), { status: 502 });
    const ichLeer = istLeer(this.einst.werte);
    const partnerLeer = pz.leer === true;
    let uebernommen = null;
    if (rolle === 'haupt') {
      if (ichLeer && !partnerLeer) {
        const s = await p.anfrage('GET', '/api/sicherung');
        this.anwenden(s.einstellungen, { pausen: true });
        uebernommen = 'vom Partner';
      }
      const { code } = this.hauptWerden();
      if (eigen !== this.eigeneUrl) this.eigeneUrl = eigen;
      await p.anfrage('POST', '/api/spiegel/ersatz', { url: eigen, code });
      this.z.ersatz = { ...(this.z.ersatz || {}), url: ziel, zeit: (this.z.ersatz && this.z.ersatz.zeit) || null, ip: (this.z.ersatz && this.z.ersatz.ip) || null };
      this.z.eigene_url = eigen; this.speichern();
    } else {
      if (pz.rolle === 'ersatz') await p.anfrage('POST', '/api/spiegel/loesen', {});
      const { code } = await p.anfrage('POST', '/api/spiegel/haupt', {});
      if (partnerLeer && !ichLeer) { await p.anfrage('POST', '/api/wiederherstellung', standVon(this.einst, this.version)); uebernommen = 'zum Partner'; }
      if (eigen !== this.eigeneUrl) this.eigeneUrl = eigen;
      await this.ersatzWerden(ziel, code);
      this.z.eigene_url = eigen; this.speichern();
    }
    return { rolle, partner: ziel, uebernommen, status: this.status() };
  }

  /** Ersatz: Stand des Haupts holen und bei Änderung übernehmen. Fehler bleiben im Status (Hinweis in der Oberfläche). */
  async abgleichen() {
    if (!this.istErsatz()) return this.status();
    if (this.laeuft) return this.laeuft;
    this.laeuft = (async () => {
      try {
        const stand = await this.holenFn(this.z.haupt_url, entschluesseln(this.z.code, this.geheimnis), undefined, this.eigeneUrl);
        if (!stand || stand.art !== 'fah-adblock-sicherung' || !stand.einstellungen) throw new Error('Der Haupt liefert keine Einstellungen');
        if (istLeer(stand.einstellungen) && !istLeer(this.einst.werte)) throw new Error(LEER_TEXT);
        const h = hash(JSON.stringify(stand.einstellungen));
        if (h !== this.z.stand_hash) { this.anwenden(stand.einstellungen, { pausen: true }); this.z.stand_hash = h; this.z.letzte_aenderung = this.jetzt(); }
        this.z.letzter_abgleich = this.jetzt(); this.z.fehler = null;
        // Kinderschutz: eigene Ereignisse und Nutzung an den Haupt, dessen „aufgebraucht“ übernehmen (Fehler stören den Abgleich nicht)
        if (this.austausch) {
          const daten = this.austausch.sammeln(), code = entschluesseln(this.z.code, this.geheimnis);
          try { this.austausch.uebernehmen(await this.sendenFn(this.z.haupt_url, code, daten), code); this.z.meldung_fehler = null; }
          catch (e) { this.austausch.zurueck?.(daten); this.z.meldung_fehler = e.message; }
        }
      } catch (e) { this.z.fehler = e.message; if (e.antwort) this.z.haupt_gesehen = this.jetzt(); }
      this.speichern();
      return this.status();
    })();
    try { return await this.laeuft; } finally { this.laeuft = null; }
  }
  starten() {
    this.stoppen();
    if (!this.istErsatz()) return;
    this.timer = setInterval(() => { this.abgleichen().catch(() => {}); }, ABGLEICH_MS);
    if (this.timer.unref) this.timer.unref();
  }
  stoppen() { if (this.timer) clearInterval(this.timer); this.timer = null; }
}

module.exports = { Spiegel, standVon, holen, senden, istLeer, partnerAnmelden, ABGLEICH_MS };
