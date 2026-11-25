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
// Seit 25.11.2026 (Prüfung K2) geht der Code beim ABGLEICH nie über die Leitung – Ablauf siehe „Transport v2“ unten. Beim einmaligen Koppeln
// (hauptWerden/ersatzWerden, partnerKoppeln) wird er weiterhin einmal über die Oberfläche übertragen – dort also nur im eigenen Netz koppeln.
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

// ── Transport v2 (25.11.2026, Prüfung K2) ───────────────────────────────────────────────────────────────────────────────────
// Vorher schickte der Ersatz alle 2 min den Kopplungscode als „Bearer“ über http, der Stand (samt DoH-Geheimnissen der Geräte) kam im
// Klartext zurück – wer im LAN einmal mitlas, konnte sich danach selbst als Ersatz ausgeben. Jetzt:
// • Schlüssel K = sha256(Code) – am Haupt verschlüsselt gespeichert (data/spiegel.json, Feld k). Beim Abgleich verlässt der Code den Ersatz nie.
// • Jede Anfrage trägt Zeitstempel, Einmalwert (Nonce) und einen frischen X25519-Schlüssel des Ersatzes, alles per HMAC-SHA256(K) signiert.
//   Der Haupt lehnt Anfragen ab, die älter als 5 min sind oder deren Nonce er schon gesehen hat (keine Wiederholung).
// • Daten des Ersatzes (Meldungen, Zeitkonto) gehen AES-256-GCM-verschlüsselt mit HKDF(K, Nonce).
// • Die Antwort des Haupts (ganzer Stand bzw. Austausch) ist an den Einmalschlüssel des Ersatzes verschlüsselt: X25519 + HKDF mit K als Salz,
//   AES-256-GCM, gebunden an Nonce und beide öffentlichen Schlüssel. Ohne K lässt sie sich weder lesen noch fälschen, eine alte Antwort passt
//   nie zu einer neuen Anfrage, und ein später bekannt gewordener Code öffnet mitgeschnittene Antworten nicht (Vorwärtsgeheimnis).
const PROTOKOLL = 'fah-adblock-spiegel-v2', FENSTER_MS = 5 * 60000;
const ALT_TEXT = 'Der Ersatz nutzt die alte Kopplung (vor 2026.11.25-2) – bitte Haupt und Ersatz auf dieselbe Version aktualisieren';
const schluesselVonCode = (code) => crypto.createHash('sha256').update(String(code)).digest();
const hkdf = (ikm, salz, info) => Buffer.from(crypto.hkdfSync('sha256', ikm, salz, info, 32));
const pubDer = (k) => k.export({ format: 'der', type: 'spki' }).toString('base64');
const pubAusText = (b64) => crypto.createPublicKey({ key: Buffer.from(String(b64), 'base64'), format: 'der', type: 'spki' });
function aesZu(schluessel, aad, text) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', schluessel, iv, { authTagLength: 16 }); c.setAAD(Buffer.from(aad));
  const d = Buffer.concat([c.update(text, 'utf8'), c.final()]);
  return `${iv.toString('base64')}.${c.getAuthTag().toString('base64')}.${d.toString('base64')}`;
}
function aesAuf(schluessel, aad, kiste) {
  const [iv, tag, d] = String(kiste).split('.');
  if (!iv || !tag || d === undefined) throw new Error('Umschlag beschädigt');
  const x = crypto.createDecipheriv('aes-256-gcm', schluessel, Buffer.from(iv, 'base64'), { authTagLength: 16 }); x.setAAD(Buffer.from(aad)); x.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([x.update(Buffer.from(d, 'base64')), x.final()]).toString('utf8');
}
const signatur = (K, pfad, u) => crypto.createHmac('sha256', K).update([PROTOKOLL, pfad, u.ts, u.n, u.k, u.url || '', u.daten || ''].join('\n')).digest('base64url');
const anfrageSchluessel = (K, u) => hkdf(K, Buffer.from(u.n), 'fah-adblock-spiegel-anfrage-v2');
const antwortSchluessel = (geteilt, K) => hkdf(geteilt, K, 'fah-adblock-spiegel-antwort-v2');

/** Ersatz: signierten Umschlag für `pfad` bauen (optional mit verschlüsselten Daten) → {umschlag, oeffnen(antwort)} */
function umschlagBauen(K, pfad, daten, url = '', jetzt = Date.now()) {
  const eph = crypto.generateKeyPairSync('x25519');
  const u = { v: 2, ts: jetzt, n: crypto.randomBytes(18).toString('base64url'), k: pubDer(eph.publicKey), url: String(url || '') };
  if (daten !== undefined) u.daten = aesZu(anfrageSchluessel(K, u), `${u.ts}|${u.n}|${u.k}`, JSON.stringify(daten));
  u.s = signatur(K, pfad, u);
  const oeffnen = (a) => {
    if (!a || a.v !== 2 || typeof a.pub !== 'string' || a.pub.length > 200 || typeof a.daten !== 'string') throw new Error('Antwort des Haupts im falschen Format');
    let text;
    try { text = aesAuf(antwortSchluessel(crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: pubAusText(a.pub) }), K), `${u.k}|${a.pub}|${u.n}`, a.daten); }
    catch (e) { throw new Error('Antwort des Haupts nicht entschlüsselbar – falscher Kopplungscode oder unterwegs verändert'); }
    return JSON.parse(text);
  };
  return { umschlag: u, oeffnen };
}

/** Ersatz → Haupt: POST mit Umschlag, Antwort entschlüsselt. Hat der Haupt per HTTP geantwortet, trägt der Fehler `antwort: true`. */
function spiegelAnfrage(url, pfad, code, daten, { zeitlimit_ms = 10000, eigene = '', max = 5e6, jetzt = Date.now() } = {}) {
  return new Promise((ok, nein) => {
    let u; try { u = new URL(pfad, url); } catch (e) { return nein(new Error('Adresse des Haupts ungültig')); }
    const { umschlag, oeffnen } = umschlagBauen(schluesselVonCode(code), pfad, daten, eigene, jetzt);
    const mod = u.protocol === 'https:' ? https : http, text = JSON.stringify(umschlag);
    const req = mod.request(u, { method: 'POST', headers: { 'User-Agent': 'FAH-Adblock-Ersatz', 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) }, timeout: zeitlimit_ms, rejectUnauthorized: false }, (res) => {
      const nein0 = nein; nein = (e) => nein0(Object.assign(e, { antwort: true }));   // der Haupt läuft – er hat geantwortet
      let t = ''; res.setEncoding('utf8');
      res.on('data', (d) => { t += d; if (t.length > max) req.destroy(new Error('Antwort zu groß')); });
      res.on('end', () => {
        let j = null; try { j = JSON.parse(t); } catch (e) {}
        if (res.statusCode === 401 || res.statusCode === 403) return nein(new Error(j?.fehler ? `Der Haupt lehnt ab: ${j.fehler}` : 'Der Haupt lehnt den Kopplungscode ab'));
        if (res.statusCode === 409) return nein(new Error(j?.fehler || 'Die Gegenstelle ist kein Haupt'));
        if (res.statusCode === 404 || res.statusCode === 405) return nein(new Error('Der Haupt kennt die neue Kopplung nicht – bitte Haupt und Ersatz auf dieselbe Version aktualisieren'));
        if (res.statusCode !== 200) return nein(new Error(`Haupt antwortet mit HTTP ${res.statusCode}`));
        if (!j) return nein(new Error('Antwort des Haupts ist kein JSON'));
        // Entschlüsseln scheitert = Antwort nicht vom Haupt (falscher Code oder verändert) → zählt NICHT als „Haupt gesehen“
        try { ok(oeffnen(j)); } catch (e) { nein0(e); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('Haupt antwortet nicht (Zeitüberschreitung)')));
    req.on('error', (e) => nein(e.code === 'ECONNREFUSED' ? new Error('Haupt nicht erreichbar (Verbindung abgewiesen)') : e));
    req.end(text);
  });
}
/** Stand des Haupts holen (Ersatz). `eigene` = Adresse dieses Ersatzes (der Haupt merkt sie sich). */
const holen = (url, code, zeitlimit_ms = 10000, eigene = '') => spiegelAnfrage(url, '/api/spiegel/stand', code, undefined, { zeitlimit_ms, eigene });
/** Meldungen, Zeitkonto, „zuletzt gesehen“ an den Haupt (Ersatz) → Antwort des Haupts */
const senden = (url, code, daten, zeitlimit_ms = 10000) => spiegelAnfrage(url, '/api/spiegel/meldung', code, daten || {}, { zeitlimit_ms, max: 1e6 });

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
    // Seit Transport v2 IST sha256(Code) der Schlüssel – am Haupt deshalb nur noch verschlüsselt gespeichert (mit dem Geheimnis der Instanz).
    // Ältere spiegel.json mit Klartext-Hash werden beim Start einmal umgestellt.
    if (this.z.code_hash && !this.z.k) { this.z.k = verschluesseln(this.z.code_hash, this.geheimnis); delete this.z.code_hash; try { this.speichern(); } catch (e) {} }
    this.timer = null; this.laeuft = null;
    this.nonces = new Map();   // Haupt: zuletzt gesehene Einmalwerte des Ersatzes (Schutz gegen Wiederholung), älteste zuerst
    this.gestartet = this.jetzt();   // die Einmalwerte liegen nur im Speicher → Umschläge von vor dem Start werden abgelehnt (keine Wiederholung nach Neustart)
  }
  speichern() { fs.writeFileSync(this.datei + '.tmp', JSON.stringify(this.z, null, 1), { mode: 0o600 }); fs.renameSync(this.datei + '.tmp', this.datei); }
  get rolle() { return this.z.rolle || 'allein'; }
  /** Haupt: K = sha256(Kopplungscode) als 32 Byte (leer, wenn nicht gekoppelt oder nicht entschlüsselbar) */
  schluesselHaupt() { const h = this.z.k ? entschluesseln(this.z.k, this.geheimnis) : ''; return /^[0-9a-f]{64}$/.test(h || '') ? Buffer.from(h, 'hex') : Buffer.alloc(0); }
  /** Wann der Haupt sich zuletzt ausgewiesen hat (Antwort ließ sich mit dem Kopplungsschlüssel öffnen) – für die Übernahme. Unsignierte
   *  Fehlerantworten zählen nicht: sonst könnte ein Dritter im LAN mit gefälschtem 401/409 die Übernahme dauerhaft verhindern (25.11.2026). */
  hauptZuletzt() { return Math.max(this.z.letzter_abgleich || 0, this.z.haupt_gesehen || 0); }
  istErsatz() { return this.rolle === 'ersatz'; }
  status() {
    const z = this.z;
    return { rolle: this.rolle, haupt_url: z.haupt_url || null, letzter_abgleich: z.letzter_abgleich || null, letzte_aenderung: z.letzte_aenderung || null,
      fehler: z.fehler || null, ersatz: z.ersatz || null, code_gesetzt: !!(z.k || z.code_hash), leer: istLeer(this.einst.werte), eigene_url: this.eigeneUrl || null,
      partner_url: this.rolle === 'ersatz' ? z.haupt_url || null : this.rolle === 'haupt' ? (z.ersatz && z.ersatz.url) || null : null };
  }

  /** Diese Instanz wird Haupt: neuer Kopplungscode (nur jetzt sichtbar, gespeichert wird der Hash). */
  hauptWerden() {
    const code = crypto.randomBytes(18).toString('base64url');
    this.z = { rolle: 'haupt', k: verschluesseln(hash(code), this.geheimnis), ersatz: this.z.rolle === 'haupt' ? this.z.ersatz || null : null };
    this.speichern(); this.stoppen();
    return { code };
  }
  /** Haupt: Umschlag des Ersatzes prüfen (Rolle, Format, Zeitfenster, Signatur, Wiederholung) → {K, daten}. Wirft mit status 400/401/409. */
  umschlagPruefen(pfad, u) {
    const f = (status, text) => { throw Object.assign(new Error(text), { status }); };
    if (this.rolle !== 'haupt') f(409, 'Diese Instanz ist kein Haupt');
    if (!u || typeof u !== 'object' || u.v !== 2) f(409, ALT_TEXT);
    if (!Number.isFinite(u.ts) || typeof u.n !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(u.n) || typeof u.k !== 'string' || u.k.length > 200 || typeof u.s !== 'string' || u.s.length > 100
      || (u.url !== undefined && (typeof u.url !== 'string' || u.url.length > 300)) || (u.daten !== undefined && (typeof u.daten !== 'string' || u.daten.length > 4e6))) f(400, 'Anfrage des Ersatzes ungültig');
    const K = this.schluesselHaupt();
    if (K.length !== 32 || !gleich(signatur(K, pfad, u), u.s)) f(401, 'Kopplungscode falsch');
    // erst NACH gültiger Signatur: Zeitfenster und Wiederholung (sonst könnte ein Fremder den Nonce-Speicher füllen)
    const jetzt = this.jetzt();
    if (Math.abs(jetzt - u.ts) > FENSTER_MS) f(401, 'Uhrzeit von Haupt und Ersatz weicht über 5 Minuten ab – Zeit (NTP) beider Geräte prüfen');
    if (u.ts < this.gestartet) f(401, 'Anfrage von vor dem Neustart des Haupts – abgelehnt (nächster Abgleich klappt)');
    for (const [n, t] of this.nonces) { if (jetzt - t > 2 * FENSTER_MS || this.nonces.size > 5000) this.nonces.delete(n); else break; }
    if (this.nonces.has(u.n)) f(401, 'Anfrage wiederholt – abgelehnt');
    this.nonces.set(u.n, jetzt);
    let daten = {};
    if (u.daten) { try { daten = JSON.parse(aesAuf(anfrageSchluessel(K, u), `${u.ts}|${u.n}|${u.k}`, u.daten)); } catch (e) { f(400, 'Daten des Ersatzes nicht lesbar'); } }
    try { pubAusText(u.k); } catch (e) { f(400, 'Schlüssel des Ersatzes ungültig'); }
    return { K, daten };
  }
  /** Haupt: Antwort an den Einmalschlüssel des Ersatzes verschlüsseln */
  antwortVerschluesseln(K, u, obj) {
    const eph = crypto.generateKeyPairSync('x25519'), pub = pubDer(eph.publicKey);
    const geteilt = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: pubAusText(u.k) });
    return { v: 2, pub, daten: aesZu(antwortSchluessel(geteilt, K), `${u.k}|${pub}|${u.n}`, JSON.stringify(obj)) };
  }
  /** Haupt: Abruf des Ersatzes prüfen und merken (für die Anzeige „zuletzt abgeholt“) → verschlüsselter Stand */
  standFuer(umschlag, ip) {
    const { K } = this.umschlagPruefen('/api/spiegel/stand', umschlag);
    let u = null; try { u = umschlag.url ? adresse(umschlag.url) : null; } catch (e) {}
    this.z.ersatz = { ip: ip || null, zeit: this.jetzt(), url: u || (this.z.ersatz && this.z.ersatz.url) || null }; this.speichern();
    return this.antwortVerschluesseln(K, umschlag, standVon(this.einst, this.version));
  }
  /** Haupt: Meldungen/Zeitkonto des Ersatzes annehmen (Kinderschutz) → verschlüsselte Antwort (aufgebrauchte Zeitlimits, Unterwegs-Paket) */
  meldungFuer(umschlag) {
    const { K, daten } = this.umschlagPruefen('/api/spiegel/meldung', umschlag);
    return this.antwortVerschluesseln(K, umschlag, this.austausch ? this.austausch.empfangen(daten || {}, K) : {});
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
      const code = entschluesseln(this.z.code, this.geheimnis);
      let stand = null;
      try {
        stand = await this.holenFn(this.z.haupt_url, code, undefined, this.eigeneUrl);
        // Der Haupt hat geantwortet und die Antwort ließ sich öffnen → er lebt, auch wenn die Prüfung unten scheitert (Prüfung K4: sonst übernahm
        // der Ersatz nach 6 min den Schutz unterwegs, obwohl der Haupt lief – z. B. wenn der Haupt schon neuer ist als der Ersatz)
        this.z.haupt_gesehen = this.jetzt();
        if (!stand || stand.art !== 'fah-adblock-sicherung' || !stand.einstellungen) throw new Error('Der Haupt liefert keine Einstellungen');
        if (istLeer(stand.einstellungen) && !istLeer(this.einst.werte)) throw new Error(LEER_TEXT);
        const h = hash(JSON.stringify(stand.einstellungen));
        if (h !== this.z.stand_hash) { this.anwenden(stand.einstellungen, { pausen: true }); this.z.stand_hash = h; this.z.letzte_aenderung = this.jetzt(); }
        this.z.letzter_abgleich = this.jetzt(); this.z.fehler = null;
      } catch (e) { this.z.fehler = e.message; }   // Fehlerantworten (401/404/409) sind nicht signiert und zählen NICHT als Lebenszeichen (Codex-Nachprüfung R2)
      // Kinderschutz: eigene Ereignisse und Nutzung an den Haupt, dessen „aufgebraucht“ übernehmen – auch wenn die Übernahme des Stands oben
      // scheiterte (K4), aber nur, wenn der Haupt erreichbar war und sich ausgewiesen hat. Fehler stören den Abgleich nicht.
      if (this.austausch && stand) {
        const daten = this.austausch.sammeln();
        try { this.austausch.uebernehmen(await this.sendenFn(this.z.haupt_url, code, daten), schluesselVonCode(code)); this.z.meldung_fehler = null; }
        catch (e) { this.austausch.zurueck?.(daten); this.z.meldung_fehler = e.message; }
      }
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

module.exports = { Spiegel, standVon, holen, senden, istLeer, partnerAnmelden, umschlagBauen, schluesselVonCode, ALT_TEXT, ABGLEICH_MS };
