// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Benachrichtigungen aufs Handy (Kinderschutz, 24.11.2026) – zusätzlich zur Liste in FAH-Adblock, beide Wege freiwillig:
//   · Web-Push: FAH-Adblock als App auf dem Home-Bildschirm (iPhone ab iOS 16.4, Android, Desktop-Browser) – ohne Fremd-App.
//     Verschlüsselung nach RFC 8291 (aes128gcm), Absenderkennung nach RFC 8292 (VAPID) – nur Node-Bordmittel.
//   · ntfy: Thema in der ntfy-App abonnieren (ntfy.sh oder eigener Server).
// Ist nichts eingerichtet, bleibt es bei der Liste in FAH-Adblock. Nach draußen gehen nur Titel und kurzer Text, nie die
// aufgerufenen Seiten. Daten: data/benachrichtigung.json (0600), Geheimnisse darin mit dem Instanz-Geheimnis verschlüsselt.
// Haupt/Ersatz: eingerichtet wird am Haupt; der Ersatz bekommt alles beim Abgleich verschlüsselt (Paket des Schutzes
// unterwegs) und sendet nur, solange er für den ausgefallenen Haupt einspringt.
'use strict';
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const net = require('net');
const { lookup } = require('./aufloeser');
const { verschluesseln, entschluesseln } = require('./einstellungen');

const b64 = (x) => Buffer.from(x).toString('base64url');
const vonB64 = (t) => Buffer.from(String(t || ''), 'base64url');
// Nur die Push-Dienste der Browser – sonst könnte ein Abo FAH-Adblock beliebige Adressen aufrufen lassen
const PUSH_HOSTS = [/^web\.push\.apple\.com$/, /^fcm\.googleapis\.com$/, /^updates\.push\.services\.mozilla\.com$/, /^[a-z0-9-]+\.notify\.windows\.com$/];
const MAX_ABOS = 20;
const NTFY_THEMA = /^[A-Za-z0-9_-]{12,64}$/;
const NTFY_URL = /^https?:\/\/[^\s/]+(\/[^\s]*)?$/i;
// Nur echte IP-Adressen zählen als „eigenes Netz“ (ein Name wie 10.irgendwas.example wäre umgehbar)
const privatIp = (h) => net.isIPv4(h) && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h);
const gesperrtIp = (h) => (net.isIPv4(h) && /^(127\.|169\.254\.|0\.)/.test(h)) || h === 'localhost' || h === '[::1]' || /^\[?(fe80|::1)/i.test(h);
const NEUTRAL_SUB = 'https://fah-adblock.example.org';   // Absenderkennung für die Push-Dienste – verrät weder Hostnamen noch E-Mail
/** ntfy-Adresse: https überall, http nur an eine private IP im Heimnetz; nie Loopback/Link-Local */
function ntfyUrlPruefen(u) {
  if (!NTFY_URL.test(u)) throw new Error('ntfy-Adresse als https://… angeben (z. B. https://ntfy.sh); http nur für einen ntfy-Server im Heimnetz per IP');
  const x = new URL(u);
  if (x.username || x.password || gesperrtIp(x.hostname)) throw new Error('Diese ntfy-Adresse ist nicht erlaubt');
  if (x.protocol === 'http:' && !privatIp(x.hostname)) throw new Error('http nur für einen ntfy-Server im Heimnetz per IP (z. B. http://192.168.1.20) – sonst https://');
  return x;
}

/** RFC 8291: Nachricht für ein Abo verschlüsseln (ein Datensatz, aes128gcm). Optional feste Schlüssel/Salz für den Prüfvektor. */
function pushVerschluesseln(uaPublic, authSecret, klartext, { asPrivat = null, salz = null } = {}) {
  const ua = Buffer.from(uaPublic), auth = Buffer.from(authSecret);
  if (ua.length !== 65 || ua[0] !== 4) throw new Error('Push-Abo: Schlüssel p256dh ungültig');
  if (auth.length !== 16) throw new Error('Push-Abo: auth ungültig');
  const ecdh = crypto.createECDH('prime256v1');
  if (asPrivat) ecdh.setPrivateKey(Buffer.from(asPrivat)); else ecdh.generateKeys();
  const asPublic = ecdh.getPublicKey(), geteilt = ecdh.computeSecret(ua);
  const ikm = Buffer.from(crypto.hkdfSync('sha256', geteilt, auth, Buffer.concat([Buffer.from('WebPush: info\0'), ua, asPublic]), 32));
  const salt = salz ? Buffer.from(salz) : crypto.randomBytes(16);
  const cek = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: aes128gcm\0'), 16));
  const nonce = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from('Content-Encoding: nonce\0'), 12));
  const c = crypto.createCipheriv('aes-128-gcm', cek, nonce);
  const inhalt = Buffer.concat([c.update(Buffer.concat([Buffer.from(klartext), Buffer.from([2])])), c.final(), c.getAuthTag()]);
  const kopf = Buffer.alloc(21); salt.copy(kopf, 0); kopf.writeUInt32BE(4096, 16); kopf[20] = asPublic.length;
  return Buffer.concat([kopf, asPublic, inhalt]);
}

/** RFC 8292: Authorization-Kopf für einen Push-Dienst */
function vapidKopf(endpunkt, schluessel, sub, jetzt = Date.now()) {
  const aud = new URL(endpunkt).origin;
  const teil = `${b64(JSON.stringify({ typ: 'JWT', alg: 'ES256' }))}.${b64(JSON.stringify({ aud, exp: Math.floor(jetzt / 1000) + 12 * 3600, sub }))}`;
  const sig = crypto.sign('sha256', Buffer.from(teil), { key: schluessel.privat, dsaEncoding: 'ieee-p1363' });
  return `vapid t=${teil}.${b64(sig)}, k=${schluessel.oeffentlich}`;
}

function endpunktOk(e) {
  try { const u = new URL(String(e)); return u.protocol === 'https:' && !u.port && !u.username && !u.password && PUSH_HOSTS.some((r) => r.test(u.hostname)) && String(e).length <= 1024; } catch (x) { return false; }
}

function anfrage(url, { methode = 'POST', kopf = {}, daten = null, zeitlimit = 15000 } = {}) {
  return new Promise((ok, nein) => {
    let fertig = false;
    const ende = (fn, x) => { if (fertig) return; fertig = true; clearTimeout(frist); fn(x); };
    const u = new URL(url), mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, { method: methode, lookup, timeout: zeitlimit, headers: { 'User-Agent': 'FAH-Adblock', ...kopf, ...(daten ? { 'Content-Length': Buffer.byteLength(daten) } : {}) } }, (res) => {
      let t = ''; res.on('data', (d) => { if (t.length < 2000) t += d; });
      res.on('end', () => ende(ok, { status: res.statusCode, text: t }));
      res.on('aborted', () => ende(nein, new Error('Verbindung abgebrochen')));
      res.on('error', (e) => ende(nein, e));
      res.on('close', () => ende(nein, new Error('Verbindung abgebrochen')));
    });
    // Harte Gesamtfrist – die Leerlaufzeit allein reicht nicht (ein Server kann tröpfchenweise antworten)
    const frist = setTimeout(() => { req.destroy(); ende(nein, new Error('Zeitüberschreitung')); }, zeitlimit);
    req.on('timeout', () => req.destroy(new Error('Zeitüberschreitung')));
    req.on('error', (e) => ende(nein, e));
    req.end(daten || undefined);
  });
}

class Benachrichtigung {
  constructor({ verzeichnis, geheimnis, istErsatz = () => false, jetzt = () => Date.now(), anfrager = anfrage, protokoll = (t) => console.log(`[benachrichtigung] ${t}`) }) {
    Object.assign(this, { datei: path.join(verzeichnis, 'benachrichtigung.json'), geheimnis, istErsatz, jetzt, anfrager, protokoll });
    this.z = { ntfy: { url: 'https://ntfy.sh', thema: '', schluessel: null }, vapid: null, abos: [], vomHaupt: false };
    this.stand = {};   // aboId → {zuletzt, fehler}  (nur Laufzeit, geht nicht an den Ersatz)
    this.ntfyFehler = null; this.ntfyZuletzt = null;
    try { const z = JSON.parse(fs.readFileSync(this.datei, 'utf8')); if (z && typeof z === 'object') this.z = { ...this.z, ...z, ntfy: { ...this.z.ntfy, ...(z.ntfy || {}) }, abos: Array.isArray(z.abos) ? z.abos : [] }; } catch (e) {}
  }
  speichern() {
    try { fs.writeFileSync(this.datei + '.tmp', JSON.stringify(this.z), { mode: 0o600 }); fs.renameSync(this.datei + '.tmp', this.datei); } catch (e) { this.protokoll(`speichern: ${e.message}`); }
  }
  // ── Schlüssel ──
  schluessel() {
    if (!this.z.vapid) {
      if (this.istErsatz()) return null;   // der Ersatz nimmt den Schlüssel des Haupt (Abos hängen daran)
      const j = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });
      this.z.vapid = { d: verschluesseln(j.d, this.geheimnis), x: j.x, y: j.y }; this.speichern();
    }
    const v = this.z.vapid, d = entschluesseln(v.d, this.geheimnis);
    if (!d) {
      if (this.istErsatz()) return null;
      // Haupt: Schlüssel nicht mehr lesbar (z. B. neues Instanz-Geheimnis) → neu erzeugen; alte Abos hängen am alten Schlüssel
      this.protokoll('Push-Schlüssel nicht mehr lesbar – neu erzeugt, Geräte bitte Push neu einschalten');
      this.z.vapid = null; this.z.abos = []; this.stand = {}; return this.schluessel();
    }
    return { privat: crypto.createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d, x: v.x, y: v.y }, format: 'jwk' }), oeffentlich: b64(Buffer.concat([Buffer.from([4]), vonB64(v.x), vonB64(v.y)])) };
  }
  oeffentlicherSchluessel() { return this.schluessel()?.oeffentlich || null; }
  // ── Einrichtung ──
  ntfySetzen({ url, thema, schluessel, schluesselLoeschen } = {}) {
    const n = this.z.ntfy;
    if (url !== undefined) { const u = String(url || '').trim().replace(/\/+$/, '') || 'https://ntfy.sh'; ntfyUrlPruefen(u); if (new URL(u).origin !== (() => { try { return new URL(n.url).origin; } catch (e) { return ''; } })()) n.schluessel = null; n.url = u; }
    if (thema !== undefined) {
      const t = String(thema || '').trim();
      if (t && !NTFY_THEMA.test(t)) throw new Error('Thema: 12–64 Zeichen aus Buchstaben, Ziffern, - und _ – schwer erratbar, wer es kennt, liest mit');
      // Auf dem öffentlichen ntfy.sh kann jeder mitlesen, der das Thema errät – dort mindestens 20 Zeichen (🎲 erzeugt 24)
      if (t && t.length < 20 && /(^|\.)ntfy\.sh$/i.test(new URL(n.url).hostname)) throw new Error('Auf ntfy.sh kann jeder mitlesen, der das Thema errät – bitte mindestens 20 Zeichen (🎲 erzeugt ein sicheres)');
      n.thema = t;
    }
    if (schluessel) { if (!/^[A-Za-z0-9_\-.]{8,200}$/.test(schluessel)) throw new Error('Zugangsschlüssel hat ein unerwartetes Format'); n.schluessel = verschluesseln(schluessel, this.geheimnis); }
    else if (schluesselLoeschen) n.schluessel = null;
    this.speichern();
  }
  aboHinzufuegen({ abo, name, sub }) {
    const endpoint = abo?.endpoint, p256dh = vonB64(abo?.keys?.p256dh), auth = vonB64(abo?.keys?.auth);
    if (!endpunktOk(endpoint)) throw new Error('Dieser Push-Dienst wird nicht unterstützt (erlaubt: Apple, Google, Mozilla, Microsoft)');
    if (p256dh.length !== 65 || p256dh[0] !== 4 || auth.length !== 16) throw new Error('Push-Abo unvollständig');
    const vorhanden = this.z.abos.find((a) => a.endpoint === endpoint);
    if (!vorhanden && this.z.abos.length >= MAX_ABOS) throw new Error(`Höchstens ${MAX_ABOS} Geräte – erst eines entfernen`);
    const eintrag = { id: vorhanden?.id || crypto.randomBytes(8).toString('hex'), name: String(name || 'Gerät').replace(/[\u0000-\u001f<>]/g, '').slice(0, 60) || 'Gerät', endpoint, p256dh: b64(p256dh), auth: b64(auth), sub: NEUTRAL_SUB, seit: vorhanden?.seit || this.jetzt() };
    this.z.abos = [...this.z.abos.filter((a) => a.endpoint !== endpoint), eintrag];
    delete this.stand[eintrag.id];
    this.speichern();
    return eintrag.id;
  }
  aboEntfernen(id) { const vorher = this.z.abos.length; this.z.abos = this.z.abos.filter((a) => a.id !== id); delete this.stand[id]; if (this.z.abos.length !== vorher) this.speichern(); return this.z.abos.length !== vorher; }
  eingerichtet() { return !!(this.z.ntfy.thema || this.z.abos.length); }
  // ── Senden ──
  async ntfy({ titel, text, ernst }) {
    const n = this.z.ntfy; if (!n.thema) return null;
    const u = ntfyUrlPruefen(n.url), schluessel = entschluesseln(n.schluessel, this.geheimnis);
    // Der Zugangsschlüssel geht nur verschlüsselt (https) oder an einen Server im eigenen Netz (private IP)
    if (schluessel && u.protocol !== 'https:' && !privatIp(u.hostname)) throw new Error('Zugangsschlüssel nur über https – Adresse auf https:// umstellen');
    const daten = JSON.stringify({ topic: n.thema, title: titel, message: text, tags: [ernst ? 'warning' : 'information_source'], priority: ernst ? 4 : 3 });
    const r = await this.anfrager(n.url, { kopf: { 'Content-Type': 'application/json', ...(schluessel ? { Authorization: `Bearer ${schluessel}` } : {}) }, daten });
    if (r.status < 200 || r.status >= 300) throw new Error(`ntfy antwortet mit HTTP ${r.status}${r.text ? `: ${r.text.slice(0, 120)}` : ''}`);
    return true;
  }
  async pushAn(abo, nachricht, schluessel) {
    const daten = pushVerschluesseln(vonB64(abo.p256dh), vonB64(abo.auth), JSON.stringify(nachricht));
    const r = await this.anfrager(abo.endpoint, { kopf: { 'Content-Type': 'application/octet-stream', 'Content-Encoding': 'aes128gcm', TTL: '86400', Urgency: nachricht.ernst ? 'high' : 'normal', Authorization: vapidKopf(abo.endpoint, schluessel, NEUTRAL_SUB, this.jetzt()) }, daten });
    if (r.status === 404 || r.status === 410) { this.protokoll(`Push-Abo „${abo.name}“ ist abgelaufen – entfernt`); this.aboEntfernen(abo.id); return false; }
    if (r.status < 200 || r.status >= 300) throw new Error(`Push-Dienst antwortet mit HTTP ${r.status}${r.text ? `: ${r.text.slice(0, 120)}` : ''}`);
    return true;
  }
  /** Eine Meldung an alle eingerichteten Wege. Ergebnis: {ntfy: true|false|null, push: Anzahl erreicht, fehler: [..]} */
  async senden({ titel, text, ernst = false, tag = '' }, { nurAbo = null } = {}) {
    const erg = { ntfy: null, push: 0, fehler: [] };
    const abos = nurAbo ? this.z.abos.filter((a) => a.id === nurAbo) : [...this.z.abos];
    if (this.z.ntfy.thema && !nurAbo) {
      try { erg.ntfy = await this.ntfy({ titel, text, ernst }); this.ntfyFehler = null; this.ntfyZuletzt = this.jetzt(); }
      catch (e) { erg.ntfy = false; this.ntfyFehler = e.message; erg.fehler.push(`ntfy: ${e.message}`); this.protokoll(`ntfy: ${e.message}`); }
    }
    if (abos.length) {
      // ältere Abos trugen den Hostnamen als Absenderkennung – immer neutral senden
      const schluessel = this.schluessel();
      if (!schluessel) erg.fehler.push('Push: Schlüssel fehlt (Ersatz wartet auf den Abgleich mit dem Haupt)');
      else {
        const nachricht = { titel: String(titel).slice(0, 200), text: String(text).slice(0, 1000), ernst: !!ernst, tag: String(tag).slice(0, 64), url: './#kinderschutz' };
        await Promise.all(abos.map(async (abo) => {
          try { if (await this.pushAn(abo, nachricht, schluessel)) { erg.push++; this.stand[abo.id] = { zuletzt: this.jetzt(), fehler: null }; } }
          catch (e) { this.stand[abo.id] = { ...(this.stand[abo.id] || {}), fehler: e.message }; erg.fehler.push(`Push ${abo.name}: ${e.message}`); this.protokoll(`Push an ${abo.name}: ${e.message}`); }
        }));
      }
    }
    return erg;
  }
  async test(id = null) {
    if (!this.eingerichtet()) throw new Error('Noch kein Weg eingerichtet – Push auf diesem Gerät einschalten oder ein ntfy-Thema eintragen');
    if (id && !this.z.abos.some((a) => a.id === id)) throw new Error('Gerät nicht gefunden');
    return this.senden({ titel: 'FAH-Adblock: Testnachricht', text: 'Die Benachrichtigungen kommen an. So sieht eine Meldung des Kinderschutzes aus.', tag: 'test' }, { nurAbo: id });
  }
  status() {
    return {
      vomHaupt: !!this.z.vomHaupt, ersatz: this.istErsatz(),
      ntfy: { url: this.z.ntfy.url, thema: this.z.ntfy.thema, schluesselGesetzt: !!entschluesseln(this.z.ntfy.schluessel, this.geheimnis), fehler: this.ntfyFehler, zuletzt: this.ntfyZuletzt },
      push: { schluessel: this.oeffentlicherSchluessel(), abos: this.z.abos.map((a) => ({ id: a.id, name: a.name, seit: a.seit, dienst: new URL(a.endpoint).hostname, kennung: crypto.createHash('sha256').update(a.endpoint).digest('hex').slice(0, 16), zuletzt: this.stand[a.id]?.zuletzt || null, fehler: this.stand[a.id]?.fehler || null })) },
    };
  }
  // ── Haupt/Ersatz (über das verschlüsselte Paket des Schutzes unterwegs) ──
  fuerErsatz() {
    if (this.istErsatz()) return null;
    const v = this.schluessel() && this.z.vapid ? { d: entschluesseln(this.z.vapid.d, this.geheimnis), x: this.z.vapid.x, y: this.z.vapid.y } : null;
    return { ntfy: { url: this.z.ntfy.url, thema: this.z.ntfy.thema, schluessel: entschluesseln(this.z.ntfy.schluessel, this.geheimnis) || '' }, vapid: v, abos: this.z.abos.map(({ id, name, endpoint, p256dh, auth, sub, seit }) => ({ id, name, endpoint, p256dh, auth, sub, seit })) };
  }
  vomHaupt(x) {
    if (!x || typeof x !== 'object' || !this.istErsatz()) return false;
    const n = x.ntfy || {}, url = (() => { try { ntfyUrlPruefen(String(n.url || '')); return String(n.url); } catch (e) { return 'https://ntfy.sh'; } })();
    const abos = (Array.isArray(x.abos) ? x.abos : []).slice(0, MAX_ABOS).filter((a) => a && endpunktOk(a.endpoint) && vonB64(a.p256dh).length === 65 && vonB64(a.auth).length === 16 && /^[a-f0-9]{16}$/.test(String(a.id)))
      .map((a) => ({ id: a.id, name: String(a.name || 'Gerät').replace(/[\u0000-\u001f<>]/g, '').slice(0, 60) || 'Gerät', endpoint: a.endpoint, p256dh: a.p256dh, auth: a.auth, sub: NEUTRAL_SUB, seit: Number(a.seit) || this.jetzt() }));
    let vapid = null;
    if (x.vapid && /^[A-Za-z0-9_-]{43}$/.test(String(x.vapid.d)) && /^[A-Za-z0-9_-]{43}$/.test(String(x.vapid.x)) && /^[A-Za-z0-9_-]{43}$/.test(String(x.vapid.y))) {
      try { crypto.createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d: x.vapid.d, x: x.vapid.x, y: x.vapid.y }, format: 'jwk' }); vapid = { d: verschluesseln(x.vapid.d, this.geheimnis), x: x.vapid.x, y: x.vapid.y }; } catch (e) {}
    }
    this.z = { ntfy: { url, thema: NTFY_THEMA.test(String(n.thema || '')) ? String(n.thema) : '', schluessel: n.schluessel && /^[A-Za-z0-9_\-.]{8,200}$/.test(n.schluessel) ? verschluesseln(n.schluessel, this.geheimnis) : null }, vapid, abos, vomHaupt: true };
    this.speichern();
    return true;
  }
}

module.exports = { Benachrichtigung, pushVerschluesseln, vapidKopf, endpunktOk, ntfyUrlPruefen, PUSH_HOSTS, anfrageFuerTest: anfrage };
