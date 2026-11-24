// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// ACME-Client (RFC 8555) für die Zertifikate des Schutzes unterwegs (DNS-over-TLS braucht ein echtes Zertifikat je Gerätename).
// Nur Node-Bordmittel: ES256-Kontoschlüssel, JWS, HTTP-01, CSR in DER von Hand. Let's Encrypt prüft http://<name>/.well-known/
// acme-challenge/<token> – FAH-Proxy leitet den Namen an FAH-Adblock weiter (Umleitung auf https folgt Let's Encrypt).
// Daten: data/acme/konto.pem (Kontoschlüssel, 0600), data/acme/konto.json (Kontoadresse).
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const { lookup } = require('./aufloeser');

const LE = 'https://acme-v02.api.letsencrypt.org/directory';
const LE_TEST = 'https://acme-staging-v02.api.letsencrypt.org/directory';
const b64 = (x) => Buffer.from(x).toString('base64url');

// ── DER (nur was ein CSR braucht) ──
function laenge(n) { if (n < 128) return Buffer.from([n]); const b = []; while (n > 0) { b.unshift(n & 0xff); n >>= 8; } return Buffer.from([0x80 | b.length, ...b]); }
const tlv = (tag, ...inhalt) => { const c = Buffer.concat(inhalt.map((x) => Buffer.from(x))); return Buffer.concat([Buffer.from([tag]), laenge(c.length), c]); };
function oid(text) {
  const t = text.split('.').map(Number), b = [40 * t[0] + t[1]];
  for (const n of t.slice(2)) { const teil = [n & 0x7f]; let x = n >> 7; while (x > 0) { teil.unshift(0x80 | (x & 0x7f)); x >>= 7; } b.push(...teil); }
  return tlv(0x06, Buffer.from(b));
}
const seq = (...x) => tlv(0x30, ...x), menge = (...x) => tlv(0x31, ...x);

/** CSR (DER) für genau einen Namen, signiert mit dem Zertifikatsschlüssel (ECDSA P-256) */
function csr(host, schluessel) {
  const spki = crypto.createPublicKey(schluessel).export({ type: 'spki', format: 'der' });
  const name = seq(menge(seq(oid('2.5.4.3'), tlv(0x0c, Buffer.from(host, 'utf8')))));
  const san = seq(seq(oid('2.5.29.17'), tlv(0x04, seq(tlv(0x82, Buffer.from(host, 'ascii'))))));
  const attribute = tlv(0xa0, seq(oid('1.2.840.113549.1.9.14'), menge(san)));
  const info = seq(tlv(0x02, Buffer.from([0])), name, spki, attribute);
  const sig = crypto.sign('sha256', info, schluessel);   // DER-Signatur
  return seq(info, seq(oid('1.2.840.10045.4.3.2')), tlv(0x03, Buffer.concat([Buffer.from([0]), sig])));
}

function anfrage(url, { methode = 'GET', kopf = {}, daten = null, zeitlimit = 20000 } = {}) {
  return new Promise((ok, nein) => {
    const req = https.request(url, { method: methode, lookup, timeout: zeitlimit, headers: { 'User-Agent': 'FAH-Adblock-ACME', ...kopf, ...(daten ? { 'Content-Type': 'application/jose+json', 'Content-Length': Buffer.byteLength(daten) } : {}) } }, (res) => {
      const teile = []; let n = 0;
      res.on('data', (d) => { n += d.length; if (n > 2e6) req.destroy(new Error('ACME-Antwort zu groß')); else teile.push(d); });
      res.on('end', () => { const text = Buffer.concat(teile).toString('utf8'); let json = null; try { json = JSON.parse(text); } catch (e) {} ok({ status: res.statusCode, kopf: res.headers, text, json }); });
    });
    req.on('timeout', () => req.destroy(new Error('ACME: Zeitüberschreitung')));
    req.on('error', nein);
    req.end(daten || undefined);
  });
}

class Acme {
  constructor({ verzeichnis, verzeichnisUrl = process.env.ACME_DIRECTORY || LE, email = () => '', anfrager = anfrage, warten = (ms) => new Promise((r) => setTimeout(r, ms)), protokoll = (t) => console.log(`[acme] ${t}`) }) {
    Object.assign(this, { verzeichnis: path.join(verzeichnis, 'acme'), verzeichnisUrl, email, anfrager, warten, protokoll });
    this.herausforderungen = new Map();   // token → Schlüsselautorisierung (für /.well-known/acme-challenge/)
    this.dir = null; this.nonce = null; this.kid = null; this.schluessel = null;
  }
  antwort(token) { return this.herausforderungen.get(String(token)) || null; }
  kontoSchluessel() {
    if (this.schluessel) return this.schluessel;
    const datei = path.join(this.verzeichnis, 'konto.pem');
    fs.mkdirSync(this.verzeichnis, { recursive: true, mode: 0o700 });
    if (!fs.existsSync(datei)) fs.writeFileSync(datei, crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    this.schluessel = crypto.createPrivateKey(fs.readFileSync(datei));
    return this.schluessel;
  }
  jwk() { const j = crypto.createPublicKey(this.kontoSchluessel()).export({ format: 'jwk' }); return { crv: j.crv, kty: j.kty, x: j.x, y: j.y }; }
  daumen() { const j = this.jwk(); return b64(crypto.createHash('sha256').update(JSON.stringify({ crv: j.crv, kty: j.kty, x: j.x, y: j.y })).digest()); }
  async verzeichnisHolen() {
    if (!this.dir) { const r = await this.anfrager(this.verzeichnisUrl); if (r.status !== 200 || !r.json?.newNonce) throw new Error(`ACME-Verzeichnis nicht lesbar (HTTP ${r.status})`); this.dir = r.json; }
    return this.dir;
  }
  async frischeNonce() { const r = await this.anfrager((await this.verzeichnisHolen()).newNonce, { methode: 'HEAD' }); this.nonce = r.kopf['replay-nonce']; if (!this.nonce) throw new Error('ACME: keine Nonce'); }
  /** Signierte Anfrage (payload null = POST-as-GET). Wiederholt einmal bei badNonce. */
  async post(url, payload, { mitJwk = false, versuch = 0 } = {}) {
    if (!this.nonce) await this.frischeNonce();
    const geschuetzt = { alg: 'ES256', nonce: this.nonce, url, ...(mitJwk ? { jwk: this.jwk() } : { kid: this.kid }) };
    const p = b64(JSON.stringify(geschuetzt)), l = payload === null ? '' : b64(JSON.stringify(payload));
    const sig = crypto.sign('sha256', Buffer.from(`${p}.${l}`), { key: this.kontoSchluessel(), dsaEncoding: 'ieee-p1363' });
    const r = await this.anfrager(url, { methode: 'POST', daten: JSON.stringify({ protected: p, payload: l, signature: b64(sig) }) });
    this.nonce = r.kopf['replay-nonce'] || null;
    if (r.status === 400 && r.json?.type === 'urn:ietf:params:acme:error:badNonce' && versuch < 2) return this.post(url, payload, { mitJwk, versuch: versuch + 1 });
    if (r.status >= 400) throw new Error(`ACME: ${r.json?.detail || `HTTP ${r.status}`}`);
    return r;
  }
  async konto() {
    if (this.kid) return this.kid;
    const datei = path.join(this.verzeichnis, 'konto.json');
    try { const k = JSON.parse(fs.readFileSync(datei, 'utf8')); if (k.verzeichnis === this.verzeichnisUrl && k.kid) { this.kid = k.kid; return this.kid; } } catch (e) {}
    const dir = await this.verzeichnisHolen(), mail = this.email();
    const r = await this.post(dir.newAccount, { termsOfServiceAgreed: true, ...(mail ? { contact: [`mailto:${mail}`] } : {}) }, { mitJwk: true });
    this.kid = r.kopf.location;
    if (!this.kid) throw new Error('ACME: keine Kontoadresse');
    fs.writeFileSync(datei, JSON.stringify({ verzeichnis: this.verzeichnisUrl, kid: this.kid }), { mode: 0o600 });
    return this.kid;
  }
  async abwarten(url, fertig, schritte = 30) {
    for (let i = 0; i < schritte; i++) {
      const r = await this.post(url, null);
      if (fertig(r.json)) return r.json;
      if (r.json?.status === 'invalid') throw new Error(`ACME: ${r.json?.challenges?.find((c) => c.error)?.error?.detail || r.json?.error?.detail || 'Prüfung fehlgeschlagen'}`);
      await this.warten(2000);
    }
    throw new Error('ACME: keine Antwort in 60 s');
  }
  /** Zertifikat für einen Namen holen → {schluessel (PEM), kette (PEM), bis (ms)} */
  async zertifikat(host) {
    await this.konto();
    const dir = await this.verzeichnisHolen();
    const bestellung = await this.post(dir.newOrder, { identifiers: [{ type: 'dns', value: host }] });
    const order = bestellung.json, orderUrl = bestellung.kopf.location;
    const tokens = [];
    try {
      for (const az of order.authorizations || []) {
        const a = (await this.post(az, null)).json;
        if (a.status === 'valid') continue;
        const ch = (a.challenges || []).find((c) => c.type === 'http-01');
        if (!ch) throw new Error('ACME: keine HTTP-Prüfung angeboten');
        this.herausforderungen.set(ch.token, `${ch.token}.${this.daumen()}`); tokens.push(ch.token);
        await this.post(ch.url, {});
        await this.abwarten(az, (j) => j?.status === 'valid');
      }
      const schluessel = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
      await this.post(order.finalize, { csr: b64(csr(host, schluessel)) });
      const fertig = await this.abwarten(orderUrl, (j) => j?.status === 'valid' && j.certificate);
      const kette = (await this.post(fertig.certificate, null)).text;
      if (!kette.includes('BEGIN CERTIFICATE')) throw new Error('ACME: kein Zertifikat erhalten');
      const bis = Date.parse(new crypto.X509Certificate(kette).validTo);
      return { schluessel: schluessel.export({ type: 'pkcs8', format: 'pem' }), kette, bis };
    } finally { for (const t of tokens) this.herausforderungen.delete(t); }
  }
}

module.exports = { Acme, csr, LE, LE_TEST };
