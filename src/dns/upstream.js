// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Verschlüsseltes DNS nach außen (DNS-over-HTTPS, RFC 8484, HTTP/2) mit Rückfall auf den
// nächsten Anbieter, Zwischenspeicher (TTL, LRU) und Vorab-Erneuern beliebter Einträge.
// Dazu die bedingte Weiterleitung lokaler Zonen an das Gateway (klassisch per UDP).
'use strict';
const http2 = require('http2');
const dgram = require('dgram');
const { ttlVon, rcodeVon, RCODE, dnsPacket } = require('./paket');
const roh = require('./roh');
const { lookup } = require('../aufloeser');

const TIMEOUT = 1500, CACHE_MAX = 20000, TTL_MIN = 5, TTL_MAX = 86400, NEG_MAX = 300;

// Sperrantwort eines filternden Anbieters (DNSforge, Mullvad AdBlock, AdGuard …): NXDOMAIN oder ausschließlich Null-Adressen (0.0.0.0 / ::)
function sperrantwort(buf) {
  const rc = rcodeVon(buf);
  if (rc === RCODE.NXDOMAIN) return true;
  if (rc !== RCODE.NOERROR) return false;
  try {
    const adressen = roh.eintraege(buf).filter((e) => e.abschnitt === 'an' && (e.typ === 1 || e.typ === 28));
    return adressen.length > 0 && adressen.every((e) => buf.subarray(e.daten, e.ende).every((b) => b === 0));
  } catch (e) { return false; }
}

class DohAnbieter {
  constructor({ name, url }) {
    const u = new URL(url);
    Object.assign(this, { name, url, ursprung: u.origin, pfad: u.pathname + u.search });
    this.sitzung = null; this.fehler = 0; this.letzterFehler = null; this.gesperrtBis = 0; this.ms = null; this.anfragen = 0;
    this.zeitueberschreitungen = 0;   // in Folge – ab der zweiten gilt die HTTP/2-Sitzung als tot
  }
  // Sitzung wegwerfen (ohne Fehler bei bereits geschlossener), der nächste Versuch verbindet neu
  sitzungVerwerfen() { const s = this.sitzung; this.sitzung = null; if (s) try { s.destroy(); } catch (e) {} }
  verbindung() {
    if (this.sitzung && !this.sitzung.closed && !this.sitzung.destroyed) return this.sitzung;
    const s = http2.connect(this.ursprung, { settings: { enablePush: false }, lookup });   // eigene Auflösung (nicht über den eigenen Blocker)
    s.on('error', (e) => { this.letzterFehler = e.message; });
    s.on('goaway', () => s.close());
    s.setTimeout(60000, () => s.close());
    s.unref?.();
    this.sitzung = s;
    return s;
  }
  frage(buf, timeout = TIMEOUT) {
    return new Promise((ok, nein) => {
      const start = process.hrtime.bigint();
      let fertig = false;
      const ende = (fn, wert) => { if (fertig) return; fertig = true; clearTimeout(uhr); fn(wert); };
      const uhr = setTimeout(() => {
        try { req?.close(http2.constants.NGHTTP2_CANCEL); } catch (e) {}
        // Eine Sitzung, die nicht mehr antwortet, würde sonst nie ersetzt (jede Anfrage setzt ihr Leerlauf-Timeout zurück)
        if (++this.zeitueberschreitungen >= 2 && this.sitzung === sitzung) this.sitzungVerwerfen();
        ende(nein, new Error(`${this.name}: Zeitüberschreitung`));
      }, timeout);
      let req, sitzung;
      try {
        sitzung = this.verbindung();
        req = sitzung.request({ ':method': 'POST', ':path': this.pfad, 'content-type': 'application/dns-message', accept: 'application/dns-message', 'content-length': buf.length });
      } catch (e) { this.sitzungVerwerfen(); return ende(nein, e); }
      const teile = []; let status = 0;
      req.on('response', (h) => { status = h[':status']; });
      req.on('data', (d) => teile.push(d));
      req.on('end', () => {
        if (status !== 200) return ende(nein, new Error(`${this.name}: HTTP ${status}`));
        this.ms = Number(process.hrtime.bigint() - start) / 1e6; this.anfragen++; this.zeitueberschreitungen = 0;
        ende(ok, Buffer.concat(teile));
      });
      req.on('error', (e) => { if (this.sitzung === sitzung) this.sitzung = null; ende(nein, e); });
      req.end(buf);
    });
  }
  status() { return { name: this.name, url: this.url, ms: this.ms != null ? Math.round(this.ms * 10) / 10 : null, fehler: this.fehler, letzterFehler: this.letzterFehler, anfragen: this.anfragen, gesperrt: this.gesperrtBis > Date.now() }; }
}

class Upstream {
  constructor({ anbieter = [], jetzt = () => Date.now(), anbieterFabrik = (a) => new DohAnbieter(a) } = {}) {
    Object.assign(this, { jetzt, anbieterFabrik });
    this.konfigurieren(anbieter);
    this.cache = new Map(); this.laufend = new Map();
    this.treffer = 0; this.fehlgriffe = 0;
  }
  konfigurieren(anbieter) {
    for (const a of this.anbieter || []) try { a.sitzung?.close(); } catch (e) {}
    this.anbieter = anbieter.map((a) => this.anbieterFabrik(a));
  }
  schluessel(anfrage) { const f = anfrage.frage; return `${f.name}|${f.typ}|${f.klasse}|${anfrage.edns?.do ? 1 : 0}|${anfrage.cd ? 1 : 0}`; }
  // Liefert {buf, alterSek, cache: bool, anbieter}
  // ungefiltert: für das, was der Betreiber ausdrücklich freigibt (geschützter Dienst, eigene Freigabe) – die Sperrantwort eines filternden
  // Anbieters zählt dann nicht, auch nicht aus dem Zwischenspeicher; der nächste Anbieter wird gefragt (Teams: DNSforge sperrt config.edge.skype.com)
  async frage(anfrage, upstreamBuf, { ungefiltert = false } = {}) {
    const k = this.schluessel(anfrage), jetzt = this.jetzt(), e = this.cache.get(k);
    if (e && e.bis > jetzt && !(ungefiltert && sperrantwort(e.buf))) {
      this.treffer++; e.treffer++;
      this.cache.delete(k); this.cache.set(k, e);                      // LRU: nach hinten
      if (e.treffer >= 3 && e.bis - jetzt < (e.bis - e.ab) * 0.1 && !this.laufend.has(k)) this.hole(k, upstreamBuf, ungefiltert).catch(() => {});   // vorab erneuern
      return { buf: e.buf, alterSek: Math.floor((jetzt - e.ab) / 1000), cache: true, anbieter: e.anbieter };
    }
    this.fehlgriffe++;
    const r = await this.hole(k, upstreamBuf, ungefiltert);
    return { ...r, alterSek: 0, cache: false };
  }
  hole(k, upstreamBuf, ungefiltert = false) {
    const lauf = ungefiltert ? `${k}|frei` : k;   // eine gleichzeitig laufende gefilterte Abfrage nicht mitbenutzen
    if (this.laufend.has(lauf)) return this.laufend.get(lauf);
    const p = (async () => {
      let letzter = null, gesperrt = null;
      for (const a of this.anbieter) {
        if (a.gesperrtBis > this.jetzt()) continue;
        try {
          const buf = await a.frage(upstreamBuf);
          a.fehler = 0;
          const rc = rcodeVon(buf);
          if (ungefiltert && sperrantwort(buf)) { gesperrt = gesperrt || { buf, anbieter: a.name }; continue; }   // nächsten Anbieter fragen
          if (rc === RCODE.NOERROR || rc === RCODE.NXDOMAIN) {
            const ttl = ttlVon(buf), grenze = rc === RCODE.NXDOMAIN ? NEG_MAX : TTL_MAX;
            if (ttl > 0) this.ablegen(k, buf, Math.max(TTL_MIN, Math.min(grenze, ttl)), a.name);
          }
          return { buf, anbieter: a.name };
        } catch (e) {
          letzter = e; a.fehler++; a.letzterFehler = e.message;
          if (a.fehler >= 3) a.gesperrtBis = this.jetzt() + 30000;        // 30 s aussetzen, dann erneut versuchen
        }
      }
      if (gesperrt) return gesperrt;   // alle erreichbaren Anbieter sperren (oder den Namen gibt es wirklich nicht) – Antwort nicht speichern
      if (this.anbieter.every((a) => a.gesperrtBis > this.jetzt())) for (const a of this.anbieter) a.gesperrtBis = 0;   // nie alle dauerhaft aussperren
      throw letzter || new Error('kein Upstream eingerichtet');
    })().finally(() => this.laufend.delete(lauf));
    this.laufend.set(lauf, p);
    return p;
  }
  ablegen(k, buf, ttlSek, anbieter) {
    const jetzt = this.jetzt();
    this.cache.delete(k);
    this.cache.set(k, { buf, ab: jetzt, bis: jetzt + ttlSek * 1000, treffer: 0, anbieter });
    if (this.cache.size > CACHE_MAX) this.cache.delete(this.cache.keys().next().value);
  }
  leeren() { this.cache.clear(); }
  status() {
    const gesamt = this.treffer + this.fehlgriffe;
    return { anbieter: this.anbieter.map((a) => a.status()), cache: { eintraege: this.cache.size, trefferquote: gesamt ? Math.round(this.treffer / gesamt * 100) : null } };
  }
}

// Lokale Zonen (Heimnetz-Namen, Rückwärtsauflösung) ans Gateway
class Lokal {
  constructor({ gateway = '192.168.1.1', zonen = [], port = 53 } = {}) { this.port = port; this.konfigurieren({ gateway, zonen }); }
  konfigurieren({ gateway, zonen }) {
    this.gateway = gateway;
    this.zonen = (zonen || []).map((z) => String(z).toLowerCase().replace(/^\.|\.$/g, '')).filter(Boolean);
  }
  zustaendig(name) { return !!this.gateway && this.zonen.some((z) => name === z || name.endsWith(`.${z}`)); }
  // Antwort muss zur Frage passen (ID sowie Name/Typ der Frage) – Fremdpakete werden verworfen, gewartet wird bis zum Timeout
  frage(buf, timeout = 1500) {
    return new Promise((ok, nein) => {
      const s = dgram.createSocket(this.gateway.includes(':') ? 'udp6' : 'udp4');
      const uhr = setTimeout(() => { s.close(); nein(new Error('Gateway: Zeitüberschreitung')); }, timeout);
      let frage = null; try { frage = dnsPacket.decode(buf).questions?.[0] || null; } catch (e) {}
      const passt = (m) => {
        if (m.length < 12 || m.readUInt16BE(0) !== buf.readUInt16BE(0) || !(m.readUInt16BE(2) & 0x8000)) return false;
        if (!frage) return true;
        try { const a = dnsPacket.decode(m).questions?.[0]; return !!a && String(a.name).toLowerCase() === String(frage.name).toLowerCase() && a.type === frage.type; } catch (e) { return false; }
      };
      s.on('message', (m) => { if (!passt(m)) return; clearTimeout(uhr); s.close(); ok(m); });
      s.on('error', (e) => { clearTimeout(uhr); try { s.close(); } catch (x) {} nein(e); });
      s.send(buf, this.port, this.gateway);
    });
  }
}

module.exports = { Upstream, DohAnbieter, Lokal };
