// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// FAH-Proxy-Kopplung (Schutz unterwegs, 23.11.2026): FAH-Adblock legt die Domains seiner Geräte (dns-…) in FAH-Proxy selbst an
// und löscht sie wieder – nichts doppelt eintragen (Betreiber). FAH-Proxy hat Haupt und Fail-over: FAH-Adblock kennt beide
// Adressen, fragt /api/uebersicht und schreibt an die gerade AKTIVE Instanz; FAH-Proxy spiegelt zur anderen.
// Zugang: eigenes FAH-Proxy-Konto „fah-adblock“ mit der eingeschränkten Rolle „dienst“ (ab FAH-Proxy 0.9.6): darf NUR die Gruppe
// „AdBlock DNS Domains“ pflegen (PUT /api/dienst/dns), keine Oberfläche, keine anderen Einträge. Angelegt beim Koppeln mit einem Admin-Login,
// das NICHT gespeichert wird. Gespeichert in data/fah-proxy.json (0600): Adressen, Kontoname, Passwort verschlüsselt, Zertifikats-
// Abdruck je Adresse (beim ersten Kontakt festgenagelt – ein fremdes Zertifikat wird abgelehnt). Nur Haupt/allein gleicht ab.
// FAH-Proxy selbst begrenzt den Dienst auf dns-Namen direkt unter der Basisdomain, private Ziele und die eigene Gruppe.
'use strict';
const fs = require('fs');
const path = require('path');
const http = require('http');
const tls = require('tls');
const net = require('net');
const crypto = require('crypto');
const { verschluesseln, entschluesseln } = require('./einstellungen');

const NOTIZ = 'FAH-Adblock unterwegs';
const GRUPPE = 'AdBlock DNS Domains';
const KONTO = 'fah-adblock';

function adresse(roh) {
  const u = String(roh || '').trim().replace(/\/+$/, '');
  let x; try { x = new URL(u); } catch (e) { throw Object.assign(new Error(`FAH-Proxy-Adresse ungültig: ${roh}`), { status: 400 }); }
  if (x.protocol !== 'https:' || (x.pathname !== '/' && x.pathname !== '')) throw Object.assign(new Error('FAH-Proxy-Adresse als https://IP:28181 angeben (nur https)'), { status: 400 });
  return x.origin;
}

/** Eine Sitzung an einer FAH-Proxy-Oberfläche (Cookie fp_sitzung + CSRF fp_csrf), mit festgenageltem Zertifikat */
class Sitzung {
  constructor(basis, { abdruck = null, zeitlimit = 15000 } = {}) { Object.assign(this, { basis, abdruck, zeitlimit }); this.kekse = {}; this.cookie = ''; this.csrf = ''; this.gesehen = null; }
  // Erst TLS aufbauen und den Abdruck prüfen, DANN auf genau dieser Verbindung senden – ein falsches Gegenüber bekommt nie Passwort oder Sitzung
  anfrage(methode, pfad, daten) {
    return new Promise((ok, nein) => {
      const u = new URL(pfad, this.basis), host = u.hostname.replace(/^\[|\]$/g, ''), text = daten === undefined ? undefined : JSON.stringify(daten);
      const fehler = (t) => Object.assign(new Error(t), { status: 502 });
      const s = tls.connect({ host, port: Number(u.port || 443), servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false });
      const uhr = setTimeout(() => { s.destroy(); nein(fehler(`${this.basis} antwortet nicht`)); }, this.zeitlimit);
      s.once('error', (e) => { clearTimeout(uhr); nein(fehler(`${this.basis}: ${e.code === 'ECONNREFUSED' ? 'nicht erreichbar' : e.message}`)); });
      s.once('secureConnect', () => {
        const fp = s.getPeerCertificate().fingerprint256 || '';
        this.gesehen = fp;
        if (this.abdruck && fp !== this.abdruck) { clearTimeout(uhr); s.destroy(); return nein(fehler(`Zertifikat von ${this.basis} hat sich geändert – nichts gesendet. War das gewollt, FAH-Proxy entkoppeln und neu koppeln.`)); }
        const req = http.request({ method: methode, path: u.pathname + u.search, createConnection: () => s, headers: { Host: u.host, 'User-Agent': 'FAH-Adblock', Accept: 'application/json', 'Sec-Fetch-Site': 'same-origin',
          ...(this.cookie ? { Cookie: this.cookie } : {}), ...(this.csrf && methode !== 'GET' ? { 'X-FP-CSRF': this.csrf } : {}), ...(text !== undefined ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) } : {}) } }, (res) => {
          const teile = []; let n = 0;
          res.on('data', (d) => { n += d.length; if (n > 5e6) req.destroy(new Error('Antwort zu groß')); else teile.push(d); });
          res.on('end', () => {
            clearTimeout(uhr);
            for (const c of [].concat(res.headers['set-cookie'] || [])) { const nv = String(c).split(';')[0], i2 = nv.indexOf('='); if (i2 > 0) this.kekse[nv.slice(0, i2)] = nv.slice(i2 + 1); }
            this.csrf = this.kekse.fp_csrf || ''; this.cookie = Object.entries(this.kekse).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join('; ');
            let j = null; try { j = JSON.parse(Buffer.concat(teile).toString('utf8')); } catch (e) {}
            if (!j || typeof j !== 'object') return nein(fehler(`Unter ${this.basis} antwortet kein FAH-Proxy (HTTP ${res.statusCode})`));
            if (j.ok === false || res.statusCode >= 400) return nein(Object.assign(fehler(`FAH-Proxy: ${j.fehler?.meldung || j.fehler?.text || j.fehler || `HTTP ${res.statusCode}`}`), { details: j.fehler }));
            ok(j.ergebnis === undefined ? j : j.ergebnis);
          });
        });
        req.on('error', (e) => { clearTimeout(uhr); nein(fehler(`${this.basis}: ${e.message}`)); });
        req.end(text);
      });
    });
  }
  async anmelden(name, passwort, code) { await this.anfrage('POST', '/api/anmelden', { name, passwort, ...(code ? { code } : {}) }); return this; }
}

class FahProxy {
  constructor({ verzeichnis, geheimnis, sitzungFabrik = (b, o) => new Sitzung(b, o), protokoll = (t) => console.log(`[fah-proxy] ${t}`) }) {
    Object.assign(this, { geheimnis, sitzungFabrik, protokoll });
    this.datei = path.join(verzeichnis, 'fah-proxy.json');
    this.stand = { fehler: null, instanz: null, zeit: null, eintraege: 0 };
  }
  lesen() { try { const k = JSON.parse(fs.readFileSync(this.datei, 'utf8')); return k && Array.isArray(k.urls) && k.name && k.passwort ? k : null; } catch (e) { return null; } }
  schreiben(k) { fs.writeFileSync(this.datei + '.tmp', JSON.stringify(k, null, 1), { mode: 0o600 }); fs.renameSync(this.datei + '.tmp', this.datei); }
  gekoppelt() { return !!this.lesen(); }
  loesen() { try { fs.unlinkSync(this.datei); } catch (e) {} this.stand = { fehler: null, instanz: null, zeit: null, eintraege: 0 }; }
  /** Entkoppeln: eigenes Konto in FAH-Proxy löschen (FAH-Proxy spiegelt das), dann lokal vergessen */
  async entkoppeln() {
    let fehler = null;
    try { const { s } = await this.aktiveSitzung(); await s.anfrage('DELETE', '/api/dienst/konto'); } catch (e) { fehler = e.message; }
    this.loesen();
    return { kontoGeloescht: !fehler, fehler };
  }
  /**
   * Einmal koppeln: mit einem Admin-Login (nicht gespeichert) an der aktiven Instanz das Konto „fah-adblock“ mit Zufallspasswort anlegen
   * (gibt es es schon, wird es ersetzt). Beide Adressen (Haupt + Fail-over) merken; FAH-Proxy spiegelt das Konto selbst.
   */
  async koppeln({ urls, name, passwort, code }) {
    const liste = [...new Set((Array.isArray(urls) ? urls : [urls]).filter(Boolean).map(adresse))].slice(0, 4);
    if (!liste.length) throw Object.assign(new Error('Mindestens eine FAH-Proxy-Adresse angeben'), { status: 400 });
    if (!String(name || '').trim() || !passwort) throw Object.assign(new Error('Name und Passwort eines FAH-Proxy-Admins angeben (werden nicht gespeichert)'), { status: 400 });
    const alt = this.lesen(), abdruecke = {};
    let aktiv = null, letzterFehler = null;
    for (const url of liste) {
      try {
        const s = this.sitzungFabrik(url, { abdruck: alt?.abdruecke?.[url] || null });   // schon bekannte Instanz: nur mit demselben Zertifikat
        await s.anmelden(String(name).trim(), String(passwort), code);
        abdruecke[url] = s.gesehen;
        const u = await s.anfrage('GET', '/api/uebersicht');
        if (u.aktiv && !aktiv) aktiv = s;
      } catch (e) { letzterFehler = e; }
    }
    if (!aktiv) throw Object.assign(new Error(letzterFehler ? letzterFehler.message : 'Keine aktive FAH-Proxy-Instanz gefunden'), { status: 502 });
    const geheim = crypto.randomBytes(24).toString('base64url');
    const vorhanden = (await aktiv.anfrage('GET', '/api/konten')).some((k) => k.name === KONTO);
    if (vorhanden) await aktiv.anfrage('DELETE', `/api/konten/${KONTO}`);
    try { await aktiv.anfrage('POST', '/api/konten', { name: KONTO, passwort: geheim, rolle: 'dienst' }); } catch (e) {
      throw Object.assign(new Error(/Rolle/.test(e.message) ? 'FAH-Proxy kennt die Dienst-Rolle noch nicht – bitte FAH-Proxy auf 0.9.6 oder neuer aktualisieren' : e.message), { status: 502 });
    }
    try { await aktiv.anfrage('POST', '/api/abmelden', {}); } catch (e) {}
    // Probe: das Dienst-Konto darf nur seine Gruppe – und genau das muss gehen
    const probe = this.sitzungFabrik(aktiv.basis, { abdruck: abdruecke[aktiv.basis] || null });
    await probe.anmelden(KONTO, geheim); await probe.anfrage('GET', '/api/dienst/dns'); try { await probe.anfrage('POST', '/api/abmelden', {}); } catch (e) {}
    this.schreiben({ urls: liste, name: KONTO, passwort: verschluesseln(geheim, this.geheimnis), abdruecke, gekoppelt: Date.now(), rolle: 'dienst' });
    return { urls: liste, aktiv: aktiv.basis };
  }
  /** Aktive Instanz anmelden (beide Adressen probieren) */
  async aktiveSitzung() {
    const k = this.lesen(); if (!k) throw new Error('FAH-Proxy ist nicht gekoppelt');
    const passwort = entschluesseln(k.passwort, this.geheimnis); if (!passwort) throw new Error('Kopplung unlesbar – bitte neu koppeln');
    const fehler = [];
    for (const url of k.urls) {
      try {
        const s = this.sitzungFabrik(url, { abdruck: k.abdruecke?.[url] || null });
        await s.anmelden(k.name, passwort);
        if (!k.abdruecke?.[url] && s.gesehen) { k.abdruecke = { ...(k.abdruecke || {}), [url]: s.gesehen }; this.schreiben(k); }
        const u = await s.anfrage('GET', '/api/dienst/dns');
        // vor 0.9.6 angelegt (Admin): Konto stuft sich einmal selbst zum Dienst herab
        if (k.rolle !== 'dienst') { try { await s.anfrage('POST', '/api/dienst/herabstufen', {}); k.rolle = 'dienst'; this.schreiben(k); this.protokoll('Konto „fah-adblock“ auf Rolle Dienst herabgestuft'); } catch (e) { this.protokoll(`Herabstufen: ${e.message}`); } }
        if (u.aktiv) return { s, uebersicht: u };
        fehler.push(`${url}: nicht aktiv`);
      } catch (e) { fehler.push(e.message); }
    }
    throw new Error(`Keine aktive FAH-Proxy-Instanz erreichbar (${fehler.join('; ')})`);
  }
  /** Soll-Liste [{domain, name}] mit Ziel herstellen → {angelegt, geloescht, geaendert, instanz} */
  async abgleichen(soll, ziel, basis) {
    try {
      if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(String(basis || ''))) throw new Error('Basisdomain fehlt');
      const { s } = await this.aktiveSitzung();
      const r = await s.anfrage('PUT', '/api/dienst/dns', { basis, ziel, soll: soll.map((x) => ({ domain: x.domain, name: x.name })) });
      const fehler = r.fremd?.length ? `${r.fremd.join(', ')} gibt es in FAH-Proxy schon (nicht in der Gruppe „${GRUPPE}“) – bitte dort löschen` : null;
      this.stand = { fehler, instanz: s.basis, zeit: Date.now(), eintraege: soll.length };
      if (r.angelegt?.length || r.geloescht?.length || r.geaendert?.length) this.protokoll(`${s.basis}: +${r.angelegt.join(',') || '–'} −${r.geloescht.join(',') || '–'} ~${r.geaendert.join(',') || '–'}`);
      try { await s.anfrage('POST', '/api/abmelden', {}); } catch (e) {}
      return { angelegt: r.angelegt || [], geaendert: r.geaendert || [], geloescht: r.geloescht || [], fehler, instanz: s.basis };
    } catch (e) { this.stand = { ...this.stand, fehler: e.message, zeit: Date.now() }; throw e; }
  }
  /** Zertifikate der eigenen Gruppe von der aktiven Instanz */
  async zertifikate() {
    const { s } = await this.aktiveSitzung();
    try { return await s.anfrage('GET', '/api/dienst/zertifikate'); } finally { try { await s.anfrage('POST', '/api/abmelden', {}); } catch (e) {} }
  }
  passwort() { const k = this.lesen(); return k ? entschluesseln(k.passwort, this.geheimnis) : ''; }
  /** Ersatz: Zugang vom Haupt übernehmen (mit dem eigenen Geheimnis neu verschlüsselt) */
  uebernehmen({ urls, name, passwort, abdruecke }) {
    if (!Array.isArray(urls) || !urls.length || !name || !passwort) return;
    this.schreiben({ urls: urls.map(adresse), name: String(name), passwort: verschluesseln(String(passwort), this.geheimnis), abdruecke: abdruecke || {}, gekoppelt: Date.now(), vomHaupt: true, rolle: 'dienst' });
  }
  status() { const k = this.lesen(); return { gekoppelt: !!k, urls: k?.urls || [], konto: k?.name || null, ...this.stand }; }
}

module.exports = { FahProxy, Sitzung, NOTIZ, KONTO, GRUPPE, adresse };
