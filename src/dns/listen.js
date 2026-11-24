// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Blocklisten: werden zur Laufzeit geladen (nicht mitgeliefert), lokal gespeichert und
// alle 24 h mit If-Modified-Since erneuert. Treffer gelten für die Domain und alle Subdomains.
// Speicher: eine Map Domain → Bitmaske der Listen (höchstens 30 Listen).
'use strict';
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const zlib = require('zlib');
const { normDomain, suffixe } = require('../netz');
const { lookup } = require('../aufloeser');

const TAG = 86400000;

// Zeilenformate: hosts („0.0.0.0 domain“), AdBlock („||domain^“), reine Domains, „*.domain“.
// Blocklisten: jeder Eintrag gilt für die Domain und alle Subdomains.
// Freigabelisten (art „erlauben“): reine Domains und „|domain^|“ gelten genau (so meinen es die Listen),
// „||domain^“, „@@||domain^“ und „*.domain“ inklusive Subdomains; Muster mit * mitten im Namen werden übersprungen.
function parse(text, { art = 'sperren' } = {}) {
  const domains = new Set(), exakt = new Set();
  const freigabe = art === 'erlauben';
  let ungueltig = 0;
  for (let zeile of text.split(/\r?\n/)) {
    zeile = zeile.trim();
    if (!zeile || zeile[0] === '#' || zeile[0] === '!' || zeile[0] === '[') continue;
    const hash = zeile.indexOf(' #'); if (hash > 0) zeile = zeile.slice(0, hash).trim();
    if (zeile.startsWith('@@')) { if (!freigabe) continue; zeile = zeile.slice(2); }   // Ausnahmen gehören nur in Freigabelisten
    zeile = zeile.replace(/\$[^$]*$/, '');                                            // Modifikatoren ($important …)
    let d = '', genau = false;
    const ab = /^\|\|([^\^/|]+)\^\|?$/.exec(zeile), abGenau = /^\|([^\^/|]+)\^\|?$/.exec(zeile);
    if (ab) d = ab[1];
    else if (abGenau) { d = abGenau[1]; genau = true; }
    else {
      const teile = zeile.split(/\s+/);
      d = teile.length >= 2 && /^(0\.0\.0\.0|127\.0\.0\.1|::1?|::)$/.test(teile[0]) ? teile[1] : teile.length === 1 ? teile[0] : '';
      if (d.startsWith('*.')) d = d.slice(2);
      else if (freigabe) genau = true;
    }
    if (d.includes('*')) { ungueltig++; continue; }
    const n = normDomain(d);
    if (!n || n === 'localhost' || n === 'localhost.localdomain' || n === 'local' || n === 'broadcasthost' || !n.includes('.')) { if (d) ungueltig++; continue; }
    (genau ? exakt : domains).add(n);
  }
  return { domains, exakt, ungueltig, anzahl: domains.size + exakt.size };
}

// Eingebaute Listen („eingebaut:<name>“) kommen aus dem Programm selbst (src/daten) – sie wandern mit jedem Update mit
const EINGEBAUT = { anonym: () => require('../daten/kinderschutz').ANONYM.join('\n') };

function holen(url, { seit = null, timeout = 60000 } = {}, umleitungen = 0) {
  if (String(url).startsWith('eingebaut:')) {
    const quelle = EINGEBAUT[String(url).slice(10)];
    return quelle ? Promise.resolve({ text: quelle(), geaendert: Date.now() }) : Promise.reject(new Error('Eingebaute Liste unbekannt'));
  }
  return new Promise((ok, nein) => {
    const modul = url.startsWith('https:') ? https : http;
    const req = modul.get(url, { timeout, lookup, headers: { 'User-Agent': 'FAH-Adblock/1.0', 'Accept-Encoding': 'gzip', ...(seit ? { 'If-Modified-Since': new Date(seit).toUTCString() } : {}) } }, (res) => {
      if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location && umleitungen < 5) { res.resume(); return ok(holen(new URL(res.headers.location, url).href, { seit, timeout }, umleitungen + 1)); }
      if (res.statusCode === 304) { res.resume(); return ok({ unveraendert: true }); }
      if (res.statusCode !== 200) { res.resume(); return nein(new Error(`HTTP ${res.statusCode}`)); }
      const strom = res.headers['content-encoding'] === 'gzip' ? res.pipe(zlib.createGunzip()) : res;
      const teile = []; let groesse = 0;
      strom.on('data', (d) => { groesse += d.length; if (groesse > 80 * 1024 * 1024) { req.destroy(new Error('Liste größer als 80 MB')); } else teile.push(d); });
      strom.on('end', () => ok({ text: Buffer.concat(teile).toString('utf8'), geaendert: res.headers['last-modified'] ? Date.parse(res.headers['last-modified']) : Date.now() }));
      strom.on('error', nein);
    });
    req.on('timeout', () => req.destroy(new Error('Zeitüberschreitung')));
    req.on('error', nein);
  });
}

class Listen {
  constructor({ verzeichnis, jetzt = () => Date.now(), protokoll = (t) => console.log(`[listen] ${t}`), holer = holen }) {
    Object.assign(this, { verzeichnis, jetzt, protokoll, holer });
    this.quellen = [];          // [{id, name, url, kategorie, an}]
    this.index = new Map();     // domain → Bitmaske (gilt inkl. Subdomains)
    this.exakt = new Map();     // domain → Bitmaske (gilt nur genau für diese Domain)
    this.bits = new Map();      // listen-id → Bit
    this.stand = {};            // id → {anzahl, geprueft, geaendert, fehler, laedt}
    this.laufend = null;
  }
  statusDatei() { return path.join(this.verzeichnis, 'listen-stand.json'); }
  dateiVon(id) { return path.join(this.verzeichnis, 'listen', `${id}.txt`); }
  konfigurieren(quellen) {
    this.quellen = quellen.slice(0, 30);
    this.bits = new Map(this.quellen.map((q, i) => [q.id, 1 << i]));
  }
  laden() {
    try { this.stand = JSON.parse(fs.readFileSync(this.statusDatei(), 'utf8')) || {}; } catch (e) { this.stand = {}; }
    this.neuAufbauen();
  }
  speichernStand() {
    try { fs.mkdirSync(this.verzeichnis, { recursive: true }); fs.writeFileSync(this.statusDatei() + '.tmp', JSON.stringify(this.stand)); fs.renameSync(this.statusDatei() + '.tmp', this.statusDatei()); } catch (e) {}
  }
  // Index aus den gespeicherten Dateien aller eingeschalteten Listen
  neuAufbauen() {
    const index = new Map(), exakt = new Map();
    for (const q of this.quellen) {
      if (!q.an) continue;
      let text = '';
      try { text = fs.readFileSync(this.dateiVon(q.id), 'utf8'); } catch (e) { continue; }
      const bit = this.bits.get(q.id);
      let n = 0;
      for (const d of text.split('\n')) {
        if (!d) continue;
        if (d[0] === '=') { const x = d.slice(1); exakt.set(x, (exakt.get(x) || 0) | bit); } else index.set(d, (index.get(d) || 0) | bit);
        n++;
      }
      this.stand[q.id] = { ...(this.stand[q.id] || {}), anzahl: n };
    }
    this.index = index; this.exakt = exakt;
    return index.size + exakt.size;
  }
  // Treffer: IDs aller Listen, die die Domain oder eine übergeordnete Domain enthalten
  treffer(domain) {
    let maske = this.exakt.get(domain) || 0;
    for (const s of suffixe(domain)) { const m = this.index.get(s); if (m) maske |= m; }
    if (!maske) return [];
    return this.quellen.filter((q) => maske & this.bits.get(q.id)).map((q) => q.id);
  }
  // eingebaute Listen einmal je Start neu schreiben – ein Update bringt neue Einträge mit
  faellig(q) { const s = this.stand[q.id]; return q.an && (!s?.geprueft || this.jetzt() - s.geprueft > TAG || (s.fehler && this.jetzt() - s.geprueft > 3600000) || (String(q.url).startsWith('eingebaut:') && !(this.eingebautFrisch ||= new Set()).has(q.id))); }
  // gruppe: nur Freigabelisten („freigabe“) oder nur Sperrlisten („sperren“)
  async aktualisieren({ alle = false, nur = null, gruppe = null } = {}) {
    if (this.laufend) return this.laufend;
    this.laufend = (async () => {
      const ergebnis = {}; let geschrieben = false;
      for (const q of this.quellen) {
        if (nur && q.id !== nur) continue;
        if (gruppe && (q.kategorie === 'freigabe') !== (gruppe === 'freigabe')) continue;
        if (!q.an || (!alle && !nur && !this.faellig(q))) continue;
        const alt = this.stand[q.id] || {};
        this.stand[q.id] = { ...alt, laedt: true };
        try {
          const hatDatei = fs.existsSync(this.dateiVon(q.id));
          const r = await this.holer(q.url, { seit: hatDatei && !alle ? alt.geaendert : null });
          if (r.unveraendert) { this.stand[q.id] = { ...alt, geprueft: this.jetzt(), fehler: null, laedt: false }; ergebnis[q.id] = 'unverändert'; continue; }
          const { domains, exakt, ungueltig, anzahl } = parse(r.text, { art: q.kategorie === 'freigabe' ? 'erlauben' : 'sperren' });
          if (anzahl < 10) throw new Error(`nur ${anzahl} gültige Einträge – Liste verworfen`);
          if (alt.anzahl > 1000 && anzahl < alt.anzahl * 0.3) throw new Error(`nur ${anzahl} statt ~${alt.anzahl} Einträge – Liste verworfen`);
          fs.mkdirSync(path.dirname(this.dateiVon(q.id)), { recursive: true });
          fs.writeFileSync(this.dateiVon(q.id) + '.tmp', [...domains, ...[...exakt].map((d) => '=' + d)].join('\n'));
          fs.renameSync(this.dateiVon(q.id) + '.tmp', this.dateiVon(q.id));
          geschrieben = true;
          this.stand[q.id] = { anzahl, ungueltig, geprueft: this.jetzt(), geaendert: r.geaendert || this.jetzt(), fehler: null, laedt: false };
          if (String(q.url).startsWith('eingebaut:')) (this.eingebautFrisch ||= new Set()).add(q.id);
          ergebnis[q.id] = `${anzahl} Einträge`;
        } catch (e) {
          this.stand[q.id] = { ...alt, geprueft: this.jetzt(), fehler: e.message, laedt: false };
          ergebnis[q.id] = `Fehler: ${e.message}`;
          this.protokoll(`${q.name}: ${e.message}`);
        }
      }
      if (geschrieben) this.neuAufbauen();   // Index nur neu bauen, wenn sich eine Liste geändert hat
      this.speichernStand();
      return ergebnis;
    })().finally(() => { this.laufend = null; });
    return this.laufend;
  }
  status() {
    return { gesamt: this.index.size + this.exakt.size, quellen: this.quellen.map((q) => ({ ...q, ...(this.stand[q.id] || {}) })) };
  }
}

module.exports = { Listen, parse, holen };
