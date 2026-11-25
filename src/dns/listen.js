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
const net = require('net');
const { normDomain, suffixe, listenIdOk, netzliste } = require('../netz');
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

// Wohin ein Listen-Download verbinden darf (25.11.2026, Prüfung K12): nie Loopback, Link-local (Cloud-Metadaten), Multicast, „unspezifiziert“;
// private Netze nur, wenn der Betreiber die Liste ausdrücklich mit einer privaten IP-Adresse eingetragen hat (nicht über einen Namen, nicht nach
// einer Umleitung). Geprüft wird die TATSÄCHLICH verbundene Adresse (über den lookup-Haken) – so hilft auch DNS-Rebinding nicht.
// IPv4 in IPv6 (::ffff:… wird vorher zu IPv4; ::/96 „IPv4-kompatibel“, NAT64 64:ff9b::/96, 6to4 2002::/16) könnte sonst interne IPv4-Ziele tragen
const NIE = netzliste(['0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4', '::/96', 'fe80::/10', 'ff00::/8', '64:ff9b::/96', '64:ff9b:1::/48', '2002::/16']);
const PRIVAT = netzliste(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', 'fc00::/7', 'fec0::/10']);
const zielErlaubt = (adresse, privatOk) => !NIE.enthaelt(adresse) && (privatOk || !PRIVAT.enthaelt(adresse));

function holen(url, { seit = null, timeout = 60000, aufloesen = lookup } = {}, umleitungen = 0) {
  if (String(url).startsWith('eingebaut:')) {
    if (umleitungen) return Promise.reject(new Error('Umleitung auf eine eingebaute Liste ist nicht erlaubt'));
    const quelle = EINGEBAUT[String(url).slice(10)];
    return quelle ? Promise.resolve({ text: quelle(), geaendert: Date.now() }) : Promise.reject(new Error('Eingebaute Liste unbekannt'));
  }
  let ziel; try { ziel = new URL(url); } catch (e) { return Promise.reject(new Error('Adresse ungültig')); }
  if (!['http:', 'https:'].includes(ziel.protocol)) return Promise.reject(new Error('Nur http(s)-Adressen'));
  const host = ziel.hostname.replace(/^\[|\]$/g, '');
  const privatOk = umleitungen === 0 && net.isIP(host) > 0 && PRIVAT.enthaelt(host);
  if (net.isIP(host) && !zielErlaubt(host, privatOk)) return Promise.reject(new Error(`Ziel ${host} liegt im internen Netz – nicht geladen`));
  const pruefLookup = (name, optionen, rueckruf) => {
    if (typeof optionen === 'function') { rueckruf = optionen; optionen = {}; }
    aufloesen(name, { ...optionen, all: true }, (e, liste) => {
      if (e) return rueckruf(e);
      const gut = (liste || []).filter((a) => zielErlaubt(a.address, privatOk));
      if (!gut.length) return rueckruf(Object.assign(new Error(`${name} zeigt ins interne Netz (${liste?.[0]?.address || '?'}) – nicht geladen`), { code: 'EZIELINTERN' }));
      if (optionen?.all) rueckruf(null, gut); else rueckruf(null, gut[0].address, gut[0].family);
    });
  };
  return new Promise((ok, nein) => {
    const modul = ziel.protocol === 'https:' ? https : http;
    const req = modul.get(ziel, { timeout, lookup: pruefLookup, headers: { 'User-Agent': 'FAH-Adblock/1.0', 'Accept-Encoding': 'gzip', ...(seit ? { 'If-Modified-Since': new Date(seit).toUTCString() } : {}) } }, (res) => {
      if ([301, 302, 307, 308].includes(res.statusCode) && res.headers.location && umleitungen < 5) { res.resume(); let weiter; try { weiter = new URL(res.headers.location, url).href; } catch (e) { return nein(new Error('Umleitung ungültig')); } return ok(holen(weiter, { seit, timeout, aufloesen }, umleitungen + 1)); }
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
  dateiVon(id) {
    if (!listenIdOk(id)) throw new Error(`Listen-ID ungültig: ${String(id).slice(0, 40)}`);
    return path.join(this.verzeichnis, 'listen', `${id}.txt`);
  }
  konfigurieren(quellen) {
    const ids = new Set();
    this.quellen = quellen.filter((q) => { const ok = listenIdOk(q?.id) && !ids.has(q.id); if (q?.id !== undefined) ids.add(q.id); if (!ok) this.protokoll(`Liste mit ungültiger oder doppelter ID übersprungen: ${String(q?.id).slice(0, 40)}`); return ok; }).slice(0, 30);
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
    this.index = index; this.exakt = exakt; this.indexQuellen = this.quellen.slice(); this.indexBits = new Map(this.bits);
    return index.size + exakt.size;
  }
  // Zur Laufzeit (Listen-Schalter, neuer Listenstand) in Häppchen bauen und der DNS-Beantwortung dazwischen Luft lassen (25.11.2026, Messung:
  // 1,2 Mio. Einträge ≈ 0,5 s am Stück schon auf dem Mac). Bis zum Austausch gilt der alte Index – zusammen mit SEINER Listenzuordnung
  // (indexQuellen/indexBits), sonst zeigten Bits kurz auf die falsche Liste. Ein neuer Wunsch währenddessen führt genau einen weiteren Durchlauf aus.
  neuAufbauenSanft({ haeppchen = 20000 } = {}) {
    if (this.bauLauf) { this.bauNochmal = true; return this.bauLauf; }
    this.bauLauf = (async () => {
      do {
        this.bauNochmal = false;
        const quellen = this.quellen.slice(), bits = new Map(this.bits), index = new Map(), exakt = new Map(), anzahl = {};
        for (const q of quellen) {
          if (!q.an) continue;
          let text = '';
          try { text = await fs.promises.readFile(this.dateiVon(q.id), 'utf8'); } catch (e) { continue; }
          const bit = bits.get(q.id), zeilen = text.split('\n'); text = '';
          let n = 0;
          for (let i = 0; i < zeilen.length; i++) {
            const d = zeilen[i];
            if (d) { if (d[0] === '=') { const x = d.slice(1); exakt.set(x, (exakt.get(x) || 0) | bit); } else index.set(d, (index.get(d) || 0) | bit); n++; }
            if (i % haeppchen === haeppchen - 1) await new Promise((r) => setImmediate(r));
          }
          anzahl[q.id] = n;
        }
        if (this.bauNochmal) continue;   // Listen haben sich währenddessen geändert → mit dem neuen Stand von vorn
        this.index = index; this.exakt = exakt; this.indexQuellen = quellen; this.indexBits = bits;
        for (const [id, n] of Object.entries(anzahl)) this.stand[id] = { ...(this.stand[id] || {}), anzahl: n };
      } while (this.bauNochmal);
      return this.index.size + this.exakt.size;
    })().finally(() => { this.bauLauf = null; });
    return this.bauLauf;
  }
  // Treffer: IDs aller Listen, die die Domain oder eine übergeordnete Domain enthalten
  treffer(domain) {
    let maske = this.exakt.get(domain) || 0;
    for (const s of suffixe(domain)) { const m = this.index.get(s); if (m) maske |= m; }
    if (!maske) return [];
    const quellen = this.indexQuellen || this.quellen, bits = this.indexBits || this.bits;
    return quellen.filter((q) => maske & bits.get(q.id)).map((q) => q.id);
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
      if (geschrieben) await this.neuAufbauenSanft();   // Index nur neu bauen, wenn sich eine Liste geändert hat – in Häppchen (DNS läuft weiter)
      this.speichernStand();
      return ergebnis;
    })().finally(() => { this.laufend = null; });
    return this.laufend;
  }
  status() {
    return { gesamt: this.index.size + this.exakt.size, quellen: this.quellen.map((q) => ({ ...q, ...(this.stand[q.id] || {}) })) };
  }
}

module.exports = { Listen, parse, holen, zielErlaubt };
