// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Anfrageprotokoll in SQLite (node:sqlite, WAL). Einträge werden gebündelt geschrieben
// (alle 200 ms), Stunden-Summen je Gerät laufen mit (schnelle Statistik),
// ein Ringpuffer hält die letzten Einträge für die Live-Ansicht.
'use strict';
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { Worker } = require('worker_threads');

// Leser-Thread mit eigener, nur lesender Verbindung (25.11.2026, Messung am Haupt: 2,8 Mio. Zeilen → „Meistgeblockt“ über 30 Tage 470 ms,
// Suche nach einem seltenen Begriff 1,4 s – solange stand die DNS-Beantwortung). Schwere Auswertungen laufen jetzt dort.
const LESER = `
const { parentPort, workerData } = require('worker_threads');
const { DatabaseSync } = require('node:sqlite');
let db = null;
parentPort.on('message', ({ id, sql, werte }) => {
  try { db = db || new DatabaseSync(workerData.datei, { readOnly: true }); parentPort.postMessage({ id, zeilen: db.prepare(sql).all(...werte) }); }
  catch (e) { parentPort.postMessage({ id, fehler: e.message }); }
});`;

const AKTION = { erlaubt: 0, geblockt: 1, lokal: 2, fehler: 3, gebremst: 4 };
const AKTION_NAME = Object.fromEntries(Object.entries(AKTION).map(([k, v]) => [v, k]));
const STUNDE = 3600000, TAG = 86400000;

class Protokoll {
  constructor({ datei, tage = () => 7, jetzt = () => Date.now(), ring = 1500 }) {
    Object.assign(this, { datei, tage, jetzt, ringGroesse: ring });
    fs.mkdirSync(path.dirname(datei), { recursive: true });
    this.db = new DatabaseSync(datei);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY;
      CREATE TABLE IF NOT EXISTS anfragen(ts INTEGER NOT NULL, ip TEXT, geraet TEXT, domain TEXT, typ TEXT, aktion INTEGER, grund TEXT, detail TEXT, ms REAL, cache INTEGER);
      CREATE INDEX IF NOT EXISTS i_ts ON anfragen(ts);
      CREATE INDEX IF NOT EXISTS i_geraet_ts ON anfragen(geraet, ts);
      CREATE INDEX IF NOT EXISTS i_aktion_ts ON anfragen(aktion, ts);
      CREATE TABLE IF NOT EXISTS stunden(stunde INTEGER NOT NULL, geraet TEXT NOT NULL, erlaubt INTEGER DEFAULT 0, geblockt INTEGER DEFAULT 0, sonst INTEGER DEFAULT 0, PRIMARY KEY(stunde, geraet));
      CREATE TABLE IF NOT EXISTS geraete(geraet TEXT PRIMARY KEY, name TEXT, ip TEXT, zuletzt INTEGER);`);
    this.einfuegen = this.db.prepare('INSERT INTO anfragen(ts, ip, geraet, domain, typ, aktion, grund, detail, ms, cache) VALUES (?,?,?,?,?,?,?,?,?,?)');
    this.stundeUpsert = this.db.prepare(`INSERT INTO stunden(stunde, geraet, erlaubt, geblockt, sonst) VALUES (?,?,?,?,?)
      ON CONFLICT(stunde, geraet) DO UPDATE SET erlaubt=erlaubt+excluded.erlaubt, geblockt=geblockt+excluded.geblockt, sonst=sonst+excluded.sonst`);
    this.geraetUpsert = this.db.prepare(`INSERT INTO geraete(geraet, name, ip, zuletzt) VALUES (?,?,?,?) ON CONFLICT(geraet) DO UPDATE SET name=excluded.name, ip=excluded.ip, zuletzt=excluded.zuletzt`);
    this.warte = []; this.ring = []; this.fehler = null; this.cache = new Map();
    // kleine Bündel alle 200 ms: kurze Sperren der Ereignisschleife auch unter Last
    this.schreibUhr = setInterval(() => this.schreiben(), 200); this.schreibUhr.unref?.();
    this.putzUhr = setInterval(() => this.aufraeumen(), STUNDE); this.putzUhr.unref?.();
  }
  aufnehmen(e) {
    this.ring.push(e); if (this.ring.length > this.ringGroesse) this.ring.splice(0, this.ring.length - this.ringGroesse);
    this.warte.push(e);
    if (this.warte.length >= 500) setImmediate(() => this.schreiben());
  }
  schreiben() {
    if (!this.warte.length) return;
    const liste = this.warte; this.warte = [];
    const stunden = new Map(), geraete = new Map();
    try {
      this.db.exec('BEGIN');
      for (const e of liste) {
        const a = AKTION[e.aktion] ?? 3;
        const detail = e.dienst || (e.listen?.length ? e.listen.join(',') : e.regel || e.cname || e.anbieter || '');
        this.einfuegen.run(e.ts, e.ip, e.geraet, e.domain, e.typ, a, e.grund || '', detail, e.ms ?? null, e.cache ? 1 : 0);
        const k = `${Math.floor(e.ts / STUNDE)}|${e.geraet}`, s = stunden.get(k) || [0, 0, 0];
        if (a === 0 || a === 2) s[0]++; else if (a === 1) s[1]++; else s[2]++;
        stunden.set(k, s);
        geraete.set(e.geraet, [e.geraetName || '', e.ip, e.ts]);
      }
      for (const [k, s] of stunden) { const [stunde, geraet] = k.split('|'); this.stundeUpsert.run(+stunde, geraet, s[0], s[1], s[2]); }
      for (const [g, [name, ip, ts]] of geraete) this.geraetUpsert.run(g, name, ip, ts);
      this.db.exec('COMMIT');
      this.fehler = null;
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch (e) {}
      this.fehler = err.message;
    }
  }
  aufraeumen() {
    const grenze = this.jetzt() - Math.max(1, this.tage()) * TAG;
    try {
      this.db.prepare('DELETE FROM anfragen WHERE ts < ?').run(grenze);
      this.db.prepare('DELETE FROM stunden WHERE stunde < ?').run(Math.floor((this.jetzt() - 35 * TAG) / STUNDE));
      this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } catch (e) { this.fehler = e.message; }
  }
  // Kurzzeit-Zwischenspeicher für Statistiken: abgelaufene Einträge fliegen beim Einfügen raus, höchstens 200 Einträge
  gemerkt(schluessel, ms, fn) {
    const jetzt = this.jetzt(), c = this.cache.get(schluessel);
    if (c && jetzt - c.ts < c.ms) return c.wert;
    const wert = fn();
    for (const [k, e] of this.cache) if (jetzt - e.ts >= e.ms) this.cache.delete(k);
    this.cache.set(schluessel, { ts: jetzt, ms, wert });
    while (this.cache.size > 200) this.cache.delete(this.cache.keys().next().value);
    return wert;
  }
  // Mitternacht in der eingestellten Zeitzone (für „heute“)
  mitternacht(zeitzone = process.env.TZ || 'Europe/Berlin') {
    const jetzt = new Date(this.jetzt());
    const teile = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: zeitzone, hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).formatToParts(jetzt).map((p) => [p.type, p.value]));
    return this.jetzt() - ((+teile.hour) * 3600 + (+teile.minute) * 60 + (+teile.second)) * 1000 - (jetzt.getMilliseconds());
  }
  // Kennzahlen für „heute" (seit Mitternacht) und für einen gleitenden Zeitraum
  // (24 h, 7 Tage, 30 Tage) – die Stundenstatistik wird 35 Tage vorgehalten.
  kennzahlen(stunden = 24) {
    const h = [24, 168, 720].includes(+stunden) ? +stunden : 24;
    return this.gemerkt(`kennzahlen|${h}`, 3000, () => {
      const summe = (abMs) => {
        const ab = Math.floor(abMs / STUNDE);
        const s = this.db.prepare('SELECT COALESCE(SUM(erlaubt),0) e, COALESCE(SUM(geblockt),0) g, COALESCE(SUM(sonst),0) s FROM stunden WHERE stunde >= ?').get(ab);
        const offen = this.warte.reduce((a, e) => { if (e.ts >= abMs) { if (e.aktion === 'geblockt') a.g++; else if (e.aktion === 'erlaubt' || e.aktion === 'lokal') a.e++; else a.s++; } return a; }, { e: 0, g: 0, s: 0 });
        const erlaubt = s.e + offen.e, geblockt = s.g + offen.g, gesamt = erlaubt + geblockt + s.s + offen.s;
        return { anfragen: gesamt, geblockt, erlaubt, quote: gesamt ? Math.round(geblockt / gesamt * 1000) / 10 : 0 };
      };
      const aktiv = this.db.prepare('SELECT COUNT(*) n FROM geraete WHERE zuletzt >= ?').get(this.jetzt() - 10 * 60000).n;
      return { heute: summe(this.mitternacht()), zeitraum: { stunden: h, ...summe(this.jetzt() - h * STUNDE) }, aktiveGeraete: aktiv };
    });
  }
  verlauf(zeitraum = '24h') {
    return this.gemerkt(`verlauf|${zeitraum}`, 15000, () => {
      if (zeitraum === '7d') {
        const ab = Math.floor((this.jetzt() - 7 * TAG) / STUNDE);
        const zeilen = this.db.prepare('SELECT stunde, SUM(erlaubt) e, SUM(geblockt) g FROM stunden WHERE stunde >= ? GROUP BY stunde ORDER BY stunde').all(ab);
        const tage = new Map();
        for (const z of zeilen) { const t = new Intl.DateTimeFormat('sv-SE', { timeZone: process.env.TZ || 'Europe/Berlin' }).format(new Date(z.stunde * STUNDE)); const x = tage.get(t) || { tag: t, erlaubt: 0, geblockt: 0 }; x.erlaubt += z.e; x.geblockt += z.g; tage.set(t, x); }
        return [...tage.values()];
      }
      const ab = Math.floor((this.jetzt() - 24 * STUNDE) / STUNDE) + 1;
      const zeilen = new Map(this.db.prepare('SELECT stunde, SUM(erlaubt) e, SUM(geblockt) g FROM stunden WHERE stunde >= ? GROUP BY stunde').all(ab).map((z) => [z.stunde, z]));
      const aus = []; for (let h = ab; h <= Math.floor(this.jetzt() / STUNDE); h++) { const z = zeilen.get(h); aus.push({ stunde: h * STUNDE, erlaubt: z?.e || 0, geblockt: z?.g || 0 }); }
      return aus;
    });
  }
  topDomains({ aktion = 'geblockt', seit = this.jetzt() - TAG, geraet = '', limit = 15 } = {}) {
    const n = Math.max(1, Math.min(50, Math.round(+limit) || 15));
    return this.gemerkt(`top|${aktion}|${Math.floor(seit / STUNDE)}|${geraet}|${n}`, 30000, () =>
      this.db.prepare(`SELECT domain, COUNT(*) n, MAX(ts) zuletzt FROM anfragen WHERE aktion = ? AND ts >= ? ${geraet ? 'AND geraet = ?' : ''} GROUP BY domain ORDER BY n DESC LIMIT ?`)
        .all(...[AKTION[aktion], seit, ...(geraet ? [geraet] : []), n]));
  }
  geraeteStatistik(seit = this.jetzt() - TAG) {
    return this.gemerkt(`geraete|${Math.floor(seit / STUNDE)}`, 5000, () => {
      const stunden = this.db.prepare('SELECT geraet, SUM(erlaubt) e, SUM(geblockt) g FROM stunden WHERE stunde >= ? GROUP BY geraet').all(Math.floor(seit / STUNDE));
      const namen = new Map(this.db.prepare('SELECT geraet, name, ip, zuletzt FROM geraete').all().map((z) => [z.geraet, z]));
      const verlauf = this.db.prepare('SELECT geraet, stunde, erlaubt + geblockt n, geblockt g FROM stunden WHERE stunde >= ?').all(Math.floor((this.jetzt() - 12 * STUNDE) / STUNDE));
      const jeGeraet = new Map();
      for (const v of verlauf) { const l = jeGeraet.get(v.geraet) || []; l.push(v); jeGeraet.set(v.geraet, l); }
      const jetztStunde = Math.floor(this.jetzt() / STUNDE);
      return stunden.map((s) => {
        const n = namen.get(s.geraet) || {}, l = jeGeraet.get(s.geraet) || [];
        const kurve = Array.from({ length: 12 }, (_, i) => { const h = jetztStunde - 11 + i, z = l.find((x) => x.stunde === h); return z ? [z.n, z.g] : [0, 0]; });
        return { id: s.geraet, name: n.name || s.geraet, ip: n.ip || '', zuletzt: n.zuletzt || 0, erlaubt: s.e, geblockt: s.g, quote: s.e + s.g ? Math.round(s.g / (s.e + s.g) * 1000) / 10 : 0, kurve };
      }).sort((a, b) => b.zuletzt - a.zuletzt);
    });
  }
  rettung(geraet, minuten = 15) {
    this.schreiben();
    return this.db.prepare(`SELECT domain, COUNT(*) n, MAX(ts) zuletzt, grund, MAX(detail) detail FROM anfragen WHERE geraet = ? AND aktion = 1 AND ts >= ? AND grund != 'DoH-Kanarie' GROUP BY domain ORDER BY zuletzt DESC LIMIT 60`)
      .all(geraet, this.jetzt() - minuten * 60000);
  }
  eintraegeSql({ geraet = '', nurGeblockt = false, suche = '', vor = 0, limit = 100 } = {}) {
    const bed = [], werte = [];
    if (geraet) { bed.push('geraet = ?'); werte.push(geraet); }
    if (nurGeblockt) bed.push('aktion = 1');
    if (suche) { bed.push('domain LIKE ?'); werte.push(`%${String(suche).replace(/[%_]/g, '')}%`); }
    if (vor) { bed.push('ts < ?'); werte.push(+vor); }
    return { sql: `SELECT a.ts, a.ip, a.geraet, g.name, a.domain, a.typ, a.aktion, a.grund, a.detail, a.ms, a.cache FROM anfragen a LEFT JOIN geraete g ON g.geraet = a.geraet ${bed.length ? 'WHERE ' + bed.map((b) => 'a.' + b).join(' AND ') : ''} ORDER BY a.ts DESC LIMIT ?`,
      werte: [...werte, Math.max(1, Math.min(500, Math.round(+limit) || 100))] };
  }
  eintraege(opts = {}) {
    this.schreiben();
    const { sql, werte } = this.eintraegeSql(opts);
    return this.db.prepare(sql).all(...werte).map((z) => ({ ...z, aktion: AKTION_NAME[z.aktion], cache: !!z.cache }));
  }
  // ── Auswertungen über den Leser-Thread (für die Weboberfläche) ──
  leserAbfrage(sql, werte, zeitlimit_ms = 30000) {
    if (!this.leser) {
      const w = new Worker(LESER, { eval: true, workerData: { datei: this.datei } });
      w.unref(); this.leser = w; this.leserOffen = new Map(); this.leserId = 0;
      const allesAb = (e) => { for (const o of this.leserOffen.values()) { clearTimeout(o.uhr); o.nein(e); } this.leserOffen.clear(); if (this.leser === w) this.leser = null; };
      w.on('message', ({ id, zeilen, fehler }) => { const o = this.leserOffen.get(id); if (!o) return; this.leserOffen.delete(id); clearTimeout(o.uhr); fehler ? o.nein(new Error(fehler)) : o.ok(zeilen); });
      w.on('error', allesAb); w.on('exit', () => allesAb(new Error('Leser-Thread beendet')));
    }
    return new Promise((ok, nein) => {
      const id = ++this.leserId, uhr = setTimeout(() => { this.leserOffen.delete(id); nein(new Error('Auswertung dauert zu lange')); }, zeitlimit_ms);
      uhr.unref?.(); this.leserOffen.set(id, { ok, nein, uhr }); this.leser.postMessage({ id, sql, werte });
    });
  }
  /** Wie eintraege – mit Suchbegriff (Volltextsuche über alle Zeilen) im Leser-Thread */
  async eintraegeAsync(opts = {}) {
    if (!opts.suche) return this.eintraege(opts);
    this.schreiben();
    const { sql, werte } = this.eintraegeSql(opts);
    return (await this.leserAbfrage(sql, werte)).map((z) => ({ ...z, aktion: AKTION_NAME[z.aktion], cache: !!z.cache }));
  }
  /** Wie topDomains – Zeiträume über einen Tag im Leser-Thread (2 min gemerkt) */
  topDomainsAsync(opts = {}) {
    const { aktion = 'geblockt', seit = this.jetzt() - TAG, geraet = '', limit = 15 } = opts;
    if (this.jetzt() - seit <= TAG + STUNDE) return Promise.resolve(this.topDomains(opts));
    const n = Math.max(1, Math.min(50, Math.round(+limit) || 15)), schluessel = `topA|${aktion}|${Math.floor(seit / STUNDE)}|${geraet}|${n}`;
    return this.gemerkt(schluessel, 120000, () => this.leserAbfrage(`SELECT domain, COUNT(*) n, MAX(ts) zuletzt FROM anfragen WHERE aktion = ? AND ts >= ? ${geraet ? 'AND geraet = ?' : ''} GROUP BY domain ORDER BY n DESC LIMIT ?`,
      [AKTION[aktion], seit, ...(geraet ? [geraet] : []), n]).catch((e) => { this.cache.delete(schluessel); throw e; }));
  }
  // Letzte bekannte Geräte für Geraete.vorbelegen (neueste zuerst)
  bekannteGeraete() {
    try {
      return this.db.prepare("SELECT geraet, name, ip, zuletzt FROM geraete WHERE ip IS NOT NULL AND ip != '' ORDER BY zuletzt DESC").all()
        .map((r) => (r.geraet.startsWith('ip:') ? { ipId: true, ip: r.ip, zuletzt: r.zuletzt } : { mac: r.geraet, name: r.name, ip: r.ip, zuletzt: r.zuletzt }));
    } catch (e) { return []; }
  }
  // Anfragen, die unter „ip:…“ liefen, bevor die MAC bekannt war, dem Gerät zuordnen (Anfragen, Stunden-Summen, Geräteliste, Livepuffer)
  zusammenfuehren(von, nach, seit, name = '') {
    if (!von || !nach || von === nach) return 0;
    this.schreiben();
    let n = 0;
    try {
      this.db.exec('BEGIN');
      n = Number(this.db.prepare('UPDATE anfragen SET geraet = ? WHERE geraet = ? AND ts >= ?').run(nach, von, seit).changes);
      const ab = Math.floor(seit / STUNDE);
      for (const z of this.db.prepare('SELECT stunde, erlaubt, geblockt, sonst FROM stunden WHERE geraet = ? AND stunde >= ?').all(von, ab)) this.stundeUpsert.run(z.stunde, nach, z.erlaubt, z.geblockt, z.sonst);
      this.db.prepare('DELETE FROM stunden WHERE geraet = ? AND stunde >= ?').run(von, ab);
      const alt = this.db.prepare('SELECT name, ip, zuletzt FROM geraete WHERE geraet = ?').get(von);
      if (alt) {
        const rest = this.db.prepare('SELECT MAX(ts) z FROM anfragen WHERE geraet = ?').get(von).z;
        if (rest) this.db.prepare('UPDATE geraete SET zuletzt = ? WHERE geraet = ?').run(rest, von);
        else this.db.prepare('DELETE FROM geraete WHERE geraet = ?').run(von);
        if (n) this.db.prepare('INSERT INTO geraete(geraet, name, ip, zuletzt) VALUES (?,?,?,?) ON CONFLICT(geraet) DO UPDATE SET zuletzt = MAX(zuletzt, excluded.zuletzt)').run(nach, name || alt.name || '', alt.ip || '', alt.zuletzt || 0);
      }
      this.db.exec('COMMIT');
    } catch (err) {
      try { this.db.exec('ROLLBACK'); } catch (e) {}
      this.fehler = err.message; return 0;
    }
    for (const e of this.ring) if (e.geraet === von && e.ts >= seit) { e.geraet = nach; if (name) e.geraetName = name; }
    this.cache.clear();
    return n;
  }
  groesse() { try { return fs.statSync(this.datei).size + (fs.existsSync(this.datei + '-wal') ? fs.statSync(this.datei + '-wal').size : 0); } catch (e) { return 0; } }
  schliessen() { this.schreiben(); clearInterval(this.schreibUhr); clearInterval(this.putzUhr); try { this.leser?.terminate(); } catch (e) {} try { this.db.close(); } catch (e) {} }
}

module.exports = { Protokoll, AKTION };
