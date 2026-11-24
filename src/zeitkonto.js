// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Zeitkonto (Kinderschutz, 23.11.2026): Wie lange hat ein Gerät heute einen Dienst oder eine Rubrik genutzt?
// Ein DNS-Filter sieht keine Bildschirmzeit, nur Anfragen. Geschätzt wird deshalb in Sitzungen: Die erste Anfrage zählt eine
// Minute, jede weitere innerhalb von 5 Minuten die Zeit seit der vorigen. Längere Pausen beenden die Sitzung.
// Hintergrund-Aktivität einer App kann mitzählen – die Oberfläche sagt das ehrlich dazu.
// Je Gerät und Ziel („dienst:tiktok“, „rubrik:spiele“); um Mitternacht (Zeitzone des Blockers) beginnt ein neuer Tag.
// Zusatzzeit („+15 min“) gilt nur für heute. Der Ersatz schickt seine Nutzung an den Haupt und übernimmt dessen „aufgebraucht“.
'use strict';
const fs = require('fs');

const LUECKE = 5 * 60000, START = 60000;
const VERBOTEN = new Set(['__proto__', 'constructor', 'prototype']);
const schluesselOk = (k) => typeof k === 'string' && k.length > 0 && k.length <= 64 && !VERBOTEN.has(k);

class Zeitkonto {
  constructor({ datei = null, jetzt = () => Date.now(), zeitzone = process.env.TZ || 'Europe/Berlin' } = {}) {
    Object.assign(this, { datei, jetzt, zeitzone });
    this.fmt = new Intl.DateTimeFormat('en-CA', { timeZone: zeitzone, year: 'numeric', month: '2-digit', day: '2-digit' });
    this.z = { tag: this.tagVon(jetzt()), geraete: {} };   // gid → { ziele: {ziel: {ms, letzte}}, extra: {ziel: minuten} }
    this.delta = {};    // gid → {ziel: ms} – seit dem letzten Abholen (Ersatz → Haupt)
    this.fremd = {};    // gid → [ziele] – vom Haupt gemeldet aufgebraucht (nur am Ersatz)
    this.geaendert = false;
    if (datei) { try { const z = JSON.parse(fs.readFileSync(datei, 'utf8')); if (z && z.tag === this.z.tag && z.geraete && typeof z.geraete === 'object') this.z = z; } catch (e) {} }
  }
  tagVon(ts) { return this.fmt.format(new Date(ts)); }
  heute(ts = this.jetzt()) {
    const tag = this.tagVon(ts);
    if (tag !== this.z.tag) { this.z = { tag, geraete: {} }; this.delta = {}; this.fremd = {}; this.geaendert = true; }
    return this.z;
  }
  eintrag(gid) { if (!schluesselOk(gid)) throw new Error('Ungültige Geräte-ID'); const z = this.heute(); if (!Object.hasOwn(z.geraete, gid)) z.geraete[gid] = { ziele: {}, extra: {} }; return z.geraete[gid]; }
  /** Erlaubte Anfrage eines Geräts zu diesen Zielen vermerken */
  vermerke(gid, ziele, ts = this.jetzt()) {
    if (!schluesselOk(gid) || !ziele.length) return;
    const g = this.eintrag(gid);
    for (const ziel of ziele) {
      const e = (g.ziele[ziel] ||= { ms: 0, letzte: 0 });
      const plus = e.letzte && ts >= e.letzte && ts - e.letzte <= LUECKE ? ts - e.letzte : (ts - e.letzte > LUECKE || !e.letzte ? START : 0);
      e.ms += plus; e.letzte = Math.max(e.letzte, ts);
      if (plus) { const d = (this.delta[gid] ||= {}); d[ziel] = (d[ziel] || 0) + plus; }
    }
    this.geaendert = true;
  }
  genutztMin(gid, ziel) { return Math.floor((this.heute().geraete[gid]?.ziele[ziel]?.ms || 0) / 60000); }
  extraMin(gid, ziel) { return this.heute().geraete[gid]?.extra[ziel] || 0; }
  /** Erstes aufgebrauchtes Ziel dieses Dienstes für das Gerät, sonst null. `ziele` aus Filter.limitZiele */
  aufgebraucht(gid, profil, ziele) {
    for (const ziel of ziele) {
      if (this.fremd[gid]?.includes(ziel)) return ziel;
      const grenze = (profil.limits?.[ziel] || 0) + this.extraMin(gid, ziel);
      if (grenze && this.genutztMin(gid, ziel) >= grenze) return ziel;
    }
    return null;
  }
  // Schnittstelle für den Filter: braucht die Ziele aus dem Profil
  erschoepft(gid, profil, dienst) {
    const l = profil?.limits; if (!gid || !l || !dienst || dienst.fest) return null;
    const ziele = [];
    if (l[`dienst:${dienst.id}`]) ziele.push(`dienst:${dienst.id}`);
    if (l[`rubrik:${dienst.gruppe}`] && !dienst.einzelnFrei) ziele.push(`rubrik:${dienst.gruppe}`);
    return ziele.length ? this.aufgebraucht(gid, profil, ziele) : null;
  }
  /** Zusatzzeit für heute (Minuten; 0 = Zusatz zurücknehmen) */
  mehr(gid, ziel, minuten) {
    const g = this.eintrag(gid);
    if (minuten > 0) g.extra[ziel] = Math.min(1440, (g.extra[ziel] || 0) + minuten); else delete g.extra[ziel];
    if (this.fremd[gid]) this.fremd[gid] = this.fremd[gid].filter((z) => z !== ziel);
    this.geaendert = true;
  }
  // ── Haupt/Ersatz ──
  abholen() { const d = this.delta; this.delta = {}; return d; }
  hinzufuegen(nutzung, ts = this.jetzt()) {
    if (!nutzung || typeof nutzung !== 'object') return;
    for (const [gid, ziele] of Object.entries(nutzung).slice(0, 500)) {
      if (!schluesselOk(gid) || !ziele || typeof ziele !== 'object') continue;
      const g = this.eintrag(gid);
      for (const [ziel, ms] of Object.entries(ziele).slice(0, 50)) {
        if (!/^(dienst|rubrik):[a-z0-9-]{1,40}$/.test(ziel) || !(ms > 0)) continue;
        const e = (g.ziele[ziel] ||= { ms: 0, letzte: 0 });
        e.ms += Math.min(Number(ms), 30 * 60000); e.letzte = Math.max(e.letzte, ts - 60000);
      }
    }
    this.geaendert = true;
  }
  /** {gid: [ziele]} aller heute aufgebrauchten Ziele – profilVon(gid) liefert das Profil */
  aufgebrauchtAlle(profilVon) {
    const aus = {};
    for (const gid of Object.keys(this.heute().geraete)) {
      const p = profilVon(gid), ziele = Object.keys(p?.limits || {}).filter((z) => this.aufgebraucht(gid, p, [z]));
      if (ziele.length) aus[gid] = ziele;
    }
    return aus;
  }
  uebernehmenFremd(liste) {
    this.fremd = {};
    if (!liste || typeof liste !== 'object') return;
    for (const [gid, ziele] of Object.entries(liste).slice(0, 500)) if (schluesselOk(gid) && Array.isArray(ziele)) this.fremd[gid] = ziele.filter((z) => typeof z === 'string').slice(0, 50);
  }
  speichern() {
    if (!this.datei || !this.geaendert) return;
    try { fs.writeFileSync(this.datei + '.tmp', JSON.stringify(this.z), { mode: 0o600 }); fs.renameSync(this.datei + '.tmp', this.datei); this.geaendert = false; } catch (e) {}
  }
}

module.exports = { Zeitkonto, LUECKE, START };
