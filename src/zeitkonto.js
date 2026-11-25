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
const crypto = require('crypto');

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
  // ── Haupt/Ersatz (25.11.2026, Prüfung K11) ──
  // Der Ersatz schickt seine Nutzung in Paketen mit Lauf-ID und Tag. Ein Paket bleibt ausstehend, bis der Haupt seine ID bestätigt, und geht
  // bis dahin UNVERÄNDERT erneut mit; der Haupt zählt jede ID nur einmal und nur am selben Tag. Vorher wurde bei verlorener Antwort das ganze
  // Delta erneut (und kumuliert) gebucht, und Nutzung von vor Mitternacht konnte dem neuen Tag zugeschlagen werden.
  /** Ersatz: neue Nutzung als Paket einreihen → die ältesten ausstehenden Pakete von heute, zusammen höchstens `maxZeichen` groß (der Rest geht
   *  beim nächsten Abgleich; Codex R-P23-007: eine riesige Anfrage würde der Haupt jedes Mal ablehnen und nie bestätigen) */
  abholen(maxZeichen = 400000) {
    const z = this.heute();   // Tageswechsel zuerst: Nutzung von gestern geht nie an den neuen Tag
    const aus = Array.isArray(z.ausstehend) ? z.ausstehend : [];
    if (Object.keys(this.delta).length) {
      // in Pakete von höchstens ~50 KB teilen (je Gerät höchstens 50 Ziele → ein Gerät passt immer in ein Paket), Codex R-R7-011
      let stueck = {}, groesse = 0;
      const weg = () => { if (Object.keys(stueck).length) aus.push({ lauf: crypto.randomBytes(12).toString('base64url'), tag: z.tag, daten: stueck }); stueck = {}; groesse = 0; };
      // höchstens 500 Geräte je Paket – mehr liest annehmen() nicht (Codex R4-002)
      for (const [gid, ziele] of Object.entries(this.delta)) { const g = JSON.stringify({ [gid]: ziele }).length; if (groesse && (groesse + g > 50000 || Object.keys(stueck).length >= 500)) weg(); stueck[gid] = ziele; groesse += g; }
      weg(); this.delta = {}; this.geaendert = true;
    }
    // Unbestätigte Pakete NIE still verwerfen (Codex-Nachprüfung R4): im 2-min-Takt sind das höchstens ~720 am Tag, danach gilt ein neuer Tag
    z.ausstehend = aus.filter((p) => p.tag === z.tag);
    if (z.ausstehend.length > 1000 && !this.warnte) { this.warnte = true; console.warn(`[zeitkonto] ${z.ausstehend.length} unbestätigte Pakete – der Haupt bestätigt seit Langem nicht`); }
    // Altlast (Codex R-R7-013/R4-001): Ein Paket über 1 500 000 Bytes JSON ergibt verschlüsselt (Base64 = 4/3) mehr als die 2 000 000 Zeichen, die der Haupt
    // je Anfrage annimmt → wurde mit Sicherheit nie gezählt → gefahrlos in Teile mit eigener Kennung zerlegen. Alles darunter behält seine Kennung (sonst
    // Doppelzählung, falls nur die Antwort verloren ging) und geht notfalls allein. Danach füllen weitere Pakete bis maxZeichen auf.
    const HART = 1500000;
    z.ausstehend = z.ausstehend.flatMap((p) => {
      if (Buffer.byteLength(JSON.stringify(p)) <= HART) return [p];
      const teile = []; let stueck = {}, g = 0;
      for (const [gid, ziele] of Object.entries(p.daten || {})) { const n = JSON.stringify({ [gid]: ziele }).length; if (g && (g + n > 50000 || Object.keys(stueck).length >= 500)) { teile.push(stueck); stueck = {}; g = 0; } stueck[gid] = ziele; g += n; }
      if (Object.keys(stueck).length) teile.push(stueck);
      this.geaendert = true;
      // Kennung aus Hash der GANZEN alten Kennung + Teilnummer (kollisionssicher, passt zu /^[A-Za-z0-9_-]{8,64}$/)
      return teile.map((daten, i) => ({ lauf: `t${crypto.createHash('sha256').update(`${p.lauf}|${i}`).digest('base64url').slice(0, 40)}`, tag: p.tag, daten }));
    });
    const teil = []; let groesse = 0;
    for (const p of z.ausstehend) { const g = Buffer.byteLength(JSON.stringify(p)) + 1; if (teil.length && groesse + g + 2 > maxZeichen) break; teil.push(p); groesse += g; }   // Bytes inkl. Komma/Klammern
    return teil;
  }
  /** Ersatz: vom Haupt bestätigte Pakete streichen */
  bestaetigen(laeufe) {
    if (!Array.isArray(laeufe) || !Array.isArray(this.z.ausstehend)) return;
    const s = new Set(laeufe.filter((x) => typeof x === 'string'));
    const vorher = this.z.ausstehend.length; this.z.ausstehend = this.z.ausstehend.filter((p) => !s.has(p.lauf));
    if (this.z.ausstehend.length !== vorher) this.geaendert = true;
  }
  /** Haupt: Pakete des Ersatzes annehmen → bestätigte Lauf-IDs (auch verworfene: anderer Tag oder schon gezählt) */
  annehmen(pakete, ts = this.jetzt(), kanonisch = (gid) => gid) {
    if (!Array.isArray(pakete)) return [];
    const z = this.heute(), gesehen = (z.gesehen && typeof z.gesehen === 'object') ? z.gesehen : (z.gesehen = {}), ok = [];
    for (const p of pakete.slice(0, 1500)) {
      if (!p || typeof p.lauf !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(p.lauf)) continue;
      ok.push(p.lauf);
      if (p.tag !== z.tag || Object.hasOwn(gesehen, p.lauf)) continue;
      gesehen[p.lauf] = ts;
      // Geräte-IDs des Ersatzes auf das Hauptgerät abbilden (weitere MAC-Adressen, Codex R-R3-010)
      const daten = {}; for (const [gid, ziele] of Object.entries(p.daten && typeof p.daten === 'object' ? p.daten : {}).slice(0, 25000)) { let k = gid; try { k = kanonisch(gid) || gid; } catch (e) {} daten[k] = { ...(daten[k] || {}), ...Object.fromEntries(Object.entries(ziele || {}).map(([z, ms]) => [z, ((daten[k] || {})[z] || 0) + (Number(ms) || 0)])) }; }
      this.hinzufuegen(daten, ts);
    }
    const ids = Object.keys(gesehen); if (ids.length > 5000) for (const id of ids.slice(0, ids.length - 5000)) delete gesehen[id];
    this.geaendert = true;
    return ok;
  }
  /** Nutzung von `von` dem Gerät `nach` zuschlagen (MAC umgezogen oder verbunden, 25.11.2026, Codex-Nachprüfung R3): heutige Minuten,
   *  letzte Zeitpunkte, Zusatzzeit, „aufgebraucht“ vom Haupt, Delta und ausstehende Pakete */
  zusammenfuehren(von, nach) {
    if (!schluesselOk(von) || !schluesselOk(nach) || von === nach) return false;
    const z = this.heute(), a = Object.hasOwn(z.geraete, von) ? z.geraete[von] : null;
    if (a) {
      const b = this.eintrag(nach);
      for (const [ziel, e] of Object.entries(a.ziele || {})) { const x = (b.ziele[ziel] ||= { ms: 0, letzte: 0 }); x.ms += Number(e?.ms) || 0; x.letzte = Math.max(x.letzte, Number(e?.letzte) || 0); }
      for (const [ziel, m] of Object.entries(a.extra || {})) b.extra[ziel] = Math.max(b.extra[ziel] || 0, Number(m) || 0);
      delete z.geraete[von];
    }
    const addiere = (ziel, quelle) => { for (const [k, ms] of Object.entries(quelle || {})) ziel[k] = (ziel[k] || 0) + (Number(ms) || 0); };
    if (this.delta[von]) { addiere((this.delta[nach] ||= {}), this.delta[von]); delete this.delta[von]; }
    if (this.fremd[von]) { this.fremd[nach] = [...new Set([...(this.fremd[nach] || []), ...this.fremd[von]])]; delete this.fremd[von]; }
    for (const p of Array.isArray(z.ausstehend) ? z.ausstehend : []) if (p?.daten?.[von]) { addiere((p.daten[nach] ||= {}), p.daten[von]); delete p.daten[von]; }
    this.geaendert = true;
    return true;
  }
  hinzufuegen(nutzung, ts = this.jetzt()) {
    if (!nutzung || typeof nutzung !== 'object') return;
    for (const [gid, ziele] of Object.entries(nutzung).slice(0, 25000)) {   // signierte Pakete des Ersatzes: großzügig (Codex R4-002)
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
    for (const [gid, ziele] of Object.entries(liste).slice(0, 25000)) if (schluesselOk(gid) && Array.isArray(ziele)) this.fremd[gid] = ziele.filter((z) => typeof z === 'string').slice(0, 50);
  }
  speichern() {
    if (!this.datei || !this.geaendert) return;
    try { fs.writeFileSync(this.datei + '.tmp', JSON.stringify(this.z), { mode: 0o600 }); fs.renameSync(this.datei + '.tmp', this.datei); this.geaendert = false; } catch (e) {}
  }
}

module.exports = { Zeitkonto, LUECKE, START };
