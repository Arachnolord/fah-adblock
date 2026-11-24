// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Meldungen an die Eltern (Kinderschutz, 23.11.2026) – immer in FAH-Adblock selbst (Ansicht Kinderschutz, Kachel im Schutzschild),
// zusätzlich aufs Handy, wenn eingerichtet (Web-Push und/oder ntfy, siehe benachrichtigung.js – 24.11.2026). Nach draußen gehen nur
// Titel und kurzer Text, welche Seiten genau, steht nur hier. Nur für Geräte in den gewählten Profilen:
//   · Sperre in einer beobachteten Kategorie (anonyme Chats, Jugendschutz, Drogen, Umgehung …)
//   · optional: gesperrter Dienst, aufgebrauchtes Zeitlimit
//   · Umgehungsverdacht: UniFi sieht das Gerät im Netz, bei FAH-Adblock kommt aber seit X Minuten keine Anfrage an
//     (eigenes DNS, VPN, iCloud Privat-Relay …)
// Gebündelt: erste Sperre öffnet ein Fenster von 60 s, danach EINE Nachricht; je Gerät und Art Ruhe (Vorgabe 60 min).
// Haupt und Ersatz: nur Haupt/allein führt die Liste. Der Ersatz reicht seine Ereignisse und „zuletzt gesehen“ beim Abgleich weiter –
// außer er springt gerade für den ausgefallenen Haupt ein (istErsatz() ist dann falsch).
'use strict';
const fs = require('fs');

const FENSTER = 60000, STILLE_RUHE = 6 * 3600000;

class Meldungen {
  constructor({ einst, geraete = null, filter = null, jetzt = () => Date.now(), datei = null, istErsatz = () => false, kategorieName = (k) => k, senden = null, protokoll = (t) => console.log(`[meldungen] ${t}`) }) {
    Object.assign(this, { einst, geraete, filter, jetzt, datei, istErsatz, kategorieName, senden, protokoll });
    this.zuletzt = new Map();       // gid → letzte Anfrage (für den Umgehungsverdacht)
    this.neuGesehen = new Map();    // gid → ts (Ersatz: seit dem letzten Abgleich)
    this.buendel = new Map(); this.ruhe = new Map(); this.stilleGemeldet = new Map();
    this.ausgang = [];              // Ersatz: Ereignisse für den Haupt
    this.verlauf = []; this.fehler = null; this.unterdrueckt = 0;
    if (datei) { try { const v = JSON.parse(fs.readFileSync(datei, 'utf8')); if (Array.isArray(v)) this.verlauf = v.slice(0, 100); } catch (e) {} }
  }
  get m() { return this.einst.werte.meldungen || {}; }
  /** Letzte Anfrage-Zeiten aus dem Protokoll übernehmen (nach dem Start) */
  vorbelegen(liste = []) { for (const g of liste) if (g.id && g.zuletzt) this.zuletzt.set(g.id, Math.max(this.zuletzt.get(g.id) || 0, g.zuletzt)); }
  /** Jede Anfrage (DNS-Ereignis) */
  beachte(e) {
    if (!e || !e.geraet) return;
    if (e.ts > (this.zuletzt.get(e.geraet) || 0)) { this.zuletzt.set(e.geraet, e.ts); if (this.istErsatz()) this.neuGesehen.set(e.geraet, e.ts); }
    if (e.aktion !== 'geblockt' || !this.m.an || !this.m.profile?.includes(e.profil)) return;
    let art = null;
    if ((e.grund === 'Liste' || e.grund === 'CNAME-Tarnung') && this.m.kategorien?.includes(e.kategorie)) art = `kat:${e.kategorie}`;
    else if (e.grund === 'Dienst gesperrt' && this.m.dienste) art = `dienst:${e.dienst}`;
    else if (e.grund === 'Zeitlimit' && this.m.zeitlimit) art = `limit:${e.dienst}`;
    if (!art) return;
    if (this.istErsatz()) { if (this.ausgang.length < 500) this.ausgang.push({ ts: e.ts, geraet: e.geraet, geraetName: e.geraetName, profil: e.profil, aktion: e.aktion, grund: e.grund, kategorie: e.kategorie, dienst: e.dienst, domain: e.domain }); return; }
    this.sammle(art, e);
  }
  sammle(art, e) {
    const schluessel = `${e.geraet}|${art}`, jetzt = this.jetzt();
    if ((this.ruhe.get(schluessel) || 0) > jetzt) { this.unterdrueckt++; return; }
    let b = this.buendel.get(schluessel);
    if (!b) {
      b = { geraet: e.geraet, name: e.geraetName || e.geraet, benannt: !!e.geraetName, art, kategorie: e.kategorie, dienst: e.dienst, domains: new Map(), anzahl: 0 };
      this.buendel.set(schluessel, b);
      const t = setTimeout(() => this.abschicken(schluessel).catch(() => {}), FENSTER); t.unref?.();
    }
    b.anzahl++; b.domains.set(e.domain, (b.domains.get(e.domain) || 0) + 1);
  }
  async abschicken(schluessel) {
    const b = this.buendel.get(schluessel); if (!b) return;
    this.buendel.delete(schluessel);
    this.ruhe.set(schluessel, this.jetzt() + (this.m.ruheMin || 60) * 60000);
    const domains = [...b.domains.entries()].sort((x, y) => y[1] - x[1]).slice(0, 4).map(([d, n]) => `${d}${n > 1 ? ` (${n}×)` : ''}`).join(', ');
    const was = b.art.startsWith('kat:') ? `${this.kategorieName(b.kategorie)} gesperrt` : b.art.startsWith('limit:') ? `Zeitlimit für ${b.dienst} aufgebraucht` : `Gesperrter Dienst ${b.dienst} aufgerufen`;
    const ernst = ['kat:anonym', 'kat:umgehung', 'kat:jugendschutz', 'kat:drogen'].includes(b.art);
    const text = b.art.startsWith('limit:') ? 'Die Zeit für heute ist aufgebraucht – mehr Zeit gibst du unter Zeitkonten.' : `${b.anzahl} ${b.anzahl === 1 ? 'Versuch' : 'Versuche'} – gesperrt.`;
    const aussen = b.art.startsWith('limit:') ? 'Die Zeit für heute ist aufgebraucht. Mehr Zeit gibst du in FAH-Adblock unter Kinderschutz.' : `${b.anzahl} ${b.anzahl === 1 ? 'Versuch' : 'Versuche'} – gesperrt. Welche Seiten, steht in FAH-Adblock unter Kinderschutz.`;
    await this.melden({ titel: `${b.name}: ${was}`, aussenTitel: `${b.benannt ? b.name : 'Unbenanntes Gerät'}: ${was}`, text, aussen, details: b.art.startsWith('limit:') ? '' : domains, ernst, geraet: b.geraet, art: b.art });
  }
  async melden({ titel, aussenTitel = null, text, aussen = null, details = '', ernst = false, geraet = '', art = '', handy = true }) {
    // Erst in die Liste (geht nie verloren), dann aufs Handy – ein hängender Versand hält nichts auf
    const eintrag = { ts: this.jetzt(), titel, text, details, geraet, art, ernst };
    this.verlauf.unshift(eintrag); this.verlauf = this.verlauf.slice(0, 100);
    this.sichern();
    if (this.senden && handy) {
      try { const r = await this.senden({ titel: aussenTitel || titel, text: aussen || text, ernst, tag: `${geraet}|${art}`.slice(0, 64) }); if (r && (r.ntfy !== null || r.push || r.fehler?.length)) eintrag.handy = { ntfy: r.ntfy, push: r.push, fehler: r.fehler?.length ? r.fehler.slice(0, 3) : undefined }; }
      catch (e) { eintrag.handy = { fehler: [e.message] }; }
      if (eintrag.handy) this.sichern();
    }
    return eintrag;
  }
  sichern() { if (this.datei) { try { fs.writeFileSync(this.datei + '.tmp', JSON.stringify(this.verlauf), { mode: 0o600 }); fs.renameSync(this.datei + '.tmp', this.datei); } catch (e) {} } }
  /** Umgehungsverdacht: Gerät laut UniFi verbunden (letzte Abfrage), aber seit stilleMin keine Anfrage hier */
  pruefeStille() {
    if (!this.m.an || !this.m.stille || this.istErsatz() || !this.geraete || !this.filter) return [];
    const jetzt = this.jetzt(), st = this.geraete.stand || 0;
    if (!st || jetzt - st > 12 * 60000) return [];
    const grenze = (this.m.stilleMin || 30) * 60000, gemeldet = [];
    for (const [mac, c] of this.geraete.jeMac || []) {
      if (!c.gesehen || c.gesehen < st - 1000 || !c.ip) continue;                     // nicht in der letzten UniFi-Abfrage verbunden
      if (!this.m.profile?.includes(this.filter.profilVon(mac).id)) continue;
      const letzte = this.zuletzt.get(mac);
      if (!letzte) continue;                                                          // hat hier noch nie gefragt – kein Verdacht
      const seit = Math.max(letzte, c.verbunden || 0);
      if (jetzt - seit < grenze || (this.stilleGemeldet.get(mac) || 0) > jetzt - STILLE_RUHE) continue;
      this.stilleGemeldet.set(mac, jetzt);
      const min = Math.round((jetzt - seit) / 60000), echt = this.einst.werte.geraete?.[mac]?.name || c.name, name = echt || mac;
      gemeldet.push(mac);
      this.melden({ titel: `${name}: fragt FAH-Adblock nicht mehr`, aussenTitel: `${echt || 'Unbenanntes Gerät'}: fragt FAH-Adblock nicht mehr`, text: `Im Netz, aber seit ${min} Minuten keine Anfrage an FAH-Adblock. Mögliche Ursachen: eigenes DNS, eine VPN-App oder iCloud Privat-Relay – der Filter wird dann umgangen.`, ernst: true, geraet: mac, art: 'stille' }).catch(() => {});
    }
    return gemeldet;
  }
  // ── Haupt/Ersatz ──
  abholen() { const a = { ereignisse: this.ausgang, zuletzt: Object.fromEntries(this.neuGesehen) }; this.ausgang = []; this.neuGesehen = new Map(); return a; }
  empfangen({ ereignisse = [], zuletzt = {} } = {}) {
    if (zuletzt && typeof zuletzt === 'object') for (const [gid, ts] of Object.entries(zuletzt).slice(0, 1000)) if (typeof gid === 'string' && gid.length <= 64 && Number.isFinite(ts) && ts <= this.jetzt() + 60000 && ts > (this.zuletzt.get(gid) || 0)) this.zuletzt.set(gid, ts);
    if (!Array.isArray(ereignisse)) return;
    for (const e of ereignisse.slice(0, 500)) {
      if (!e || typeof e !== 'object' || typeof e.geraet !== 'string' || e.geraet.length > 64) continue;
      this.beachte({ ts: Number(e.ts) || this.jetzt(), geraet: e.geraet, geraetName: String(e.geraetName || '').slice(0, 80), profil: String(e.profil || ''), aktion: 'geblockt', grund: String(e.grund || ''), kategorie: String(e.kategorie || ''), dienst: String(e.dienst || '').slice(0, 80), domain: String(e.domain || '').slice(0, 253) });
    }
  }
  heute() { const tag = new Date(this.jetzt()).toDateString(); return this.verlauf.filter((v) => new Date(v.ts).toDateString() === tag).length; }
  status() { return { verlauf: this.verlauf.slice(0, 40), heute: this.heute(), unterdrueckt: this.unterdrueckt }; }
}

module.exports = { Meldungen };
