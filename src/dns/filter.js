// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Entscheidung je Anfrage – rein, ohne Netz:
//   1. Pause (global oder Gerät)          → erlaubt
//   2. Freigabe (Gerät, Profil oder alle)  → erlaubt
//   3. eigene Sperrregel                   → geblockt
//   4. Blocklisten-Treffer in einer Kategorie, die im Profil des Geräts gerade aktiv ist → geblockt –
//      außer eine Freigabeliste enthält die Domain:
//      · selbst hinzugefügte Freigabelisten (id „eigen-…“) heben jede Sperre auf (Betreiber-Vorgabe 15.09.2026)
//      · Freigabelisten aus dem Internet nur Sperren der Kategorie „Werbung & Tracker“
//        (sie beheben Fehlalarme von Werbelisten; Schadsoftware, Jugendschutz usw. bleiben gesperrt)
//   Manuelle Freigaben (Regeln „erlauben“) greifen schon in Schritt 2 für alle Kategorien.
//   3b. Dienste (src/dienste.js, Rubriken wie bei AdGuard): „frei“ = geschützt, keine Liste blockt ihn (Vorgabe für
//      Medien, Musik, Geräte-Grundfunktionen); „sperren“ = vom Betreiber gesperrt (alle/Profil/Gerät);
//      „listen“ = normal, es entscheiden Blocklisten und Profil (Vorgabe für Social Media, Spiele, Shopping …).
//   Kinderschutz (23.11.2026):
//   1b. Hilfsangebote (Rubrik „Hilfe & Beratung“) → immer erlaubt, vor jeder Sperre
//   3a. Ruhezeit einer Rubrik im Profil (z. B. Messenger 21:00–06:30) → geblockt
//   3a. Zeitlimit eines Dienstes oder einer Rubrik für heute aufgebraucht → geblockt
//   Sichere Suche (sicherZiel): Google/Bing/DuckDuckGo und YouTube werden auf ihre gefilterte Fassung umgelenkt (server.js).
// Regeln: „beispiel.de“ gilt für die Domain und alle Subdomains, „*.beispiel.de“ nur für Subdomains.
'use strict';
const { normDomain, suffixe } = require('../netz');
const dienste = require('../dienste');
const kinderschutz = require('../daten/kinderschutz');

const WOCHENTAG = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 };
function zeitVon(ts, zeitzone) {
  const f = zeitVon.cache[zeitzone] || (zeitVon.cache[zeitzone] = new Intl.DateTimeFormat('en-GB', { timeZone: zeitzone, weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }));
  const teile = Object.fromEntries(f.formatToParts(new Date(ts)).map((p) => [p.type, p.value]));
  return { tag: WOCHENTAG[teile.weekday], minute: (+teile.hour) * 60 + (+teile.minute) };
}
zeitVon.cache = {};
const minuteVon = (hhmm) => { const m = /^(\d{1,2}):(\d{2})$/.exec(String(hhmm || '')); return m ? Math.min(1440, (+m[1]) * 60 + (+m[2])) : null; };

// Ist ein Zeitplan gerade aktiv? Leerer Zeitplan = immer. Fenster über Mitternacht gehören zum Starttag.
function zeitplanAktiv(zeitplan, ts, zeitzone) {
  if (!Array.isArray(zeitplan) || !zeitplan.length) return true;
  const { tag, minute } = zeitVon(ts, zeitzone), gestern = tag === 1 ? 7 : tag - 1;
  return zeitplan.some((f) => {
    const von = minuteVon(f.von), bis = minuteVon(f.bis), tage = f.tage || [1, 2, 3, 4, 5, 6, 7];
    if (von === null || bis === null) return false;
    if (von < bis) return tage.includes(tag) && minute >= von && minute < bis;
    if (von === bis) return tage.includes(tag);                                   // ganzer Tag
    return (tage.includes(tag) && minute >= von) || (tage.includes(gestern) && minute < bis);
  });
}

// Sekunden bis zum nächsten Beginn eines Fensters (innerhalb einer Woche), null = kein Fenster. Ganztägige Fenster beginnen um 00:00.
function sekundenBisStart(zeitplan, ts, zeitzone) {
  if (!Array.isArray(zeitplan) || !zeitplan.length) return null;
  const { tag, minute } = zeitVon(ts, zeitzone), sek = Math.floor(ts / 1000) % 60;
  let best = null;
  for (const f of zeitplan) {
    const von = minuteVon(f?.von), bis = minuteVon(f?.bis), tage = Array.isArray(f?.tage) ? f.tage : [1, 2, 3, 4, 5, 6, 7];
    if (von === null || bis === null) continue;
    const start = von === bis ? 0 : von;
    for (let d = 0; d <= 7; d++) {
      const t = ((tag - 1 + d) % 7) + 1;
      if (!tage.includes(t)) continue;
      const s = (d * 1440 + start - minute) * 60 - sek;
      if (s > 0) { if (best === null || s < best) best = s; break; }
    }
  }
  return best;
}

function musterLesen(text) {
  const s = String(text || '').trim().toLowerCase();
  const nurSub = s.startsWith('*.');
  const domain = normDomain(nurSub ? s.slice(2) : s);
  if (!domain) throw new Error('Keine gültige Domain (z. B. werbung.de oder *.werbung.de)');
  return { domain, nurSub, text: nurSub ? `*.${domain}` : domain };
}

class Filter {
  constructor({ listen, jetzt = () => Date.now(), zeitzone = process.env.TZ || 'Europe/Berlin', zeitkonto = null }) {
    Object.assign(this, { listen, jetzt, zeitzone, zeitkonto });
    this.regeln = []; this.regelIndex = new Map();
    this.profile = new Map(); this.kategorieVonListe = new Map();
    this.geraete = {}; this.pausen = { global: 0, geraete: {} };
    this.dienstIndex = dienste.index(); this.dienstAusser = dienste.ausnahmen(); this.dienstEinst = {};
  }
  // Einstellungen übernehmen (nach jeder Änderung)
  konfigurieren({ regeln = [], profile = [], listen = [], geraete = {}, pausen = { global: 0, geraete: {} }, dienste: dienstEinst = {} }) {
    this.dienstEinst = dienstEinst || {};
    this.regeln = regeln;
    const index = new Map();
    for (const r of regeln) { try { const m = musterLesen(r.muster); const liste = index.get(m.domain) || []; liste.push({ ...r, _m: m }); index.set(m.domain, liste); } catch (e) {} }
    this.regelIndex = index;
    this.profile = new Map(profile.map((p) => [p.id, p]));
    this.kategorieVonListe = new Map(listen.map((l) => [l.id, l.kategorie]));
    this.geraete = geraete; this.pausen = pausen;
  }
  // eine Ausnahme (Mess-Adresse innerhalb einer Dienst-Domain) gehört zu keinem Dienst → die Listen entscheiden
  dienstVon(domain) { if (this.dienstAusser.trifft(domain)) return null; for (const s of suffixe(domain)) { const d = this.dienstIndex.get(s); if (d) return d; } return null; }
  // 'frei' (geschützt), 'listen' (Blocklisten entscheiden) oder 'sperren' für dieses Gerät;
  // eine Ausnahme im Profil (z. B. „TikTok im Profil Kinder sperren“) überstimmt die allgemeine Einstellung
  dienstModus(dienst, geraetId, profil) {
    const profilId = typeof profil === 'string' ? profil : profil?.id;
    const imProfil = typeof profil === 'object' ? profil?.dienste?.[dienst.id] : null;
    if (imProfil === 'frei' || imProfil === 'sperren' || imProfil === 'listen') return imProfil;
    const { modus, geltung, grund } = dienste.modusVon(dienst, this.dienstEinst);
    if (modus !== 'sperren') return modus;
    return geltung === 'alle' || geltung === `profil:${profilId}` || geltung === `geraet:${geraetId}` ? 'sperren' : (grund || 'listen');
  }
  profilVon(geraetId) { return this.profile.get(this.geraete[geraetId]?.profil) || this.profile.get('standard') || [...this.profile.values()][0] || { id: 'standard', kategorien: {} }; }
  pauseBis(geraetId, jetzt = this.jetzt()) {
    const g = this.pausen.global > jetzt ? this.pausen.global : 0, d = this.pausen.geraete?.[geraetId] > jetzt ? this.pausen.geraete[geraetId] : 0;
    return Math.max(g, d);
  }
  aktiveKategorien(profil, jetzt = this.jetzt()) {
    return Object.entries(profil.kategorien || {}).filter(([, k]) => k?.an && zeitplanAktiv(k.zeitplan, jetzt, this.zeitzone)).map(([id]) => id);
  }
  passendeRegeln(name, typ, geraetId, profilId, jetzt) {
    const treffer = [];
    for (const s of suffixe(name)) {
      for (const r of this.regelIndex.get(s) || []) {
        if (r.typ !== typ || (r.bis && r.bis <= jetzt)) continue;
        if (r._m.nurSub && s === name) continue;
        const g = r.geltung || 'alle';
        if (g === 'alle' || g === `geraet:${geraetId}` || g === `profil:${profilId}`) treffer.push(r);
      }
    }
    return treffer;
  }
  // Sperrseite: Ist die Domain für irgendein Gerät als Seite gesperrt? Werbung allein zählt nicht.
  sperrgrund(name, jetzt = this.jetzt()) {
    for (const geraetId of ['', ...Object.keys(this.geraete || {})]) {
      const e = this.entscheide({ geraetId, name, jetzt });
      if (e.aktion === 'geblockt' && e.seite !== false) return e;
    }
    return null;
  }
  // Sichere Suche: Umlenkziel für diesen Namen im Profil des Geräts (nicht während einer Pause), sonst null
  sicherZiel(geraetId, name, jetzt = this.jetzt()) {
    if (this.pauseBis(geraetId, jetzt)) return null;
    return kinderschutz.sicherZiel(String(name || '').toLowerCase().replace(/\.$/, ''), this.profilVon(geraetId).sicher);
  }
  // „Mitbenutzte“ Domains (z. B. giphy, Windows-/Office-Hintergrund bei Teams) gehören zur Infrastruktur, nicht zur Nutzung des Dienstes:
  // keine Sperre, keine Ruhezeit, kein Zeitlimit – und sie zählen auch NICHT ins Zeitkonto (25.11.2026, K6: vorher zählten sie, sperrten aber nie)
  istMitbenutzt(dienst, domain) { return !!dienst?.mitbenutzt?.some((m) => domain === m || domain.endsWith('.' + m)); }
  // TTL-Deckel für eine ERLAUBTE Antwort (25.11.2026, Prüfung K15): Beginnt später ein Fenster, das diese Domain für dieses Gerät sperrt
  // (Ruhezeit der Rubrik oder Zeitplan einer Kategorie, deren Liste die Domain führt), darf das Gerät die Antwort nicht über dessen Beginn
  // hinaus behalten – sonst lief z. B. ein um 19:25 aufgelöster Spielename mit TTL 3600 nach Ruhezeitbeginn 19:30 noch eine Stunde weiter.
  // → Sekunden (mindestens 10) oder 0 = kein Deckel
  ttlDeckel(geraetId, name, jetzt = this.jetzt()) {
    const profil = this.profilVon(geraetId), kats = profil.kategorien || {}, ruhen = profil.ruhezeiten || {};
    const mitPlan = Object.values(kats).some((k) => k?.an && Array.isArray(k.zeitplan) && k.zeitplan.length) || Object.values(ruhen).some((r) => Array.isArray(r) && r.length);
    if (!mitPlan) return 0;
    const domain = String(name || '').toLowerCase().replace(/\.$/, ''), dienst = this.dienstVon(domain);
    if (dienst?.fest) return 0;
    let bis = null;
    const nimm = (s) => { if (s !== null && (bis === null || s < bis)) bis = s; };
    if (dienst && !dienst.einzelnFrei && !this.istMitbenutzt(dienst, domain)) nimm(sekundenBisStart(ruhen[dienst.gruppe], jetzt, this.zeitzone));
    if (!dienst || this.dienstModus(dienst, geraetId, profil) !== 'frei') {
      for (const id of this.listen.treffer(domain)) {
        const k = this.kategorieVonListe.get(id); if (!k || k === 'freigabe' || !kats[k]?.an) continue;
        nimm(sekundenBisStart(kats[k].zeitplan, jetzt, this.zeitzone));
      }
    }
    return bis === null ? 0 : Math.max(10, bis);
  }
  // Zeitlimit-Ziele eines Dienstes in einem Profil (für das Zeitkonto); `domain` angegeben → mitbenutzte Domains zählen nicht
  limitZiele(profil, dienst, domain = null) {
    if (domain && this.istMitbenutzt(dienst, domain)) return [];
    const l = profil?.limits; if (!l || !dienst || dienst.fest) return [];
    const z = [];
    if (l[`dienst:${dienst.id}`]) z.push(`dienst:${dienst.id}`);
    if (l[`rubrik:${dienst.gruppe}`] && !dienst.einzelnFrei) z.push(`rubrik:${dienst.gruppe}`);
    return z;
  }
  entscheide({ geraetId = '', name, jetzt = this.jetzt() }) {
    const domain = String(name || '').toLowerCase().replace(/\.$/, '');
    if (!domain) return { aktion: 'erlaubt', grund: 'leer' };
    const profil = this.profilVon(geraetId);
    const pause = this.pauseBis(geraetId, jetzt);
    if (pause) return { aktion: 'erlaubt', grund: 'Pause', bis: pause, profil: profil.id };
    const dienst = this.dienstVon(domain);
    if (dienst?.fest) return { aktion: 'erlaubt', grund: 'Hilfsangebot', dienst: dienst.id, dienstName: dienst.name, profil: profil.id };
    const frei = this.passendeRegeln(domain, 'erlauben', geraetId, profil.id, jetzt);
    if (frei.length) return { aktion: 'erlaubt', grund: 'Freigabe', regel: frei[0].id, profil: profil.id };
    const sperre = this.passendeRegeln(domain, 'sperren', geraetId, profil.id, jetzt);
    if (sperre.length) return { aktion: 'geblockt', grund: 'Eigene Regel', regel: sperre[0].id, profil: profil.id };
    if (dienst && !this.istMitbenutzt(dienst, domain)) {
      // Ruhezeit der Rubrik (einzeln freigestellte Dienste wie Pokémon GO zählen nicht zur Rubrik)
      const ruhe = !dienst.einzelnFrei && profil.ruhezeiten?.[dienst.gruppe];
      if (Array.isArray(ruhe) && ruhe.length && zeitplanAktiv(ruhe, jetzt, this.zeitzone)) return { aktion: 'geblockt', grund: 'Ruhezeit', dienst: dienst.id, dienstName: dienst.name, rubrik: dienst.gruppe, profil: profil.id };
      const limit = this.zeitkonto?.erschoepft(geraetId, profil, dienst, jetzt);
      if (limit) return { aktion: 'geblockt', grund: 'Zeitlimit', dienst: dienst.id, dienstName: dienst.name, ziel: limit, profil: profil.id };
    }
    if (dienst) {
      const modus = this.dienstModus(dienst, geraetId, profil);
      if (modus === 'sperren' && !this.istMitbenutzt(dienst, domain)) return { aktion: 'geblockt', grund: 'Dienst gesperrt', dienst: dienst.id, dienstName: dienst.name, profil: profil.id };
      if (modus === 'frei') return { aktion: 'erlaubt', grund: 'Geschützter Dienst', dienst: dienst.id, dienstName: dienst.name, listen: this.listen.treffer(domain), profil: profil.id };
    }
    const treffer = this.listen.treffer(domain);
    const freigaben = treffer.filter((id) => this.kategorieVonListe.get(id) === 'freigabe');
    const sperren = treffer.filter((id) => this.kategorieVonListe.get(id) !== 'freigabe');
    if (sperren.length) {
      const aktiv = new Set(this.aktiveKategorien(profil, jetzt));
      const greifend = sperren.filter((id) => aktiv.has(this.kategorieVonListe.get(id)));
      if (greifend.length) {
        const eigene = freigaben.filter((id) => String(id).startsWith('eigen-'));
        if (eigene.length) return { aktion: 'erlaubt', grund: 'Freigabeliste', listen: eigene, gesperrtVon: greifend, profil: profil.id };
        if (freigaben.length && greifend.every((id) => this.kategorieVonListe.get(id) === 'werbung')) return { aktion: 'erlaubt', grund: 'Freigabeliste', listen: freigaben, gesperrtVon: greifend, profil: profil.id };
        const seiteKategorie = greifend.map((id) => this.kategorieVonListe.get(id)).find((k) => k !== 'werbung');   // nur Werbung → keine Sperrseite
        return { aktion: 'geblockt', grund: 'Liste', listen: greifend, kategorie: this.kategorieVonListe.get(greifend[0]), seite: !!seiteKategorie, seiteKategorie, profil: profil.id };
      }
    }
    return { aktion: 'erlaubt', grund: sperren.length ? 'Kategorie im Profil aus' : freigaben.length ? 'auf Freigabeliste' : 'nicht gelistet', listen: freigaben.length ? freigaben : undefined, profil: profil.id };
  }
}

module.exports = { Filter, zeitplanAktiv, sekundenBisStart, musterLesen };
