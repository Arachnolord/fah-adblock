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
// Regeln: „beispiel.de“ gilt für die Domain und alle Subdomains, „*.beispiel.de“ nur für Subdomains.
'use strict';
const { normDomain, suffixe } = require('../netz');
const dienste = require('../dienste');

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

function musterLesen(text) {
  const s = String(text || '').trim().toLowerCase();
  const nurSub = s.startsWith('*.');
  const domain = normDomain(nurSub ? s.slice(2) : s);
  if (!domain) throw new Error('Keine gültige Domain (z. B. werbung.de oder *.werbung.de)');
  return { domain, nurSub, text: nurSub ? `*.${domain}` : domain };
}

class Filter {
  constructor({ listen, jetzt = () => Date.now(), zeitzone = process.env.TZ || 'Europe/Berlin' }) {
    Object.assign(this, { listen, jetzt, zeitzone });
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
    const { modus, geltung } = dienste.modusVon(dienst, this.dienstEinst);
    if (modus !== 'sperren') return modus;
    return geltung === 'alle' || geltung === `profil:${profilId}` || geltung === `geraet:${geraetId}` ? 'sperren' : 'listen';
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
  entscheide({ geraetId = '', name, jetzt = this.jetzt() }) {
    const domain = String(name || '').toLowerCase().replace(/\.$/, '');
    if (!domain) return { aktion: 'erlaubt', grund: 'leer' };
    const profil = this.profilVon(geraetId);
    const pause = this.pauseBis(geraetId, jetzt);
    if (pause) return { aktion: 'erlaubt', grund: 'Pause', bis: pause, profil: profil.id };
    const frei = this.passendeRegeln(domain, 'erlauben', geraetId, profil.id, jetzt);
    if (frei.length) return { aktion: 'erlaubt', grund: 'Freigabe', regel: frei[0].id, profil: profil.id };
    const sperre = this.passendeRegeln(domain, 'sperren', geraetId, profil.id, jetzt);
    if (sperre.length) return { aktion: 'geblockt', grund: 'Eigene Regel', regel: sperre[0].id, profil: profil.id };
    const dienst = this.dienstVon(domain);
    if (dienst) {
      const modus = this.dienstModus(dienst, geraetId, profil);
      if (modus === 'sperren' && !dienst.mitbenutzt?.some((m) => domain === m || domain.endsWith('.' + m))) return { aktion: 'geblockt', grund: 'Dienst gesperrt', dienst: dienst.id, dienstName: dienst.name, profil: profil.id };
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

module.exports = { Filter, zeitplanAktiv, musterLesen };
