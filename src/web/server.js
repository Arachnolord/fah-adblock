// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// Weboberfläche und API auf node:http (ohne Fremdbibliotheken): Anmeldung, CSRF-Schutz,
// Sicherheitskopfzeilen, statische Dateien, Livestrom per Server-Sent Events.
'use strict';
const { sperrseiteHtml, domainAusKopf, grundText } = require('./sperrseite');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const { COOKIE, LAUFZEIT, GERAET_COOKIE, GERAET_LAUFZEIT } = require('../auth');
const { musterLesen } = require('../dns/filter');
const { netz, netzliste, normIp, normDomain, listenIdOk } = require('../netz');
const { lookup } = require('../aufloeser');
const kinderschutz = require('../daten/kinderschutz');
const { limitZielOk } = require('../einstellungen');
const { neueKennung, kennungAus, KENNUNG, neuesGeheimnis, AUSNAHME } = require('../unterwegs');
const { ALT_TEXT } = require('../spiegel');

const TYPEN = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.webmanifest': 'application/manifest+json' };
const SICHERHEIT = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

class HttpFehler extends Error { constructor(status, text) { super(text); this.status = status; } }
const pruefe = (bed, text, status = 400) => { if (!bed) throw new HttpFehler(status, text); };
const id = () => crypto.randomBytes(6).toString('hex');

function webServer(k) {
  const { auth, einst, listen, filter, upstream, dns, geraete, protokoll, live, version, statisch, daten = null, spiegel = null, sperrCa = '', zeitkonto = null, meldungen = null, unterwegs = null, acme = null, benachrichtigung = null, erweiterungen = [] } = k;
  let sperrAufrufe = 0;
  const routen = [];
  const route = (methode, muster, fn, { offen = false } = {}) => {
    const namen = [], re = new RegExp('^' + muster.replace(/:([a-z]+)/g, (_, n) => { namen.push(n); return '([^/]+)'; }) + '$');
    routen.push({ methode, re, namen, fn, offen });
  };
  const spiegelLaufend = new Map();   // Absender → offene Spiegel-Anfragen (Lesephase)
  const koerper = (req, max = 2e6, frist = 20000) => new Promise((ok, nein) => {
    if (Number(req.headers['content-length'] || 0) > max) { nein(new HttpFehler(413, 'Anfrage zu groß')); req.resume(); return; }   // gar nicht erst lesen
    const uhr = setTimeout(() => { nein(new HttpFehler(408, 'Anfrage zu langsam')); req.destroy(); }, frist); uhr.unref?.();   // Lesefrist gegen Schleich-Clients
    let t = ''; req.on('data', (d) => { t += d; if (t.length > max) { clearTimeout(uhr); nein(new HttpFehler(413, 'Anfrage zu groß')); req.destroy(); } });
    req.on('end', () => { clearTimeout(uhr); if (!t) return ok({}); try { ok(JSON.parse(t)); } catch (e) { nein(new HttpFehler(400, 'Ungültiges JSON')); } });
    req.on('error', nein);
  });
  const w = () => einst.werte;
  const minuten = (m) => Math.max(0, Math.min(7 * 24 * 60, Math.round(+m || 0)));
  const grenze = (wert, vorgabe, max) => Math.max(1, Math.min(max, Math.round(+wert) || vorgabe));
  // Sitzung + (optional) Geräte-Cookie „bekanntes Gerät“ (Anmeldebremse, K14) – beide HttpOnly, SameSite=Strict
  const cookieSetzen = (req, res, wert, geraet = null) => {
    const sicher = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    res.setHeader('Set-Cookie', [`${COOKIE}=${wert}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${LAUFZEIT / 1000}${sicher}`,
      ...(geraet ? [`${GERAET_COOKIE}=${geraet}; Path=/api/anmelden; HttpOnly; SameSite=Strict; Max-Age=${GERAET_LAUFZEIT / 1000}${sicher}`] : [])]);
  };
  // Adresse des Anfragenden für die Anmeldebremse: hinter einem vertrauten Proxy (NPM) zählt der Eintrag,
  // den der Proxy an X-Forwarded-For angehängt hat (von rechts, vertraute Proxys übersprungen) – der erste
  // Eintrag könnte vom Client selbst stammen (NPM hängt nur an).
  let proxyNetze = { texte: [], liste: [] }, proxyText = null;
  const vertraut = () => { const t = (w().web?.vertrauteProxies || []).join(','); if (t !== proxyText) { proxyText = t; try { proxyNetze = netzliste(t); } catch (e) { proxyNetze = { texte: [], liste: [] }; } } return proxyNetze; };
  const verbindung = (req) => {
    const adresse = normIp(req.socket.remoteAddress), weitergeleitet = String(req.headers['x-forwarded-for'] || '').split(',').map((x) => normIp(x)).filter(Boolean);
    let client = adresse;
    const vp = vertraut();
    if (vp.liste.length && vp.enthaelt(adresse)) for (let i = weitergeleitet.length - 1; i >= 0; i--) { if (!net.isIP(weitergeleitet[i])) break; client = weitergeleitet[i]; if (!vp.enthaelt(client)) break; }
    return { adresse, weitergeleitet, client, proxy: client !== adresse };
  };

  // ── Anmeldung ─────────────────────────────────────────────────────────────
  // Rolle und letzter Abgleich ohne Anmeldung: die Homepage zeigt daraus die Lämpchen (Haupt grün, Ersatz blau, aus rot)
  // `partner` (Adresse der anderen Instanz) – damit findet die Homepage beide Instanzen, wenn sie eine kennt
  route('GET', '/api/health', () => { const sp = spiegel ? spiegel.status() : null; return { ok: true, app: 'fah-adblock', dns: dns.status().laeuft, version, rolle: sp ? sp.rolle : 'allein', letzter_abgleich: sp ? sp.letzter_abgleich : null, abgleich_fehler: sp && sp.fehler ? true : false, partner: sp ? sp.partner_url : null, adresse: sp ? sp.eigene_url : null }; }, { offen: true });
  route('POST', '/api/anmelden', async ({ req, res, body }) => {
    const r = auth.anmelden(body.name, body.passwort, verbindung(req).client, req.headers.cookie);
    if (r.fehler) throw new HttpFehler(401, r.fehler);
    cookieSetzen(req, res, r.cookie, r.geraet);
    return { ok: true, standardPasswort: r.standardPasswort };
  }, { offen: true });
  route('POST', '/api/abmelden', ({ res, nutzer }) => { if (nutzer) auth.sitzungenBeenden(nutzer.name); res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`); return { ok: true }; }, { offen: true });
  route('GET', '/api/ich', ({ nutzer }) => ({ name: nutzer.name, standardPasswort: nutzer.standardPasswort, csrf: nutzer.csrf, version, erweiterungen: erweiterungen.filter((e) => e.oberflaeche).map((e) => e.name), spiegel: spiegel ? { rolle: spiegel.rolle, haupt_url: spiegel.status().haupt_url } : null }));
  route('POST', '/api/passwort', ({ req, res, nutzer, body }) => { const r = auth.passwortAendern(nutzer.name, body.alt, body.neu); if (r.fehler) throw new HttpFehler(400, r.fehler); cookieSetzen(req, res, r.cookie, r.geraet); return { ok: true }; });   // andere Sitzungen sind damit abgemeldet, diese läuft mit neuem Cookie weiter

  // ── Übersicht, Statistik, Live ────────────────────────────────────────────
  // Fragt FAH-Proxy vor jedem Sperrseiten-Zertifikat: nur wirklich gesperrte Domains bekommen eines
  route('GET', '/api/sperrseite/pruefe', ({ q }) => {
    const domain = domainAusKopf(q.get('domain'));
    if (!w().sperrseite?.an || !domain || !filter.sperrgrund(domain)) throw new HttpFehler(403, 'Nicht gesperrt');
    return { ok: true };
  }, { offen: true });
  route('GET', '/api/uebersicht', ({ q }) => {
    const jetzt = Date.now(), ls = listen.status();
    return {
      version, jetzt, kennzahlen: protokoll.kennzahlen(+q.get('stunden') || 24),
      warnungen: [einst.warnung, auth.warnung].filter(Boolean),   // z. B. beschädigte Einstellungs-/Nutzerdatei beim Start (K7)
      erweiterungen: erweiterungen.map((e) => { try { return e.kachel ? e.kachel() : null; } catch (x) { return null; } }).filter(Array.isArray), pause: { global: w().pausen.global > jetzt ? w().pausen.global : 0 },
      dns: dns.status(), upstream: upstream.status(), geraete: geraete.status(),
      listen: { gesamt: ls.gesamt, an: ls.quellen.filter((q) => q.an).length, fehler: ls.quellen.filter((q) => q.an && q.fehler).length, laedt: ls.quellen.some((q) => q.laedt) },
      protokoll: { groesse: protokoll.groesse(), fehler: protokoll.fehler, tage: w().protokoll.tage },
      sperrseite: { an: !!w().sperrseite?.an, aufrufe: sperrAufrufe, zertifikat: !!(sperrCa && fs.existsSync(sperrCa)) },
      kinderschutz: {
        meldungen: { an: !!w().meldungen?.an, heute: meldungen ? meldungen.heute() : 0, letzte: meldungen?.verlauf[0] ? { ts: meldungen.verlauf[0].ts, titel: meldungen.verlauf[0].titel } : null },
        zeitkonten: zeitkontoStatus().reduce((a, g) => ({ geraete: a.geraete + 1, aufgebraucht: a.aufgebraucht + g.ziele.filter((z) => z.aufgebraucht).length }), { geraete: 0, aufgebraucht: 0 }),
        unterwegs: unterwegs ? { an: !!w().unterwegs?.an, geraete: Object.values(w().unterwegs?.geraete || {}).filter((g) => g.an !== false).length, aktiv: [...unterwegs.zuletzt.values()].filter((z) => z.extern && jetzt - z.ts < 3600000).length, dot: !!unterwegs.server?.listening } : null,
      },
    };
  });
  route('GET', '/api/verlauf', ({ q }) => protokoll.verlauf(q.get('zeitraum') === '7d' ? '7d' : '24h'));
  route('GET', '/api/top', ({ q }) => {
    const stunden = Math.max(1, Math.min(720, +q.get('stunden') || 24));   // bis 30 Tage
    return protokoll.topDomainsAsync({ aktion: q.get('aktion') === 'erlaubt' ? 'erlaubt' : 'geblockt', seit: Date.now() - stunden * 3600000, geraet: q.get('geraet') || '', limit: grenze(q.get('limit'), 15, 50) });
  });
  route('GET', '/api/live', ({ req, res }) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no', ...SICHERHEIT });
    res.write(`retry: 3000\n\n`);
    const letzte = protokoll.ring.slice(-40).map(kompakt);
    res.write(`event: start\ndata: ${JSON.stringify(letzte)}\n\n`);
    live.add(res);
    const puls = setInterval(() => { if (res.writableLength > 1e6 || res.destroyed) { clearInterval(puls); live.delete(res); return res.destroy(); } res.write(': puls\n\n'); }, 20000);
    req.on('close', () => { clearInterval(puls); live.delete(res); });
    return undefined;
  });

  // ── Geräte, Pause, Rettung ────────────────────────────────────────────────
  route('GET', '/api/geraete', () => {
    const jetzt = Date.now(), einstG = w().geraete, stat = protokoll.geraeteStatistik();
    const bekannt = new Set(stat.map((s) => s.id));
    const liste = stat.map((s) => ({ ...s, weitereMacs: einstG[s.id]?.weitereMacs || [], icon: geraete.iconVon?.(s.id) || null, name: einstG[s.id]?.name || (s.name === s.id || s.name === s.ip ? geraete.nameVon(s.id) || s.name : s.name), eigenerName: !!einstG[s.id]?.name, profil: filter.profilVon(s.id).id, pauseBis: filter.pauseBis(s.id, jetzt) }));
    for (const [gid, g] of Object.entries(einstG)) if (!bekannt.has(gid)) liste.push({ id: gid, weitereMacs: g.weitereMacs || [], icon: geraete.iconVon?.(gid) || null, name: g.name || geraete.nameVon(gid) || gid, eigenerName: !!g.name, ip: '', zuletzt: 0, erlaubt: 0, geblockt: 0, quote: 0, kurve: [], profil: filter.profilVon(gid).id, pauseBis: filter.pauseBis(gid, jetzt) });
    const inListe = new Set(liste.map((x) => x.id));
    const unifiBekannt = (geraete.bekannteUnifi?.() || []).filter((x) => !inListe.has(x.id) && (!geraete.haupt || geraete.haupt(x.id) === x.id)).sort((a, b) => a.name.localeCompare(b.name, 'de')).slice(0, 500);
    return { geraete: liste, unifiBekannt, profile: w().profile.map((p) => ({ id: p.id, name: p.name, farbe: p.farbe })) };
  });
  // Gerätesymbole aus UniFi (static.ui.com) – einmal geladen und in data/symbole zwischengespeichert, damit der Browser nur diese Seite fragt
  const symbolFehler = new Map();
  route('GET', '/api/symbol/:id', async ({ p, res }) => {
    const sid = String(p.id);
    pruefe(/^\d{1,7}$/.test(sid), 'Ungültige Symbol-ID');
    const ordner = daten ? path.join(daten, 'symbole') : null, datei = ordner ? path.join(ordner, `${sid}.png`) : null;
    const senden = (buf) => { res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'private, max-age=604800', ...SICHERHEIT }); res.end(buf); };
    if (datei && fs.existsSync(datei)) return senden(fs.readFileSync(datei));
    if ((symbolFehler.get(sid) || 0) > Date.now()) throw new HttpFehler(404, 'Kein Symbol');
    try {
      const buf = await symbolLaden(sid);
      if (datei) { fs.mkdirSync(ordner, { recursive: true }); fs.writeFileSync(datei + '.tmp', buf); fs.renameSync(datei + '.tmp', datei); }
      return senden(buf);
    } catch (e) { symbolFehler.set(sid, Date.now() + 3600000); throw new HttpFehler(404, 'Kein Symbol'); }
  });
  route('PUT', '/api/geraete/:id', ({ p, body }) => {
    const gid = decodeURIComponent(p.id);
    pruefe(gid.length <= 64, 'Ungültige Geräte-ID');
    if (body.profil !== undefined) pruefe(w().profile.some((x) => x.id === body.profil), 'Profil unbekannt');
    // Weitere MAC-Adressen desselben Geräts (25.11.2026, z. B. Reiserouter: Kabel + WLAN) – alle laufen unter diesem Gerät (Profil, Statistik, Regeln)
    let macs = null;
    if (body.weitereMacs !== undefined) {
      const MAC = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;
      pruefe(MAC.test(gid), 'Weitere MAC-Adressen gehen nur bei Geräten mit MAC-Adresse');
      const roh = (Array.isArray(body.weitereMacs) ? body.weitereMacs : String(body.weitereMacs || '').split(/[\s,;]+/)).map((m) => String(m).trim()).filter(Boolean);
      const falsch = roh.filter((m) => !MAC.test(m));
      pruefe(!falsch.length, `Keine MAC-Adresse: ${falsch.slice(0, 2).join(', ')} (Form aa:bb:cc:dd:ee:ff)`);
      macs = [...new Set(roh.map((m) => m.toLowerCase().replace(/-/g, ':')))];
      pruefe(macs.length <= 5, 'Höchstens 5 weitere MAC-Adressen');
      pruefe(!macs.includes(gid), 'Die eigene MAC-Adresse muss nicht eingetragen werden');
      for (const [anderes, g] of Object.entries(w().geraete)) if (anderes !== gid && (g.weitereMacs || []).some((m) => macs.includes(m))) pruefe(false, `Eine MAC gehört schon zu „${g.name || geraete.nameVon(anderes) || anderes}“`);
      for (const m of macs) pruefe(!(w().geraete[m]?.weitereMacs || []).length, `${m} hat selbst weitere MAC-Adressen – dort erst entfernen`);
    }
    const vorher = new Set(w().geraete[gid]?.weitereMacs || []);
    einst.aendern((x) => {
      const g = x.geraete[gid] || {};
      if (body.name !== undefined) g.name = String(body.name).trim().slice(0, 60);
      if (body.profil !== undefined) g.profil = body.profil;
      if (macs) {
        if (macs.length) g.weitereMacs = macs; else delete g.weitereMacs;
        for (const m of macs) {   // was bisher unter der weiteren MAC lief, gehört jetzt dem Gerät (eigener Eintrag weg, Regeln/Pausen/Dienste umgehängt)
          delete x.geraete[m];
          if (x.pausen.geraete[m]) { x.pausen.geraete[gid] = Math.max(x.pausen.geraete[gid] || 0, x.pausen.geraete[m]); delete x.pausen.geraete[m]; }
          for (const r of x.regeln) if (r.geltung === `geraet:${m}`) r.geltung = `geraet:${gid}`;
          for (const d of Object.values(x.dienste || {})) if (d.geltung === `geraet:${m}`) d.geltung = `geraet:${gid}`;
        }
      }
      x.geraete[gid] = g;
    });
    // Verlauf der neu verbundenen MACs dem Gerät zuschlagen (Statistik, Protokoll)
    if (macs) for (const m of macs) if (!vorher.has(m)) { protokoll.zusammenfuehren?.(m, gid, 0, w().geraete[gid]?.name || ''); zeitkonto?.zusammenfuehren?.(m, gid); }
    if (macs) zeitkonto?.speichern?.();
    return { ok: true };
  });
  // Alle MAC-Adressen eines Geräts auf einmal (25.11.2026): die erste ist die Haupt-MAC, die übrigen „weitere MACs“. Weicht die erste von der
  // bisherigen ID ab, zieht das Gerät um – Name, Profil, Regeln, Pausen, Dienste, Unterwegs-Eintrag (gleiches Geheimnis, DoH-Adresse bleibt) und Verlauf.
  route('PUT', '/api/geraete/:id/macs', ({ p, body }) => {
    const gid = decodeURIComponent(p.id), MAC = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;
    pruefe(MAC.test(gid), 'MAC-Adressen gehen nur bei Geräten mit MAC-Adresse');
    const roh = (Array.isArray(body.macs) ? body.macs : String(body.macs || '').split(/[\s,;]+/)).map((m) => String(m).trim()).filter(Boolean);
    const falsch = roh.filter((m) => !MAC.test(m));
    pruefe(!falsch.length, `Keine MAC-Adresse: ${falsch.slice(0, 2).join(', ')} (Form aa:bb:cc:dd:ee:ff)`);
    const macs = [...new Set(roh.map((m) => m.toLowerCase().replace(/-/g, ':')))];
    pruefe(macs.length >= 1, 'Mindestens eine MAC-Adresse (die erste ist die Haupt-MAC)');
    pruefe(macs.length <= 6, 'Höchstens 6 MAC-Adressen je Gerät');
    const [haupt, ...weitere] = macs, x0 = w(), alteWeitere = x0.geraete[gid]?.weitereMacs || [];
    for (const [anderes, g] of Object.entries(x0.geraete)) {
      if (anderes === gid || macs.includes(anderes) && !(g.weitereMacs || []).length) continue;
      if (macs.includes(anderes)) pruefe(false, `${anderes} hat selbst weitere MAC-Adressen – dort erst entfernen`);
      if ((g.weitereMacs || []).some((m) => macs.includes(m))) pruefe(false, `Eine MAC gehört schon zu „${g.name || geraete.nameVon(anderes) || anderes}“`);
    }
    if (haupt !== gid) pruefe(!x0.unterwegs?.geraete?.[haupt] || !x0.unterwegs?.geraete?.[gid], `${haupt} ist schon für unterwegs eingerichtet`);
    const umhaengen = [gid, ...alteWeitere, ...macs].filter((m, i, a) => m !== haupt && a.indexOf(m) === i);
    einst.aendern((x) => {
      const g = { ...(x.geraete[haupt] || {}), ...(x.geraete[gid] || {}) };   // Einstellungen des bisherigen Geräts gehen vor
      if (weitere.length) g.weitereMacs = weitere; else delete g.weitereMacs;
      for (const m of umhaengen) {
        if (m !== gid && m !== haupt) { if (!g.name && x.geraete[m]?.name) g.name = x.geraete[m].name; if (!g.profil && x.geraete[m]?.profil) g.profil = x.geraete[m].profil; }
        if (!weitere.includes(m)) { /* bleibt erhalten: alte weitere MAC, die nicht mehr dazugehört, wird wieder eigenständig */ }
        if (weitere.includes(m) || m === gid) delete x.geraete[m];
        if (x.pausen.geraete[m] && (weitere.includes(m) || m === gid)) { x.pausen.geraete[haupt] = Math.max(x.pausen.geraete[haupt] || 0, x.pausen.geraete[m]); delete x.pausen.geraete[m]; }
        if (weitere.includes(m) || m === gid) {
          for (const r of x.regeln) if (r.geltung === `geraet:${m}`) r.geltung = `geraet:${haupt}`;
          for (const d of Object.values(x.dienste || {})) if (d.geltung === `geraet:${m}`) d.geltung = `geraet:${haupt}`;
        }
      }
      if (haupt !== gid && x.unterwegs?.geraete?.[gid]) { x.unterwegs.geraete[haupt] = x.unterwegs.geraete[gid]; delete x.unterwegs.geraete[gid]; }
      x.geraete[haupt] = g;
    });
    // Verlauf: bisherige ID und neu verbundene MACs dem Gerät zuschlagen
    for (const m of [gid, ...weitere]) if (m !== haupt && (m === gid || !alteWeitere.includes(m))) { protokoll.zusammenfuehren?.(m, haupt, 0, w().geraete[haupt]?.name || ''); zeitkonto?.zusammenfuehren?.(m, haupt); }
    zeitkonto?.speichern?.();
    if (haupt !== gid) unterwegsWeiter?.(true);
    return { ok: true, id: haupt, weitereMacs: weitere };
  });
  route('POST', '/api/pause', ({ body }) => {
    pruefe(!body.geraet || String(body.geraet).length <= 64, 'Ungültige Geräte-ID');
    const m = minuten(body.minuten), bis = m ? Date.now() + m * 60000 : 0;
    einst.aendern((x) => {
      if (body.geraet) { if (bis) x.pausen.geraete[body.geraet] = bis; else delete x.pausen.geraete[body.geraet]; }
      else x.pausen.global = bis;
      for (const [g, t] of Object.entries(x.pausen.geraete)) if (t < Date.now()) delete x.pausen.geraete[g];
    });
    return { ok: true, bis };
  });
  route('GET', '/api/rettung/:geraet', ({ p, q }) => ({ geraet: decodeURIComponent(p.geraet), eintraege: protokoll.rettung(decodeURIComponent(p.geraet), Math.max(1, Math.min(240, +q.get('minuten') || 15))) }));
  route('GET', '/api/protokoll', ({ q }) => protokoll.eintraegeAsync({ geraet: q.get('geraet') || '', nurGeblockt: q.get('nurGeblockt') === '1', suche: q.get('suche') || '', vor: +q.get('vor') || 0, limit: grenze(q.get('limit'), 100, 500) }));
  route('GET', '/api/pruefen', ({ q }) => {
    const domain = normDomain(q.get('domain')); pruefe(domain, 'Keine gültige Domain');
    const geraet = q.get('geraet') || '';
    return { domain, geraet, ...filter.entscheide({ geraetId: geraet, name: domain }), listen: listen.treffer(domain) };
  });

  // ── Kinderschutz: Meldungen, Zeitkonten, Altersvorlagen, Hilfsangebote ───
  const dk = require('../dienste');
  const zielName = (ziel) => { const [art, zid] = String(ziel).split(':'); return art === 'dienst' ? dk.DIENSTE.find((d) => d.id === zid)?.name || zid : `${dk.GRUPPEN.find((g) => g.id === zid)?.name || zid} (alle)`; };
  function zeitkontoStatus() {
    if (!zeitkonto) return [];
    const ids = new Set([...Object.keys(w().geraete || {}), ...Object.keys(zeitkonto.heute().geraete)]);
    const aus = [];
    for (const gid of ids) {
      const p = filter.profilVon(gid), limits = p.limits || {};
      if (!Object.keys(limits).length) continue;
      aus.push({ id: gid, name: w().geraete[gid]?.name || geraete.nameVon(gid) || gid, profil: p.id, profilName: p.name,
        ziele: Object.entries(limits).map(([ziel, limit]) => { const genutzt = zeitkonto.genutztMin(gid, ziel), extra = zeitkonto.extraMin(gid, ziel); return { ziel, name: zielName(ziel), limit, extra, genutzt, aufgebraucht: !!zeitkonto.aufgebraucht(gid, p, [ziel]) }; }) });
    }
    return aus.sort((a, b) => a.name.localeCompare(b.name, 'de'));
  }
  route('GET', '/api/vorlagen', () => kinderschutz.VORLAGEN);
  route('GET', '/api/kinderschutz', () => ({
    meldungen: { ...einst.oeffentlich().meldungen, ...(meldungen ? meldungen.status() : {}) },
    handy: benachrichtigung ? benachrichtigung.status() : null,
    zeitkonten: zeitkontoStatus(),
    unterwegs: unterwegs ? { ...unterwegs.status(), proxyVorschlag: (() => { const sp = spiegel ? spiegel.status() : {}; return [sp.eigene_url, sp.partner_url].filter(Boolean).map((u) => { try { return new URL(u).hostname; } catch (e) { return ''; } }).filter((h) => /^(10|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(h)).map((h) => `https://${h}:28181`); })() } : null,
    hilfe: dk.DIENSTE.filter((d) => d.fest).map((d) => ({ id: d.id, name: d.name, symbol: d.symbol, domains: d.domains, hinweis: d.hinweis || '' })),
    vorlagen: kinderschutz.VORLAGEN, profile: w().profile.map((p) => ({ id: p.id, name: p.name, farbe: p.farbe })),
    kategorien: w().kategorien.filter((x) => x.art !== 'erlauben'),
  }));
  route('PUT', '/api/kinderschutz/meldungen', ({ body }) => {
    const m = {};
    if (body.an !== undefined) m.an = !!body.an;
    if (body.profile !== undefined) { pruefe(Array.isArray(body.profile) && body.profile.every((x) => w().profile.some((p) => p.id === x)), 'Profil unbekannt'); m.profile = body.profile; }
    if (body.kategorien !== undefined) { pruefe(Array.isArray(body.kategorien) && body.kategorien.every((x) => w().kategorien.some((c) => c.id === x)), 'Kategorie unbekannt'); m.kategorien = body.kategorien; }
    for (const s2 of ['dienste', 'zeitlimit', 'stille']) if (body[s2] !== undefined) m[s2] = !!body[s2];
    if (body.stilleMin !== undefined) m.stilleMin = Math.max(10, Math.min(720, Math.round(+body.stilleMin) || 30));
    if (body.ruheMin !== undefined) m.ruheMin = Math.max(5, Math.min(1440, Math.round(+body.ruheMin) || 60));
    einst.aendern((x) => { x.meldungen = { ...x.meldungen, ...m }; });
    return einst.oeffentlich().meldungen;
  });
  // Benachrichtigungen aufs Handy (Web-Push, ntfy) – eingerichtet wird am Haupt, der Ersatz bekommt alles beim Abgleich
  const handyBereit = () => { pruefe(benachrichtigung, 'Benachrichtigungen nicht verfügbar', 503); pruefe(!benachrichtigung.istErsatz(), 'Bitte am Haupt einrichten – der Ersatz übernimmt alles beim Abgleich', 409); };
  const fehler400 = (fn) => { try { return fn(); } catch (e) { throw e instanceof HttpFehler ? e : new HttpFehler(400, e.message); } };
  route('GET', '/api/benachrichtigung', () => { pruefe(benachrichtigung, 'Benachrichtigungen nicht verfügbar', 503); return benachrichtigung.status(); });
  route('PUT', '/api/benachrichtigung/ntfy', ({ body }) => { handyBereit(); fehler400(() => benachrichtigung.ntfySetzen({ url: body.url, thema: body.thema, schluessel: typeof body.schluessel === 'string' ? body.schluessel : undefined, schluesselLoeschen: !!body.schluesselLoeschen })); return benachrichtigung.status(); });
  route('POST', '/api/benachrichtigung/test', async ({ body }) => {
    pruefe(benachrichtigung, 'Benachrichtigungen nicht verfügbar', 503);
    let erg; try { erg = await benachrichtigung.test(typeof body.id === 'string' ? body.id : null); } catch (e) { throw new HttpFehler(400, e.message); }
    if (!erg.push && !erg.ntfy && erg.fehler.length) throw new HttpFehler(502, erg.fehler.join(' · '));
    return erg;
  });
  route('POST', '/api/push/abo', ({ body }) => {
    handyBereit();
    const id = fehler400(() => benachrichtigung.aboHinzufuegen({ abo: body.abo, name: body.name }));
    return { id, ...benachrichtigung.status() };
  });
  route('DELETE', '/api/push/abo/:id', ({ p }) => { handyBereit(); pruefe(/^[a-f0-9]{16}$/.test(p.id), 'Unbekanntes Gerät'); benachrichtigung.aboEntfernen(p.id); return benachrichtigung.status(); });
  route('POST', '/api/zeitkonto/mehr', ({ body }) => {
    pruefe(zeitkonto, 'Zeitkonto nicht verfügbar', 503);
    const gid = String(body.geraet || ''); pruefe(gid && gid.length <= 64, 'Gerät fehlt');
    pruefe(limitZielOk(body.ziel), 'Ziel unbekannt');
    const min = Math.round(+body.minuten); pruefe([0, 15, 30, 60, 1440].includes(min), 'Minuten: 15, 30, 60, 1440 (Rest des Tages) oder 0');
    zeitkonto.mehr(gid, body.ziel, min); zeitkonto.speichern();
    return { ok: true, extra: zeitkonto.extraMin(gid, body.ziel) };
  });
  // ── Schutz unterwegs ──
  const unterwegsWeiter = (sofort = false) => { if (unterwegs) { unterwegs.dotPruefen(); unterwegs.zertifikatePflegen({ sofort }).catch(() => {}); } };
  route('PUT', '/api/unterwegs', ({ body }) => {
    const u = {};
    if (body.an !== undefined) u.an = !!body.an;
    if (body.basis !== undefined) { const b = String(body.basis || '').trim().toLowerCase().replace(/^\*?\./, ''); pruefe(!b || /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(b), 'Basisdomain wie meinname.example.de angeben'); u.basis = b; }
    if (body.email !== undefined) { const m = String(body.email || '').trim(); pruefe(!m || /^[^\s@<>]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(m), 'E-Mail-Adresse ungültig'); u.email = m; }
    // Eigene lokale Namen, die Apple-Geräte selbst auflösen (z. B. interne Firmen-Domains) – je Zeile oder durch Komma/Leerzeichen getrennt
    if (body.ausnahmen !== undefined) {
      const liste = (Array.isArray(body.ausnahmen) ? body.ausnahmen : String(body.ausnahmen || '').split(/[\s,;]+/)).map((d) => String(d).trim().toLowerCase().replace(/^\*?\./, '').replace(/\.$/, '')).filter(Boolean);
      const falsch = liste.filter((d) => !AUSNAHME.test(d));
      pruefe(!falsch.length, `Ungültiger Name: ${falsch.slice(0, 3).join(', ')} (nur Domains wie firma.intern oder corp.example.com)`);
      pruefe(liste.length <= 50, 'Höchstens 50 eigene Ausnahmen');
      u.ausnahmen = [...new Set(liste)];
    }
    einst.aendern((x) => { x.unterwegs = { ...x.unterwegs, ...u }; });
    unterwegsWeiter();
    return unterwegs ? unterwegs.status() : w().unterwegs;
  });
  // Name für unterwegs: frei wählbar (dns-…), sonst aus dem Gerätenamen, notfalls zufällig; immer eindeutig
  const freieKennung = (x, wunsch, gid) => {
    const belegt = (k) => Object.entries(x.unterwegs.geraete).some(([id, y]) => id !== gid && y.kennung === k);
    if (wunsch && KENNUNG.test(wunsch) && !belegt(wunsch)) return wunsch;
    for (let i = 2; wunsch && KENNUNG.test(wunsch) && i < 50; i++) { const k = `${wunsch.slice(0, 21)}-${i}`; if (KENNUNG.test(k) && !belegt(k)) return k; }
    let k; do { k = neueKennung(); } while (belegt(k));
    return k;
  };
  route('PUT', '/api/unterwegs/geraete/:id', ({ p, body }) => {
    let gid = decodeURIComponent(p.id); pruefe(gid.length <= 64, 'Ungültige Geräte-ID');
    // Von Hand per MAC (Gerät gerade nicht im Netz, z. B. Reiserouter unterwegs): Schreibweise vereinheitlichen (aa:bb:cc:dd:ee:ff)
    if (/^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(gid)) gid = gid.toLowerCase().replace(/-/g, ':');
    const name = body.name === undefined ? '' : String(body.name || '').trim().replace(/\s+/g, ' ').slice(0, 60);
    let wunsch = null;
    if (body.kennung !== undefined) { wunsch = `dns-${String(body.kennung || '').trim().toLowerCase().replace(/^dns-/, '').replace(/\..*$/, '')}`; pruefe(KENNUNG.test(wunsch), 'Name: Kleinbuchstaben, Ziffern und Bindestrich, 1–24 Zeichen (z. B. fairphone)'); pruefe(!Object.entries(w().unterwegs.geraete).some(([id, y]) => id !== gid && y.kennung === wunsch), 'Diesen Namen hat schon ein anderes Gerät'); }
    einst.aendern((x) => {
      const g = x.unterwegs.geraete[gid];
      if (name && !x.geraete[gid]?.name && !geraete.jeMac?.get(gid)?.name) x.geraete[gid] = { ...(x.geraete[gid] || {}), name };   // Name nur, wenn weder ein eigener noch einer aus UniFi bekannt ist
      if (!g) x.unterwegs.geraete[gid] = { kennung: freieKennung(x, wunsch || kennungAus(name || x.geraete[gid]?.name || geraete.nameVon(gid)), gid), geheim: neuesGeheimnis(), an: body.an !== false };
      else { if (body.an !== undefined) g.an = !!body.an; if (wunsch) g.kennung = wunsch; }
    });
    unterwegsWeiter(true);
    return unterwegs ? unterwegs.status() : w().unterwegs;
  });
  route('POST', '/api/unterwegs/geraete/:id/erneuern', ({ p }) => {
    const gid = decodeURIComponent(p.id); pruefe(w().unterwegs.geraete[gid], 'Gerät ist nicht für unterwegs eingerichtet', 404);
    einst.aendern((x) => { x.unterwegs.geraete[gid] = { ...x.unterwegs.geraete[gid], kennung: freieKennung(x, kennungAus(x.geraete[gid]?.name || geraete.nameVon(gid)), gid), geheim: neuesGeheimnis() }; });   // kurzer Name bleibt, das Geheimnis (iPhone-Profil) ist neu
    unterwegsWeiter(true);
    return unterwegs ? unterwegs.status() : w().unterwegs;
  });
  route('DELETE', '/api/unterwegs/geraete/:id', ({ p }) => { const gid = decodeURIComponent(p.id); einst.aendern((x) => { delete x.unterwegs.geraete[gid]; }); unterwegsWeiter(); return { ok: true }; });
  // FAH-Proxy einmal koppeln (Admin-Login wird nicht gespeichert) – danach legt FAH-Adblock die Einträge selbst an und löscht sie
  route('POST', '/api/unterwegs/proxy', async ({ body }) => {
    pruefe(unterwegs?.proxy, 'Nicht verfügbar', 503);
    try { await unterwegs.proxy.koppeln({ urls: body.urls, name: body.name, passwort: body.passwort, code: body.code }); } catch (e) { throw new HttpFehler(e.status || 502, e.message); }
    await unterwegs.freigabenPflegen().catch(() => {}); unterwegsWeiter(true);
    return unterwegs.status();
  });
  route('DELETE', '/api/unterwegs/proxy', async () => { pruefe(unterwegs?.proxy, 'Nicht verfügbar', 503); const r = await unterwegs.proxy.entkoppeln(); return { ...unterwegs.status(), entkoppelt: r }; });
  route('POST', '/api/unterwegs/freigaben', async () => { pruefe(unterwegs, 'Nicht verfügbar', 503); await unterwegs.freigabenPflegen(); return unterwegs.status(); });
  route('POST', '/api/unterwegs/zertifikate', async () => { pruefe(unterwegs, 'Nicht verfügbar', 503); await unterwegs.zertifikatePflegen({ sofort: true }); return unterwegs.status(); });

  // ── Katalog kostenloser DNS-Anbieter ─────────────────────────────────────
  const anbieterKatalog = require('../anbieter');
  route('GET', '/api/anbieter', () => ({ gruppen: anbieterKatalog.GRUPPEN, anbieter: anbieterKatalog.ANBIETER }));

  // ── Dienste (Rubriken wie bei AdGuard) ───────────────────────────────────
  const dienstKatalog = require('../dienste');
  route('GET', '/api/dienste', () => ({ gruppen: dienstKatalog.GRUPPEN, dienste: dienstKatalog.DIENSTE.map((d) => ({ ...d, ...dienstKatalog.modusVon(d, w().dienste || {}) })) }));
  route('PUT', '/api/dienste/:id', ({ p, body }) => {
    const d = dienstKatalog.DIENSTE.find((x) => x.id === p.id); pruefe(d, 'Dienst unbekannt');
    pruefe(!d.fest, 'Hilfsangebote sind immer erreichbar und lassen sich nicht ändern');
    const modus = String(body.modus || (body.gesperrt ? 'sperren' : d.vorgabe));
    pruefe(['frei', 'listen', 'sperren'].includes(modus), 'Unbekannter Zustand');
    const geltung = String(body.geltung || 'alle');
    pruefe(geltung === 'alle' || (geltung.startsWith('profil:') && w().profile.some((x) => `profil:${x.id}` === geltung)) || (geltung.startsWith('geraet:') && geltung.length <= 72), 'Ungültiger Geltungsbereich');
    // Sperre nur für ein Profil/Gerät: alle anderen behalten ihren bisherigen Grundzustand (25.11.2026, K5 – vorher fielen sie auf „nach Listen“,
    // ein geschützter Mediendienst wurde so für den Rest des Hauses wieder von Blocklisten entschieden)
    const bisher = dienstKatalog.modusVon(d, w().dienste || {}), grund = bisher.modus === 'sperren' ? w().dienste?.[d.id]?.grund : bisher.modus;
    einst.aendern((x) => { x.dienste = x.dienste || {}; if (modus === d.vorgabe && modus !== 'sperren') delete x.dienste[d.id]; else x.dienste[d.id] = modus === 'sperren' ? { modus, geltung, ...(geltung !== 'alle' && ['frei', 'listen'].includes(grund) && grund !== d.vorgabe ? { grund } : {}) } : { modus }; });
    return { ok: true };
  });

  // ── Regeln ────────────────────────────────────────────────────────────────
  route('GET', '/api/regeln', () => w().regeln.filter((r) => !r.bis || r.bis > Date.now()));
  route('POST', '/api/regeln', ({ body, nutzer }) => {
    pruefe(['erlauben', 'sperren'].includes(body.typ), 'Typ: erlauben oder sperren');
    let m; try { m = musterLesen(body.muster); } catch (e) { throw new HttpFehler(400, e.message); }
    const geltung = String(body.geltung || 'alle');
    pruefe(geltung === 'alle' || /^geraet:.{1,64}$/.test(geltung) || (geltung.startsWith('profil:') && w().profile.some((x) => `profil:${x.id}` === geltung)), 'Geltung: alle, geraet:<id> oder profil:<id>');
    const dauer = minuten(body.minuten);
    const regel = { id: id(), typ: body.typ, muster: m.text, geltung, bis: dauer ? Date.now() + dauer * 60000 : null, notiz: String(body.notiz || '').slice(0, 120), erstellt: Date.now(), von: nutzer.name };
    einst.aendern((x) => {
      x.regeln = x.regeln.filter((r) => (!r.bis || r.bis > Date.now()) && !(r.muster === regel.muster && r.geltung === regel.geltung));   // gleiche Regel ersetzen
      x.regeln.push(regel);
    });
    return regel;
  });
  route('DELETE', '/api/regeln/:id', ({ p }) => { einst.aendern((x) => { x.regeln = x.regeln.filter((r) => r.id !== p.id); }); return { ok: true }; });

  // ── Listen ────────────────────────────────────────────────────────────────
  route('GET', '/api/listen', () => ({ ...listen.status(), kategorien: w().kategorien }));
  route('POST', '/api/listen', ({ body }) => {
    let url; try { url = new URL(String(body.url || '')); } catch (e) { throw new HttpFehler(400, 'Ungültige Adresse'); }
    pruefe(['https:', 'http:'].includes(url.protocol), 'Nur http(s)-Adressen');
    pruefe(w().kategorien.some((c) => c.id === body.kategorie), 'Kategorie unbekannt');
    pruefe(w().listen.length < 30, 'Höchstens 30 Listen');
    const liste = { id: `eigen-${id()}`, name: String(body.name || url.hostname).slice(0, 60), url: url.href, kategorie: body.kategorie, an: true };
    einst.aendern((x) => { x.listen.push(liste); });
    listen.aktualisieren({ nur: liste.id }).catch(() => {});
    return liste;
  });
  route('PUT', '/api/listen/:id', ({ p, body }) => {
    pruefe(w().listen.some((l) => l.id === p.id), 'Liste unbekannt', 404);
    if (body.kategorie !== undefined) pruefe(w().kategorien.some((c) => c.id === body.kategorie), 'Kategorie unbekannt');
    einst.aendern((x) => { const l = x.listen.find((y) => y.id === p.id); if (body.an !== undefined) l.an = !!body.an; if (body.name) l.name = String(body.name).slice(0, 60); if (body.kategorie) l.kategorie = body.kategorie; });
    const l = w().listen.find((y) => y.id === p.id);
    if (l.an && !listen.stand[l.id]?.anzahl) listen.aktualisieren({ nur: l.id }).catch(() => {});
    return { ok: true };
  });
  route('DELETE', '/api/listen/:id', ({ p }) => { einst.aendern((x) => { x.listen = x.listen.filter((l) => l.id !== p.id); }); try { fs.unlinkSync(listen.dateiVon(p.id)); } catch (e) {} return { ok: true }; });
  route('POST', '/api/listen/aktualisieren', async ({ body }) => ({ ergebnis: await listen.aktualisieren({ alle: !body.id, nur: body.id || null, gruppe: ['sperren', 'freigabe'].includes(body.gruppe) ? body.gruppe : null }), status: listen.status() }));

  // ── Profile ───────────────────────────────────────────────────────────────
  route('GET', '/api/profile', () => ({ profile: w().profile, kategorien: w().kategorien }));
  const vorlageWerte = (vid) => {
    const v = kinderschutz.VORLAGEN.find((x) => x.id === vid); pruefe(v, 'Vorlage unbekannt');
    const kopie = JSON.parse(JSON.stringify(v));
    return { kategorien: kopie.kategorien, dienste: kopie.dienste, ruhezeiten: kopie.ruhezeiten, sicher: kopie.sicher, limits: kopie.limits, beschreibung: kopie.beschreibung, farbe: kopie.farbe, name: kopie.name };
  };
  route('POST', '/api/profile', ({ body }) => {
    const vorlage = body.vorlage ? vorlageWerte(String(body.vorlage)) : null;
    const name = String(body.name || vorlage?.name || '').trim().slice(0, 40); pruefe(name, 'Name fehlt');
    const profil = { id: `p-${id()}`, name, farbe: /^#[0-9a-f]{6}$/i.test(body.farbe) ? body.farbe : vorlage?.farbe || '#7aa2ff', beschreibung: vorlage?.beschreibung || '', kategorien: { werbung: { an: true, zeitplan: [] }, schadsoftware: { an: true, zeitplan: [] } } };
    if (vorlage) Object.assign(profil, { kategorien: vorlage.kategorien, dienste: vorlage.dienste, ruhezeiten: vorlage.ruhezeiten, sicher: vorlage.sicher, limits: vorlage.limits });
    einst.aendern((x) => { x.profile.push(profil); });
    return profil;
  });
  route('PUT', '/api/profile/:id/vorlage', ({ p, body }) => {
    pruefe(w().profile.some((x) => x.id === p.id), 'Profil unbekannt', 404);
    const v = vorlageWerte(String(body.vorlage || ''));
    einst.aendern((x) => { const pr = x.profile.find((y) => y.id === p.id); Object.assign(pr, { kategorien: v.kategorien, dienste: v.dienste, ruhezeiten: v.ruhezeiten, sicher: v.sicher, limits: v.limits, beschreibung: v.beschreibung }); });
    return { ok: true };
  });
  const zeitplanLesen = (liste) => {
    const zeitplan = (Array.isArray(liste) ? liste : []).slice(0, 14).map((f) => ({ tage: (f.tage || []).map(Number).filter((t) => t >= 1 && t <= 7), von: String(f.von), bis: String(f.bis) }));
    for (const f of zeitplan) pruefe(/^\d{1,2}:\d{2}$/.test(f.von) && /^\d{1,2}:\d{2}$/.test(f.bis) && f.tage.length, 'Zeitplan: Tage und Uhrzeiten (HH:MM) angeben');
    return zeitplan;
  };
  route('PUT', '/api/profile/:id', ({ p, body }) => {
    pruefe(w().profile.some((x) => x.id === p.id), 'Profil unbekannt', 404);
    // Kinderschutz: Ruhezeiten je Rubrik, sichere Suche, Tageslimits
    let ruhezeiten = null, sicher = null, limits = null;
    if (body.ruhezeiten && typeof body.ruhezeiten === 'object') {
      ruhezeiten = {};
      for (const [r, z] of Object.entries(body.ruhezeiten)) { pruefe(kinderschutz.RUHE_RUBRIKEN.includes(r), `Rubrik ohne Ruhezeit: ${r}`); const zp = zeitplanLesen(z); if (zp.length) ruhezeiten[r] = zp; }
    }
    if (body.sicher && typeof body.sicher === 'object') { pruefe(['aus', 'moderat', 'streng'].includes(body.sicher.youtube || 'aus'), 'YouTube: aus, moderat oder streng'); sicher = { suche: !!body.sicher.suche, youtube: body.sicher.youtube || 'aus' }; }
    if (body.limits && typeof body.limits === 'object') {
      limits = {};
      for (const [ziel, m] of Object.entries(body.limits)) { pruefe(limitZielOk(ziel), `Zeitlimit: Ziel unbekannt (${ziel})`); const n = Math.round(+m); pruefe(n >= 5 && n <= 1440, 'Zeitlimit: 5 bis 1440 Minuten'); limits[ziel] = n; }
    }
    const kategorien = {};
    for (const [kid, kw] of Object.entries(body.kategorien || {})) {
      const kat = w().kategorien.find((c) => c.id === kid);
      pruefe(kat, `Kategorie unbekannt: ${kid}`);
      if (kat.art === 'erlauben') continue;   // Freigabelisten sind keine Sperrkategorie (ältere Oberflächen schickten sie mit)
      const zeitplan = (kw.zeitplan || []).slice(0, 14).map((f) => ({ tage: (f.tage || []).map(Number).filter((t) => t >= 1 && t <= 7), von: String(f.von), bis: String(f.bis) }));
      for (const f of zeitplan) pruefe(/^\d{1,2}:\d{2}$/.test(f.von) && /^\d{1,2}:\d{2}$/.test(f.bis) && f.tage.length, 'Zeitplan: Tage und Uhrzeiten (HH:MM) angeben');
      kategorien[kid] = { an: !!kw.an, zeitplan };
    }
    // Ausnahmen je Dienst (z. B. im Profil „Kinder“: TikTok sperren, WhatsApp erlauben)
    let profilDienste = null;
    if (body.dienste && typeof body.dienste === 'object') {
      profilDienste = {};
      for (const [did, wert] of Object.entries(body.dienste)) {
        const d = dienstKatalog.DIENSTE.find((x) => x.id === did); pruefe(d, `Dienst unbekannt: ${did}`);
        if (d.fest) continue;   // Hilfsangebote sind nie sperrbar
        if (wert === 'frei' || wert === 'sperren' || wert === 'listen') profilDienste[did] = wert;
      }
    }
    einst.aendern((x) => { const pr = x.profile.find((y) => y.id === p.id); if (body.name) pr.name = String(body.name).slice(0, 40); if (/^#[0-9a-f]{6}$/i.test(body.farbe || '')) pr.farbe = body.farbe; if (body.kategorien) pr.kategorien = kategorien; if (profilDienste) pr.dienste = profilDienste; if (ruhezeiten) pr.ruhezeiten = ruhezeiten; if (sicher) pr.sicher = sicher; if (limits) pr.limits = limits; });
    return { ok: true };
  });
  route('DELETE', '/api/profile/:id', ({ p }) => {
    pruefe(p.id !== 'standard', 'Das Profil „Standard“ bleibt');
    einst.aendern((x) => { x.profile = x.profile.filter((y) => y.id !== p.id); for (const g of Object.values(x.geraete)) if (g.profil === p.id) delete g.profil; });
    return { ok: true };
  });

  // ── Einstellungen ─────────────────────────────────────────────────────────
  route('GET', '/api/einstellungen', ({ req }) => ({ ...einst.oeffentlich(), verbindung: verbindung(req) }));
  route('PUT', '/api/einstellungen', ({ body }) => {
    const aenderung = {};
    if (body.upstream) {
      const liste = body.upstream.slice(0, 5).map((u) => { let url; try { url = new URL(u.url); } catch (e) { throw new HttpFehler(400, `Ungültige DoH-Adresse: ${u.url}`); } pruefe(url.protocol === 'https:', 'DoH-Adressen müssen https sein'); return { name: String(u.name || url.hostname).slice(0, 40), url: url.href }; });
      pruefe(liste.length, 'Mindestens ein Anbieter');
      aenderung.upstream = liste;
    }
    if (body.dns) {
      const d = {};
      if (body.dns.erlaubteNetze) { let n; try { n = body.dns.erlaubteNetze.map((s) => netz(s).text); } catch (e) { throw new HttpFehler(400, e.message); } pruefe(n.length, 'Mindestens ein erlaubtes Netz'); d.erlaubteNetze = n; }
      if (body.dns.lokaleZonen) d.lokaleZonen = body.dns.lokaleZonen.map((z) => normDomain(z) || String(z).toLowerCase()).filter((z) => /^[a-z0-9.-]+$/.test(z)).slice(0, 30);
      if (body.dns.lokaleRecords !== undefined) {
        pruefe(Array.isArray(body.dns.lokaleRecords), 'Lokale Records als Liste');
        d.lokaleRecords = body.dns.lokaleRecords.slice(0, 100).map((r) => {
          const host = (String((r && r.host) || '').trim().startsWith('*.') ? String(r.host).trim().toLowerCase() : normDomain(r && r.host)) || String((r && r.host) || '').toLowerCase().trim();
          pruefe(host && /^(\*\.)?[a-z0-9.-]+$/.test(host), `Ungültiger Name für lokalen Record: ${(r && r.host) || ''}`);
          const ip = String((r && r.ip) || '').trim();
          pruefe(net.isIP(ip), `Ungültige IP bei ${host}: ${(r && r.ip) || ''}`);
          return { host, ip };
        });
      }
      if (body.dns.gateway !== undefined) { const g = String(body.dns.gateway || '').trim(); pruefe(!g || net.isIP(g), 'Gateway als IP-Adresse angeben (z. B. 192.168.1.1)'); d.gateway = g; }
      aenderung.dns = d;
    }
    if (body.sperrseite) aenderung.sperrseite = { an: !!body.sperrseite.an };
    if (body.protokoll?.tage !== undefined) aenderung.tage = Math.max(1, Math.min(90, Math.round(+body.protokoll.tage)));
    if (body.web?.vertrauteProxies !== undefined) {
      pruefe(Array.isArray(body.web.vertrauteProxies), 'Vertraute Proxys als Liste');
      let n; try { n = body.web.vertrauteProxies.slice(0, 20).map((s) => netz(s).text); } catch (e) { throw new HttpFehler(400, e.message); }
      aenderung.web = { vertrauteProxies: n };
    }
    einst.aendern((x) => {
      if (aenderung.upstream) x.upstream = aenderung.upstream;
      if (aenderung.dns) x.dns = { ...x.dns, ...aenderung.dns };
      if (aenderung.sperrseite) x.sperrseite = aenderung.sperrseite;
      if (aenderung.tage) x.protokoll.tage = aenderung.tage;
      if (aenderung.web) x.web = { ...(x.web || {}), ...aenderung.web };
    });
    return einst.oeffentlich();
  });
  route('POST', '/api/einstellungen/unifi', ({ body }) => {
    const url = String(body.url || '').trim().replace(/\/$/, '');
    pruefe(!url || /^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(url), 'UniFi-Adresse als https://IP');
    pruefe(!body.schluessel || /^[A-Za-z0-9_\-.]{16,200}$/.test(body.schluessel), 'API-Schlüssel hat ein unerwartetes Format');
    einst.setzeUnifi(url, body.schluessel || undefined);
    geraete.unifiLesen().catch(() => {});
    return einst.oeffentlich();
  });
  route('POST', '/api/einstellungen/unifi/test', async () => { const n = await geraete.unifiLesen(); return { ok: n !== false, geraete: n || 0, fehler: geraete.fehler }; });
  route('POST', '/api/cache/leeren', () => { upstream.leeren(); return { ok: true }; });
  route('GET', '/api/sicherung', ({ res }) => { res.setHeader('Content-Disposition', `attachment; filename="fah-adblock-sicherung-${new Date().toISOString().slice(0, 10)}.json"`); const s = einst.oeffentlich(); delete s.unifi; return { art: 'fah-adblock-sicherung', version, erstellt: Date.now(), einstellungen: s }; });
  // Sicherung prüfen wie die einzelnen API-Aufrufe – eine kaputte Datei darf nie übernommen werden
  // (der nächste Start würde sonst scheitern und das Heimnetz stünde ohne DNS)
  const sicherungPruefen = (s) => {
    const objekt = (x) => x && typeof x === 'object' && !Array.isArray(x);
    const f = (t) => { throw new HttpFehler(400, `Sicherung nicht übernommen: ${t}`); };
    const liste = (name, pruefung) => { if (s[name] === undefined) return; if (!Array.isArray(s[name])) f(`„${name}“ ist keine Liste`); s[name].forEach((e, i) => { if (!objekt(e) || typeof e.id !== 'string' || !e.id) f(`${name} Nr. ${i + 1} ohne ID`); pruefung(e, i); }); };
    const httpUrl = (u, was) => { let x; try { x = new URL(String(u)); } catch (e) { f(`${was}: ungültige Adresse „${u}“`); } if (!['https:', 'http:'].includes(x.protocol)) f(`${was}: nur http(s)-Adressen`); return x; };
    const kategorien = new Set([...(Array.isArray(s.kategorien) ? s.kategorien : w().kategorien).map((k) => k?.id)]);
    liste('kategorien', (k) => { if (typeof k.name !== 'string') f(`Kategorie „${k.id}“ ohne Namen`); });
    { const ids = new Set(); for (const l of Array.isArray(s.listen) ? s.listen : []) { if (l && !listenIdOk(l.id)) f(`Liste „${String(l.id).slice(0, 40)}“: ID ungültig (nur Buchstaben, Ziffern, - und _)`); if (l && ids.has(l.id)) f(`Liste „${l.id}“ doppelt`); if (l) ids.add(l.id); } }
    liste('listen', (l) => { if (String(l.url).startsWith('eingebaut:')) { if (l.url !== 'eingebaut:anonym') f(`Liste „${l.id}“: eingebaute Liste unbekannt`); } else httpUrl(l.url, `Liste „${l.id}“`); if (!kategorien.has(l.kategorie)) f(`Liste „${l.id}“: Kategorie „${l.kategorie}“ unbekannt`); });
    liste('profile', (p) => { if (typeof p.name !== 'string' || !p.name) f(`Profil „${p.id}“ ohne Namen`); if (p.kategorien !== undefined && !objekt(p.kategorien)) f(`Profil „${p.id}“: Kategorien ungültig`); for (const [kid, kw] of Object.entries(p.kategorien || {})) { if (!kategorien.has(kid)) f(`Profil „${p.id}“: Kategorie „${kid}“ unbekannt`); if (!objekt(kw) || (kw.zeitplan !== undefined && !Array.isArray(kw.zeitplan))) f(`Profil „${p.id}“: Kategorie „${kid}“ ungültig`); } if (p.dienste !== undefined && !objekt(p.dienste)) f(`Profil „${p.id}“: Dienste ungültig`); if (p.ruhezeiten !== undefined && (!objekt(p.ruhezeiten) || !Object.values(p.ruhezeiten).every(Array.isArray))) f(`Profil „${p.id}“: Ruhezeiten ungültig`); if (p.limits !== undefined && (!objekt(p.limits) || !Object.entries(p.limits).every(([z, m]) => limitZielOk(z) && Number(m) >= 5 && Number(m) <= 1440))) f(`Profil „${p.id}“: Zeitlimits ungültig`); if (p.sicher !== undefined && !objekt(p.sicher)) f(`Profil „${p.id}“: sichere Suche ungültig`); });
    if (Array.isArray(s.profile) && !s.profile.some((p) => p.id === 'standard')) f('Profil „Standard“ fehlt');
    const profile = Array.isArray(s.profile) ? s.profile : w().profile;
    const geltungOk = (g) => g === 'alle' || /^geraet:.{1,64}$/.test(g) || (String(g).startsWith('profil:') && profile.some((p) => `profil:${p.id}` === g));
    liste('regeln', (r) => { if (!['erlauben', 'sperren'].includes(r.typ)) f(`Regel „${r.id}“: Typ muss erlauben oder sperren sein`); try { musterLesen(r.muster); } catch (e) { f(`Regel „${r.id}“: ${e.message}`); } if (!geltungOk(String(r.geltung || 'alle'))) f(`Regel „${r.id}“: Geltung ungültig`); });
    if (s.upstream !== undefined) { if (!Array.isArray(s.upstream) || !s.upstream.length) f('mindestens ein DoH-Anbieter'); for (const u of s.upstream) { if (!objekt(u)) f('DoH-Anbieter ungültig'); if (httpUrl(u.url, 'DoH-Anbieter').protocol !== 'https:') f(`DoH-Adresse ${u.url} muss https sein`); } }
    for (const name of ['geraete', 'dienste']) if (s[name] !== undefined) { if (!objekt(s[name])) f(`„${name}“ ist kein Objekt`); for (const [k, e] of Object.entries(s[name])) if (!objekt(e)) f(`${name}: Eintrag „${k}“ ungültig`); }
    for (const [k, g] of Object.entries(s.geraete || {})) if (g.profil !== undefined && !profile.some((p) => p.id === g.profil)) f(`Gerät „${k}“: Profil „${g.profil}“ unbekannt`);
    for (const [k, d] of Object.entries(s.dienste || {})) { if (d.modus !== undefined && !['frei', 'listen', 'sperren'].includes(d.modus)) f(`Dienst „${k}“: Zustand ungültig`); if (d.geltung !== undefined && !geltungOk(String(d.geltung))) f(`Dienst „${k}“: Geltung ungültig`); }
    if (s.dns !== undefined) {
      if (!objekt(s.dns)) f('„dns“ ist kein Objekt');
      if (s.dns.erlaubteNetze !== undefined) { if (!Array.isArray(s.dns.erlaubteNetze) || !s.dns.erlaubteNetze.length) f('mindestens ein erlaubtes Netz'); try { s.dns.erlaubteNetze.forEach(netz); } catch (e) { f(e.message); } }
      if (s.dns.lokaleZonen !== undefined && (!Array.isArray(s.dns.lokaleZonen) || !s.dns.lokaleZonen.every((z) => typeof z === 'string' && /^[a-z0-9.-]+$/i.test(z)))) f('lokale Zonen ungültig');
      if (s.dns.lokaleRecords !== undefined && (!Array.isArray(s.dns.lokaleRecords) || !s.dns.lokaleRecords.every((r) => r && typeof r === 'object' && typeof r.host === 'string' && /^(\*\.)?[a-z0-9.-]+$/i.test(r.host) && net.isIP(String(r.ip))))) f('lokale Records ungültig');
      if (s.dns.gateway !== undefined && s.dns.gateway !== '' && !net.isIP(String(s.dns.gateway))) f(`Gateway „${s.dns.gateway}“ ist keine IP-Adresse`);
      if (s.dns.bremse !== undefined && (!objekt(s.dns.bremse) || !(s.dns.bremse.rate > 0) || !(s.dns.bremse.schub > 0))) f('Bremse ungültig');
    }
    if (s.meldungen !== undefined && (!objekt(s.meldungen) || (s.meldungen.profile !== undefined && !Array.isArray(s.meldungen.profile)) || (s.meldungen.kategorien !== undefined && !Array.isArray(s.meldungen.kategorien)))) f('Meldungen ungültig');
    if (s.unterwegs !== undefined && objekt(s.unterwegs) && ((s.unterwegs.basis && !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(String(s.unterwegs.basis))) || (s.unterwegs.email && !/^[^\s@<>]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(String(s.unterwegs.email))))) f('Schutz unterwegs: Basisdomain oder E-Mail ungültig');
    if (s.unterwegs !== undefined && (!objekt(s.unterwegs) || (s.unterwegs.geraete !== undefined && !objekt(s.unterwegs.geraete)) || !Object.values(s.unterwegs.geraete || {}).every((g) => objekt(g) && /^dns-[a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?$/.test(String(g.kennung)) && /^[A-Za-z0-9_-]{20,64}$/.test(String(g.geheim))))) f('Schutz unterwegs ungültig');
    if (s.protokoll !== undefined && (!objekt(s.protokoll) || (s.protokoll.tage !== undefined && !(Number(s.protokoll.tage) >= 1 && Number(s.protokoll.tage) <= 90)))) f('Protokoll-Tage: 1 bis 90');
    if (s.web !== undefined) { if (!objekt(s.web)) f('„web“ ist kein Objekt'); if (s.web.vertrauteProxies !== undefined) { if (!Array.isArray(s.web.vertrauteProxies)) f('vertraute Proxys als Liste'); try { s.web.vertrauteProxies.forEach(netz); } catch (e) { f(e.message); } } }
  };
  /** Geprüfte Sicherung übernehmen; `pausen` nur beim Abgleich mit dem Haupt (eine Sicherungsdatei bringt alte Pausen mit). */
  const sicherungAnwenden = (s, { pausen = false } = {}) => {
    sicherungPruefen(s);
    einst.aendern((x) => {
      if (pausen && s.pausen && typeof s.pausen === 'object') x.pausen = { global: Number(s.pausen.global) || 0, geraete: s.pausen.geraete && typeof s.pausen.geraete === 'object' ? { ...s.pausen.geraete } : {} };
      for (const kk of ['upstream', 'listen', 'profile', 'geraete', 'regeln', 'kategorien', 'dienste']) if (Array.isArray(s[kk]) || ((kk === 'geraete' || kk === 'dienste') && s[kk] && typeof s[kk] === 'object')) x[kk] = s[kk];
      if (s.dns) { const { erlaubteNetze, lokaleZonen, lokaleRecords, gateway, bremse } = s.dns; x.dns = { ...x.dns, ...(erlaubteNetze !== undefined ? { erlaubteNetze } : {}), ...(lokaleZonen !== undefined ? { lokaleZonen } : {}), ...(lokaleRecords !== undefined ? { lokaleRecords } : {}), ...(gateway !== undefined ? { gateway } : {}), ...(bremse !== undefined ? { bremse } : {}) }; }
      if (s.protokoll?.tage !== undefined) x.protokoll = { ...x.protokoll, tage: Math.round(Number(s.protokoll.tage)) };
      if (typeof s.sperrseite?.an === 'boolean') x.sperrseite = { an: s.sperrseite.an };
      // Kinderschutz: Meldungen (ältere Sicherungen bringen noch ntfy-Felder mit – werden nicht übernommen)
      if (s.meldungen && typeof s.meldungen === 'object') { const { url, thema, schluessel, schluesselGesetzt, ...rest } = s.meldungen; x.meldungen = { ...x.meldungen, ...rest }; }
      if (s.unterwegs && typeof s.unterwegs === 'object') x.unterwegs = { an: !!s.unterwegs.an, basis: String(s.unterwegs.basis || ''), email: String(s.unterwegs.email || ''), geraete: { ...(s.unterwegs.geraete || {}) },
        // eigene lokale Namen (Apple-Profil) gehören mit – vorher gingen sie am Ersatz bei jedem Abgleich und beim Wiederherstellen verloren (Codex R-R1-009)
        ausnahmen: [...new Set((Array.isArray(s.unterwegs.ausnahmen) ? s.unterwegs.ausnahmen : []).map((d) => String(d).trim().toLowerCase().replace(/^\*?\./, '').replace(/\.$/, '')).filter((d) => AUSNAHME.test(d)))].slice(0, 50) };
      if (s.web?.vertrauteProxies !== undefined) x.web = { ...(x.web || {}), vertrauteProxies: s.web.vertrauteProxies.map((n) => netz(n).text) };
    });
  };
  route('POST', '/api/wiederherstellung', ({ body }) => {
    pruefe(body?.art === 'fah-adblock-sicherung' && body.einstellungen && typeof body.einstellungen === 'object', 'Keine FAH-Adblock-Sicherung');
    sicherungAnwenden(body.einstellungen);
    return { ok: true };
  });

  // ── Haupt/Ersatz (Fail-over) ──────────────────────────────────────────────
  if (spiegel) {
    spiegel.anwenden = (s, o) => sicherungAnwenden(s, o);
    route('GET', '/api/spiegel', () => spiegel.status());
    route('POST', '/api/spiegel/haupt', () => ({ ...spiegel.hauptWerden(), status: spiegel.status() }));
    route('POST', '/api/spiegel/ersatz', async ({ body }) => spiegel.ersatzWerden(body.url, body.code));
    route('POST', '/api/spiegel/abgleichen', async () => spiegel.abgleichen());
    route('POST', '/api/spiegel/loesen', () => spiegel.loesen());
    route('POST', '/api/spiegel/partner', async ({ body }) => {
      pruefe(body.bestaetigt === true, 'Bitte ausdrücklich bestätigen');
      try { return await spiegel.partnerKoppeln({ rolle: body.rolle, url: body.url, name: body.name, passwort: body.passwort, eigene_url: body.eigene_url }); } catch (e) { throw new HttpFehler(e.status || 502, e.message); }
    });
    // Vom Ersatz (ohne Sitzung): signierter, verschlüsselter Umschlag – der Kopplungscode selbst geht nie über die Leitung (25.11.2026, K2).
    // Kinderschutz: Ereignisse und Nutzung des Ersatzes → aufgebrauchte Zeitlimits und Unterwegs-Paket zurück
    route('POST', '/api/spiegel/meldung', ({ body }) => {
      try { return spiegel.meldungFuer(body); } catch (e) { throw new HttpFehler(e.status || 500, e.message); }
    }, { offen: true });
    route('POST', '/api/spiegel/stand', ({ req, body }) => {
      try { return spiegel.standFuer(body, verbindung(req).client); } catch (e) { throw new HttpFehler(e.status || 500, e.message); }
    }, { offen: true });
    // alter Ersatz (Bearer-Code per GET) → klarer Hinweis statt Daten; 409 zählt dort als „Haupt lebt“, er übernimmt also nicht
    route('GET', '/api/spiegel/stand', () => { throw new HttpFehler(409, ALT_TEXT); }, { offen: true });
  }
  // Am Ersatz ändert man nichts – sonst wäre es beim nächsten Abgleich wieder weg (Ausnahmen: Instanz-eigene Dinge)
  // Optionale Erweiterungen hängen ihre Routen an (gleicher Schutz: Anmeldung, CSRF, Herkunft, Ersatz nur lesend)
  for (const e of erweiterungen) { try { if (e.routen) e.routen(route, { pruefe, HttpFehler, w }); } catch (x) { console.warn(`[erweiterungen] ${e.name}: Routen: ${x.message}`); } }
  const ERSATZ_ERLAUBT = /^\/api\/(anmelden|abmelden|passwort|spiegel(\/.*)?|cache\/leeren|listen\/aktualisieren|einstellungen\/unifi(\/test)?)$/;

  // ── Verteilung ────────────────────────────────────────────────────────────
  // Unter einem Gerätenamen (dns-…<basis>, von draußen über FAH-Proxy) gibt es nur DoH, die ACME-Prüfung und das Profil – nie Oberfläche oder API
  const nurText = (res, status, text) => { res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); res.end(text); };
  const profilSenden = (res, geheim) => {
    const gid = unterwegs?.geraetVonGeheimnis(geheim), xml = gid ? unterwegs.profil(gid) : null;
    if (!xml) return nurText(res, 404, 'Nicht gefunden');
    res.writeHead(200, { 'Content-Type': 'application/x-apple-aspen-config', 'Content-Disposition': `attachment; filename="fah-adblock-${unterwegs.u.geraete[gid].kennung}.mobileconfig"`, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    return res.end(xml);
  };
  const mikrotikSenden = (res, geheim) => {
    const gid = unterwegs?.geraetVonGeheimnis(geheim), text = gid && unterwegs.mikrotik ? unterwegs.mikrotik(gid) : null;
    if (!text) return nurText(res, 404, 'Nicht gefunden');
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Disposition': `attachment; filename="fah-adblock-${unterwegs.u.geraete[gid].kennung}.rsc"`, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    return res.end(text);
  };
  // Profil (Apple) oder Einrichtungsdatei (MikroTik) eines Unterwegs-Geräts – das Geheimnis im Pfad ist der Zugang
  const unterwegsDatei = (req, res, url) => {
    const m = /^\/unterwegs\/([A-Za-z0-9_-]{20,64})\/(profil\.mobileconfig|reiserouter\.rsc)$/.exec(url.pathname);
    if (!m || req.method !== 'GET') return false;
    (m[2] === 'reiserouter.rsc' ? mikrotikSenden : profilSenden)(res, m[1]);
    return true;
  };
  async function geraeteHost(req, res, url, host) {
    const acmeTreffer = /^\/\.well-known\/acme-challenge\/([A-Za-z0-9_-]{8,128})$/.exec(url.pathname);
    if (acmeTreffer && req.method === 'GET') { const a = acme?.antwort(acmeTreffer[1]); return a ? nurText(res, 200, a) : nurText(res, 404, 'Nicht gefunden'); }
    const doh = /^\/dns-query\/([A-Za-z0-9_-]{20,64})$/.exec(url.pathname);
    if (doh && (req.method === 'GET' || req.method === 'POST')) {
      const gid = unterwegs.geraetVonGeheimnis(doh[1]);
      if (!gid || unterwegs.geraetVonHost(host) !== gid) return nurText(res, 404, 'Nicht gefunden');
      return unterwegs.doh(req, res, gid, verbindung(req).client);
    }
    if (unterwegsDatei(req, res, url) !== false) return;
    return nurText(res, 404, 'Nicht gefunden');
  }
  // Jede Anfrage läuft in `bearbeiten`; was dort trotzdem entkommt, fängt der `.catch` – eine unbehandelte Ablehnung beendete
  // früher den ganzen Prozess (DNS mit), z. B. reichte `GET //` (ungültige Adresse vor dem try, 25.11.2026).
  const server = http.createServer((req, res) => {
    bearbeiten(req, res).catch((e) => {
      console.error('[web]', e);
      try { if (res.headersSent) return res.destroy(); res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SICHERHEIT }); res.end(JSON.stringify({ fehler: 'Interner Fehler' })); } catch (x) { req.socket?.destroy(); }
    });
  });
  async function bearbeiten(req, res) {
    try {
      let url;
      try { url = new URL(req.url, 'http://x'); } catch (e) { throw new HttpFehler(400, 'Ungültige Adresse'); }
      const host = String(req.headers.host || '').toLowerCase().split(':')[0];
      if (unterwegs && unterwegs.istHost(host)) return await geraeteHost(req, res, url, host);
      if (unterwegsDatei(req, res, url) !== false) return;
      if (url.pathname.startsWith('/api/')) {
        const r = routen.find((x) => x.methode === req.method && x.re.test(url.pathname));
        if (!r) throw new HttpFehler(404, 'Unbekannte Adresse');
        const nutzer = auth.sitzungLesen(req.headers.cookie);
        if (!r.offen && !nutzer) throw new HttpFehler(401, 'Bitte anmelden');
        if (req.method !== 'GET' && spiegel && spiegel.istErsatz() && !ERSATZ_ERLAUBT.test(url.pathname)) {
          throw new HttpFehler(409, `Diese Instanz ist der Ersatz – Einstellungen kommen alle 2 Minuten vom Haupt (${spiegel.status().haupt_url}). Bitte dort ändern.`);
        }
        if (req.method !== 'GET') {
          const herkunft = req.headers.origin;
          if (herkunft && new URL(herkunft).host !== req.headers.host) throw new HttpFehler(403, 'Fremde Herkunft');
          if (!r.offen && req.headers['x-csrf'] !== nutzer.csrf) throw new HttpFehler(403, 'Sitzung abgelaufen – bitte neu laden');
        }
        const m = r.re.exec(url.pathname), p = Object.fromEntries(r.namen.map((n, i) => [n, m[i + 1]]));
        // Prototype-Pollution: Pfadteile wie __proto__ werden als Objektschlüssel benutzt (Geräte, Dienste, Profile)
        if (Object.values(p).some((x) => { try { return ['__proto__', 'constructor', 'prototype'].includes(decodeURIComponent(x)); } catch (e) { return true; } })) throw new HttpFehler(400, 'Ungültige Adresse');
        // Austausch Ersatz → Haupt darf größer sein (verschlüsselt; Zeitkonto-Altpakete bis 1,5 MB samt Meldungen, Codex R4-003), sonst 2 MB. Die Signatur
        // prüft der Haupt erst NACH dem Lesen – deshalb vorher: Content-Length-Abbruch, Lesefrist und höchstens 2 gleichzeitige Spiegel-Anfragen je Absender
        const spiegelRoute = r.offen && url.pathname.startsWith('/api/spiegel/'), absender = spiegelRoute ? verbindung(req).client : '';
        if (spiegelRoute) { const n = spiegelLaufend.get(absender) || 0; if (n >= 2) throw new HttpFehler(429, 'Zu viele gleichzeitige Anfragen'); spiegelLaufend.set(absender, n + 1); }
        let body;
        try { body = ['POST', 'PUT', 'DELETE'].includes(req.method) ? await koerper(req, url.pathname === '/api/spiegel/meldung' ? 8e6 : 2e6) : {}; }
        finally { if (spiegelRoute) { const n = (spiegelLaufend.get(absender) || 1) - 1; if (n > 0) spiegelLaufend.set(absender, n); else spiegelLaufend.delete(absender); } }
        const ergebnis = await r.fn({ req, res, p, q: url.searchParams, body, nutzer });
        if (ergebnis === undefined) return;
        const text = JSON.stringify(ergebnis);
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SICHERHEIT });
        return res.end(text);
      }
      if (url.pathname === '/sperrseite') {
        const domain = domainAusKopf(req.headers['x-sperr-domain']);
        sperrAufrufe++;
        const grund = domain ? grundText(filter.sperrgrund(domain), w().kategorien || []) : '';
        res.writeHead(403, { 'Content-Type': TYPEN['.html'], 'Cache-Control': 'no-store', ...SICHERHEIT });
        return res.end(sperrseiteHtml({ domain, grund }));
      }
      if (url.pathname === '/sperrseite/zertifikat.crt' && sperrCa && fs.existsSync(sperrCa)) {
        res.writeHead(200, { 'Content-Type': 'application/x-x509-ca-cert', 'Content-Disposition': 'attachment; filename="fah-adblock-sperrseite.crt"', 'Cache-Control': 'no-store', ...SICHERHEIT });
        return fs.createReadStream(sperrCa).pipe(res);
      }
      // statische Dateien
      let datei; try { datei = url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname); } catch (e) { throw new HttpFehler(400, 'Ungültige Adresse'); }
      const voll = path.join(statisch, path.normalize(datei).replace(/^(\.\.[/\\])+/, ''));
      if (!voll.startsWith(statisch) || !fs.existsSync(voll) || fs.statSync(voll).isDirectory()) { datei = '/index.html'; }
      const ziel = voll.startsWith(statisch) && fs.existsSync(voll) && !fs.statSync(voll).isDirectory() ? voll : path.join(statisch, 'index.html');
      if (ziel.endsWith('index.html')) {
        const html = fs.readFileSync(ziel, 'utf8').replace(/((?:app|domaininfo)\.(?:js|css))"/g, `$1?v=${encodeURIComponent(version)}"`);
        res.writeHead(200, { 'Content-Type': TYPEN['.html'], 'Cache-Control': 'no-store', ...SICHERHEIT });
        return res.end(html);
      }
      res.writeHead(200, { 'Content-Type': TYPEN[path.extname(ziel)] || 'application/octet-stream', 'Cache-Control': 'no-cache', ...SICHERHEIT });
      fs.createReadStream(ziel).pipe(res);
    } catch (e) {
      const status = e.status || 500;
      if (status === 500) console.error('[web]', e);
      if (res.headersSent) return res.destroy();   // Antwort schon begonnen (z. B. Livestrom) – abbrechen statt JSON anhängen
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SICHERHEIT });
      res.end(JSON.stringify({ fehler: status === 500 ? 'Interner Fehler' : e.message }));
    }
  }
  return server;
}

function symbolLaden(sid) {
  return new Promise((ok, nein) => {
    const req = https.get(`https://static.ui.com/fingerprint/0/${sid}_129x129.png`, { lookup, timeout: 8000, headers: { 'User-Agent': 'FAH-Adblock' } }, (res) => {
      if (res.statusCode !== 200 || !/^image\/png/.test(res.headers['content-type'] || '')) { res.resume(); return nein(new Error(`HTTP ${res.statusCode}`)); }
      const teile = []; let n = 0;
      res.on('data', (d) => { n += d.length; if (n > 300000) req.destroy(new Error('zu groß')); else teile.push(d); });
      res.on('end', () => { const buf = Buffer.concat(teile); buf.length > 8 && buf.readUInt32BE(0) === 0x89504e47 ? ok(buf) : nein(new Error('kein PNG')); });
      res.on('error', nein);
    });
    req.on('timeout', () => req.destroy(new Error('Zeitüberschreitung')));
    req.on('error', nein);
  });
}

// Livestrom an alle Zuhörer (25.11.2026, K17): wer nicht mehr liest (Tab im Hintergrund hinter einem Proxy), ließ die Warteschlange bis zur
// Speichergrenze des Containers wachsen → ab 1 MB Rückstau wird die Verbindung getrennt (EventSource verbindet sich selbst neu)
function liveSenden(live, text, grenze = 1e6) {
  for (const res of live) {
    if (res.writableLength > grenze || res.destroyed) { live.delete(res); try { res.destroy(); } catch (e) {} continue; }
    try { res.write(text); } catch (e) { live.delete(res); }
  }
}

// Kompakte Form für den Livestrom
function kompakt(e) {
  return { t: e.ts, g: e.geraet, n: e.geraetName, d: e.domain, y: e.typ, a: e.aktion, r: e.grund, l: e.dienst || e.listen?.[0] || e.regel || e.cname || '', k: e.kategorie || '', c: e.cache ? 1 : 0, m: e.ms };
}

module.exports = { webServer, kompakt, liveSenden };
