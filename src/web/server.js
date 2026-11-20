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
const { COOKIE, LAUFZEIT } = require('../auth');
const { musterLesen } = require('../dns/filter');
const { netz, netzliste, normIp, normDomain } = require('../netz');
const { lookup } = require('../aufloeser');

const TYPEN = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.webmanifest': 'application/manifest+json' };
const SICHERHEIT = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

class HttpFehler extends Error { constructor(status, text) { super(text); this.status = status; } }
const pruefe = (bed, text, status = 400) => { if (!bed) throw new HttpFehler(status, text); };
const id = () => crypto.randomBytes(6).toString('hex');

function webServer(k) {
  const { auth, einst, listen, filter, upstream, dns, geraete, protokoll, live, version, statisch, daten = null, spiegel = null, sperrCa = '' } = k;
  let sperrAufrufe = 0;
  const routen = [];
  const route = (methode, muster, fn, { offen = false } = {}) => {
    const namen = [], re = new RegExp('^' + muster.replace(/:([a-z]+)/g, (_, n) => { namen.push(n); return '([^/]+)'; }) + '$');
    routen.push({ methode, re, namen, fn, offen });
  };
  const koerper = (req) => new Promise((ok, nein) => {
    let t = ''; req.on('data', (d) => { t += d; if (t.length > 2e6) { nein(new HttpFehler(413, 'Anfrage zu groß')); req.destroy(); } });
    req.on('end', () => { if (!t) return ok({}); try { ok(JSON.parse(t)); } catch (e) { nein(new HttpFehler(400, 'Ungültiges JSON')); } });
    req.on('error', nein);
  });
  const w = () => einst.werte;
  const minuten = (m) => Math.max(0, Math.min(7 * 24 * 60, Math.round(+m || 0)));
  const grenze = (wert, vorgabe, max) => Math.max(1, Math.min(max, Math.round(+wert) || vorgabe));
  const cookieSetzen = (req, res, wert) => res.setHeader('Set-Cookie', `${COOKIE}=${wert}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${LAUFZEIT / 1000}${req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : ''}`);
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
    const r = auth.anmelden(body.name, body.passwort, verbindung(req).client);
    if (r.fehler) throw new HttpFehler(401, r.fehler);
    cookieSetzen(req, res, r.cookie);
    return { ok: true, standardPasswort: r.standardPasswort };
  }, { offen: true });
  route('POST', '/api/abmelden', ({ res, nutzer }) => { if (nutzer) auth.sitzungenBeenden(nutzer.name); res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`); return { ok: true }; }, { offen: true });
  route('GET', '/api/ich', ({ nutzer }) => ({ name: nutzer.name, standardPasswort: nutzer.standardPasswort, csrf: nutzer.csrf, version, spiegel: spiegel ? { rolle: spiegel.rolle, haupt_url: spiegel.status().haupt_url } : null }));
  route('POST', '/api/passwort', ({ req, res, nutzer, body }) => { const r = auth.passwortAendern(nutzer.name, body.alt, body.neu); if (r.fehler) throw new HttpFehler(400, r.fehler); cookieSetzen(req, res, r.cookie); return { ok: true }; });   // andere Sitzungen sind damit abgemeldet, diese läuft mit neuem Cookie weiter

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
      version, jetzt, kennzahlen: protokoll.kennzahlen(+q.get('stunden') || 24), pause: { global: w().pausen.global > jetzt ? w().pausen.global : 0 },
      dns: dns.status(), upstream: upstream.status(), geraete: geraete.status(),
      listen: { gesamt: ls.gesamt, an: ls.quellen.filter((q) => q.an).length, fehler: ls.quellen.filter((q) => q.an && q.fehler).length, laedt: ls.quellen.some((q) => q.laedt) },
      protokoll: { groesse: protokoll.groesse(), fehler: protokoll.fehler, tage: w().protokoll.tage },
      sperrseite: { an: !!w().sperrseite?.an, aufrufe: sperrAufrufe, zertifikat: !!(sperrCa && fs.existsSync(sperrCa)) },
    };
  });
  route('GET', '/api/verlauf', ({ q }) => protokoll.verlauf(q.get('zeitraum') === '7d' ? '7d' : '24h'));
  route('GET', '/api/top', ({ q }) => {
    const stunden = Math.max(1, Math.min(720, +q.get('stunden') || 24));   // bis 30 Tage
    return protokoll.topDomains({ aktion: q.get('aktion') === 'erlaubt' ? 'erlaubt' : 'geblockt', seit: Date.now() - stunden * 3600000, geraet: q.get('geraet') || '', limit: grenze(q.get('limit'), 15, 50) });
  });
  route('GET', '/api/live', ({ req, res }) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no', ...SICHERHEIT });
    res.write(`retry: 3000\n\n`);
    const letzte = protokoll.ring.slice(-40).map(kompakt);
    res.write(`event: start\ndata: ${JSON.stringify(letzte)}\n\n`);
    live.add(res);
    const puls = setInterval(() => res.write(': puls\n\n'), 20000);
    req.on('close', () => { clearInterval(puls); live.delete(res); });
    return undefined;
  });

  // ── Geräte, Pause, Rettung ────────────────────────────────────────────────
  route('GET', '/api/geraete', () => {
    const jetzt = Date.now(), einstG = w().geraete, stat = protokoll.geraeteStatistik();
    const bekannt = new Set(stat.map((s) => s.id));
    const liste = stat.map((s) => ({ ...s, icon: geraete.iconVon?.(s.id) || null, name: einstG[s.id]?.name || (s.name === s.id || s.name === s.ip ? geraete.nameVon(s.id) || s.name : s.name), eigenerName: !!einstG[s.id]?.name, profil: filter.profilVon(s.id).id, pauseBis: filter.pauseBis(s.id, jetzt) }));
    for (const [gid, g] of Object.entries(einstG)) if (!bekannt.has(gid)) liste.push({ id: gid, icon: geraete.iconVon?.(gid) || null, name: g.name || geraete.nameVon(gid) || gid, eigenerName: !!g.name, ip: '', zuletzt: 0, erlaubt: 0, geblockt: 0, quote: 0, kurve: [], profil: filter.profilVon(gid).id, pauseBis: filter.pauseBis(gid, jetzt) });
    return { geraete: liste, profile: w().profile.map((p) => ({ id: p.id, name: p.name, farbe: p.farbe })) };
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
    einst.aendern((x) => {
      const g = x.geraete[gid] || {};
      if (body.name !== undefined) g.name = String(body.name).trim().slice(0, 60);
      if (body.profil !== undefined) g.profil = body.profil;
      x.geraete[gid] = g;
    });
    return { ok: true };
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
  route('GET', '/api/protokoll', ({ q }) => protokoll.eintraege({ geraet: q.get('geraet') || '', nurGeblockt: q.get('nurGeblockt') === '1', suche: q.get('suche') || '', vor: +q.get('vor') || 0, limit: grenze(q.get('limit'), 100, 500) }));
  route('GET', '/api/pruefen', ({ q }) => {
    const domain = normDomain(q.get('domain')); pruefe(domain, 'Keine gültige Domain');
    const geraet = q.get('geraet') || '';
    return { domain, geraet, ...filter.entscheide({ geraetId: geraet, name: domain }), listen: listen.treffer(domain) };
  });

  // ── Katalog kostenloser DNS-Anbieter ─────────────────────────────────────
  const anbieterKatalog = require('../anbieter');
  route('GET', '/api/anbieter', () => ({ gruppen: anbieterKatalog.GRUPPEN, anbieter: anbieterKatalog.ANBIETER }));

  // ── Dienste (Rubriken wie bei AdGuard) ───────────────────────────────────
  const dienstKatalog = require('../dienste');
  route('GET', '/api/dienste', () => ({ gruppen: dienstKatalog.GRUPPEN, dienste: dienstKatalog.DIENSTE.map((d) => ({ ...d, ...dienstKatalog.modusVon(d, w().dienste || {}) })) }));
  route('PUT', '/api/dienste/:id', ({ p, body }) => {
    const d = dienstKatalog.DIENSTE.find((x) => x.id === p.id); pruefe(d, 'Dienst unbekannt');
    const modus = String(body.modus || (body.gesperrt ? 'sperren' : d.vorgabe));
    pruefe(['frei', 'listen', 'sperren'].includes(modus), 'Unbekannter Zustand');
    const geltung = String(body.geltung || 'alle');
    pruefe(geltung === 'alle' || (geltung.startsWith('profil:') && w().profile.some((x) => `profil:${x.id}` === geltung)) || (geltung.startsWith('geraet:') && geltung.length <= 72), 'Ungültiger Geltungsbereich');
    einst.aendern((x) => { x.dienste = x.dienste || {}; if (modus === d.vorgabe && modus !== 'sperren') delete x.dienste[d.id]; else x.dienste[d.id] = modus === 'sperren' ? { modus, geltung } : { modus }; });
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
  route('POST', '/api/profile', ({ body }) => {
    const name = String(body.name || '').trim().slice(0, 40); pruefe(name, 'Name fehlt');
    const profil = { id: `p-${id()}`, name, farbe: /^#[0-9a-f]{6}$/i.test(body.farbe) ? body.farbe : '#7aa2ff', beschreibung: '', kategorien: { werbung: { an: true, zeitplan: [] }, schadsoftware: { an: true, zeitplan: [] } } };
    einst.aendern((x) => { x.profile.push(profil); });
    return profil;
  });
  route('PUT', '/api/profile/:id', ({ p, body }) => {
    pruefe(w().profile.some((x) => x.id === p.id), 'Profil unbekannt', 404);
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
        if (wert === 'frei' || wert === 'sperren' || wert === 'listen') profilDienste[did] = wert;
      }
    }
    einst.aendern((x) => { const pr = x.profile.find((y) => y.id === p.id); if (body.name) pr.name = String(body.name).slice(0, 40); if (/^#[0-9a-f]{6}$/i.test(body.farbe || '')) pr.farbe = body.farbe; if (body.kategorien) pr.kategorien = kategorien; if (profilDienste) pr.dienste = profilDienste; });
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
    liste('listen', (l) => { httpUrl(l.url, `Liste „${l.id}“`); if (!kategorien.has(l.kategorie)) f(`Liste „${l.id}“: Kategorie „${l.kategorie}“ unbekannt`); });
    liste('profile', (p) => { if (typeof p.name !== 'string' || !p.name) f(`Profil „${p.id}“ ohne Namen`); if (p.kategorien !== undefined && !objekt(p.kategorien)) f(`Profil „${p.id}“: Kategorien ungültig`); for (const [kid, kw] of Object.entries(p.kategorien || {})) { if (!kategorien.has(kid)) f(`Profil „${p.id}“: Kategorie „${kid}“ unbekannt`); if (!objekt(kw) || (kw.zeitplan !== undefined && !Array.isArray(kw.zeitplan))) f(`Profil „${p.id}“: Kategorie „${kid}“ ungültig`); } if (p.dienste !== undefined && !objekt(p.dienste)) f(`Profil „${p.id}“: Dienste ungültig`); });
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
    // vom Ersatz abgerufen: ohne Sitzung, mit Kopplungscode (Bearer)
    route('GET', '/api/spiegel/stand', ({ req }) => {
      const code = /^Bearer\s+(\S+)$/.exec(String(req.headers.authorization || ''));
      try { return spiegel.standFuer(code ? code[1] : '', verbindung(req).client, String(req.headers['x-fah-adblock-url'] || '')); } catch (e) { throw new HttpFehler(e.status || 500, e.message); }
    }, { offen: true });
  }
  // Am Ersatz ändert man nichts – sonst wäre es beim nächsten Abgleich wieder weg (Ausnahmen: Instanz-eigene Dinge)
  const ERSATZ_ERLAUBT = /^\/api\/(anmelden|abmelden|passwort|spiegel(\/.*)?|cache\/leeren|listen\/aktualisieren|einstellungen\/unifi(\/test)?)$/;

  // ── Verteilung ────────────────────────────────────────────────────────────
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    try {
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
        const body = ['POST', 'PUT', 'DELETE'].includes(req.method) ? await koerper(req) : {};
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
      let datei = url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname);
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
      if (!res.headersSent) res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SICHERHEIT });
      res.end(JSON.stringify({ fehler: status === 500 ? 'Interner Fehler' : e.message }));
    }
  });
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

// Kompakte Form für den Livestrom
function kompakt(e) {
  return { t: e.ts, g: e.geraet, n: e.geraetName, d: e.domain, y: e.typ, a: e.aktion, r: e.grund, l: e.dienst || e.listen?.[0] || e.regel || e.cname || '', k: e.kategorie || '', c: e.cache ? 1 : 0, m: e.ms };
}

module.exports = { webServer, kompakt };
