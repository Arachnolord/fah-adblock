// ============================================================================
// Erdacht und programmiert von Fabian Hammer.
// (c) 2026 Fabian Hammer - Alle Rechte vorbehalten. Geistiges Eigentum.
// Unbefugte Vervielfaeltigung, Weitergabe oder Verwertung dieses Quellcodes ohne
// schriftliche Genehmigung des Urhebers ist untersagt.
// ============================================================================
// FAH-Adblock – Start: Einstellungen, Listen, Filter, Upstream, DNS-Server, Protokoll, Web.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Einstellungen } = require('./einstellungen');
const { Listen } = require('./dns/listen');
const { Filter } = require('./dns/filter');
const { Upstream, Lokal } = require('./dns/upstream');
const { DnsServer } = require('./dns/server');
const { Records } = require('./dns/records');
const { Geraete } = require('./geraete');
const { Protokoll } = require('./protokoll');
const { Auth } = require('./auth');
const { webServer, kompakt } = require('./web/server');
const { netzliste } = require('./netz');
const { setzeServer } = require('./aufloeser');
const { Spiegel } = require('./spiegel');

const WURZEL = path.join(__dirname, '..');
const DATEN = process.env.DATEN_DIR || path.join(WURZEL, 'data');
const VERSION = (() => { try { return fs.readFileSync(path.join(WURZEL, 'BUILD_VERSION'), 'utf8').trim(); } catch (e) { return 'dev'; } })();

// Sitzungsgeheimnis: aus der Umgebung oder einmal erzeugt und in data/ gemerkt
function geheimnis() {
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 16) return process.env.SESSION_SECRET;
  const datei = path.join(DATEN, '.geheimnis');
  try { return fs.readFileSync(datei, 'utf8').trim(); } catch (e) {}
  const neu = crypto.randomBytes(32).toString('base64url');
  fs.mkdirSync(DATEN, { recursive: true }); fs.writeFileSync(datei, neu, { mode: 0o600 });
  return neu;
}

async function main() {
  const GEHEIM = geheimnis();
  const einst = new Einstellungen({ verzeichnis: DATEN, geheimnis: GEHEIM }).laden();
  const w = () => einst.werte;
  const listen = new Listen({ verzeichnis: DATEN });
  listen.konfigurieren(w().listen); listen.laden();
  const filter = new Filter({ listen });
  const upstream = new Upstream({ anbieter: w().upstream });
  const lokal = new Lokal({ gateway: w().dns.gateway, zonen: w().dns.lokaleZonen });
  const records = new Records({ eintraege: w().dns.lokaleRecords });
  const protokoll = new Protokoll({ datei: path.join(DATEN, 'protokoll.db'), tage: () => w().protokoll.tage });
  // Gerät zuerst nur per IP bekannt, jetzt mit MAC: Protokoll und eigene Einstellungen (Name/Profil) übernehmen
  // Auch Regeln, Pausen und Dienst-Sperren, die noch auf „geraet:ip:…“ zeigen, gehören jetzt der MAC
  const zuordnung = ({ von, nach, name, seit }) => {
    const n = protokoll.zusammenfuehren(von, nach, seit, name);
    const x = w(), gVon = `geraet:${von}`, gNach = `geraet:${nach}`;
    const betroffen = x.geraete[von] || x.pausen.geraete[von] || x.regeln.some((r) => r.geltung === gVon) || Object.values(x.dienste || {}).some((d) => d.geltung === gVon);
    if (betroffen) einst.aendern((y) => {
      if (y.geraete[von]) { if (!y.geraete[nach]) y.geraete[nach] = y.geraete[von]; delete y.geraete[von]; }
      if (y.pausen.geraete[von]) { y.pausen.geraete[nach] = Math.max(y.pausen.geraete[nach] || 0, y.pausen.geraete[von]); delete y.pausen.geraete[von]; }
      y.regeln = y.regeln.filter((r) => !(r.geltung === gVon && y.regeln.some((z) => z.geltung === gNach && z.muster === r.muster && z.typ === r.typ)));   // gleiche Regel gibt es für die MAC schon
      for (const r of y.regeln) if (r.geltung === gVon) r.geltung = gNach;
      for (const d of Object.values(y.dienste || {})) if (d.geltung === gVon) d.geltung = gNach;
    });
    if (n) console.log(`[geraete] ${von} → ${nach} (${name || '?'}): ${n} Anfragen zugeordnet`);
  };
  const geraete = new Geraete({ zugang: () => einst.unifiZugang(), gateway: () => w().dns.gateway, eigene: () => w().geraete, onZuordnung: zuordnung });
  geraete.vorbelegen(protokoll.bekannteGeraete());
  geraete.starten();
  const erlaubt = netzliste(w().dns.erlaubteNetze);
  const dns = new DnsServer({ sperrseite: () => !!einst.werte.sperrseite?.an, bind: process.env.DNS_BIND || '127.0.0.1', port: +process.env.DNS_PORT || 53, erlaubt, filter, upstream, lokal, records, geraete, bremse: w().dns.bremse });
  const konfigurieren = () => {
    const x = w();
    const alteListen = JSON.stringify(listen.quellen.map((q) => [q.id, q.an, q.url]));
    listen.konfigurieren(x.listen);
    if (JSON.stringify(listen.quellen.map((q) => [q.id, q.an, q.url])) !== alteListen) listen.neuAufbauen();
    filter.konfigurieren({ regeln: x.regeln, profile: x.profile, listen: x.listen, geraete: x.geraete, pausen: x.pausen, dienste: x.dienste || {} });
    if (JSON.stringify(upstream.anbieter.map((a) => [a.name, a.url])) !== JSON.stringify(x.upstream.map((a) => [a.name, a.url]))) { upstream.konfigurieren(x.upstream); upstream.leeren(); }
    lokal.konfigurieren({ gateway: x.dns.gateway, zonen: x.dns.lokaleZonen });
    records.konfigurieren({ eintraege: x.dns.lokaleRecords });
    setzeServer(x.dns.gateway);
    dns.erlaubt = netzliste(x.dns.erlaubteNetze); dns.bremse = x.dns.bremse || dns.bremse;
  };
  konfigurieren();
  einst.beobachten(konfigurieren);

  // Livestrom: Ereignisse sammeln und alle 300 ms gebündelt senden
  const live = new Set(); let stapel = [];
  dns.on('anfrage', (e) => { protokoll.aufnehmen(e); if (live.size) stapel.push(e); });
  dns.on('warnung', (t) => console.warn('[dns]', t));
  setInterval(() => {
    if (!stapel.length || !live.size) { stapel = []; return; }
    const teil = stapel.length > 120 ? stapel.slice(-120) : stapel, extra = stapel.length - teil.length;
    const text = `event: anfragen\ndata: ${JSON.stringify({ e: teil.map(kompakt), extra })}\n\n`;
    stapel = [];
    for (const res of live) res.write(text);
  }, 300).unref();

  // Ereignisschleife beobachten (Diagnose unter Last)
  const { monitorEventLoopDelay } = require('perf_hooks');
  const schleife = monitorEventLoopDelay({ resolution: 10 }); schleife.enable();
  dns.schleife = () => ({ p99: Math.round(schleife.percentile(99) / 1e4) / 100, max: Math.round(schleife.max / 1e4) / 100 });
  setInterval(() => schleife.reset(), 60000).unref();
  await dns.starten();
  console.log(`[fah-adblock] ${VERSION} · DNS auf ${dns.bind}:${dns.port} (UDP/TCP) · erlaubte Netze ${dns.erlaubt.texte.join(', ')}`);
  const port = +process.env.WEB_PORT || 8053;
  // eigene Adresse für den Partner: EIGENE_URL, sonst DNS-Adresse + Web-Port (beide Instanzen laufen im Host-Netz)
  const bind = process.env.DNS_BIND || '';
  const eigeneUrl = process.env.EIGENE_URL || (bind && !['127.0.0.1', '0.0.0.0', '::'].includes(bind) ? `http://${bind}:${+process.env.WEB_PORT || 8053}` : '');
  const spiegel = new Spiegel({ verzeichnis: DATEN, einst, geheimnis: GEHEIM, version: VERSION, eigeneUrl, anwenden: () => { throw new Error('Weboberfläche noch nicht bereit'); } });
  const web = webServer({ sperrCa: path.join(DATEN, 'sperrseite-ca.crt'), auth: new Auth({ verzeichnis: DATEN, geheimnis: GEHEIM }), einst, listen, filter, upstream, dns, geraete, protokoll, live, version: VERSION, statisch: path.join(WURZEL, 'public'), daten: DATEN, spiegel });
  if (spiegel.istErsatz()) { spiegel.starten(); setTimeout(() => spiegel.abgleichen().catch(() => {}), 5000).unref(); }
  web.on('error', (e) => { console.error(`[fah-adblock] Weboberfläche auf Port ${port} nicht startbar: ${e.code === 'EADDRINUSE' ? 'Port ist schon belegt (WEB_PORT in der .env ändern oder ./manage.sh port <PORT>)' : e.message}`); process.exit(1); });
  web.listen(port, process.env.WEB_BIND || '0.0.0.0', () => console.log(`[fah-adblock] Weboberfläche auf Port ${port}`));

  // Listen beim Start (fehlende sofort, sonst nach Fälligkeit) und dann stündlich prüfen
  setTimeout(() => listen.aktualisieren().then((r) => Object.keys(r).length && console.log('[listen]', JSON.stringify(r))).catch(() => {}), 2000).unref();
  setInterval(() => listen.aktualisieren().catch(() => {}), 3600000).unref();
  // abgelaufene Pausen/Regeln aufräumen
  setInterval(() => {
    const jetzt = Date.now(), x = w();
    const alt = Object.values(x.pausen.geraete).some((t) => t < jetzt) || (x.pausen.global && x.pausen.global < jetzt) || x.regeln.some((r) => r.bis && r.bis < jetzt);
    if (alt) einst.aendern((y) => { for (const [g, t] of Object.entries(y.pausen.geraete)) if (t < jetzt) delete y.pausen.geraete[g]; if (y.pausen.global < jetzt) y.pausen.global = 0; y.regeln = y.regeln.filter((r) => !r.bis || r.bis > jetzt); });
  }, 60000).unref();

  const ende = () => { console.log('[fah-adblock] beende …'); dns.stoppen(); protokoll.schliessen(); process.exit(0); };
  process.on('SIGTERM', ende); process.on('SIGINT', ende);
}

main().catch((e) => { console.error('[fah-adblock] Start fehlgeschlagen:', e.message); process.exit(1); });
